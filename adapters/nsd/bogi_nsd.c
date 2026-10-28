\
/*
 * NSD query-path Dig (Model B / R031).
 * mmap image; Auth calls Dig via namedb hooks. Hydrate is query-scoped:
 * after each answer, release non-seed RRs so the host store does not accumulate.
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "nsd.h"
#include "options.h"
#include "query.h"
#include "dname.h"
#include "util.h"
#include "namedb.h"
#include "zonec.h"
#include "difffile.h"
#include "dns.h"
#include "region-allocator.h"
#include "zone.h"
#include "bogi_nsd.h"

#include "bogi23_reader.h"
#include "bogi23_dig.h"
#include "bogi23_export.h"

/* R035a stage timers */
#include <time.h>
#include <stdint.h>
#include <pthread.h>

typedef struct {
        uint64_t lookup_ns;
        uint64_t getrrset_ns;
        uint64_t fmt_ns;
        uint64_t parse_ns;
        uint64_t insert_ns;
        uint64_t lookup_n;
        uint64_t getrrset_n;
        uint64_t fmt_n;
        uint64_t parse_n;
        uint64_t insert_n;
} bogi_nsd_stage_t;

static bogi_nsd_stage_t g_stage;
static pthread_mutex_t g_stage_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_stage_enabled = -1;
static uint64_t g_stage_flush_every = 100;
static uint64_t g_stage_events = 0;
static char g_stage_log[512];

static uint64_t
stage_now_ns(void)
{
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void
stage_init_once(void)
{
        const char *p;
        if (g_stage_enabled >= 0)
                return;
        p = getenv("BOGI_NSD_STAGE_LOG");
        if (p && p[0]) {
                snprintf(g_stage_log, sizeof g_stage_log, "%s", p);
                g_stage_enabled = 1;
        } else {
                g_stage_enabled = 0;
                g_stage_log[0] = '\0';
        }
        p = getenv("BOGI_NSD_STAGE_EVERY");
        if (p && p[0]) {
                unsigned long v = strtoul(p, NULL, 10);
                if (v > 0)
                        g_stage_flush_every = v;
        }
}

static void
stage_add(uint64_t *sum, uint64_t *cnt, uint64_t dt)
{
        stage_init_once();
        if (!g_stage_enabled)
                return;
        pthread_mutex_lock(&g_stage_mu);
        *sum += dt;
        (*cnt)++;
        g_stage_events++;
        if (g_stage_events % g_stage_flush_every == 0) {
                FILE *f = fopen(g_stage_log, "a");
                if (f) {
                        fprintf(f,
                                "{\"events\":%llu,\"lookup_ns\":%llu,\"lookup_n\":%llu,"
                                "\"getrrset_ns\":%llu,\"getrrset_n\":%llu,"
                                "\"fmt_ns\":%llu,\"fmt_n\":%llu,"
                                "\"parse_ns\":%llu,\"parse_n\":%llu,"
                                "\"insert_ns\":%llu,\"insert_n\":%llu}\n",
                                (unsigned long long)g_stage_events,
                                (unsigned long long)g_stage.lookup_ns,
                                (unsigned long long)g_stage.lookup_n,
                                (unsigned long long)g_stage.getrrset_ns,
                                (unsigned long long)g_stage.getrrset_n,
                                (unsigned long long)g_stage.fmt_ns,
                                (unsigned long long)g_stage.fmt_n,
                                (unsigned long long)g_stage.parse_ns,
                                (unsigned long long)g_stage.parse_n,
                                (unsigned long long)g_stage.insert_ns,
                                (unsigned long long)g_stage.insert_n);
                        fclose(f);
                }
        }
        pthread_mutex_unlock(&g_stage_mu);
}


extern int32_t zonec_accept(
        zone_parser_t *parser, const zone_name_t *owner, uint16_t type,
        uint16_t class, uint32_t ttl, uint16_t rdlength, const uint8_t *rdata,
        void *user_data);

typedef struct bogi_zone_slot {
        char apex[256];
        char path[512];
        Bogi23Reader reader;
        int reader_open;
        struct namedb *db;
        struct bogi_zone_slot *next;
} bogi_zone_slot;

static bogi_zone_slot *g_slots = NULL;
static __thread int g_hydrate_depth = 0;

int bogi_nsd_hydrate_depth(void) { return g_hydrate_depth; }

static void
canon_owner(const char *in, char *out, size_t out_sz)
{
        size_t n = 0, i;
        for (i = 0; in[i] && n + 2 < out_sz; i++) {
                char c = in[i];
                if (c >= 'A' && c <= 'Z')
                        c = (char)(c - 'A' + 'a');
                out[n++] = c;
        }
        out[n] = '\0';
        if (n == 0) {
                snprintf(out, out_sz, ".");
                return;
        }
        if (out[n - 1] != '.' && n + 1 < out_sz) {
                out[n++] = '.';
                out[n] = '\0';
        }
}

static int
apex_equal(const char *a, const char *b)
{
        char ca[256], cb[256];
        canon_owner(a, ca, sizeof ca);
        canon_owner(b, cb, sizeof cb);
        return strcmp(ca, cb) == 0;
}

static int
is_under_apex(const char *name, const char *apex)
{
        size_t nl, al;
        if (strcmp(apex, ".") == 0)
                return 1;
        nl = strlen(name);
        al = strlen(apex);
        if (nl < al)
                return 0;
        if (strcmp(name, apex) == 0)
                return 1;
        return (nl > al && name[nl - al - 1] == '.' &&
                strcmp(name + (nl - al), apex) == 0);
}

static bogi_zone_slot *
find_slot_by_apex(const char *apex)
{
        bogi_zone_slot *s;
        for (s = g_slots; s; s = s->next)
                if (apex_equal(apex, s->apex))
                        return s;
        return NULL;
}

static bogi_zone_slot *
find_slot_for_name(const char *name)
{
        bogi_zone_slot *best = NULL;
        size_t best_len = 0;
        bogi_zone_slot *s;
        char q[256];
        canon_owner(name, q, sizeof q);
        for (s = g_slots; s; s = s->next) {
                if (!is_under_apex(q, s->apex))
                        continue;
                if (strlen(s->apex) >= best_len) {
                        best = s;
                        best_len = strlen(s->apex);
                }
        }
        return best;
}

static void
mark_existing(domain_type *d)
{
        while (d && !d->is_existing) {
                d->is_existing = 1;
                d = d->parent;
        }
}

static int
add_slot(const char *apex, const char *path, struct namedb *db)
{
        bogi_zone_slot *slot = find_slot_by_apex(apex);
        if (slot) {
                if (db)
                        slot->db = db;
                return 0;
        }
        slot = calloc(1, sizeof(*slot));
        if (!slot)
                return -1;
        canon_owner(apex, slot->apex, sizeof slot->apex);
        snprintf(slot->path, sizeof slot->path, "%s", path);
        if (bogi23_open(&slot->reader, path) != 0) {
                log_msg(LOG_ERR, "bogi23_open failed: %s", path);
                free(slot);
                return -1;
        }
        slot->reader_open = 1;
        slot->db = db;
        slot->next = g_slots;
        g_slots = slot;
        log_msg(LOG_INFO, "bogi Dig-direct mmap zone=%s file=%s", slot->apex, path);
        return 0;
}

void
bogi_nsd_close_all(void)
{
        bogi_zone_slot *s = g_slots;
        while (s) {
                bogi_zone_slot *n = s->next;
                if (s->reader_open)
                        bogi23_close(&s->reader);
                free(s);
                s = n;
        }
        g_slots = NULL;
}

void
bogi_nsd_open_all(struct nsd *nsd)
{
        const char *apex = getenv("AGENTDNS_NSD_BOGI_APEX");
        const char *file = getenv("AGENTDNS_NSD_BOGI_FILE");
        if (apex && file && *apex && *file)
                (void)add_slot(apex, file, nsd && nsd->db ? nsd->db : NULL);
        if (!g_slots)
                log_msg(LOG_INFO, "bogi: no AGENTDNS_NSD_BOGI_* configured");
}

int
bogi_nsd_try_answer(struct nsd *nsd, struct query *q)
{
        (void)nsd; (void)q;
        return 0;
}

static void
bogi_log_cb(zone_parser_t *parser, uint32_t category, const char *file,
            size_t line, const char *message, void *user_data)
{
        (void)parser; (void)file; (void)line; (void)user_data;
        if (category >= ZONE_ERROR)
                log_msg(LOG_ERR, "bogi lazy: %s", message);
}

static int32_t
bogi_include_cb(zone_parser_t *parser, const char *file, const char *path,
                void *user_data)
{
        (void)parser; (void)file; (void)path; (void)user_data;
        return 0;
}

struct bogi_zonec_state {
        struct namedb *database;
        struct domain_table *domains;
        struct zone *zone;
        struct domain *domain;
        size_t errors;
        size_t records;
};

static int
parse_text_into_zone(struct namedb *db, struct zone *zone, const char *text)
{
        char tmp[160];
        FILE *f;
        zone_parser_t parser;
        zone_options_t options;
        zone_name_buffer_t name_buffer;
        zone_rdata_buffer_t rdata_buffer;
        zone_buffers_t buffers = { 1, &name_buffer, &rdata_buffer };
        const dname_type *origin;
        struct bogi_zonec_state state;
        int rc;
        uint64_t t0, t1;

        t0 = stage_now_ns();
        snprintf(tmp, sizeof tmp, "/tmp/bogi-lazy-%d.zone", (int)getpid());
        f = fopen(tmp, "w");
        if (!f)
                return -1;
        fputs(text, f);
        fclose(f);

        memset(&state, 0, sizeof state);
        state.database = db;
        state.domains = db->domains;
        state.zone = zone;

        origin = domain_dname(zone->apex);
        memset(&options, 0, sizeof options);
        options.origin.octets = dname_name(origin);
        options.origin.length = origin->name_size;
        options.default_ttl = 3600;
        options.default_class = CLASS_IN;
        options.pretty_ttls = true;
        options.log.callback = &bogi_log_cb;
        options.accept.callback = &zonec_accept;
        options.include.callback = &bogi_include_cb;

        g_hydrate_depth++;
        rc = zone_parse(&parser, &options, &buffers, tmp, &state);
        g_hydrate_depth--;
        unlink(tmp);
        t1 = stage_now_ns();
        stage_add(&g_stage.parse_ns, &g_stage.parse_n, t1 - t0);
        return (rc != 0 || state.errors > 0) ? -1 : 0;
}

static int
hydrate_type(struct namedb *db, struct zone *zone, bogi_zone_slot *slot,
             const char *owner, const char *rrtype)
{
        Bogi23OwnerGroup group;
        int found = 0;
        char text[65536];
        size_t i;
        uint16_t tcode;
        const dname_type *odn;
        domain_type *cm = NULL, *ce = NULL;

        /* Already in namedb? (safe under g_hydrate_depth: find_rrset will not re-enter). */
        tcode = rrtype_from_string(rrtype);
        odn = dname_parse(db->region, owner);
        if (tcode && odn &&
            domain_table_search(db->domains, odn, &cm, &ce) && cm &&
            domain_find_rrset(cm, zone, tcode))
                return 0;

        memset(&group, 0, sizeof group);
        {
                uint64_t t0 = stage_now_ns();
                if (bogi23_dig_get_rrset(&slot->reader, owner, rrtype, &group, &found) != 0)
                        return -1;
                stage_add(&g_stage.getrrset_ns, &g_stage.getrrset_n, stage_now_ns() - t0);
        }
        if (!found) {
                bogi23_free_group(&slot->reader, &group);
                return 0;
        }
        if (group.count == 0 || group.sets[0].rdata_count == 0) {
                uint64_t t0 = stage_now_ns();
                const dname_type *dn = dname_parse(db->region, owner);
                if (dn)
                        mark_existing(domain_table_insert(db->domains, dn));
                stage_add(&g_stage.insert_ns, &g_stage.insert_n, stage_now_ns() - t0);
                bogi23_free_group(&slot->reader, &group);
                return 0;
        }
        {
                uint64_t t0 = stage_now_ns();
                text[0] = '\0';
                for (i = 0; i < group.sets[0].rdata_count; i++) {
                        char line[2048];
                        snprintf(line, sizeof line, "%s %llu IN %s %s\n", owner,
                                 (unsigned long long)group.sets[0].ttl,
                                 group.sets[0].rrtype,
                                 group.sets[0].rdatas[i] ? group.sets[0].rdatas[i] : "");
                        if (strlen(text) + strlen(line) + 1 < sizeof text)
                                strcat(text, line);
                }
                stage_add(&g_stage.fmt_ns, &g_stage.fmt_n, stage_now_ns() - t0);
        }
        bogi23_free_group(&slot->reader, &group);
        return parse_text_into_zone(db, zone, text);
}

static void
hydrate_ancestors_ns(struct namedb *db, struct zone *zone, bogi_zone_slot *slot,
                     const char *name)
{
        char cur[512];
        snprintf(cur, sizeof cur, "%s", name);
        for (;;) {
                char *dot;
                if (is_under_apex(cur, slot->apex))
                        (void)hydrate_type(db, zone, slot, cur, "NS");
                if (apex_equal(cur, slot->apex))
                        break;
                dot = strchr(cur, '.');
                if (!dot)
                        break;
                memmove(cur, dot + 1, strlen(dot + 1) + 1);
        }
}

int
bogi_nsd_seed_zone(struct nsd *nsd, struct zone *zone, const char *bogi_path)
{
        char apex_buf[256];
        bogi_zone_slot *slot;
        const char *zname;

        if (!nsd || !nsd->db || !zone || !bogi_path)
                return -1;
        zname = zone->opts && zone->opts->name ? zone->opts->name : "?";
        canon_owner(zname, apex_buf, sizeof apex_buf);
        if (add_slot(apex_buf, bogi_path, nsd->db) != 0)
                return -1;
        slot = find_slot_by_apex(apex_buf);
        if (!slot)
                return -1;

        namedb_zone_free_filenames(nsd->db, zone);
        zone->filename = region_strdup(nsd->db->region, bogi_path);
        delete_zone_rrs(nsd->db, zone);

        if (hydrate_type(nsd->db, zone, slot, apex_buf, "SOA") != 0 ||
            hydrate_type(nsd->db, zone, slot, apex_buf, "NS") != 0 ||
            !zone->soa_rrset) {
                log_msg(LOG_ERR, "bogi Dig-direct seed failed for %s", zname);
                return -1;
        }
        log_msg(LOG_INFO, "bogi Dig-direct seed OK zone=%s (apex SOA+NS)", zname);
        return 0;
}

void
bogi_nsd_lazy_lookup(struct namedb *db, const dname_type *qname)
{
        char name[512];
        char succ[512];
        Bogi23DigLookupKind kind;
        bogi_zone_slot *slot;
        zone_type *zone;
        const dname_type *dn;

        if (!db || !qname || g_hydrate_depth || !g_slots)
                return;
        snprintf(name, sizeof name, "%s", dname_to_string((dname_type *)qname, NULL));
        canon_owner(name, name, sizeof name);
        slot = find_slot_for_name(name);
        if (!slot || !slot->reader_open)
                return;
        dn = dname_parse(db->region, slot->apex);
        if (!dn)
                return;
        zone = namedb_find_zone(db, dn);
        if (!zone)
                return;

        succ[0] = '\0';
        kind = BOGI23_DIG_NONE;
        {
                uint64_t t0 = stage_now_ns();
                if (bogi23_dig_lookup(&slot->reader, name, &kind, succ, sizeof succ) != 0)
                        return;
                stage_add(&g_stage.lookup_ns, &g_stage.lookup_n, stage_now_ns() - t0);
        }

        g_hydrate_depth++;
        hydrate_ancestors_ns(db, zone, slot, name);
        if (kind == BOGI23_DIG_EXACT) {
                const dname_type *qd = dname_parse(db->region, name);
                if (qd)
                        mark_existing(domain_table_insert(db->domains, qd));
                (void)hydrate_type(db, zone, slot, name, "A");
                (void)hydrate_type(db, zone, slot, name, "AAAA");
                (void)hydrate_type(db, zone, slot, name, "NS");
                (void)hydrate_type(db, zone, slot, name, "CNAME");
                (void)hydrate_type(db, zone, slot, name, "MX");
                (void)hydrate_type(db, zone, slot, name, "TXT");
                (void)hydrate_type(db, zone, slot, name, "SOA");
        } else if (kind == BOGI23_DIG_SUCCESSOR && succ[0]) {
                char sc[512];
                const dname_type *sd;
                canon_owner(succ, sc, sizeof sc);
                sd = dname_parse(db->region, sc);
                if (sd)
                        mark_existing(domain_table_insert(db->domains, sd));
        }
        g_hydrate_depth--;
}

void
bogi_nsd_lazy_rrset(struct namedb *db, domain_type *domain, zone_type *zone,
                    uint16_t type)
{
        char name[512];
        const char *ts;
        bogi_zone_slot *slot;

        if (!domain || !zone || g_hydrate_depth || !g_slots)
                return;
        if (!db) {
                slot = find_slot_for_name(domain_to_string(domain));
                db = slot ? slot->db : NULL;
        }
        if (!db)
                return;
        snprintf(name, sizeof name, "%s", domain_to_string(domain));
        canon_owner(name, name, sizeof name);
        slot = find_slot_for_name(name);
        if (!slot || !slot->reader_open)
                return;
        ts = rrtype_to_string(type);
        if (!ts)
                return;
        g_hydrate_depth++;
        (void)hydrate_type(db, zone, slot, name, ts);
        g_hydrate_depth--;
}

void
bogi_nsd_release_zone(struct zone *zone)
{
        bogi_zone_slot *slot;
        char apex_buf[256];
        const char *zname;
        struct namedb *db;

        /* R035b: optionally retain hydrated RRs across queries.
         * R035a showed zone_parse dominates (~76%); releasing after every
         * answer forces repeated text parse on R034-style repeats. */
        {
                const char *keep = getenv("BOGI_NSD_KEEP_HYDRATE");
                if (keep != NULL && keep[0] != 0 && keep[0] != '0')
                        return;
        }

        if (!zone || g_hydrate_depth || !g_slots)
                return;
        zname = zone->opts && zone->opts->name ? zone->opts->name : NULL;
        if (!zname)
                return;
        canon_owner(zname, apex_buf, sizeof apex_buf);
        slot = find_slot_by_apex(apex_buf);
        if (!slot || !slot->reader_open)
                return;
        db = slot->db;
        if (!db)
                return;

        /* Drop everything Auth hydrated this query; re-seed apex only. */
        g_hydrate_depth++;
        delete_zone_rrs(db, zone);
        if (hydrate_type(db, zone, slot, apex_buf, "SOA") != 0 ||
            hydrate_type(db, zone, slot, apex_buf, "NS") != 0 ||
            !zone->soa_rrset) {
                log_msg(LOG_ERR, "bogi Dig-direct re-seed failed zone=%s", zname);
        }
        g_hydrate_depth--;
}

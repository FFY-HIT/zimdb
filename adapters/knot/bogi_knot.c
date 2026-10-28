\
/*
 * Knot DNS query-time lazy Dig (Model B / R026).
 * Startup: apex SOA+NS seed. Query miss: Dig Lookup/GetRRset -> zone_contents.
 * Auth remains Knot solve_name / internet. Answer short-circuit stays off.
 */
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "knot/common/log.h"
#include "knot/nameserver/bogi_knot.h"
#include "knot/zone/adjust.h"
#include "knot/zone/contents.h"
#include "knot/zone/node.h"
#include "knot/zone/zone-tree.h"
#include "knot/zone/zonefile.h"
#include "libknot/libknot.h"
#include "libzscanner/scanner.h"

#include "bogi23_reader.h"
#include "bogi23_dig.h"
#include "bogi23_export.h"

typedef struct bogi_zone_slot {
	char apex[256];
	char path[512];
	Bogi23Reader reader;
	int reader_open;
	zone_contents_t *contents;
	struct bogi_zone_slot *next;
} bogi_zone_slot;

static bogi_zone_slot *g_slots = NULL;
static __thread int g_hydrate_depth = 0;
static pthread_mutex_t g_hydrate_mu = PTHREAD_MUTEX_INITIALIZER;

int bogi_knot_hydrate_depth(void)
{
	return g_hydrate_depth;
}

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

static int
add_slot(const char *apex, const char *path)
{
	bogi_zone_slot *slot = find_slot_by_apex(apex);
	if (slot)
		return 0;
	slot = calloc(1, sizeof(*slot));
	if (!slot)
		return -1;
	canon_owner(apex, slot->apex, sizeof slot->apex);
	snprintf(slot->path, sizeof slot->path, "%s", path);
	if (bogi23_open(&slot->reader, path) != 0) {
		log_error("bogi23_open failed: %s", path);
		free(slot);
		return -1;
	}
	slot->reader_open = 1;
	slot->next = g_slots;
	g_slots = slot;
	log_info("bogi Dig lazy mmap zone=%s file=%s", slot->apex, path);
	return 0;
}

void
bogi_knot_close_all(void)
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
bogi_knot_open_all(void)
{
	const char *apex = getenv("AGENTDNS_KNOT_BOGI_APEX");
	const char *path = getenv("AGENTDNS_KNOT_BOGI_FILE");
	const char *map = getenv("AGENTDNS_KNOT_BOGI_MAP");
	bogi_knot_close_all();
	if (apex && path && *apex && *path)
		(void)add_slot(apex, path);
	if (map && *map) {
		FILE *f = fopen(map, "r");
		char line[1024];
		if (!f) {
			log_error("bogi map open failed: %s", map);
		} else {
			while (fgets(line, sizeof line, f)) {
				char *tab, *nl;
				if (line[0] == '#' || line[0] == '\n')
					continue;
				nl = strchr(line, '\n');
				if (nl)
					*nl = '\0';
				tab = strchr(line, '\t');
				if (!tab)
					tab = strchr(line, ' ');
				if (!tab)
					continue;
				*tab = '\0';
				(void)add_slot(line, tab + 1);
			}
			fclose(f);
		}
	}
	if (!g_slots)
		log_info("bogi: no AGENTDNS_KNOT_BOGI_* configured");
}

int
bogi_knot_try_answer(knot_pkt_t *pkt, knotd_qdata_t *qdata)
{
	(void)pkt;
	(void)qdata;
	return 0;
}

typedef struct {
	zone_contents_t *contents;
	int ret;
} bogi_scan_ctx;

static void
bogi_scan_error(zs_scanner_t *s)
{
	bogi_scan_ctx *ctx = s->process.data;
	log_error("bogi lazy parse: %s", zs_strerror(s->error.code));
	ctx->ret = -1;
	s->state = ZS_STATE_STOP;
}

static void
bogi_scan_data(zs_scanner_t *scanner)
{
	bogi_scan_ctx *ctx = scanner->process.data;
	knot_dname_t *owner;
	knot_rrset_t rr;
	int ret;

	if (ctx->ret != 0) {
		scanner->state = ZS_STATE_STOP;
		return;
	}
	owner = knot_dname_copy(scanner->r_owner, NULL);
	if (!owner) {
		ctx->ret = -1;
		return;
	}
	knot_rrset_init(&rr, owner, scanner->r_type, scanner->r_class, scanner->r_ttl);
	ret = knot_rrset_add_rdata(&rr, scanner->r_data, scanner->r_data_length, NULL);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&rr, NULL);
		ctx->ret = -1;
		return;
	}
	(void)knot_rrset_rr_to_canonical(&rr);
	ret = zcreator_step(ctx->contents, &rr, NULL);
	knot_rrset_clear(&rr, NULL);
	if (ret != KNOT_EOK)
		ctx->ret = -1;
}

static int
parse_text_into_contents(zone_contents_t *contents, const char *origin, const char *text)
{
	zs_scanner_t scanner;
	bogi_scan_ctx ctx = { .contents = contents, .ret = 0 };

	if (zs_init(&scanner, origin, KNOT_CLASS_IN, 3600) != 0)
		return -1;
	if (zs_set_processing(&scanner, bogi_scan_data, bogi_scan_error, &ctx) != 0) {
		zs_deinit(&scanner);
		return -1;
	}
	if (zs_set_input_string(&scanner, text, strlen(text)) != 0) {
		zs_deinit(&scanner);
		return -1;
	}
	if (zs_parse_all(&scanner) != 0 || ctx.ret != 0) {
		zs_deinit(&scanner);
		return -1;
	}
	zs_deinit(&scanner);
	return 0;
}

static zone_node_t *
bogi_new_node_cb(const knot_dname_t *dname, void *ctx)
{
	zone_contents_t *z = ctx;
	return node_new_for_tree(dname, z->nodes, NULL);
}

static int
ensure_node(zone_contents_t *z, const char *owner_str)
{
	knot_dname_storage_t buf;
	knot_dname_t *dn;
	zone_node_t *n = NULL;

	dn = knot_dname_from_str(buf, owner_str, sizeof buf);
	if (!dn)
		return -1;
	if (zone_contents_find_node(z, dn) != NULL)
		return 0;
	return zone_tree_add_node(z->nodes, z->apex, dn, bogi_new_node_cb, z, &n) == KNOT_EOK ? 0 : -1;
}

static int
hydrate_type(zone_contents_t *contents, bogi_zone_slot *slot,
             const char *owner, const char *rrtype)
{
	Bogi23OwnerGroup group;
	int found = 0;
	char text[65536];
	size_t i;
	uint16_t tcode = 0;
	knot_dname_storage_t buf;
	const knot_dname_t *odn;
	const zone_node_t *node;

	if (knot_rrtype_from_string(rrtype, &tcode) != 0)
		return -1;
	odn = knot_dname_from_str(buf, owner, sizeof buf);
	if (odn) {
		node = zone_contents_find_node(contents, odn);
		if (node && node_rdataset(node, tcode) != NULL)
			return 0;
	}

	memset(&group, 0, sizeof group);
	if (bogi23_dig_get_rrset(&slot->reader, owner, rrtype, &group, &found) != 0)
		return -1;
	if (!found) {
		bogi23_free_group(&slot->reader, &group);
		return 0;
	}
	if (group.count == 0 || group.sets[0].rdata_count == 0) {
		(void)ensure_node(contents, owner);
		bogi23_free_group(&slot->reader, &group);
		return 0;
	}
	text[0] = '\0';
	for (i = 0; i < group.sets[0].rdata_count; i++) {
		char line[2048];
		snprintf(line, sizeof line, "%s %u IN %s %s\n", owner,
			 (unsigned)group.sets[0].ttl,
			 group.sets[0].rrtype,
			 group.sets[0].rdatas[i] ? group.sets[0].rdatas[i] : "");
		if (strlen(text) + strlen(line) + 1 < sizeof text)
			strcat(text, line);
	}
	bogi23_free_group(&slot->reader, &group);
	return parse_text_into_contents(contents, slot->apex, text);
}

static void
hydrate_ancestors_ns(zone_contents_t *contents, bogi_zone_slot *slot, const char *name)
{
	char cur[512];
	snprintf(cur, sizeof cur, "%s", name);
	for (;;) {
		char *dot;
		if (is_under_apex(cur, slot->apex))
			(void)hydrate_type(contents, slot, cur, "NS");
		if (apex_equal(cur, slot->apex))
			break;
		dot = strchr(cur, '.');
		if (!dot)
			break;
		memmove(cur, dot + 1, strlen(dot + 1) + 1);
	}
}

static void
adjust_after(zone_contents_t *contents)
{
	if (!contents)
		return;
	/* First phase only here; zone load's zone_update runs zone_adjust_full. */
	(void)zone_adjust_contents(contents, adjust_cb_flags, adjust_cb_nsec3_flags,
	                           true, true, 1, NULL);
}

int
bogi_knot_seed_contents(zone_contents_t **contents, const knot_dname_t *zone_name)
{
	char apex_buf[256];
	bogi_zone_slot *slot;
	zone_contents_t *fresh;

	if (!contents || !*contents || !zone_name)
		return -1;
	if (knot_dname_to_str(apex_buf, zone_name, sizeof apex_buf) == NULL)
		return -1;
	canon_owner(apex_buf, apex_buf, sizeof apex_buf);

	/* Ensure slot from env (open_all may run after zone load). */
	{
		const char *apex = getenv("AGENTDNS_KNOT_BOGI_APEX");
		const char *path = getenv("AGENTDNS_KNOT_BOGI_FILE");
		if (apex && path && *apex && *path && apex_equal(apex, apex_buf))
			(void)add_slot(apex, path);
	}
	slot = find_slot_by_apex(apex_buf);
	if (!slot || !slot->reader_open) {
			return 1; /* not a bogi zone */
	}

	/* Fresh non-binode tree so query-time Dig can mutate safely. */
	/* Harness may Dig-write apex SOA+NS (+glue) into the zonefile.
	 * Replacing with Dig-only SOA/NS drops glue and re-triggers Knot
	 * semantic glue chase via the system resolver (~200 ms). */
	if (*contents && (*contents)->apex &&
	    node_rdataset((*contents)->apex, KNOT_RRTYPE_SOA) != NULL) {
		log_info("bogi Dig lazy seed skip zone=%s (stub SOA present)", apex_buf);
		return 0;
	}
	fresh = zone_contents_new(zone_name, true); /* binodes: required by zone_adjust_full in load */
	if (!fresh)
		return -1;

	g_hydrate_depth++;
	if (hydrate_type(fresh, slot, apex_buf, "SOA") != 0) {
			g_hydrate_depth--;
		zone_contents_deep_free(fresh);
		log_error("bogi lazy seed failed for %s", apex_buf);
		return -1;
	}
	if (hydrate_type(fresh, slot, apex_buf, "NS") != 0) {
			g_hydrate_depth--;
		zone_contents_deep_free(fresh);
		log_error("bogi lazy seed failed for %s", apex_buf);
		return -1;
	}
	if (node_rdataset(fresh->apex, KNOT_RRTYPE_SOA) == NULL) {
			g_hydrate_depth--;
		zone_contents_deep_free(fresh);
		log_error("bogi lazy seed failed for %s", apex_buf);
		return -1;
	}
	g_hydrate_depth--;
	adjust_after(fresh);

	zone_contents_deep_free(*contents);
	*contents = fresh;
	slot->contents = fresh;
	log_info("bogi Dig lazy seed OK zone=%s (apex SOA+NS)", apex_buf);
	return 0;
}

void
bogi_knot_lazy_lookup(zone_contents_t *contents, const knot_dname_t *qname)
{
	char name[512];
	char succ[512];
	Bogi23DigLookupKind kind;
	bogi_zone_slot *slot;

	if (!contents || !qname || g_hydrate_depth || !g_slots)
		return;
	if (knot_dname_to_str(name, qname, sizeof name) == NULL)
		return;
	canon_owner(name, name, sizeof name);
	slot = find_slot_for_name(name);
	if (!slot || !slot->reader_open)
		return;
	if (slot->contents == NULL)
		slot->contents = contents;
	if (slot->contents != contents)
		return;

	succ[0] = '\0';
	kind = BOGI23_DIG_NONE;
	if (bogi23_dig_lookup(&slot->reader, name, &kind, succ, sizeof succ) != 0)
		return;

	pthread_mutex_lock(&g_hydrate_mu);
	g_hydrate_depth++;
	hydrate_ancestors_ns(contents, slot, name);
	if (kind == BOGI23_DIG_EXACT) {
		(void)ensure_node(contents, name);
		(void)hydrate_type(contents, slot, name, "A");
		(void)hydrate_type(contents, slot, name, "AAAA");
		(void)hydrate_type(contents, slot, name, "NS");
		(void)hydrate_type(contents, slot, name, "CNAME");
		(void)hydrate_type(contents, slot, name, "MX");
		(void)hydrate_type(contents, slot, name, "TXT");
		(void)hydrate_type(contents, slot, name, "SOA");
	} else if (kind == BOGI23_DIG_SUCCESSOR && succ[0]) {
		char sc[512];
		canon_owner(succ, sc, sizeof sc);
		(void)ensure_node(contents, sc);
	}
	adjust_after(contents);
	g_hydrate_depth--;
	pthread_mutex_unlock(&g_hydrate_mu);
}

void
bogi_knot_lazy_rrset(const zone_node_t *node, uint16_t type)
{
	char name[512];
	char tbuf[32];
	bogi_zone_slot *slot;
	zone_contents_t *contents;

	if (!node || g_hydrate_depth || !g_slots)
		return;
	/* DNSSEC proofs not in Dig store for these zones; avoid useless hydrate. */
	if (type == KNOT_RRTYPE_RRSIG || type == KNOT_RRTYPE_NSEC ||
	    type == KNOT_RRTYPE_NSEC3 || type == KNOT_RRTYPE_NSEC3PARAM ||
	    type == KNOT_RRTYPE_DNSKEY || type == KNOT_RRTYPE_DS)
		return;
	if (knot_dname_to_str(name, node->owner, sizeof name) == NULL)
		return;
	canon_owner(name, name, sizeof name);
	slot = find_slot_for_name(name);
	if (!slot || !slot->reader_open || !slot->contents)
		return;
	contents = slot->contents;
	if (knot_rrtype_to_string(type, tbuf, sizeof tbuf) < 0)
		return;

	pthread_mutex_lock(&g_hydrate_mu);
	g_hydrate_depth++;
	(void)hydrate_type(contents, slot, name, tbuf);
	adjust_after(contents);
	g_hydrate_depth--;
	pthread_mutex_unlock(&g_hydrate_mu);
}

void
bogi_knot_release_contents(zone_contents_t **contents, const knot_dname_t *zone_name)
{
	if (!contents || !zone_name || bogi_knot_hydrate_depth() > 0)
		return;
	(void)bogi_knot_seed_contents(contents, zone_name);
}

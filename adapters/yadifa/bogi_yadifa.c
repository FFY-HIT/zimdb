\
#include <strings.h>
/*
 * YADIFA query-time lazy Dig (Model B / R028).
 * Env: AGENTDNS_YADIFA_BOGI_APEX + AGENTDNS_YADIFA_BOGI_FILE
 * Dig → zdb_zone_record_add; Auth remains database_query / zdb_query_to_wire.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <dnscore/dnsname.h>
#include <dnscore/dns_message.h>
#include <dnscore/rfc.h>
#include <dnscore/zone_reader_text.h>
#include <dnsdb/zdb.h>
#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_arc.h>
#include <dnsdb/zdb_rr_label.h>
#include <dnsdb/zdb_zone_resource_record.h>
#include <dnsdb/zdb_zone_lock.h>

#include "bogi_yadifa.h"
#include "bogi23_reader.h"
#include "bogi23_dig.h"
#include "bogi23_export.h"
#include "database.h"
#include "confs.h"

typedef struct bogi_zone_slot {
	char apex[256];
	char path[512];
	Bogi23Reader reader;
	int reader_open;
	int seeded;
	struct bogi_zone_slot *next;
} bogi_zone_slot;

static bogi_zone_slot *g_slots = NULL;
static __thread int g_depth = 0;

static void canon_owner(const char *in, char *out, size_t out_sz)
{
	size_t n = 0, i;
	for (i = 0; in[i] && n + 2 < out_sz; i++) {
		char c = in[i];
		if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
		out[n++] = c;
	}
	out[n] = '\0';
	if (n == 0) { snprintf(out, out_sz, "."); return; }
	if (out[n - 1] != '.' && n + 1 < out_sz) { out[n++] = '.'; out[n] = '\0'; }
}

static int apex_equal(const char *a, const char *b)
{
	char ca[256], cb[256];
	canon_owner(a, ca, sizeof ca); canon_owner(b, cb, sizeof cb);
	return strcmp(ca, cb) == 0;
}

static int is_under(const char *name, const char *apex)
{
	size_t nl, al;
	if (strcmp(apex, ".") == 0) return 1;
	nl = strlen(name); al = strlen(apex);
	if (nl < al) return 0;
	if (strcmp(name, apex) == 0) return 1;
	return (nl > al && name[nl - al - 1] == '.' && strcmp(name + (nl - al), apex) == 0);
}

static bogi_zone_slot *find_slot(const char *name)
{
	bogi_zone_slot *best = NULL; size_t best_len = 0; bogi_zone_slot *s;
	char q[256];
	canon_owner(name, q, sizeof q);
	for (s = g_slots; s; s = s->next) {
		if (!is_under(q, s->apex)) continue;
		if (strlen(s->apex) >= best_len) { best = s; best_len = strlen(s->apex); }
	}
	return best;
}

static int add_slot(const char *apex, const char *path)
{
	bogi_zone_slot *slot;
	for (slot = g_slots; slot; slot = slot->next)
		if (apex_equal(apex, slot->apex)) return 0;
	slot = calloc(1, sizeof(*slot));
	if (!slot) return -1;
	canon_owner(apex, slot->apex, sizeof slot->apex);
	snprintf(slot->path, sizeof slot->path, "%s", path);
	if (bogi23_open(&slot->reader, path) != 0) {
		fprintf(stderr, "bogi23_open failed: %s\n", path);
		free(slot); return -1;
	}
	slot->reader_open = 1;
	slot->next = g_slots; g_slots = slot;
	fprintf(stderr, "bogi Dig lazy mmap [yadifa] zone=%s file=%s\n", slot->apex, path);
	return 0;
}

void bogi_yadifa_close_all(void)
{
	bogi_zone_slot *s = g_slots;
	while (s) {
		bogi_zone_slot *n = s->next;
		if (s->reader_open) bogi23_close(&s->reader);
		free(s); s = n;
	}
	g_slots = NULL;
}

void bogi_yadifa_open_all(void)
{
	const char *apex = getenv("AGENTDNS_YADIFA_BOGI_APEX");
	const char *path = getenv("AGENTDNS_YADIFA_BOGI_FILE");
	bogi_yadifa_close_all();
	if (apex && path && *apex && *path) (void)add_slot(apex, path);
	if (!g_slots) fprintf(stderr, "bogi: no AGENTDNS_YADIFA_BOGI_* configured\n");
}

int bogi_yadifa_try_answer(dns_message_t *mesg)
{
	(void)mesg;
	return 0;
}

static uint16_t type_from_str(const char *t)
{
	if (!t) return 0;
	if (strcasecmp(t, "A") == 0) return TYPE_A;
	if (strcasecmp(t, "AAAA") == 0) return TYPE_AAAA;
	if (strcasecmp(t, "NS") == 0) return TYPE_NS;
	if (strcasecmp(t, "CNAME") == 0) return TYPE_CNAME;
	if (strcasecmp(t, "MX") == 0) return TYPE_MX;
	if (strcasecmp(t, "TXT") == 0) return TYPE_TXT;
	if (strcasecmp(t, "SOA") == 0) return TYPE_SOA;
	return 0;
}

static int
hydrate_type(zdb_zone_t *zone, bogi_zone_slot *slot, const char *owner, const char *rrtype)
{
	Bogi23OwnerGroup group;
	int found = 0;
	size_t i;
	uint16_t rtype;
	uint8_t origin_wire[256];
	uint8_t name_wire[256];
	dnsname_vector_t name_vec;

	rtype = type_from_str(rrtype);
	if (!rtype) return 0;
	if (FAIL(dnsname_init_with_cstr(origin_wire, slot->apex))) return -1;
	if (FAIL(dnsname_init_with_cstr(name_wire, owner))) return -1;
	dnsname_to_dnsname_vector(name_wire, &name_vec);

	memset(&group, 0, sizeof group);
	if (bogi23_dig_get_rrset(&slot->reader, owner, rrtype, &group, &found) != 0)
		return -1;
	if (!found || group.count == 0 || group.sets[0].rdata_count == 0) {
		bogi23_free_group(&slot->reader, &group);
		return 0;
	}

	for (i = 0; i < group.sets[0].rdata_count; i++) {
		uint8_t rdata[8192];
		ya_result rdlen;
		zdb_resource_record_data_t *rrd;
		const char *txt = group.sets[0].rdatas[i] ? group.sets[0].rdatas[i] : "";
		rdlen = zone_reader_text_copy_rdata(txt, rtype, rdata, sizeof rdata, origin_wire);
		if (FAIL(rdlen)) continue;
		rrd = zdb_resource_record_data_new_instance_copy((uint16_t)rdlen, rdata);
		if (!rrd) continue;
		zdb_zone_record_add(zone, name_vec.labels, name_vec.size, rtype,
				    (int32_t)group.sets[0].ttl, rrd);
	}
	bogi23_free_group(&slot->reader, &group);
	return 0;
}

static zdb_zone_t *acquire_zone(const char *apex)
{
	uint8_t origin[256];
	zdb_t *db;
	if (FAIL(dnsname_init_with_cstr(origin, apex))) return NULL;
	db = g_config ? g_config->database : NULL;
	if (!db) return NULL;
	return zdb_acquire_zone_write_lock_from_fqdn(db, origin, ZDB_ZONE_MUTEX_DYNUPDATE);
}

static void seed_if_needed(bogi_zone_slot *slot)
{
	/* Apex SOA+NS already Dig-written into stub zonefile by harness. */
	if (slot->seeded) return;
	slot->seeded = 1;
	fprintf(stderr, "bogi Dig lazy seed OK zone=%s (apex SOA+NS via Dig stub)", slot->apex);
	fputc(10, stderr);
}

static int wire_qname_to_str(const uint8_t *wire, size_t len, char *out, size_t out_sz)
{
	size_t pos = 12; size_t n = 0;
	if (len < 12) return -1;
	out[0] = '\0';
	while (pos < len) {
		uint8_t lab = wire[pos++];
		if (lab == 0) {
			if (n == 0) { if (out_sz < 2) return -1; out[0] = '.'; out[1] = '\0'; }
			else if (n + 1 < out_sz) { out[n++] = '.'; out[n] = '\0'; }
			return 0;
		}
		if ((lab & 0xc0) == 0xc0) return -1;
		if (pos + lab > len) return -1;
		if (n && n + 1 < out_sz) out[n++] = '.';
		for (size_t i = 0; i < lab && n + 1 < out_sz; i++) {
			char c = (char)wire[pos++];
			if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
			out[n++] = c;
		}
		out[n] = '\0';
	}
	return -1;
}

void bogi_yadifa_lazy(dns_message_t *mesg)
{
	char name[512];
	char succ[512];
	Bogi23DigLookupKind kind;
	bogi_zone_slot *slot;
	zdb_zone_t *zone;
	const char *types[] = {"A","AAAA","NS","CNAME","MX","TXT","SOA", NULL};
	const uint8_t *qwire;
	size_t qlen;
	int i;

	if (!mesg || g_depth || !g_slots) return;
	qlen = dns_message_get_size(mesg);
	if (qlen < 12) return;
	qwire = dns_message_get_buffer_const(mesg);
	if (wire_qname_to_str(qwire, qlen, name, sizeof name) != 0) return;
	canon_owner(name, name, sizeof name);
	slot = find_slot(name);
	if (!slot || !slot->reader_open) return;
	seed_if_needed(slot);
	zone = acquire_zone(slot->apex);
	if (!zone) return;

	succ[0] = '\0';
	kind = BOGI23_DIG_NONE;
	if (bogi23_dig_lookup(&slot->reader, name, &kind, succ, sizeof succ) != 0) {
		zdb_zone_release_unlock(zone, ZDB_ZONE_MUTEX_DYNUPDATE);
		return;
	}
	g_depth++;
	{
		char cur[512];
		snprintf(cur, sizeof cur, "%s", name);
		for (;;) {
			char *dot;
			if (is_under(cur, slot->apex))
				(void)hydrate_type(zone, slot, cur, "NS");
			if (apex_equal(cur, slot->apex)) break;
			dot = strchr(cur, '.');
			if (!dot) break;
			memmove(cur, dot + 1, strlen(dot + 1) + 1);
		}
	}
	if (kind == BOGI23_DIG_EXACT) {
		for (i = 0; types[i]; i++)
			(void)hydrate_type(zone, slot, name, types[i]);
	}
	g_depth--;
	zdb_zone_release_unlock(zone, ZDB_ZONE_MUTEX_DYNUPDATE);
}

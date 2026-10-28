\
/*
 * Unbound query-time lazy Dig (Model B / R029).
 * Env: AGENTDNS_UNBOUND_BOGI_APEX + AGENTDNS_UNBOUND_BOGI_FILE
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sldns/sbuffer.h"
#include "sldns/str2wire.h"
#include "util/data/msgreply.h"
#include "util/data/dname.h"
#include "services/authzone.h"
#include "daemon/bogi_unbound.h"
#include "bogi23_reader.h"
#include "bogi23_dig.h"
#include "bogi23_export.h"

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
	fprintf(stderr, "bogi Dig lazy mmap [unbound] zone=%s file=%s\n", slot->apex, path);
	return 0;
}

void bogi_unbound_close_all(void)
{
	bogi_zone_slot *s = g_slots;
	while (s) {
		bogi_zone_slot *n = s->next;
		if (s->reader_open) bogi23_close(&s->reader);
		free(s); s = n;
	}
	g_slots = NULL;
}

void bogi_unbound_open_all(void)
{
	const char *apex = getenv("AGENTDNS_UNBOUND_BOGI_APEX");
	const char *path = getenv("AGENTDNS_UNBOUND_BOGI_FILE");
	bogi_unbound_close_all();
	if (apex && path && *apex && *path) (void)add_slot(apex, path);
	if (!g_slots) fprintf(stderr, "bogi: no AGENTDNS_UNBOUND_BOGI_* configured\n");
}

int bogi_unbound_try_answer(struct sldns_buffer *buf)
{
	(void)buf;
	return 0;
}

static int hydrate_type(struct auth_zone *z, bogi_zone_slot *slot,
			const char *owner, const char *rrtype)
{
	Bogi23OwnerGroup group;
	int found = 0;
	size_t i;
	memset(&group, 0, sizeof group);
	if (bogi23_dig_get_rrset(&slot->reader, owner, rrtype, &group, &found) != 0)
		return -1;
	if (!found || group.count == 0 || group.sets[0].rdata_count == 0) {
		bogi23_free_group(&slot->reader, &group);
		return 0;
	}
	for (i = 0; i < group.sets[0].rdata_count; i++) {
		char line[2048];
		snprintf(line, sizeof line, "%s %u IN %s %s", owner,
			 (unsigned)group.sets[0].ttl,
			 group.sets[0].rrtype,
			 group.sets[0].rdatas[i] ? group.sets[0].rdatas[i] : "");
		(void)auth_zone_add_rr_str(z, line);
	}
	bogi23_free_group(&slot->reader, &group);
	return 0;
}

static struct auth_zone *find_auth(struct auth_zones *az, const char *apex)
{
	uint8_t *nm = NULL;
	size_t nmlen = 0;
	struct auth_zone *z;
	if (!az || !apex) return NULL;
	nm = sldns_str2wire_dname(apex, &nmlen);
	if (!nm) return NULL;
	z = auth_zone_find(az, nm, nmlen, LDNS_RR_CLASS_IN);
	free(nm);
	return z;
}

static void seed_if_needed(struct auth_zones *az, bogi_zone_slot *slot)
{
	struct auth_zone *z;
	if (slot->seeded) return;
	z = find_auth(az, slot->apex);
	if (!z) return;
	/* Drop stub zonefile RRs so Dig apex is sole SOA/NS. */
	auth_zone_clear_data(z);
	g_depth++;
	(void)hydrate_type(z, slot, slot->apex, "SOA");
	(void)hydrate_type(z, slot, slot->apex, "NS");
	g_depth--;
	slot->seeded = 1;
	fprintf(stderr, "bogi Dig lazy seed OK zone=%s (apex SOA+NS)", slot->apex);
	fputc(10, stderr);
}

void bogi_unbound_lazy(struct auth_zones *az, struct query_info *qinfo)
{
	char name[512];
	char succ[512];
	Bogi23DigLookupKind kind;
	bogi_zone_slot *slot;
	struct auth_zone *z;
	const char *types[] = {"A","AAAA","NS","CNAME","MX","TXT","SOA", NULL};
	int i;

	if (!az || !qinfo || !qinfo->qname || g_depth || !g_slots)
		return;
	dname_str(qinfo->qname, name);
	canon_owner(name, name, sizeof name);
	slot = find_slot(name);
	if (!slot || !slot->reader_open) return;
	seed_if_needed(az, slot);
	z = find_auth(az, slot->apex);
	if (!z) return;

	succ[0] = '\0';
	kind = BOGI23_DIG_NONE;
	if (bogi23_dig_lookup(&slot->reader, name, &kind, succ, sizeof succ) != 0)
		return;
	g_depth++;
	{
		char cur[512];
		snprintf(cur, sizeof cur, "%s", name);
		for (;;) {
			char *dot;
			if (is_under(cur, slot->apex))
				(void)hydrate_type(z, slot, cur, "NS");
			if (apex_equal(cur, slot->apex)) break;
			dot = strchr(cur, '.');
			if (!dot) break;
			memmove(cur, dot + 1, strlen(dot + 1) + 1);
		}
	}
	if (kind == BOGI23_DIG_EXACT) {
		for (i = 0; types[i]; i++)
			(void)hydrate_type(z, slot, name, types[i]);
	}
	g_depth--;
}

void bogi_unbound_release(struct auth_zones *az)
{
	bogi_zone_slot *s;
	if (!az) return;
	for (s = g_slots; s; s = s->next) {
		struct auth_zone *z;
		if (!s->seeded) continue;
		z = find_auth(az, s->apex);
		if (!z) continue;
		auth_zone_clear_data(z);
		s->seeded = 0;
		seed_if_needed(az, s);
	}
}

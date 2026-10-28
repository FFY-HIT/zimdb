/* BOGI-v2.3 authoritative answer builder (Reader-A resolve + DNS wire). */
#include "bogi_auth_answer.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CLASS_IN 1
#define MAX_NAME 255
#define MAX_LABELS 128
#define MAX_RRSETS 64
#define MAX_RDATAS 64
#define MAX_CNAME_DEPTH 16

enum {
	RCODE_NOERROR = 0,
	RCODE_FORMERR = 1,
	RCODE_SERVFAIL = 2,
	RCODE_NXDOMAIN = 3,
	RCODE_NOTIMP = 4,
	RCODE_REFUSED = 5
};

static const struct { const char *name; uint16_t num; } TYPE_MAP[] = {
	{"A", 1},
	{"NS", 2},
	{"CNAME", 5},
	{"SOA", 6},
	{"MX", 15},
	{"TXT", 16},
	{"AAAA", 28},
	{NULL, 0}
};

typedef struct {
	char owner[MAX_NAME];
	char rrtype[16];
	uint32_t ttl;
	char *rdatas[MAX_RDATAS];
	size_t rdata_count;
} AuthRRset;

typedef struct {
	int rcode;
	int aa;
	AuthRRset answer[MAX_RRSETS];
	size_t answer_count;
	AuthRRset authority[MAX_RRSETS];
	size_t authority_count;
	AuthRRset additional[MAX_RRSETS];
	size_t additional_count;
} AuthResponse;

static int type_num(const char *name, uint16_t *out)
{
	size_t i;
	for (i = 0; TYPE_MAP[i].name != NULL; i++) {
		if (strcmp(TYPE_MAP[i].name, name) == 0) {
			*out = TYPE_MAP[i].num;
			return 0;
		}
	}
	return -1;
}

static const char *type_name(uint16_t num)
{
	size_t i;
	for (i = 0; TYPE_MAP[i].name != NULL; i++) {
		if (TYPE_MAP[i].num == num)
			return TYPE_MAP[i].name;
	}
	return NULL;
}

static int type_supported(const char *name)
{
	uint16_t n;
	return type_num(name, &n) == 0;
}

static void rrset_clear(AuthRRset *rr)
{
	size_t i;
	for (i = 0; i < rr->rdata_count; i++) {
		free(rr->rdatas[i]);
		rr->rdatas[i] = NULL;
	}
	rr->rdata_count = 0;
	rr->owner[0] = '\0';
	rr->rrtype[0] = '\0';
	rr->ttl = 0;
}

static void response_clear(AuthResponse *resp)
{
	size_t i;
	for (i = 0; i < resp->answer_count; i++)
		rrset_clear(&resp->answer[i]);
	for (i = 0; i < resp->authority_count; i++)
		rrset_clear(&resp->authority[i]);
	for (i = 0; i < resp->additional_count; i++)
		rrset_clear(&resp->additional[i]);
	memset(resp, 0, sizeof(*resp));
}

static int rrset_from_bogi(AuthRRset *dst, const Bogi23RRset *src, const char *owner_override)
{
	size_t i;
	const char *own = owner_override != NULL ? owner_override : src->owner;
	if (own == NULL || src->rrtype == NULL)
		return -1;
	if (strlen(own) >= MAX_NAME || strlen(src->rrtype) >= sizeof(dst->rrtype))
		return -1;
	rrset_clear(dst);
	snprintf(dst->owner, sizeof(dst->owner), "%s", own);
	snprintf(dst->rrtype, sizeof(dst->rrtype), "%s", src->rrtype);
	dst->ttl = (uint32_t)(src->ttl & 0xffffffffu);
	for (i = 0; i < src->rdata_count && i < MAX_RDATAS; i++) {
		if (src->rdatas[i] == NULL)
			return -1;
		dst->rdatas[i] = strdup(src->rdatas[i]);
		if (dst->rdatas[i] == NULL)
			return -1;
		dst->rdata_count++;
	}
	return 0;
}

static int find_rrtype(const Bogi23OwnerGroup *g, const char *rrtype, const Bogi23RRset **out)
{
	size_t i;
	*out = NULL;
	for (i = 0; i < g->count; i++) {
		if (g->sets[i].rrtype != NULL && strcmp(g->sets[i].rrtype, rrtype) == 0) {
			*out = &g->sets[i];
			return 1;
		}
	}
	return 0;
}

static int name_inside(const char *name, const char *origin)
{
	size_t nl, ol;
	if (name == NULL || origin == NULL)
		return 0;
	if (strcmp(name, origin) == 0)
		return 1;
	nl = strlen(name);
	ol = strlen(origin);
	if (nl <= ol + 1)
		return 0;
	return name[nl - ol - 1] == '.' && strcmp(name + (nl - ol), origin) == 0;
}

static int parent_name(const char *name, const char *origin, char *out, size_t out_sz)
{
	const char *dot;
	if (strcmp(name, origin) == 0)
		return -1;
	dot = strchr(name, '.');
	if (dot == NULL || dot[1] == '\0')
		return -1;
	if (strlen(dot + 1) >= out_sz)
		return -1;
	snprintf(out, out_sz, "%s", dot + 1);
	return 0;
}

static void ascii_lower(char *s)
{
	for (; *s; s++)
		*s = (char)tolower((unsigned char)*s);
}

static int canonical_query(const Bogi23Reader *reader, const char *token, char *out, size_t out_sz)
{
	char tmp[MAX_NAME];
	size_t i, nlab;
	char *labels[MAX_LABELS];
	char buf[MAX_NAME];
	char *save = NULL;
	char *tok;
	if (token == NULL || strchr(token, '\\') != NULL)
		return -1;
	if (strcmp(token, "@") == 0) {
		if (strlen(reader->origin) >= out_sz)
			return -1;
		snprintf(out, out_sz, "%s", reader->origin);
		return 0;
	}
	if (strlen(token) >= sizeof(tmp))
		return -1;
	snprintf(tmp, sizeof(tmp), "%s", token);
	ascii_lower(tmp);
	if (tmp[strlen(tmp) - 1] == '.') {
		if (strlen(tmp) >= out_sz)
			return -1;
		snprintf(out, out_sz, "%s", tmp);
	} else {
		if (snprintf(out, out_sz, "%s.%s", tmp, reader->origin) >= (int)out_sz)
			return -1;
	}
	if (strlen(out) > 254)
		return -1;
	snprintf(buf, sizeof(buf), "%s", out);
	if (buf[0] == '\0' || buf[strlen(buf)-1] != '.')
		return -1;
	buf[strlen(buf)-1] = '\0';
	nlab = 0;
	for (tok = strtok_r(buf, ".", &save); tok != NULL; tok = strtok_r(NULL, ".", &save)) {
		if (tok[0] == '\0' || strlen(tok) > 63)
			return -1;
		if (nlab >= MAX_LABELS)
			return -1;
		labels[nlab++] = tok;
	}
	if (nlab == 0)
		return -1;
	for (i = 0; i < nlab; i++) {
		if (strcmp(labels[i], "*") == 0 && i != 0)
			return -1;
	}
	(void)labels;
	return 0;
}

static int lookup_group(Bogi23Reader *reader, const char *owner, Bogi23OwnerGroup *g, int *found)
{
	memset(g, 0, sizeof(*g));
	*found = 0;
	return bogi23_lookup_group(reader, owner, g, found);
}

static int node_exists(Bogi23Reader *reader, const char *owner, int *exists)
{
	*exists = 0;
	return bogi23_node_exists(reader, owner, exists);
}

static int nearest_cut(Bogi23Reader *reader, const char *name, char *out, size_t out_sz)
{
	char cur[MAX_NAME];
	char parent[MAX_NAME];
	char walk[MAX_NAME];
	Bogi23OwnerGroup g;
	const Bogi23RRset *ns;
	int found;
	if (strlen(name) >= sizeof(cur))
		return 0;
	snprintf(cur, sizeof(cur), "%s", name);
	for (;;) {
		if (strcmp(cur, reader->origin) != 0) {
			if (lookup_group(reader, cur, &g, &found) != 0)
				return -1;
			if (found && find_rrtype(&g, "NS", &ns)) {
				int below_cut = 0;
				if (parent_name(cur, reader->origin, parent, sizeof(parent)) == 0) {
					snprintf(walk, sizeof(walk), "%s", parent);
					while (strcmp(walk, reader->origin) != 0) {
						Bogi23OwnerGroup ag;
						const Bogi23RRset *ans;
						int anc_found;
						if (lookup_group(reader, walk, &ag, &anc_found) != 0) {
							bogi23_free_group(reader, &g);
							return -1;
						}
						if (anc_found && find_rrtype(&ag, "NS", &ans)) {
							below_cut = 1;
							bogi23_free_group(reader, &ag);
							break;
						}
						if (anc_found)
							bogi23_free_group(reader, &ag);
						if (parent_name(walk, reader->origin, parent, sizeof(parent)) != 0)
							break;
						snprintf(walk, sizeof(walk), "%s", parent);
					}
				}
				if (!below_cut) {
					snprintf(out, out_sz, "%s", cur);
					bogi23_free_group(reader, &g);
					return 1;
				}
			}
			if (found)
				bogi23_free_group(reader, &g);
		}
		if (strcmp(cur, reader->origin) == 0)
			break;
		if (parent_name(cur, reader->origin, parent, sizeof(parent)) != 0)
			break;
		snprintf(cur, sizeof(cur), "%s", parent);
	}
	return 0;
}

static int closest_enclosing(Bogi23Reader *reader, const char *name, char *out, size_t out_sz)
{
	char cur[MAX_NAME];
	char parent[MAX_NAME];
	int exists;
	if (strlen(name) >= sizeof(cur))
		return -1;
	snprintf(cur, sizeof(cur), "%s", name);
	for (;;) {
		if (node_exists(reader, cur, &exists) != 0)
			return -1;
		if (exists) {
			snprintf(out, out_sz, "%s", cur);
			return 0;
		}
		if (strcmp(cur, reader->origin) == 0) {
			snprintf(out, out_sz, "%s", reader->origin);
			return 0;
		}
		if (parent_name(cur, reader->origin, parent, sizeof(parent)) != 0) {
			snprintf(out, out_sz, "%s", reader->origin);
			return 0;
		}
		snprintf(cur, sizeof(cur), "%s", parent);
	}
}

static int negative_soa(Bogi23Reader *reader, AuthRRset *out)
{
	Bogi23OwnerGroup g;
	const Bogi23RRset *soa;
	int found;
	const char *rd;
	const char *sp;
	unsigned long minimum;
	uint32_t ttl;
	if (lookup_group(reader, reader->origin, &g, &found) != 0 || !found)
		return -1;
	if (!find_rrtype(&g, "SOA", &soa) || soa->rdata_count < 1) {
		bogi23_free_group(reader, &g);
		return -1;
	}
	rd = soa->rdatas[0];
	sp = strrchr(rd, ' ');
	if (sp == NULL) {
		bogi23_free_group(reader, &g);
		return -1;
	}
	minimum = strtoul(sp + 1, NULL, 10);
	ttl = (uint32_t)soa->ttl;
	if ((uint32_t)minimum < ttl)
		ttl = (uint32_t)minimum;
	if (rrset_from_bogi(out, soa, NULL) != 0) {
		bogi23_free_group(reader, &g);
		return -1;
	}
	out->ttl = ttl;
	bogi23_free_group(reader, &g);
	return 0;
}

static int ends_with_cut(const char *target, const char *cut)
{
	size_t tl, cl;
	if (strcmp(target, cut) == 0)
		return 1;
	tl = strlen(target);
	cl = strlen(cut);
	if (tl <= cl + 1)
		return 0;
	return target[tl - cl - 1] == '.' && strcmp(target + (tl - cl), cut) == 0;
}

static int make_referral(Bogi23Reader *reader, const char *cut, AuthResponse *resp)
{
	Bogi23OwnerGroup g;
	Bogi23OwnerGroup tg;
	const Bogi23RRset *ns;
	const Bogi23RRset *glue;
	int found, tfound;
	size_t i;
	const char *types[] = {"A", "AAAA", NULL};
	size_t ti;
	/* Preserve any CNAME chain already in ANSWER (CNAME → zone cut). */
	int had_answer = resp->answer_count > 0;

	resp->rcode = RCODE_NOERROR;
	/* Pure referral: aa=0. CNAME then cut: aa=1 (BIND/NSD/Knot style). */
	resp->aa = had_answer ? 1 : 0;
	if (lookup_group(reader, cut, &g, &found) != 0 || !found)
		return -1;
	if (!find_rrtype(&g, "NS", &ns)) {
		bogi23_free_group(reader, &g);
		return -1;
	}
	if (resp->authority_count >= MAX_RRSETS ||
	    rrset_from_bogi(&resp->authority[resp->authority_count], ns, NULL) != 0) {
		bogi23_free_group(reader, &g);
		return -1;
	}
	resp->authority_count++;
	for (i = 0; i < ns->rdata_count; i++) {
		const char *target = ns->rdatas[i];
		if (!ends_with_cut(target, cut))
			continue;
		if (lookup_group(reader, target, &tg, &tfound) != 0)
			continue;
		if (!tfound)
			continue;
		for (ti = 0; types[ti] != NULL; ti++) {
			if (!find_rrtype(&tg, types[ti], &glue))
				continue;
			if (resp->additional_count >= MAX_RRSETS)
				break;
			if (rrset_from_bogi(&resp->additional[resp->additional_count], glue, NULL) == 0)
				resp->additional_count++;
		}
		bogi23_free_group(reader, &tg);
	}
	bogi23_free_group(reader, &g);
	return 0;
}

static int append_answer(AuthResponse *resp, const Bogi23RRset *src, const char *owner_override)
{
	if (resp->answer_count >= MAX_RRSETS)
		return -1;
	if (rrset_from_bogi(&resp->answer[resp->answer_count], src, owner_override) != 0)
		return -1;
	resp->answer_count++;
	return 0;
}

static int resolve_query(Bogi23Reader *reader, const char *qname, const char *qtype, AuthResponse *resp)
{
	char current[MAX_NAME];
	char cut[MAX_NAME];
	char closest[MAX_NAME];
	char wildcard[MAX_NAME];
	char higher[MAX_NAME];
	char parent[MAX_NAME];
	char seen[MAX_CNAME_DEPTH][MAX_NAME];
	int seen_n = 0;
	int followed = 0;
	int cut_rc, found, exists, i;
	Bogi23OwnerGroup g;
	Bogi23OwnerGroup wildg;
	Bogi23OwnerGroup closestg;
	const Bogi23RRset *rr;
	const Bogi23RRset *alias;
	AuthRRset neg;

	memset(resp, 0, sizeof(*resp));
	memset(&neg, 0, sizeof(neg));
	if (canonical_query(reader, qname, current, sizeof(current)) != 0)
		return -1;
	if (!type_supported(qtype) || !name_inside(current, reader->origin))
		return -1;

	for (;;) {
		for (i = 0; i < seen_n; i++) {
			if (strcmp(seen[i], current) == 0)
				return -1;
		}
		if (seen_n >= MAX_CNAME_DEPTH)
			return -1;
		snprintf(seen[seen_n++], MAX_NAME, "%s", current);

		cut_rc = nearest_cut(reader, current, cut, sizeof(cut));
		if (cut_rc < 0)
			return -1;
		if (cut_rc == 1) {
			/* CNAME already in ANSWER → attach cut NS; do not SERVFAIL. */
			return make_referral(reader, cut, resp);
		}

		if (lookup_group(reader, current, &g, &found) != 0)
			return -1;
		if (node_exists(reader, current, &exists) != 0) {
			if (found)
				bogi23_free_group(reader, &g);
			return -1;
		}

		if (exists) {
			if (found && find_rrtype(&g, qtype, &rr)) {
				if (append_answer(resp, rr, NULL) != 0) {
					bogi23_free_group(reader, &g);
					return -1;
				}
				bogi23_free_group(reader, &g);
				resp->rcode = RCODE_NOERROR;
				resp->aa = 1;
				return 0;
			}
			alias = NULL;
			if (found && strcmp(qtype, "CNAME") != 0)
				find_rrtype(&g, "CNAME", &alias);
			if (alias != NULL) {
				if (append_answer(resp, alias, NULL) != 0) {
					bogi23_free_group(reader, &g);
					return -1;
				}
				if (alias->rdata_count < 1) {
					bogi23_free_group(reader, &g);
					return -1;
				}
				followed = 1;
				snprintf(current, sizeof(current), "%s", alias->rdatas[0]);
				bogi23_free_group(reader, &g);
				if (!name_inside(current, reader->origin)) {
					resp->rcode = RCODE_NOERROR;
					resp->aa = 1;
					return 0;
				}
				continue;
			}
			if (found)
				bogi23_free_group(reader, &g);
			if (negative_soa(reader, &neg) != 0)
				return -1;
			resp->rcode = RCODE_NOERROR;
			resp->aa = 1;
			resp->authority[0] = neg;
			resp->authority_count = 1;
			memset(&neg, 0, sizeof(neg));
			return 0;
		}
		if (found)
			bogi23_free_group(reader, &g);

		if (closest_enclosing(reader, current, closest, sizeof(closest)) != 0)
			return -1;
		if (snprintf(wildcard, sizeof(wildcard), "*.%s", closest) >= (int)sizeof(wildcard))
			return -1;
		if (lookup_group(reader, wildcard, &wildg, &found) != 0)
			return -1;
		if (found && find_rrtype(&wildg, qtype, &rr)) {
			if (append_answer(resp, rr, current) != 0) {
				bogi23_free_group(reader, &wildg);
				return -1;
			}
			bogi23_free_group(reader, &wildg);
			resp->rcode = RCODE_NOERROR;
			resp->aa = 1;
			return 0;
		}
		alias = NULL;
		if (found && strcmp(qtype, "CNAME") != 0)
			find_rrtype(&wildg, "CNAME", &alias);
		if (alias != NULL) {
			if (append_answer(resp, alias, current) != 0) {
				bogi23_free_group(reader, &wildg);
				return -1;
			}
			if (alias->rdata_count < 1) {
				bogi23_free_group(reader, &wildg);
				return -1;
			}
			followed = 1;
			snprintf(current, sizeof(current), "%s", alias->rdatas[0]);
			bogi23_free_group(reader, &wildg);
			if (!name_inside(current, reader->origin)) {
				resp->rcode = RCODE_NOERROR;
				resp->aa = 1;
				return 0;
			}
			continue;
		}
		if (found) {
			bogi23_free_group(reader, &wildg);
			if (negative_soa(reader, &neg) != 0)
				return -1;
			resp->rcode = RCODE_NOERROR;
			resp->aa = 1;
			resp->authority[0] = neg;
			resp->authority_count = 1;
			memset(&neg, 0, sizeof(neg));
			return 0;
		}

		/* NXDOMAIN path */
		if (lookup_group(reader, closest, &closestg, &found) != 0)
			return -1;
		if (found)
			bogi23_free_group(reader, &closestg);
		(void)followed;
		snprintf(higher, sizeof(higher), "%s", closest);
		while (strcmp(higher, reader->origin) != 0) {
			if (parent_name(higher, reader->origin, parent, sizeof(parent)) != 0)
				break;
			snprintf(higher, sizeof(higher), "%s", parent);
			if (snprintf(wildcard, sizeof(wildcard), "*.%s", higher) >= (int)sizeof(wildcard))
				break;
			if (lookup_group(reader, wildcard, &wildg, &found) != 0)
				return -1;
			if (found) {
				bogi23_free_group(reader, &wildg);
				break;
			}
		}
		if (negative_soa(reader, &neg) != 0)
			return -1;
		resp->rcode = RCODE_NXDOMAIN;
		resp->aa = 1;
		resp->authority[0] = neg;
		resp->authority_count = 1;
		memset(&neg, 0, sizeof(neg));
		return 0;
	}
}

static int encode_name(const char *name, uint8_t *out, size_t out_cap, size_t *written)
{
	char tmp[MAX_NAME];
	const char *p;
	size_t pos = 0;
	if (name == NULL)
		return -1;
	if (strcmp(name, ".") == 0) {
		if (out_cap < 1)
			return -1;
		out[0] = 0;
		*written = 1;
		return 0;
	}
	if (strlen(name) >= sizeof(tmp))
		return -1;
	snprintf(tmp, sizeof(tmp), "%s", name);
	if (tmp[strlen(tmp)-1] != '.') {
		if (strlen(tmp) + 1 >= sizeof(tmp))
			return -1;
		strcat(tmp, ".");
	}
	p = tmp;
	while (*p) {
		const char *dot = strchr(p, '.');
		size_t lab;
		if (dot == NULL)
			return -1;
		lab = (size_t)(dot - p);
		if (lab < 1 || lab > 63)
			return -1;
		if (pos + 1 + lab > out_cap)
			return -1;
		out[pos++] = (uint8_t)lab;
		memcpy(out + pos, p, lab);
		pos += lab;
		p = dot + 1;
	}
	if (pos + 1 > out_cap)
		return -1;
	out[pos++] = 0;
	*written = pos;
	return 0;
}

static int parse_ipv4(const char *s, uint8_t out[4])
{
	unsigned a,b,c,d;
	char extra;
	if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4)
		return -1;
	if (a > 255 || b > 255 || c > 255 || d > 255)
		return -1;
	out[0]=(uint8_t)a; out[1]=(uint8_t)b; out[2]=(uint8_t)c; out[3]=(uint8_t)d;
	return 0;
}

static int encode_rdata(const char *rrtype, const char *rdata, uint8_t *out, size_t out_cap, size_t *written)
{
	uint8_t tmp[512];
	size_t n = 0, n2;
	if (strcmp(rrtype, "A") == 0) {
		if (out_cap < 4 || parse_ipv4(rdata, out) != 0)
			return -1;
		*written = 4;
		return 0;
	}
	if (strcmp(rrtype, "AAAA") == 0) {
		struct in6_addr a6;
		if (out_cap < 16 || inet_pton(AF_INET6, rdata, &a6) != 1)
			return -1;
		memcpy(out, &a6, 16);
		*written = 16;
		return 0;
	}
	if (strcmp(rrtype, "NS") == 0 || strcmp(rrtype, "CNAME") == 0)
		return encode_name(rdata, out, out_cap, written);
	if (strcmp(rrtype, "MX") == 0) {
		unsigned pref;
		char exch[MAX_NAME];
		if (sscanf(rdata, "%u %254s", &pref, exch) != 2 || pref > 65535)
			return -1;
		if (out_cap < 2)
			return -1;
		out[0] = (uint8_t)((pref >> 8) & 0xff);
		out[1] = (uint8_t)(pref & 0xff);
		if (encode_name(exch, out + 2, out_cap - 2, &n) != 0)
			return -1;
		*written = 2 + n;
		return 0;
	}
	if (strcmp(rrtype, "SOA") == 0) {
		char mname[MAX_NAME], rname[MAX_NAME];
		unsigned long serial, refresh, retry, expire, minimum;
		if (sscanf(rdata, "%254s %254s %lu %lu %lu %lu %lu",
			   mname, rname, &serial, &refresh, &retry, &expire, &minimum) != 7)
			return -1;
		if (encode_name(mname, tmp, sizeof(tmp), &n) != 0)
			return -1;
		if (encode_name(rname, tmp + n, sizeof(tmp) - n, &n2) != 0)
			return -1;
		n += n2;
		if (n + 20 > sizeof(tmp) || n + 20 > out_cap)
			return -1;
		{
			uint32_t vals[5] = {(uint32_t)serial, (uint32_t)refresh, (uint32_t)retry,
					   (uint32_t)expire, (uint32_t)minimum};
			int vi;
			for (vi = 0; vi < 5; vi++) {
				tmp[n++] = (uint8_t)((vals[vi] >> 24) & 0xff);
				tmp[n++] = (uint8_t)((vals[vi] >> 16) & 0xff);
				tmp[n++] = (uint8_t)((vals[vi] >> 8) & 0xff);
				tmp[n++] = (uint8_t)(vals[vi] & 0xff);
			}
		}
		memcpy(out, tmp, n);
		*written = n;
		return 0;
	}
	if (strcmp(rrtype, "TXT") == 0) {
		const char *text = rdata;
		size_t tlen;
		char unesc[512];
		size_t ui = 0, ri;
		tlen = strlen(rdata);
		if (tlen >= 2 && rdata[0] == 34 && rdata[tlen - 1] == 34) {
			for (ri = 1; ri + 1 < tlen; ri++) {
				if (rdata[ri] == 92 && ri + 1 < tlen - 1) {
					char nxt = rdata[ri + 1];
					if (nxt == 34 || nxt == 92) {
						if (ui + 1 >= sizeof(unesc))
							return -1;
						unesc[ui++] = nxt;
						ri++;
						continue;
					}
				}
				if (ui + 1 >= sizeof(unesc))
					return -1;
				unesc[ui++] = rdata[ri];
			}
			unesc[ui] = 0;
			text = unesc;
		}
		tlen = strlen(text);
		if (tlen > 255 || out_cap < tlen + 1)
			return -1;
		out[0] = (uint8_t)tlen;
		memcpy(out + 1, text, tlen);
		*written = tlen + 1;
		return 0;
	}
	return -1;
}

static int put_u16(uint8_t *out, size_t out_cap, size_t *pos, uint16_t v)
{
	if (*pos + 2 > out_cap)
		return -1;
	out[(*pos)++] = (uint8_t)((v >> 8) & 0xff);
	out[(*pos)++] = (uint8_t)(v & 0xff);
	return 0;
}

static int put_u32(uint8_t *out, size_t out_cap, size_t *pos, uint32_t v)
{
	if (*pos + 4 > out_cap)
		return -1;
	out[(*pos)++] = (uint8_t)((v >> 24) & 0xff);
	out[(*pos)++] = (uint8_t)((v >> 16) & 0xff);
	out[(*pos)++] = (uint8_t)((v >> 8) & 0xff);
	out[(*pos)++] = (uint8_t)(v & 0xff);
	return 0;
}

static int encode_rrset(const AuthRRset *rr, uint8_t *out, size_t out_cap, size_t *pos, size_t *rr_count)
{
	uint16_t tnum;
	size_t i, nlen, rdlen;
	uint8_t namebuf[MAX_NAME];
	uint8_t rdbuf[1024];
	if (type_num(rr->rrtype, &tnum) != 0)
		return -1;
	if (encode_name(rr->owner, namebuf, sizeof(namebuf), &nlen) != 0)
		return -1;
	for (i = 0; i < rr->rdata_count; i++) {
		size_t start;
		if (encode_rdata(rr->rrtype, rr->rdatas[i], rdbuf, sizeof(rdbuf), &rdlen) != 0)
			return -1;
		if (*pos + nlen + 10 + rdlen > out_cap)
			return -1;
		memcpy(out + *pos, namebuf, nlen);
		*pos += nlen;
		if (put_u16(out, out_cap, pos, tnum) != 0)
			return -1;
		if (put_u16(out, out_cap, pos, CLASS_IN) != 0)
			return -1;
		if (put_u32(out, out_cap, pos, rr->ttl) != 0)
			return -1;
		if (put_u16(out, out_cap, pos, (uint16_t)rdlen) != 0)
			return -1;
		memcpy(out + *pos, rdbuf, rdlen);
		*pos += rdlen;
		(*rr_count)++;
		(void)start;
	}
	return 0;
}

static size_t count_rrs(const AuthRRset *sets, size_t n)
{
	size_t i, c = 0;
	for (i = 0; i < n; i++)
		c += sets[i].rdata_count;
	return c;
}

static int build_response(uint16_t txn_id, const char *qname, uint16_t qtype_num,
			 const AuthResponse *resp, uint8_t *out, size_t out_cap)
{
	size_t pos = 0, nlen, i;
	size_t an = 0, ns = 0, ar = 0;
	uint16_t flags;
	uint8_t namebuf[MAX_NAME];
	if (out_cap < 12)
		return -1;
	flags = resp->aa ? 0x8400 : 0x8000;
	flags = (uint16_t)(flags | (resp->rcode & 0xf));
	/* placeholder header */
	pos = 12;
	if (encode_name(qname, namebuf, sizeof(namebuf), &nlen) != 0)
		return -1;
	if (pos + nlen + 4 > out_cap)
		return -1;
	memcpy(out + pos, namebuf, nlen);
	pos += nlen;
	if (put_u16(out, out_cap, &pos, qtype_num) != 0)
		return -1;
	if (put_u16(out, out_cap, &pos, CLASS_IN) != 0)
		return -1;
	for (i = 0; i < resp->answer_count; i++)
		if (encode_rrset(&resp->answer[i], out, out_cap, &pos, &an) != 0)
			return -1;
	for (i = 0; i < resp->authority_count; i++)
		if (encode_rrset(&resp->authority[i], out, out_cap, &pos, &ns) != 0)
			return -1;
	for (i = 0; i < resp->additional_count; i++)
		if (encode_rrset(&resp->additional[i], out, out_cap, &pos, &ar) != 0)
			return -1;
	{
		size_t h = 0;
		if (put_u16(out, out_cap, &h, txn_id) != 0) return -1;
		if (put_u16(out, out_cap, &h, flags) != 0) return -1;
		if (put_u16(out, out_cap, &h, 1) != 0) return -1;
		if (put_u16(out, out_cap, &h, (uint16_t)an) != 0) return -1;
		if (put_u16(out, out_cap, &h, (uint16_t)ns) != 0) return -1;
		if (put_u16(out, out_cap, &h, (uint16_t)ar) != 0) return -1;
	}
	(void)count_rrs;
	return (int)pos;
}

static int parse_query(const uint8_t *data, size_t len, uint16_t *txn_id, char *qname, size_t qname_sz, uint16_t *qtype)
{
	size_t pos = 12;
	uint16_t qdcount, qclass;
	size_t nlen = 0;
	if (len < 12)
		return -1;
	*txn_id = (uint16_t)((data[0] << 8) | data[1]);
	qdcount = (uint16_t)((data[4] << 8) | data[5]);
	if (qdcount < 1)
		return -1;
	qname[0] = 0;
	while (pos < len) {
		uint8_t lab = data[pos++];
		if (lab == 0)
			break;
		if ((lab & 0xc0) != 0)
			return -1;
		if (pos + lab > len)
			return -1;
		if (nlen + lab + 1 >= qname_sz)
			return -1;
		if (nlen != 0)
			qname[nlen++] = '.';
		memcpy(qname + nlen, data + pos, lab);
		nlen += lab;
		qname[nlen] = 0;
		pos += lab;
	}
	if (nlen + 1 >= qname_sz)
		return -1;
	qname[nlen++] = '.';
	qname[nlen] = 0;
	if (pos + 4 > len)
		return -1;
	*qtype = (uint16_t)((data[pos] << 8) | data[pos + 1]);
	qclass = (uint16_t)((data[pos + 2] << 8) | data[pos + 3]);
	if (qclass != CLASS_IN)
		return -1;
	ascii_lower(qname);
	return 0;
}

int bogi_auth_open(BogiAuthCtx *ctx, const char *image_path)
{
	if (ctx == NULL || image_path == NULL)
		return -1;
	memset(ctx, 0, sizeof(*ctx));
	ctx->reader.fd = -1;
	if (bogi23_open(&ctx->reader, image_path) != 0)
		return -1;
	ctx->open = 1;
	return 0;
}

void bogi_auth_close(BogiAuthCtx *ctx)
{
	if (ctx == NULL || !ctx->open)
		return;
	bogi23_close(&ctx->reader);
	ctx->open = 0;
}

int bogi_auth_answer_query(BogiAuthCtx *ctx,
			  const uint8_t *query_wire, size_t query_len,
			  uint8_t *out_buf, size_t out_cap)
{
	uint16_t txn_id = 0, qtype_num = 0;
	char qname[MAX_NAME];
	const char *qtype;
	AuthResponse resp;
	int rc, built;
	size_t pos;

	if (ctx == NULL || !ctx->open || query_wire == NULL || out_buf == NULL)
		return -1;
	memset(&resp, 0, sizeof(resp));
	if (parse_query(query_wire, query_len, &txn_id, qname, sizeof(qname), &qtype_num) != 0)
		return -1;
	qtype = type_name(qtype_num);
	if (qtype == NULL) {
		/* NOTIMP */
		if (out_cap < query_len)
			return -1;
		memcpy(out_buf, query_wire, query_len);
		out_buf[2] = 0x84;
		out_buf[3] = 0x04;
		out_buf[6] = 0; out_buf[7] = 0;
		out_buf[8] = 0; out_buf[9] = 0;
		out_buf[10] = 0; out_buf[11] = 0;
		return (int)query_len;
	}
	rc = resolve_query(&ctx->reader, qname, qtype, &resp);
	if (rc != 0) {
		response_clear(&resp);
		if (out_cap < 12)
			return -1;
		/* SERVFAIL with echoed question if possible */
		pos = 0;
		if (put_u16(out_buf, out_cap, &pos, txn_id) != 0) return -1;
		if (put_u16(out_buf, out_cap, &pos, 0x8402) != 0) return -1;
		if (put_u16(out_buf, out_cap, &pos, 1) != 0) return -1;
		if (put_u16(out_buf, out_cap, &pos, 0) != 0) return -1;
		if (put_u16(out_buf, out_cap, &pos, 0) != 0) return -1;
		if (put_u16(out_buf, out_cap, &pos, 0) != 0) return -1;
		if (query_len > 12 && out_cap >= query_len) {
			memcpy(out_buf + 12, query_wire + 12, query_len - 12);
			return (int)query_len;
		}
		return 12;
	}
	built = build_response(txn_id, qname, qtype_num, &resp, out_buf, out_cap);
	response_clear(&resp);
	return built;
}


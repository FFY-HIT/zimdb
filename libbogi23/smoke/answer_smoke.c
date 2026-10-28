#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "bogi_auth_answer.h"

static int encode_qname(const char *name, uint8_t *out, size_t cap, size_t *written)
{
	size_t pos = 0;
	const char *p = name;
	char tmp[256];
	if (strlen(name) >= sizeof(tmp)) return -1;
	snprintf(tmp, sizeof(tmp), "%s", name);
	if (tmp[strlen(tmp)-1] != '.') strcat(tmp, ".");
	p = tmp;
	while (*p) {
		const char *dot = strchr(p, '.');
		size_t lab;
		if (!dot) return -1;
		lab = (size_t)(dot - p);
		if (lab < 1 || lab > 63 || pos + 1 + lab > cap) return -1;
		out[pos++] = (uint8_t)lab;
		memcpy(out + pos, p, lab);
		pos += lab;
		p = dot + 1;
	}
	if (pos + 1 > cap) return -1;
	out[pos++] = 0;
	*written = pos;
	return 0;
}

static int build_query(const char *qname, uint16_t qtype, uint8_t *out, size_t cap)
{
	size_t pos = 0, nlen;
	uint8_t name[256];
	if (cap < 12) return -1;
	out[0]=0x12; out[1]=0x34;
	out[2]=0x01; out[3]=0x00;
	out[4]=0; out[5]=1;
	out[6]=0; out[7]=0;
	out[8]=0; out[9]=0;
	out[10]=0; out[11]=0;
	pos = 12;
	if (encode_qname(qname, name, sizeof(name), &nlen) != 0) return -1;
	if (pos + nlen + 4 > cap) return -1;
	memcpy(out + pos, name, nlen); pos += nlen;
	out[pos++] = (uint8_t)((qtype >> 8) & 0xff);
	out[pos++] = (uint8_t)(qtype & 0xff);
	out[pos++] = 0; out[pos++] = 1;
	return (int)pos;
}

static int section_has_type(const uint8_t *msg, size_t len, int section /*0=ans*/, uint16_t want)
{
	/* Minimal walk: skip header+question, scan answer RRs for type. */
	size_t pos = 12;
	uint16_t qd, an, i;
	if (len < 12) return 0;
	qd = (uint16_t)((msg[4]<<8)|msg[5]);
	an = (uint16_t)((msg[6]<<8)|msg[7]);
	for (i = 0; i < qd; i++) {
		while (pos < len && msg[pos] != 0) {
			if ((msg[pos] & 0xc0) == 0xc0) { pos += 2; break; }
			pos += 1 + msg[pos];
		}
		if (pos < len && msg[pos] == 0) pos++;
		pos += 4;
	}
	if (section != 0) return 0;
	for (i = 0; i < an; i++) {
		uint16_t typ, rdlen;
		if (pos >= len) return 0;
		if ((msg[pos] & 0xc0) == 0xc0) pos += 2;
		else {
			while (pos < len && msg[pos] != 0) pos += 1 + msg[pos];
			if (pos < len) pos++;
		}
		if (pos + 10 > len) return 0;
		typ = (uint16_t)((msg[pos]<<8)|msg[pos+1]);
		rdlen = (uint16_t)((msg[pos+8]<<8)|msg[pos+9]);
		pos += 10 + rdlen;
		if (typ == want) return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1]
		: "/home/administrator/agentdns-czds/prepared/czds_page/image.bogi";
	BogiAuthCtx ctx;
	uint8_t q[512], ans[4096];
	int qlen, alen;
	uint16_t rcode;
	int has_soa;

	memset(&ctx, 0, sizeof(ctx));
	if (bogi_auth_open(&ctx, path) != 0) {
		fprintf(stderr, "open fail %s\n", path);
		return 1;
	}
	qlen = build_query("page.", 6, q, sizeof(q));
	if (qlen < 0) { bogi_auth_close(&ctx); return 2; }
	alen = bogi_auth_answer_query(&ctx, q, (size_t)qlen, ans, sizeof(ans));
	bogi_auth_close(&ctx);
	if (alen < 12) {
		fprintf(stderr, "answer fail rc=%d\n", alen);
		return 3;
	}
	rcode = (uint16_t)(ans[3] & 0x0f);
	has_soa = section_has_type(ans, (size_t)alen, 0, 6);
	printf("rcode=%u ancount=%u has_soa_answer=%d alen=%d\n",
	       (unsigned)rcode,
	       (unsigned)((ans[6]<<8)|ans[7]),
	       has_soa, alen);
	return (rcode == 0 && has_soa) ? 0 : 4;
}


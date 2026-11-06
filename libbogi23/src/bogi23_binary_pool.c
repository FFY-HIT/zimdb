#define _POSIX_C_SOURCE 200809L
#include "bogi23_binary_pool.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TAG_UTF8 = 0,
	TAG_A = 1,
	TAG_AAAA = 2,
	TAG_SOA = 3,
	TAG_MX = 4,
	TAG_DS = 5,
	TAG_DNSKEY = 6,
	TAG_RRSIG = 7,
	TAG_NSEC3 = 8,
	TAG_NSEC3PARAM = 9,
	TAG_NS = 10,
	TAG_TXT = 11
};

static const char *TYPE_ORDER[] = {
	"A", "NS", "CNAME", "SOA", "MX", "TXT", "AAAA",
	"DS", "RRSIG", "NSEC3", "DNSKEY", "NSEC3PARAM"
};
static const int NTYPES = 12;

static int read_uleb(const uint8_t *p, size_t n, size_t *off, uint64_t *out)
{
	uint64_t val = 0;
	unsigned shift = 0;
	while (*off < n) {
		uint8_t b = p[(*off)++];
		val |= (uint64_t)(b & 0x7f) << shift;
		if ((b & 0x80) == 0) {
			*out = val;
			return 0;
		}
		shift += 7;
		if (shift > 63) return -1;
	}
	return -1;
}

static int read_name(const uint8_t *p, size_t n, size_t *off,
		     char *buf, size_t buflen)
{
	uint64_t len = 0;
	if (read_uleb(p, n, off, &len) != 0) return -1;
	if (len >= buflen || *off + (size_t)len > n) return -1;
	memcpy(buf, p + *off, (size_t)len);
	buf[len] = '\0';
	*off += (size_t)len;
	return 0;
}

static void b64_encode(const uint8_t *in, size_t inlen, char *out)
{
	static const char *t =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i = 0, o = 0;
	while (i + 3 <= inlen) {
		uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) |
			     in[i + 2];
		out[o++] = t[(v >> 18) & 63];
		out[o++] = t[(v >> 12) & 63];
		out[o++] = t[(v >> 6) & 63];
		out[o++] = t[v & 63];
		i += 3;
	}
	if (inlen - i == 1) {
		uint32_t v = (uint32_t)in[i] << 16;
		out[o++] = t[(v >> 18) & 63];
		out[o++] = t[(v >> 12) & 63];
		out[o++] = '=';
		out[o++] = '=';
	} else if (inlen - i == 2) {
		uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
		out[o++] = t[(v >> 18) & 63];
		out[o++] = t[(v >> 12) & 63];
		out[o++] = t[(v >> 6) & 63];
		out[o++] = '=';
	}
	out[o] = '\0';
}

static void hex_encode(const uint8_t *in, size_t inlen, char *out)
{
	static const char *h = "0123456789abcdef";
	size_t i;
	for (i = 0; i < inlen; ++i) {
		out[i * 2] = h[in[i] >> 4];
		out[i * 2 + 1] = h[in[i] & 0xf];
	}
	out[inlen * 2] = '\0';
}

static void b32hex_encode(const uint8_t *in, size_t inlen, char *out)
{
	static const char *a = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
	size_t bits_len = inlen * 8;
	size_t o = 0;
	size_t bit = 0;
	while (bit < bits_len) {
		unsigned v = 0;
		unsigned k;
		for (k = 0; k < 5; ++k) {
			size_t b = bit + k;
			v <<= 1;
			if (b < bits_len) {
				size_t byte = b / 8;
				unsigned shift = 7u - (unsigned)(b % 8);
				v |= (in[byte] >> shift) & 1u;
			}
		}
		out[o++] = a[v & 31];
		bit += 5;
	}
	out[o] = '\0';
}

static const char *rrtype_name(uint16_t num)
{
	switch (num) {
	case 1: return "A";
	case 2: return "NS";
	case 5: return "CNAME";
	case 6: return "SOA";
	case 15: return "MX";
	case 16: return "TXT";
	case 28: return "AAAA";
	case 33: return "SRV";
	case 43: return "DS";
	case 46: return "RRSIG";
	case 47: return "NSEC";
	case 48: return "DNSKEY";
	case 50: return "NSEC3";
	case 51: return "NSEC3PARAM";
	default: return NULL;
	}
}

static uint16_t be16(const uint8_t *p)
{
	return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t be64(const uint8_t *p)
{
	return ((uint64_t)be32(p) << 32) | be32(p + 4);
}

static char *dup_printf(const char *fmt, ...)
{
	va_list ap;
	char *buf = NULL;
	int n;
	va_start(ap, fmt);
	n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (n < 0) return NULL;
	buf = (char *)malloc((size_t)n + 1u);
	if (!buf) return NULL;
	va_start(ap, fmt);
	vsnprintf(buf, (size_t)n + 1u, fmt, ap);
	va_end(ap);
	return buf;
}

int bogi23_binary_pool_expand(const uint8_t *payload, size_t length, char **out)
{
	uint8_t tag;
	const uint8_t *b;
	size_t n;
	size_t off = 0;
	*out = NULL;
	if (payload == NULL || length == 0) return -1;
	tag = payload[0];
	b = payload + 1;
	n = length - 1;

	if (tag == TAG_UTF8) {
		char *t = (char *)malloc(n + 1);
		if (!t) return -1;
		memcpy(t, b, n);
		t[n] = '\0';
		*out = t;
		return 0;
	}
	if (tag == TAG_A) {
		char ip[INET_ADDRSTRLEN];
		if (n != 4) return -1;
		if (!inet_ntop(AF_INET, b, ip, sizeof ip)) return -1;
		*out = strdup(ip);
		return *out ? 0 : -1;
	}
	if (tag == TAG_AAAA) {
		char ip[INET6_ADDRSTRLEN];
		if (n != 16) return -1;
		if (!inet_ntop(AF_INET6, b, ip, sizeof ip)) return -1;
		*out = strdup(ip);
		return *out ? 0 : -1;
	}
	if (tag == TAG_SOA) {
		char mname[256], rname[256];
		uint32_t serial, refresh, retry, expire, minimum;
		if (read_name(b, n, &off, mname, sizeof mname) != 0) return -1;
		if (read_name(b, n, &off, rname, sizeof rname) != 0) return -1;
		if (off + 20 > n) return -1;
		serial = be32(b + off);
		refresh = be32(b + off + 4);
		retry = be32(b + off + 8);
		expire = be32(b + off + 12);
		minimum = be32(b + off + 16);
		*out = dup_printf("%s %s %u %u %u %u %u", mname, rname, serial,
				  refresh, retry, expire, minimum);
		return *out ? 0 : -1;
	}
	if (tag == TAG_MX) {
		char exch[256];
		uint16_t pref;
		if (n < 2) return -1;
		pref = be16(b);
		off = 2;
		if (read_name(b, n, &off, exch, sizeof exch) != 0) return -1;
		*out = dup_printf("%u %s", (unsigned)pref, exch);
		return *out ? 0 : -1;
	}
	if (tag == TAG_DS) {
		char *hex;
		uint16_t keytag;
		uint8_t alg, digt;
		size_t dlen;
		if (n < 4) return -1;
		keytag = be16(b);
		alg = b[2];
		digt = b[3];
		dlen = n - 4;
		hex = (char *)malloc(dlen * 2 + 1);
		if (!hex) return -1;
		hex_encode(b + 4, dlen, hex);
		*out = dup_printf("%u %u %u %s", (unsigned)keytag, (unsigned)alg,
				  (unsigned)digt, hex);
		free(hex);
		return *out ? 0 : -1;
	}
	if (tag == TAG_DNSKEY) {
		char *b64;
		uint16_t flags;
		uint8_t proto, alg;
		size_t klen;
		if (n < 4) return -1;
		flags = be16(b);
		proto = b[2];
		alg = b[3];
		klen = n - 4;
		b64 = (char *)malloc(((klen + 2) / 3) * 4 + 1);
		if (!b64) return -1;
		b64_encode(b + 4, klen, b64);
		*out = dup_printf("%u %u %u %s", (unsigned)flags, (unsigned)proto,
				  (unsigned)alg, b64);
		free(b64);
		return *out ? 0 : -1;
	}
	if (tag == TAG_RRSIG) {
		char signer[256], covered_buf[32], *b64;
		const char *covered;
		uint16_t cov_num, keytag;
		uint8_t alg, labels;
		uint32_t orig_ttl;
		uint64_t expire, inception;
		uint64_t slen;
		if (n < 2) return -1;
		cov_num = be16(b);
		off = 2;
		if (off >= n) return -1;
		if (b[off] == 0) {
			off += 1;
			covered = rrtype_name(cov_num);
			if (!covered) {
				snprintf(covered_buf, sizeof covered_buf, "TYPE%u",
					 (unsigned)cov_num);
				covered = covered_buf;
			}
		} else {
			off += 1;
			if (read_name(b, n, &off, covered_buf, sizeof covered_buf) != 0)
				return -1;
			covered = covered_buf;
		}
		if (off + 2 + 4 + 16 + 2 > n) return -1;
		alg = b[off];
		labels = b[off + 1];
		off += 2;
		orig_ttl = be32(b + off);
		off += 4;
		expire = be64(b + off);
		inception = be64(b + off + 8);
		off += 16;
		keytag = be16(b + off);
		off += 2;
		if (read_name(b, n, &off, signer, sizeof signer) != 0) return -1;
		if (read_uleb(b, n, &off, &slen) != 0 || off + (size_t)slen > n)
			return -1;
		b64 = (char *)malloc((((size_t)slen + 2) / 3) * 4 + 1);
		if (!b64) return -1;
		b64_encode(b + off, (size_t)slen, b64);
		*out = dup_printf("%s %u %u %u %llu %llu %u %s %s", covered,
				  (unsigned)alg, (unsigned)labels, orig_ttl,
				  (unsigned long long)expire,
				  (unsigned long long)inception, (unsigned)keytag,
				  signer, b64);
		free(b64);
		return *out ? 0 : -1;
	}
	if (tag == TAG_NSEC3) {
		char next_lab[128], types_buf[256], salt_hex[128];
		uint8_t alg, flags, sl;
		uint16_t iters, mask;
		uint64_t nl;
		const uint8_t *nxt;
		const uint8_t *salt_b;
		char *types = types_buf;
		int i, first = 1;
		size_t tlen = 0;
		if (n < 4) return -1;
		alg = b[0];
		flags = b[1];
		iters = be16(b + 2);
		off = 4;
		if (off >= n) return -1;
		sl = b[off++];
		if (off + sl > n) return -1;
		salt_b = b + off;
		off += sl;
		if (sl == 0) {
			strcpy(salt_hex, "-");
		} else {
			if (sl > 60) return -1;
			hex_encode(salt_b, sl, salt_hex);
		}
		if (read_uleb(b, n, &off, &nl) != 0 || off + (size_t)nl > n) return -1;
		nxt = b + off;
		off += (size_t)nl;
		if (off + 2 > n) return -1;
		mask = be16(b + off);
		off += 2;
		if (off >= n) return -1;
		if (b[off] == 0) {
			off += 1;
			b32hex_encode(nxt, (size_t)nl, next_lab);
		} else {
			off += 1;
			if (read_name(b, n, &off, next_lab, sizeof next_lab) != 0)
				return -1;
		}
		if (off >= n) return -1;
		if (b[off] == 0) {
			off += 1;
			types_buf[0] = '\0';
			for (i = 0; i < NTYPES; ++i) {
				if (mask & (1u << i)) {
					if (!first) types_buf[tlen++] = ' ';
					first = 0;
					strcpy(types_buf + tlen, TYPE_ORDER[i]);
					tlen += strlen(TYPE_ORDER[i]);
				}
			}
			types_buf[tlen] = '\0';
		} else {
			off += 1;
			if (read_name(b, n, &off, types_buf, sizeof types_buf) != 0)
				return -1;
		}
		*out = dup_printf("%u %u %u %s %s %s", (unsigned)alg, (unsigned)flags,
				  (unsigned)iters, salt_hex, next_lab, types);
		return *out ? 0 : -1;
	}
	if (tag == TAG_NSEC3PARAM) {
		char salt_hex[128];
		uint8_t alg, flags, sl;
		uint16_t iters;
		if (n < 5) return -1;
		alg = b[0];
		flags = b[1];
		iters = be16(b + 2);
		sl = b[4];
		if (5u + sl > n) return -1;
		if (sl == 0)
			strcpy(salt_hex, "-");
		else
			hex_encode(b + 5, sl, salt_hex);
		*out = dup_printf("%u %u %u %s", (unsigned)alg, (unsigned)flags,
				  (unsigned)iters, salt_hex);
		return *out ? 0 : -1;
	}
	if (tag == TAG_NS) {
		char name[256];
		if (read_name(b, n, &off, name, sizeof name) != 0) return -1;
		*out = strdup(name);
		return *out ? 0 : -1;
	}
	if (tag == TAG_TXT) {
		uint64_t len = 0;
		char *t;
		if (read_uleb(b, n, &off, &len) != 0 || off + (size_t)len > n)
			return -1;
		t = (char *)malloc((size_t)len + 1u);
		if (!t) return -1;
		memcpy(t, b + off, (size_t)len);
		t[len] = '\0';
		*out = t;
		return 0;
	}
	return -1;
}

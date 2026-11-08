#define _POSIX_C_SOURCE 200809L
#include "bogi23_huffman.h"

#include <string.h>

static int read_uleb_mem(const uint8_t *p, size_t n, size_t *off, uint64_t *out)
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

int bogi23_huffman_load(Bogi23HuffTable *table, const uint8_t *wire, size_t wire_len)
{
	size_t off = 0;
	uint16_t n;
	size_t i;
	(void)memset(table, 0, sizeof(*table));
	if (wire_len < 2) return -1;
	n = (uint16_t)(wire[0] | ((uint16_t)wire[1] << 8));
	off = 2;
	if (n > ZIR3_HUFF_MAX_SYMBOLS) return -1;
	for (i = 0; i < n; ++i) {
		uint8_t sym, bitlen, nbytes, k;
		uint32_t code = 0;
		if (off + 2 > wire_len) return -1;
		sym = wire[off++];
		bitlen = wire[off++];
		if (bitlen == 0 || bitlen > ZIR3_HUFF_MAX_BITS) return -1;
		nbytes = (uint8_t)((bitlen + 7) / 8);
		if (off + nbytes > wire_len) return -1;
		for (k = 0; k < nbytes; ++k) {
			code = (code << 8) | wire[off + k];
		}
		/* Keep only top bitlen bits of the packed MSB-first field. */
		{
			unsigned packed_bits = (unsigned)nbytes * 8u;
			if (packed_bits > bitlen)
				code >>= (packed_bits - bitlen);
		}
		off += nbytes;
		table->entries[i].symbol = sym;
		table->entries[i].bitlen = bitlen;
		table->entries[i].code = code;
	}
	table->count = n;
	table->ready = 1;
	return 0;
}

static int bit_at(const uint8_t *bytes, size_t bit_index)
{
	size_t byte = bit_index / 8u;
	unsigned shift = 7u - (unsigned)(bit_index % 8u);
	return (bytes[byte] >> shift) & 1;
}

int bogi23_huffman_decode_suffix(
	const Bogi23HuffTable *table,
	const uint8_t *enc,
	size_t enc_len,
	uint8_t *out,
	size_t out_cap
)
{
	size_t off = 0;
	uint64_t plain_len = 0;
	size_t produced = 0;
	size_t bit_i = 0;
	size_t bit_total;
	const uint8_t *bits;

	if (!table || !table->ready || !enc || !out) return -1;
	if (read_uleb_mem(enc, enc_len, &off, &plain_len) != 0) return -1;
	if (plain_len > out_cap) return -1;
	if (plain_len == 0) return 0;
	bits = enc + off;
	bit_total = (enc_len - off) * 8u;

	while (produced < (size_t)plain_len) {
		uint32_t acc = 0;
		unsigned have = 0;
		int matched = 0;
		size_t e;
		/* Grow one bit at a time and match against table. */
		while (bit_i < bit_total && have < ZIR3_HUFF_MAX_BITS) {
			acc = (acc << 1) | (uint32_t)bit_at(bits, bit_i);
			bit_i += 1;
			have += 1;
			for (e = 0; e < table->count; ++e) {
				if (table->entries[e].bitlen == have &&
				    table->entries[e].code == acc) {
					out[produced++] = table->entries[e].symbol;
					matched = 1;
					break;
				}
			}
			if (matched) break;
		}
		if (!matched) return -1;
	}
	return (int)plain_len;
}

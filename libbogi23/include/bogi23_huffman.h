#ifndef ZIR3_BOGI23_HUFFMAN_H
#define ZIR3_BOGI23_HUFFMAN_H

#include <stddef.h>
#include <stdint.h>

#define ZIR3_FLAG_HUFFMAN_SUFFIX 0x8u
#define ZIR3_HUFF_MAX_SYMBOLS 256u
#define ZIR3_HUFF_MAX_BITS 32u

typedef struct {
	uint8_t symbol;
	uint8_t bitlen;
	uint32_t code; /* MSB-aligned in top bitlen bits when shifted */
} Bogi23HuffEntry;

typedef struct {
	Bogi23HuffEntry entries[ZIR3_HUFF_MAX_SYMBOLS];
	size_t count;
	int ready;
} Bogi23HuffTable;

/* Parse table wire at map+off for `table_len` bytes. */
int bogi23_huffman_load(Bogi23HuffTable *table, const uint8_t *wire, size_t wire_len);

/* Decode enc blob (uleb plain_len + bits) into out[0..out_cap). Returns plain length or -1. */
int bogi23_huffman_decode_suffix(
	const Bogi23HuffTable *table,
	const uint8_t *enc,
	size_t enc_len,
	uint8_t *out,
	size_t out_cap
);

#endif

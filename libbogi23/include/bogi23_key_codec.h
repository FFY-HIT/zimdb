#ifndef BOGI23_KEY_CODEC_H
#define BOGI23_KEY_CODEC_H
#include "bogi23_reader.h"

#define BOGI23_KEY_MAGIC "ZIMBC01\0"
#define BOGI23_KEY_HEADER_BYTES 128u
#define BOGI23_KEY_DESC_BYTES 64u
#define BOGI23_KEY_COMPRESSED_RAW_LIMIT (64u * 1024u * 1024u)

/* v2 keeps the original logical BOGIP1 bytes, with one codec frame per owner.
 * The coarse restart directory and the global pool both retain stride16. */
int bogi23_key_attach(Bogi23Reader *reader);
void bogi23_key_close(Bogi23Reader *reader);
uint64_t bogi23_key_logical_size(const Bogi23Reader *reader);
int bogi23_key_read(Bogi23Reader *reader, uint64_t offset, uint64_t length, void *out);
int bogi23_key_first_key(Bogi23Reader *reader, uint64_t group,
                         uint8_t *key, size_t *length);
/* groups, owners, read calls, cache hits/misses, Snappy/LZ4 decodes,
 * decoded/stored bytes, container/frame CRC checks, cache charge/limit,
 * cached entries, maximum raw frame, configured codec, group scans,
 * plain frame accesses. Cache charge includes logical raw bytes even when a
 * plain frame borrows mmap; state/small current-group scratch is separate. */
int bogi23_key_stats(const Bogi23Reader *reader, uint64_t values[18]);

/* Full logical readback for independent byte-for-byte reconstruction tests. */
int bogi23_read_logical(Bogi23Reader *reader, uint64_t offset,
                        uint64_t length, void *out);
#endif

#ifndef ZIR3_BOGI23_NATIVE_H
#define ZIR3_BOGI23_NATIVE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define ZIR3_BOGI_MAGIC "BOGIP1\0\0"
#define ZIR3_HEADER_SIZE 128u
#define ZIR3_BLOCK_SIZE 16u
#define ZIR3_MAX_KEY 253u
#define ZIR3_NTYPES 7u
#define ZIR3_NTYPES_DNSSEC 12u
#define ZIR3_NTYPES_MAX 12u
#define ZIR3_PROFILE_P1 0x50310001u
#define ZIR3_PROFILE_DNSSEC 0x50310002u


#ifndef ZIR3_LEARNED_INDEX
#define ZIR3_LEARNED_INDEX 1
#endif

/* Open-time FITing/RMI-style auxiliary index over owner restart keys.
 * Does not change on-disk BOGIP1 layout. Prediction is always verified by
 * exact key_compare within a local window (or full binary search fallback).
 */
typedef struct {
    uint64_t x0;
    double slope;
    double intercept;
    uint64_t start; /* inclusive block index */
    uint64_t end;   /* exclusive */
    uint32_t err;   /* max |pred-actual| over the segment, rounded up */
} Zir3LearnedSeg;

typedef struct {
    uint8_t *key_bytes;
    size_t key_bytes_len;
    uint32_t *key_off;
    uint16_t *key_len;
    uint64_t *proj; /* HPT-CDF scaled to [0, 2^63) for monotone segment fit */
    Zir3LearnedSeg *segs;
    /* LITS-style Hash-enhanced Prefix Table: row = hash(prefix), col = next byte.
     * Stores conditional CDF mass so GetCDF better handles skewed DNS prefixes
     * than a uniform first-8-byte projection (Yang & Chen, PVLDB 2024). */
    float *hpt_cdf;  /* ROWS*256 */
    float *hpt_prob; /* ROWS*256 */
    uint32_t hpt_rows;
    uint64_t nkeys;
    uint64_t nsegs;
    int ready;
    int use_hpt;
} Zir3LearnedIndex;

typedef enum {
    TK_HEADER,
    TK_ORIGIN,
    TK_OWNER_RESTART,
    TK_OWNER_KEY,
    TK_OWNER_META,
    TK_OWNER_BODY,
    TK_RDATA_ID,
    TK_POOL_RESTART,
    TK_POOL_META,
    TK_POOL_PAYLOAD
} TraceKind;

typedef struct {
    uint64_t offset;
    uint64_t length;
    TraceKind kind;
} TraceEvent;

typedef struct {
    TraceEvent *events;
    size_t count;
    size_t capacity;
    int fixed;
    FILE *spill;
    TraceEvent pending;
    int has_pending;
    uint64_t owner_restart_probes_total;
    uint64_t owner_restart_probes_max;
    uint64_t owner_block_entries_total;
    uint64_t owner_block_entries_max;
    uint64_t pool_restart_reads;
    uint64_t pool_items_probed;
    uint64_t pool_items_probed_max_per_ref;
    uint64_t *result_ids;
    size_t result_id_count;
    size_t result_id_capacity;
    uint64_t visited_owner_count;
    uint64_t selected_rr_count;
    uint64_t selected_text_bytes;
} AccessTrace;

typedef struct {
    int fd;
    const uint8_t *map_base;
    size_t map_size;
    char origin[255];
    uint64_t file_size;
    uint64_t origin_off;
    uint64_t origin_len;
    uint64_t owner_restart_off;
    uint64_t owner_restart_count;
    uint64_t owner_stream_off;
    uint64_t owner_stream_len;
    uint64_t owner_count;
    uint64_t rrset_count;
    uint64_t rdata_count;
    uint64_t pool_entry_count;
    uint64_t pool_restart_off;
    uint64_t pool_restart_count;
    uint64_t pool_off;
    TraceEvent constructor_events[4];
    AccessTrace constructor_trace;
    AccessTrace *active_trace;
    uint64_t alloc_current;
    uint64_t alloc_peak;
    uint64_t alloc_requests;
    uint64_t alloc_frees;
    uint64_t query_alloc_base;
    uint64_t query_alloc_peak;
    uint64_t query_alloc_requests_base;
    uint64_t query_alloc_frees_base;
} Bogi23Reader;

int bogi23_open(Bogi23Reader *reader, const char *path);
void bogi23_close(Bogi23Reader *reader);

#endif

/* ZIR-v3 exposed-only native development reader for BOGI-v2.3.
 *
 * This program deliberately does not shape DNS wire packets.  It returns the
 * independent lookup core's normalized RRsets plus an auditable mmap access
 * trace.  A shared, separately reviewed Python layer maps the result to
 * CoreIR/ResponseIR.
 */
#include "bogi23_reader.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *TYPE_ORDER_P1[ZIR3_NTYPES] = {
    "A", "NS", "CNAME", "SOA", "MX", "TXT", "AAAA"
};
static uint32_t g_profile_id = ZIR3_PROFILE_P1;
static const char * const *g_type_order = NULL;
static size_t g_ntypes = ZIR3_NTYPES;
static size_t g_mask_bytes = 1u;
static const char *TYPE_ORDER_DNSSEC[ZIR3_NTYPES_DNSSEC] = {
    "A", "NS", "CNAME", "SOA", "MX", "TXT", "AAAA",
    "DS", "RRSIG", "NSEC3", "DNSKEY", "NSEC3PARAM"
};


typedef struct {
    uint64_t size;
} AllocationHeader;

static void fail_process(const char *message) {
    (void)fprintf(stderr, "bogi23_native: %s\n", message);
    exit(2);
}

static int checked_add_u64(uint64_t a, uint64_t b, uint64_t *out) {
    if (UINT64_MAX - a < b) return -1;
    *out = a + b;
    return 0;
}

static int checked_mul_u64(uint64_t a, uint64_t b, uint64_t *out) {
    if (a != 0u && b > UINT64_MAX / a) return -1;
    *out = a * b;
    return 0;
}

static void *tracked_malloc(Bogi23Reader *reader, size_t bytes) {
    size_t requested = bytes == 0u ? 1u : bytes;
    if (requested > SIZE_MAX - sizeof(AllocationHeader)) return NULL;
    AllocationHeader *header = (AllocationHeader *)malloc(
        sizeof(AllocationHeader) + requested
    );
    if (header == NULL) return NULL;
    header->size = (uint64_t)requested;
    reader->alloc_current += (uint64_t)requested;
    if (reader->alloc_current > reader->alloc_peak) {
        reader->alloc_peak = reader->alloc_current;
    }
    if (reader->alloc_current > reader->query_alloc_peak) {
        reader->query_alloc_peak = reader->alloc_current;
    }
    reader->alloc_requests += 1u;
    return (void *)(header + 1);
}

static void *tracked_realloc(Bogi23Reader *reader, void *pointer, size_t bytes) {
    if (pointer == NULL) return tracked_malloc(reader, bytes);
    size_t requested = bytes == 0u ? 1u : bytes;
    if (requested > SIZE_MAX - sizeof(AllocationHeader)) return NULL;
    AllocationHeader *old_header = ((AllocationHeader *)pointer) - 1;
    uint64_t old_size = old_header->size;
    AllocationHeader *new_header = (AllocationHeader *)realloc(
        old_header, sizeof(AllocationHeader) + requested
    );
    if (new_header == NULL) return NULL;
    new_header->size = (uint64_t)requested;
    reader->alloc_current = reader->alloc_current - old_size + (uint64_t)requested;
    if (reader->alloc_current > reader->alloc_peak) {
        reader->alloc_peak = reader->alloc_current;
    }
    if (reader->alloc_current > reader->query_alloc_peak) {
        reader->query_alloc_peak = reader->alloc_current;
    }
    reader->alloc_requests += 1u;
    reader->alloc_frees += 1u;
    return (void *)(new_header + 1);
}

static void tracked_free(Bogi23Reader *reader, void *pointer) {
    if (pointer == NULL) return;
    AllocationHeader *header = ((AllocationHeader *)pointer) - 1;
    reader->alloc_current -= header->size;
    reader->alloc_frees += 1u;
    free(header);
}

static char *tracked_strdup(Bogi23Reader *reader, const char *text) {
    size_t length = strlen(text);
    if (length == SIZE_MAX) return NULL;
    char *copy = (char *)tracked_malloc(reader, length + 1u);
    if (copy != NULL) (void)memcpy(copy, text, length + 1u);
    return copy;
}

static const char *trace_kind_name(TraceKind kind) {
    switch (kind) {
        case TK_HEADER: return "header";
        case TK_ORIGIN: return "origin";
        case TK_OWNER_RESTART: return "owner_restart";
        case TK_OWNER_KEY: return "owner_key";
        case TK_OWNER_META: return "owner_meta";
        case TK_OWNER_BODY: return "owner_body";
        case TK_RDATA_ID: return "rdata_id";
        case TK_POOL_RESTART: return "pool_restart";
        case TK_POOL_META: return "pool_meta";
        case TK_POOL_PAYLOAD: return "pool_payload";
    }
    return "invalid";
}

static int trace_reserve(Bogi23Reader *reader, AccessTrace *trace, size_t wanted) {
    if (wanted <= trace->capacity) return 0;
    if (trace->fixed) return -1;
    size_t capacity = trace->capacity == 0u ? 128u : trace->capacity;
    while (capacity < wanted) {
        if (capacity > SIZE_MAX / 2u) return -1;
        capacity *= 2u;
    }
    if (capacity > SIZE_MAX / sizeof(TraceEvent)) return -1;
    void *grown = tracked_realloc(
        reader, trace->events, capacity * sizeof(TraceEvent)
    );
    if (grown == NULL) return -1;
    trace->events = (TraceEvent *)grown;
    trace->capacity = capacity;
    return 0;
}

static int trace_flush_pending(AccessTrace *trace) {
    if (!trace->has_pending) return 0;
    if (trace->spill == NULL ||
        fwrite(&trace->pending, sizeof(trace->pending), 1u, trace->spill) != 1u) {
        return -1;
    }
    trace->count += 1u;
    trace->has_pending = 0;
    return 0;
}

static int trace_record(
    Bogi23Reader *reader, uint64_t offset, uint64_t length, TraceKind kind
) {
    AccessTrace *trace = reader->active_trace;
    if (trace == NULL || length == 0u) return 0;
    if (!trace->fixed) {
        uint64_t end = 0u;
        if (trace->has_pending && trace->pending.kind == kind &&
            checked_add_u64(trace->pending.offset, trace->pending.length, &end) == 0 &&
            end == offset) {
            return checked_add_u64(
                trace->pending.length, length, &trace->pending.length
            );
        }
        if (trace_flush_pending(trace) != 0) return -1;
        trace->pending.offset = offset;
        trace->pending.length = length;
        trace->pending.kind = kind;
        trace->has_pending = 1;
        return 0;
    }
    if (trace->count > 0u) {
        TraceEvent *prior = &trace->events[trace->count - 1u];
        uint64_t end = 0u;
        if (prior->kind == kind &&
            checked_add_u64(prior->offset, prior->length, &end) == 0 &&
            end == offset) {
            if (checked_add_u64(prior->length, length, &prior->length) != 0) {
                return -1;
            }
            return 0;
        }
    }
    if (trace_reserve(reader, trace, trace->count + 1u) != 0) return -1;
    trace->events[trace->count].offset = offset;
    trace->events[trace->count].length = length;
    trace->events[trace->count].kind = kind;
    trace->count += 1u;
    return 0;
}

/* The only function that dereferences or copies bytes from map_base. */
static int read_at(
    Bogi23Reader *reader,
    uint64_t offset,
    uint64_t length,
    TraceKind kind,
    void *destination
) {
    uint64_t end = 0u;
    if (checked_add_u64(offset, length, &end) != 0 || end > reader->map_size) {
        return -1;
    }
    if (trace_record(reader, offset, length, kind) != 0) return -1;
    if (length > 0u) {
        (void)memcpy(destination, reader->map_base + (size_t)offset, (size_t)length);
    }
    return 0;
}

static uint16_t little_u16(const uint8_t *value) {
    return (uint16_t)((uint16_t)value[0] | ((uint16_t)value[1] << 8u));
}

static uint32_t little_u32(const uint8_t *value) {
    return (uint32_t)value[0] |
           ((uint32_t)value[1] << 8u) |
           ((uint32_t)value[2] << 16u) |
           ((uint32_t)value[3] << 24u);
}

static uint64_t little_u64(const uint8_t *value) {
    uint64_t answer = 0u;
    unsigned int index = 0u;
    for (index = 0u; index < 8u; ++index) {
        answer |= (uint64_t)value[index] << (8u * index);
    }
    return answer;
}

static int read_u64_at(
    Bogi23Reader *reader, uint64_t offset, TraceKind kind, uint64_t *answer
) {
    uint8_t raw[8];
    if (read_at(reader, offset, 8u, kind, raw) != 0) return -1;
    *answer = little_u64(raw);
    return 0;
}

int bogi23_open(Bogi23Reader *reader, const char *path) {
    uint8_t header[ZIR3_HEADER_SIZE];
    uint64_t product = 0u;
    uint64_t end = 0u;
    struct stat status;
    void *mapping = MAP_FAILED;
    (void)memset(reader, 0, sizeof(*reader));
    reader->fd = -1;
    reader->constructor_trace.events = reader->constructor_events;
    reader->constructor_trace.capacity = 4u;
    reader->constructor_trace.fixed = 1;
    reader->active_trace = &reader->constructor_trace;

    reader->fd = open(path, O_RDONLY);
    if (reader->fd < 0) return -1;
    if (fstat(reader->fd, &status) != 0 || status.st_size < (off_t)ZIR3_HEADER_SIZE) {
        bogi23_close(reader);
        return -1;
    }
    if ((uintmax_t)status.st_size > (uintmax_t)SIZE_MAX) {
        bogi23_close(reader);
        return -1;
    }
    reader->map_size = (size_t)status.st_size;
    mapping = mmap(NULL, reader->map_size, PROT_READ, MAP_PRIVATE, reader->fd, 0);
    if (mapping == MAP_FAILED) {
        bogi23_close(reader);
        return -1;
    }
    reader->map_base = (const uint8_t *)mapping;
    if (read_at(reader, 0u, ZIR3_HEADER_SIZE, TK_HEADER, header) != 0) {
        bogi23_close(reader);
        return -1;
    }
    if (memcmp(header, ZIR3_BOGI_MAGIC, 8u) != 0 ||
        little_u16(header + 8u) != 2u ||
        little_u16(header + 10u) != 3u ||
        little_u16(header + 12u) != 0x4c45u ||
        little_u16(header + 14u) != ZIR3_HEADER_SIZE ||
        little_u32(header + 16u) != 0x424f4704u ||
         (little_u32(header + 20u) != ZIR3_PROFILE_P1 &&
         little_u32(header + 20u) != ZIR3_PROFILE_DNSSEC) ||
        little_u32(header + 24u) != 0u ||
        little_u16(header + 28u) != ZIR3_BLOCK_SIZE ||
        little_u16(header + 30u) != 0u ||
        little_u64(header + 120u) != 0u) {
        bogi23_close(reader);
        return -1;
    }
    g_profile_id = little_u32(header + 20u);
    if (g_profile_id == ZIR3_PROFILE_DNSSEC) {
        g_type_order = TYPE_ORDER_DNSSEC;
        g_ntypes = ZIR3_NTYPES_DNSSEC;
        g_mask_bytes = 2u;
    } else {
        g_type_order = TYPE_ORDER_P1;
        g_ntypes = ZIR3_NTYPES;
        g_mask_bytes = 1u;
    }
    reader->file_size = little_u64(header + 32u);
    reader->origin_off = little_u64(header + 40u);
    reader->origin_len = little_u64(header + 48u);
    reader->owner_restart_off = little_u64(header + 56u);
    reader->owner_restart_count = little_u64(header + 64u);
    reader->owner_stream_off = little_u64(header + 72u);
    reader->owner_stream_len = little_u64(header + 80u);
    reader->owner_count = little_u64(header + 88u);
    reader->rrset_count = little_u64(header + 96u);
    reader->rdata_count = little_u64(header + 104u);
    reader->pool_entry_count = little_u64(header + 112u);
    if (reader->file_size != reader->map_size ||
        reader->origin_len == 0u || reader->origin_len > 254u ||
        reader->owner_count == 0u || reader->owner_restart_count == 0u ||
        reader->pool_entry_count == 0u) {
        bogi23_close(reader);
        return -1;
    }
    reader->pool_restart_count =
        (reader->pool_entry_count + ZIR3_BLOCK_SIZE - 1u) / ZIR3_BLOCK_SIZE;
    if (checked_add_u64(reader->origin_off, reader->origin_len, &end) != 0 ||
        end > reader->file_size ||
        checked_add_u64(reader->owner_stream_off, reader->owner_stream_len,
                        &reader->pool_restart_off) != 0 ||
        checked_mul_u64(reader->pool_restart_count, 8u, &product) != 0 ||
        checked_add_u64(reader->pool_restart_off, product, &reader->pool_off) != 0 ||
        reader->pool_off > reader->file_size) {
        bogi23_close(reader);
        return -1;
    }
    if (read_at(reader, reader->origin_off, reader->origin_len, TK_ORIGIN,
                reader->origin) != 0) {
        bogi23_close(reader);
        return -1;
    }
    reader->origin[reader->origin_len] = '\0';
    reader->active_trace = NULL;
    return 0;
}

static void trace_release(Bogi23Reader *reader, AccessTrace *trace) {
    if (!trace->fixed) {
        if (trace->spill != NULL) (void)fclose(trace->spill);
        tracked_free(reader, trace->events);
        tracked_free(reader, trace->result_ids);
    }
    (void)memset(trace, 0, sizeof(*trace));
}

void bogi23_close(Bogi23Reader *reader) {
    if (reader->map_base != NULL && reader->map_size > 0u) {
        (void)munmap((void *)(uintptr_t)reader->map_base, reader->map_size);
    }
    if (reader->fd >= 0) (void)close(reader->fd);
    reader->map_base = NULL;
    reader->map_size = 0u;
    reader->fd = -1;
}

static int read_uleb(
    Bogi23Reader *reader,
    uint64_t *cursor,
    uint64_t bound,
    TraceKind kind,
    uint64_t *answer
) {
    uint64_t value = 0u;
    unsigned int shift = 0u;
    unsigned int index = 0u;
    for (index = 0u; index < 10u; ++index) {
        uint8_t byte = 0u;
        if (*cursor >= bound || read_at(reader, *cursor, 1u, kind, &byte) != 0) {
            return -1;
        }
        *cursor += 1u;
        if (index == 9u && (byte & 0xfeu) != 0u) return -1;
        value |= (uint64_t)(byte & 0x7fu) << shift;
        if ((byte & 0x80u) == 0u) {
            if (index > 0u && byte == 0u) return -1;
            *answer = value;
            return 0;
        }
        shift += 7u;
    }
    return -1;
}

static int key_compare(
    const uint8_t *left, size_t left_size,
    const uint8_t *right, size_t right_size
) {
    size_t common = left_size < right_size ? left_size : right_size;
    int compared = memcmp(left, right, common);
    if (compared != 0) return compared;
    return left_size < right_size ? -1 : left_size > right_size ? 1 : 0;
}

static int type_index(const char *rrtype) {
    size_t index = 0u;
    for (index = 0u; index < (g_type_order ? g_ntypes : ZIR3_NTYPES); ++index) {
        if (g_type_order == NULL) g_type_order = TYPE_ORDER_P1;
        if (strcmp(g_type_order[index], rrtype) == 0) return (int)index;
    }
    return -1;
}

static int append_result_id(Bogi23Reader *reader, uint64_t value) {
    AccessTrace *trace = reader->active_trace;
    size_t wanted = 0u;
    size_t capacity = 0u;
    void *grown = NULL;
    if (trace == NULL) return -1;
    wanted = trace->result_id_count + 1u;
    if (wanted > trace->result_id_capacity) {
        capacity = trace->result_id_capacity == 0u ? 32u : trace->result_id_capacity;
        while (capacity < wanted) {
            if (capacity > SIZE_MAX / 2u) return -1;
            capacity *= 2u;
        }
        if (capacity > SIZE_MAX / sizeof(uint64_t)) return -1;
        grown = tracked_realloc(
            reader, trace->result_ids, capacity * sizeof(uint64_t)
        );
        if (grown == NULL) return -1;
        trace->result_ids = (uint64_t *)grown;
        trace->result_id_capacity = capacity;
    }
    trace->result_ids[trace->result_id_count++] = value;
    return 0;
}

static int read_pool_value(
    Bogi23Reader *reader, uint64_t identifier, char **text_out
) {
    uint64_t block = 0u;
    uint64_t restart_at = 0u;
    uint64_t relative = 0u;
    uint64_t cursor = 0u;
    uint64_t first = 0u;
    uint64_t ordinal = 0u;
    uint64_t probes = 0u;
    if (identifier >= reader->pool_entry_count) return -1;
    block = identifier / ZIR3_BLOCK_SIZE;
    if (checked_mul_u64(block, 8u, &restart_at) != 0 ||
        checked_add_u64(reader->pool_restart_off, restart_at, &restart_at) != 0 ||
        read_u64_at(reader, restart_at, TK_POOL_RESTART, &relative) != 0 ||
        checked_add_u64(reader->pool_off, relative, &cursor) != 0 ||
        cursor > reader->file_size) {
        return -1;
    }
    reader->active_trace->pool_restart_reads += 1u;
    first = block * ZIR3_BLOCK_SIZE;
    for (ordinal = first; ordinal <= identifier; ++ordinal) {
        uint64_t witness_rrset = 0u;
        uint64_t witness_rdata = 0u;
        uint64_t length = 0u;
        uint64_t end = 0u;
        if (read_uleb(reader, &cursor, reader->file_size, TK_POOL_META,
                      &witness_rrset) != 0 ||
            read_uleb(reader, &cursor, reader->file_size, TK_POOL_META,
                      &witness_rdata) != 0 ||
            read_uleb(reader, &cursor, reader->file_size, TK_POOL_META,
                      &length) != 0 ||
            checked_add_u64(cursor, length, &end) != 0 ||
            end > reader->file_size) {
            return -1;
        }
        (void)witness_rrset;
        (void)witness_rdata;
        probes += 1u;
        reader->active_trace->pool_items_probed += 1u;
        if (ordinal == identifier) {
            char *text = NULL;
            if (length > SIZE_MAX - 1u) return -1;
            text = (char *)tracked_malloc(reader, (size_t)length + 1u);
            if (text == NULL ||
                read_at(reader, cursor, length, TK_POOL_PAYLOAD, text) != 0) {
                tracked_free(reader, text);
                return -1;
            }
            text[length] = '\0';
            *text_out = text;
        }
        cursor = end;
    }
    if (probes == 0u || probes > ZIR3_BLOCK_SIZE || *text_out == NULL) return -1;
    if (probes > reader->active_trace->pool_items_probed_max_per_ref) {
        reader->active_trace->pool_items_probed_max_per_ref = probes;
    }
    return append_result_id(reader, identifier);
}

typedef struct {
    char *owner;
    char *source_owner;
    char *rrtype;
    uint64_t ttl;
    uint64_t source_ttl;
    char **rdatas;
    size_t rdata_count;
} RRset;

typedef struct {
    RRset sets[ZIR3_NTYPES];
    size_t count;
    char *owner;
} OwnerGroup;

typedef struct {
    uint8_t key[ZIR3_MAX_KEY];
    size_t key_length;
    OwnerGroup group;
    int has_group;
    int relation; /* 0 exact, 1 lower bound */
    int found;
} ScanResult;

static void free_rrset(Bogi23Reader *reader, RRset *rrset) {
    size_t index = 0u;
    if (rrset == NULL) return;
    tracked_free(reader, rrset->owner);
    tracked_free(reader, rrset->source_owner);
    tracked_free(reader, rrset->rrtype);
    for (index = 0u; index < rrset->rdata_count; ++index) {
        tracked_free(reader, rrset->rdatas[index]);
    }
    tracked_free(reader, rrset->rdatas);
    (void)memset(rrset, 0, sizeof(*rrset));
}

static void free_group(Bogi23Reader *reader, OwnerGroup *group) {
    size_t index = 0u;
    if (group == NULL) return;
    for (index = 0u; index < group->count; ++index) {
        free_rrset(reader, &group->sets[index]);
    }
    tracked_free(reader, group->owner);
    (void)memset(group, 0, sizeof(*group));
}

static void free_scan(Bogi23Reader *reader, ScanResult *scan) {
    if (scan->has_group) free_group(reader, &scan->group);
    (void)memset(scan, 0, sizeof(*scan));
}

static int clone_rrset(
    Bogi23Reader *reader, const RRset *source, const char *owner_override,
    RRset *destination
) {
    size_t index = 0u;
    (void)memset(destination, 0, sizeof(*destination));
    destination->owner = tracked_strdup(
        reader, owner_override == NULL ? source->owner : owner_override
    );
    destination->source_owner = tracked_strdup(reader, source->source_owner);
    destination->rrtype = tracked_strdup(reader, source->rrtype);
    destination->ttl = source->ttl;
    destination->source_ttl = source->source_ttl;
    destination->rdata_count = source->rdata_count;
    if (source->rdata_count > SIZE_MAX / sizeof(char *)) goto failure;
    destination->rdatas = (char **)tracked_malloc(
        reader, (source->rdata_count == 0u ? 1u : source->rdata_count) * sizeof(char *)
    );
    if (destination->owner == NULL || destination->source_owner == NULL ||
        destination->rrtype == NULL ||
        destination->rdatas == NULL) goto failure;
    (void)memset(
        destination->rdatas, 0,
        (source->rdata_count == 0u ? 1u : source->rdata_count) * sizeof(char *)
    );
    for (index = 0u; index < source->rdata_count; ++index) {
        destination->rdatas[index] = tracked_strdup(reader, source->rdatas[index]);
        if (destination->rdatas[index] == NULL) goto failure;
    }
    return 0;
failure:
    free_rrset(reader, destination);
    return -1;
}

static RRset *group_get(OwnerGroup *group, const char *rrtype) {
    size_t index = 0u;
    for (index = 0u; index < group->count; ++index) {
        if (strcmp(group->sets[index].rrtype, rrtype) == 0) {
            return &group->sets[index];
        }
    }
    return NULL;
}

static int owner_to_key(
    const Bogi23Reader *reader, const char *owner,
    uint8_t *output, size_t *length_out
) {
    size_t owner_length = strlen(owner);
    size_t origin_length = strlen(reader->origin);
    size_t relative_length = 0u;
    size_t right = 0u;
    size_t produced = 0u;
    if (strcmp(owner, reader->origin) == 0) {
        *length_out = 0u;
        return 0;
    }
    if (owner_length <= origin_length + 1u ||
        owner[owner_length - origin_length - 1u] != '.' ||
        strcmp(owner + owner_length - origin_length, reader->origin) != 0) {
        return -1;
    }
    relative_length = owner_length - origin_length - 1u;
    right = relative_length;
    while (right > 0u) {
        size_t left = right;
        size_t index = 0u;
        while (left > 0u && owner[left - 1u] != '.') --left;
        if (right - left == 0u || right - left > 63u ||
            produced + (right - left) + 1u > ZIR3_MAX_KEY) return -1;
        for (index = left; index < right; ++index) {
            unsigned char byte = (unsigned char)owner[index];
            if (byte > 0x7fu || (byte >= 'A' && byte <= 'Z')) return -1;
            output[produced++] = (uint8_t)(byte + 1u);
        }
        output[produced++] = 0u;
        if (left == 0u) break;
        right = left - 1u;
    }
    *length_out = produced;
    return 0;
}

static char *key_to_owner(
    Bogi23Reader *reader, const uint8_t *key, size_t key_length
) {
    size_t starts[128];
    size_t lengths[128];
    size_t label_count = 0u;
    size_t cursor = 0u;
    size_t total = strlen(reader->origin) + 1u;
    char *answer = NULL;
    size_t output = 0u;
    if (key_length == 0u) return tracked_strdup(reader, reader->origin);
    while (cursor < key_length) {
        size_t start = cursor;
        while (cursor < key_length && key[cursor] != 0u) ++cursor;
        if (cursor == start || cursor >= key_length || label_count >= 128u) return NULL;
        starts[label_count] = start;
        lengths[label_count] = cursor - start;
        total += lengths[label_count] + 1u;
        label_count += 1u;
        cursor += 1u;
    }
    answer = (char *)tracked_malloc(reader, total);
    if (answer == NULL) return NULL;
    while (label_count > 0u) {
        size_t index = 0u;
        label_count -= 1u;
        for (index = 0u; index < lengths[label_count]; ++index) {
            uint8_t encoded = key[starts[label_count] + index];
            if (encoded == 0u) {
                tracked_free(reader, answer);
                return NULL;
            }
            answer[output++] = (char)(encoded - 1u);
        }
        answer[output++] = '.';
    }
    (void)memcpy(answer + output, reader->origin, strlen(reader->origin) + 1u);
    return answer;
}

static int restart_position(
    Bogi23Reader *reader, uint64_t number, uint64_t *position
) {
    uint64_t local = 0u;
    uint64_t offset = 0u;
    if (number >= reader->owner_restart_count ||
        checked_mul_u64(number, 8u, &offset) != 0 ||
        checked_add_u64(reader->owner_restart_off, offset, &offset) != 0 ||
        read_u64_at(reader, offset, TK_OWNER_RESTART, &local) != 0 ||
        checked_add_u64(reader->owner_stream_off, local, position) != 0 ||
        *position >= reader->pool_restart_off) {
        return -1;
    }
    return 0;
}

static int restart_key(
    Bogi23Reader *reader, uint64_t number,
    uint8_t *key, size_t *key_length
) {
    uint64_t cursor = 0u;
    uint64_t length = 0u;
    uint64_t end = 0u;
    if (restart_position(reader, number, &cursor) != 0 ||
        read_uleb(reader, &cursor, reader->pool_restart_off, TK_OWNER_META,
                  &length) != 0 ||
        length > ZIR3_MAX_KEY ||
        checked_add_u64(cursor, length, &end) != 0 ||
        end > reader->pool_restart_off ||
        read_at(reader, cursor, length, TK_OWNER_KEY, key) != 0) return -1;
    *key_length = (size_t)length;
    return 0;
}



static int select_block(
    Bogi23Reader *reader, const uint8_t *target, size_t target_length,
    uint64_t *block_out
) {
    {
    uint64_t low = 0u;
    uint64_t high = reader->owner_restart_count;
    uint64_t probes = 0u;
    while (low < high) {
        uint64_t middle = low + (high - low) / 2u;
        uint8_t key[ZIR3_MAX_KEY];
        size_t length = 0u;
        if (restart_key(reader, middle, key, &length) != 0) return -1;
        probes += 1u;
        if (key_compare(key, length, target, target_length) <= 0) low = middle + 1u;
        else high = middle;
    }
    if (reader->active_trace != NULL) {
        reader->active_trace->owner_restart_probes_total += probes;
        if (probes > reader->active_trace->owner_restart_probes_max) {
            reader->active_trace->owner_restart_probes_max = probes;
        }
    }
    *block_out = low == 0u ? 0u : low - 1u;
    return 0;
    }
}

static int decode_body(
    Bogi23Reader *reader, const uint8_t *key, size_t key_length,
    uint64_t start, uint64_t length, OwnerGroup *group
) {
    uint64_t end = 0u;
    uint64_t cursor = start;
    uint16_t mask = 0u;
    uint8_t mask_bytes[2] = {0u, 0u};
    size_t type_number = 0u;
    (void)memset(group, 0, sizeof(*group));
    if (g_type_order == NULL) {
        g_type_order = TYPE_ORDER_P1;
        g_ntypes = ZIR3_NTYPES;
        g_mask_bytes = 1u;
    }
    if (length == 0u || checked_add_u64(start, length, &end) != 0 ||
        end > reader->pool_restart_off ||
        read_at(reader, cursor, g_mask_bytes, TK_OWNER_BODY, mask_bytes) != 0) return -1;
    cursor += g_mask_bytes;
    mask = (g_mask_bytes == 1u)
        ? (uint16_t)mask_bytes[0]
        : (uint16_t)(mask_bytes[0] | ((uint16_t)mask_bytes[1] << 8));
    group->owner = key_to_owner(reader, key, key_length);
    if (group->owner == NULL) return -1;
    for (type_number = 0u; type_number < g_ntypes; ++type_number) {
        uint64_t ttl = 0u;
        uint64_t count = 0u;
        uint64_t index = 0u;
        RRset *rrset = NULL;
        if ((mask & (uint16_t)(1u << type_number)) == 0u) continue;
        if (group->count >= ZIR3_NTYPES_MAX ||
            read_uleb(reader, &cursor, end, TK_OWNER_BODY, &ttl) != 0 ||
            read_uleb(reader, &cursor, end, TK_OWNER_BODY, &count) != 0 ||
            count == 0u || count > SIZE_MAX / sizeof(char *)) goto failure;
        rrset = &group->sets[group->count++];
        rrset->owner = tracked_strdup(reader, group->owner);
        rrset->source_owner = tracked_strdup(reader, group->owner);
        rrset->rrtype = tracked_strdup(reader, g_type_order[type_number]);
        rrset->ttl = ttl;
        rrset->source_ttl = ttl;
        rrset->rdata_count = (size_t)count;
        rrset->rdatas = (char **)tracked_malloc(reader, (size_t)count * sizeof(char *));
        if (rrset->owner == NULL || rrset->source_owner == NULL ||
            rrset->rrtype == NULL || rrset->rdatas == NULL) {
            goto failure;
        }
        (void)memset(rrset->rdatas, 0, (size_t)count * sizeof(char *));
        for (index = 0u; index < count; ++index) {
            uint64_t identifier = 0u;
            if (read_uleb(reader, &cursor, end, TK_RDATA_ID, &identifier) != 0 ||
                read_pool_value(reader, identifier, &rrset->rdatas[index]) != 0) {
                goto failure;
            }
        }
    }
    if (cursor != end || group->count == 0u) goto failure;
    return 0;
failure:
    free_group(reader, group);
    return -1;
}

static int scan_owner(
    Bogi23Reader *reader, const uint8_t *target, size_t target_length,
    int decode_match, ScanResult *result
) {
    uint64_t block = 0u;
    uint64_t cursor = 0u;
    uint64_t ordinal = 0u;
    uint64_t stop = 0u;
    uint64_t visited = 0u;
    uint8_t previous[ZIR3_MAX_KEY];
    size_t previous_length = 0u;
    (void)memset(result, 0, sizeof(*result));
    if (select_block(reader, target, target_length, &block) != 0 ||
        restart_position(reader, block, &cursor) != 0) return -1;
    ordinal = block * ZIR3_BLOCK_SIZE;
    stop = reader->owner_count;
    if (ordinal + ZIR3_BLOCK_SIZE < stop) stop = ordinal + ZIR3_BLOCK_SIZE;
    while (ordinal < stop) {
        uint8_t key[ZIR3_MAX_KEY];
        size_t key_length = 0u;
        uint64_t body_length = 0u;
        uint64_t body_start = 0u;
        uint64_t after_body = 0u;
        if (ordinal % ZIR3_BLOCK_SIZE == 0u) {
            uint64_t full_length = 0u;
            if (read_uleb(reader, &cursor, reader->pool_restart_off,
                          TK_OWNER_META, &full_length) != 0 ||
                full_length > ZIR3_MAX_KEY ||
                read_at(reader, cursor, full_length, TK_OWNER_KEY, key) != 0) return -1;
            cursor += full_length;
            key_length = (size_t)full_length;
        } else {
            uint64_t common = 0u;
            uint64_t suffix_length = 0u;
            if (read_uleb(reader, &cursor, reader->pool_restart_off,
                          TK_OWNER_META, &common) != 0 ||
                read_uleb(reader, &cursor, reader->pool_restart_off,
                          TK_OWNER_META, &suffix_length) != 0 ||
                common > previous_length || suffix_length > ZIR3_MAX_KEY ||
                common + suffix_length > ZIR3_MAX_KEY) return -1;
            (void)memcpy(key, previous, (size_t)common);
            if (read_at(reader, cursor, suffix_length, TK_OWNER_KEY,
                        key + (size_t)common) != 0) return -1;
            cursor += suffix_length;
            key_length = (size_t)(common + suffix_length);
        }
        body_start = cursor;
        if (read_uleb(reader, &body_start, reader->pool_restart_off,
                      TK_OWNER_META, &body_length) != 0 ||
            checked_add_u64(body_start, body_length, &after_body) != 0 ||
            after_body > reader->pool_restart_off) return -1;
        (void)memcpy(previous, key, key_length);
        previous_length = key_length;
        visited += 1u;
        if (key_compare(key, key_length, target, target_length) >= 0) {
            result->found = 1;
            result->key_length = key_length;
            (void)memcpy(result->key, key, key_length);
            result->relation = key_compare(key, key_length, target, target_length) == 0 ? 0 : 1;
            if (decode_match && result->relation == 0) {
                if (decode_body(reader, key, key_length, body_start, body_length,
                                &result->group) != 0) return -1;
                result->has_group = 1;
            }
            reader->active_trace->owner_block_entries_total += visited;
            if (visited > reader->active_trace->owner_block_entries_max) {
                reader->active_trace->owner_block_entries_max = visited;
            }
            return 0;
        }
        cursor = after_body;
        ordinal += 1u;
    }
    reader->active_trace->owner_block_entries_total += visited;
    if (visited > reader->active_trace->owner_block_entries_max) {
        reader->active_trace->owner_block_entries_max = visited;
    }
    if (block + 1u < reader->owner_restart_count) {
        if (restart_key(reader, block + 1u, result->key,
                        &result->key_length) != 0) return -1;
        result->found = 1;
        result->relation = 1;
    }
    return 0;
}

static int lookup_group(
    Bogi23Reader *reader, const char *owner, OwnerGroup *group, int *found
) {
    uint8_t key[ZIR3_MAX_KEY];
    size_t key_length = 0u;
    ScanResult scan;
    *found = 0;
    (void)memset(group, 0, sizeof(*group));
    if (owner_to_key(reader, owner, key, &key_length) != 0 ||
        scan_owner(reader, key, key_length, 1, &scan) != 0) return -1;
    if (!scan.found || scan.relation != 0) {
        free_scan(reader, &scan);
        return 0;
    }
    *group = scan.group;
    scan.has_group = 0;
    free_scan(reader, &scan);
    *found = 1;
    return 0;
}

static int node_exists(Bogi23Reader *reader, const char *owner, int *exists) {
    uint8_t key[ZIR3_MAX_KEY];
    size_t key_length = 0u;
    ScanResult scan;
    *exists = 0;
    if (owner_to_key(reader, owner, key, &key_length) != 0) return -1;
    if (key_length == 0u) {
        *exists = 1;
        return 0;
    }
    if (scan_owner(reader, key, key_length, 0, &scan) != 0) return -1;
    if (scan.found && scan.key_length >= key_length &&
        memcmp(scan.key, key, key_length) == 0) *exists = 1;
    free_scan(reader, &scan);
    return 0;
}

static int inside_origin(const Bogi23Reader *reader, const char *name) {
    size_t name_length = strlen(name);
    size_t origin_length = strlen(reader->origin);
    if (strcmp(name, reader->origin) == 0) return 1;
    return name_length > origin_length + 1u &&
           name[name_length - origin_length - 1u] == '.' &&
           strcmp(name + name_length - origin_length, reader->origin) == 0;
}

static char *canonical_query(Bogi23Reader *reader, const char *token) {
    size_t token_length = strlen(token);
    size_t origin_length = strlen(reader->origin);
    size_t capacity = 0u;
    size_t index = 0u;
    size_t label_length = 0u;
    size_t label_number = 0u;
    char *name = NULL;
    if (strchr(token, '\\') != NULL || token_length == 0u) return NULL;
    if (strcmp(token, "@") == 0) return tracked_strdup(reader, reader->origin);
    if (token[token_length - 1u] == '.') capacity = token_length + 1u;
    else {
        if (token_length > SIZE_MAX - origin_length - 2u) return NULL;
        capacity = token_length + origin_length + 2u;
    }
    name = (char *)tracked_malloc(reader, capacity);
    if (name == NULL) return NULL;
    for (index = 0u; index < token_length; ++index) {
        unsigned char byte = (unsigned char)token[index];
        if (byte > 0x7fu) goto invalid;
        name[index] = (char)tolower(byte);
    }
    if (token[token_length - 1u] == '.') name[token_length] = '\0';
    else {
        name[token_length] = '.';
        (void)memcpy(name + token_length + 1u, reader->origin, origin_length + 1u);
    }
    if (strlen(name) > 254u) goto invalid;
    for (index = 0u; name[index] != '\0'; ++index) {
        if (name[index] == '.') {
            if (label_length == 0u || label_length > 63u) goto invalid;
            label_number += 1u;
            label_length = 0u;
        } else {
            label_length += 1u;
        }
    }
    if (label_length != 0u || label_number == 0u) goto invalid;
    return name;
invalid:
    tracked_free(reader, name);
    return NULL;
}

static int parent_of(const char *name, const char *origin, char output[255]) {
    const char *dot = NULL;
    if (strcmp(name, origin) == 0) return -1;
    dot = strchr(name, '.');
    if (dot == NULL || strlen(dot + 1u) > 254u) return -1;
    (void)memcpy(output, dot + 1u, strlen(dot + 1u) + 1u);
    return 0;
}

static int wildcard_name(const char *closest, char output[255]) {
    size_t length = strlen(closest);
    if (length > 252u) return -1;
    output[0] = '*';
    output[1] = '.';
    (void)memcpy(output + 2u, closest, length + 1u);
    return 0;
}

typedef struct {
    const char *rcode;
    const char *path;
    int aa;
    int tc;
    RRset *answer;
    size_t answer_count;
    RRset *authority;
    size_t authority_count;
    RRset *additional;
    size_t additional_count;
    char **visited;
    size_t visited_count;
    size_t visited_capacity;
    char *delegation_cut;
    char *wildcard_owner;
    char *closest_encloser;
    int cname_loop;
} Response;

static void free_rrset_vector(
    Bogi23Reader *reader, RRset *values, size_t count
) {
    size_t index = 0u;
    for (index = 0u; index < count; ++index) free_rrset(reader, &values[index]);
    tracked_free(reader, values);
}

static void free_response(Bogi23Reader *reader, Response *response) {
    size_t index = 0u;
    if (response == NULL) return;
    free_rrset_vector(reader, response->answer, response->answer_count);
    free_rrset_vector(reader, response->authority, response->authority_count);
    free_rrset_vector(reader, response->additional, response->additional_count);
    for (index = 0u; index < response->visited_count; ++index) {
        tracked_free(reader, response->visited[index]);
    }
    tracked_free(reader, response->visited);
    tracked_free(reader, response->delegation_cut);
    tracked_free(reader, response->wildcard_owner);
    tracked_free(reader, response->closest_encloser);
    (void)memset(response, 0, sizeof(*response));
}

static int append_rrset(
    Bogi23Reader *reader, RRset **values, size_t *count,
    const RRset *source, const char *owner_override
) {
    void *grown = NULL;
    size_t wanted = *count + 1u;
    if (wanted > SIZE_MAX / sizeof(RRset)) return -1;
    grown = tracked_realloc(reader, *values, wanted * sizeof(RRset));
    if (grown == NULL) return -1;
    *values = (RRset *)grown;
    (void)memset(&(*values)[*count], 0, sizeof(RRset));
    if (clone_rrset(reader, source, owner_override, &(*values)[*count]) != 0) return -1;
    *count = wanted;
    return 0;
}

static int append_visited(
    Bogi23Reader *reader, Response *response, const char *name
) {
    size_t index = 0u;
    if (response->visited_count == response->visited_capacity) {
        size_t capacity = response->visited_capacity == 0u ? 8u : response->visited_capacity * 2u;
        void *grown = NULL;
        if (capacity < response->visited_capacity ||
            capacity > SIZE_MAX / sizeof(char *)) return -1;
        grown = tracked_realloc(reader, response->visited, capacity * sizeof(char *));
        if (grown == NULL) return -1;
        response->visited = (char **)grown;
        response->visited_capacity = capacity;
    }
    for (index = 0u; index < response->visited_count; ++index) {
        if (strcmp(response->visited[index], name) == 0) {
            response->cname_loop = 1;
            return 1;
        }
    }
    response->visited[response->visited_count] = tracked_strdup(reader, name);
    if (response->visited[response->visited_count] == NULL) return -1;
    response->visited_count += 1u;
    reader->active_trace->visited_owner_count = response->visited_count;
    return 0;
}

static int make_negative(Bogi23Reader *reader, RRset *output) {
    OwnerGroup apex;
    int found = 0;
    RRset *soa = NULL;
    char *last_space = NULL;
    uint64_t minimum = 0u;
    if (lookup_group(reader, reader->origin, &apex, &found) != 0 || !found) return -1;
    soa = group_get(&apex, "SOA");
    if (soa == NULL || soa->rdata_count != 1u ||
        clone_rrset(reader, soa, NULL, output) != 0) {
        free_group(reader, &apex);
        return -1;
    }
    last_space = strrchr(output->rdatas[0], ' ');
    if (last_space == NULL) {
        free_group(reader, &apex);
        free_rrset(reader, output);
        return -1;
    }
    minimum = strtoull(last_space + 1u, NULL, 10);
    if (minimum < output->ttl) output->ttl = minimum;
    free_group(reader, &apex);
    return 0;
}

static int nearest_cut(
    Bogi23Reader *reader, const char *name, char output[255]
) {
    char current[255];
    char parent[255];
    char walk[255];
    (void)memcpy(current, name, strlen(name) + 1u);
    while (1) {
        if (strcmp(current, reader->origin) != 0) {
            OwnerGroup group;
            int found = 0;
            if (lookup_group(reader, current, &group, &found) != 0) return -1;
            if (found && group_get(&group, "NS") != NULL) {
                int below_cut = 0;
                if (parent_of(current, reader->origin, parent) == 0) {
                    (void)memcpy(walk, parent, strlen(parent) + 1u);
                    while (strcmp(walk, reader->origin) != 0) {
                        OwnerGroup ag;
                        int afound = 0;
                        if (lookup_group(reader, walk, &ag, &afound) != 0) {
                            free_group(reader, &group);
                            return -1;
                        }
                        if (afound && group_get(&ag, "NS") != NULL) {
                            below_cut = 1;
                            free_group(reader, &ag);
                            break;
                        }
                        free_group(reader, &ag);
                        if (parent_of(walk, reader->origin, parent) != 0) break;
                        (void)memcpy(walk, parent, strlen(parent) + 1u);
                    }
                }
                if (!below_cut) {
                    (void)memcpy(output, current, strlen(current) + 1u);
                    free_group(reader, &group);
                    return 1;
                }
            }
            free_group(reader, &group);
        }
        if (parent_of(current, reader->origin, output) != 0) break;
        (void)memcpy(current, output, strlen(output) + 1u);
    }
    return 0;
}

static int closest_encloser(
    Bogi23Reader *reader, const char *name, char output[255]
) {
    char current[255];
    int exists = 0;
    (void)memcpy(current, name, strlen(name) + 1u);
    while (1) {
        if (node_exists(reader, current, &exists) != 0) return -1;
        if (exists) {
            (void)memcpy(output, current, strlen(current) + 1u);
            return 0;
        }
        if (parent_of(current, reader->origin, output) != 0) break;
        (void)memcpy(current, output, strlen(output) + 1u);
    }
    (void)memcpy(output, reader->origin, strlen(reader->origin) + 1u);
    return 0;
}

typedef struct {
    Bogi23Reader *reader;
    RRset rrset;
} GlueItem;

static int compare_glue(const void *left_raw, const void *right_raw) {
    const GlueItem *left = (const GlueItem *)left_raw;
    const GlueItem *right = (const GlueItem *)right_raw;
    uint8_t left_key[ZIR3_MAX_KEY];
    uint8_t right_key[ZIR3_MAX_KEY];
    size_t left_length = 0u;
    size_t right_length = 0u;
    int answer = 0;
    if (owner_to_key(left->reader, left->rrset.owner, left_key, &left_length) != 0 ||
        owner_to_key(right->reader, right->rrset.owner, right_key, &right_length) != 0) return 0;
    answer = key_compare(left_key, left_length, right_key, right_length);
    if (answer != 0) return answer;
    return type_index(left->rrset.rrtype) - type_index(right->rrset.rrtype);
}

static int referral(
    Bogi23Reader *reader, const char *cut, Response *response
) {
    OwnerGroup group;
    int found = 0;
    RRset *ns = NULL;
    GlueItem *glue = NULL;
    size_t glue_count = 0u;
    size_t index = 0u;
    response->rcode = "NOERROR";
    response->path = "referral";
    response->aa = 0;
    response->delegation_cut = tracked_strdup(reader, cut);
    if (response->delegation_cut == NULL ||
        lookup_group(reader, cut, &group, &found) != 0 || !found) return -1;
    ns = group_get(&group, "NS");
    if (ns == NULL || append_rrset(reader, &response->authority,
                                  &response->authority_count, ns, NULL) != 0) {
        free_group(reader, &group);
        return -1;
    }
    for (index = 0u; index < ns->rdata_count; ++index) {
        const char *target = ns->rdatas[index];
        size_t target_length = strlen(target);
        size_t cut_length = strlen(cut);
        int below = strcmp(target, cut) == 0 ||
            (target_length > cut_length + 1u &&
             target[target_length - cut_length - 1u] == '.' &&
             strcmp(target + target_length - cut_length, cut) == 0);
        size_t address_index = 0u;
        OwnerGroup address;
        int address_found = 0;
        if (!below) continue;
        if (lookup_group(reader, target, &address, &address_found) != 0) {
            free_group(reader, &group);
            goto failure;
        }
        if (address_found) {
            for (address_index = 0u; address_index < 2u; ++address_index) {
                const char *type = address_index == 0u ? "A" : "AAAA";
                RRset *selected = group_get(&address, type);
                if (selected != NULL) {
                    void *grown = NULL;
                    if (glue_count + 1u > SIZE_MAX / sizeof(GlueItem)) {
                        free_group(reader, &address);
                        free_group(reader, &group);
                        goto failure;
                    }
                    grown = tracked_realloc(
                        reader, glue, (glue_count + 1u) * sizeof(GlueItem)
                    );
                    if (grown == NULL) {
                        free_group(reader, &address);
                        free_group(reader, &group);
                        goto failure;
                    }
                    glue = (GlueItem *)grown;
                    (void)memset(&glue[glue_count], 0, sizeof(GlueItem));
                    glue[glue_count].reader = reader;
                    if (clone_rrset(reader, selected, NULL,
                                    &glue[glue_count].rrset) != 0) {
                        free_group(reader, &address);
                        free_group(reader, &group);
                        goto failure;
                    }
                    glue_count += 1u;
                }
            }
        }
        free_group(reader, &address);
    }
    free_group(reader, &group);
    if (glue_count > 1u) qsort(glue, glue_count, sizeof(GlueItem), compare_glue);
    if (glue_count > 0u) {
        response->additional = (RRset *)tracked_malloc(reader, glue_count * sizeof(RRset));
        if (response->additional == NULL) goto failure;
        for (index = 0u; index < glue_count; ++index) {
            response->additional[index] = glue[index].rrset;
            (void)memset(&glue[index].rrset, 0, sizeof(RRset));
        }
        response->additional_count = glue_count;
    }
    tracked_free(reader, glue);
    return 0;
failure:
    if (glue != NULL) {
        for (index = 0u; index < glue_count; ++index) {
            free_rrset(reader, &glue[index].rrset);
        }
    }
    tracked_free(reader, glue);
    return -1;
}

static int finish_negative(
    Bogi23Reader *reader, Response *response, const char *rcode, const char *path
) {
    RRset negative;
    (void)memset(&negative, 0, sizeof(negative));
    if (make_negative(reader, &negative) != 0) return -1;
    response->authority = (RRset *)tracked_malloc(reader, sizeof(RRset));
    if (response->authority == NULL) {
        free_rrset(reader, &negative);
        return -1;
    }
    response->authority[0] = negative;
    response->authority_count = 1u;
    response->rcode = rcode;
    response->path = path;
    response->aa = 1;
    return 0;
}

static int resolve_query(
    Bogi23Reader *reader, const char *query_name, const char *query_type,
    Response *response
) {
    char *current = NULL;
    char requested[16];
    size_t type_length = strlen(query_type);
    int followed = 0;
    (void)memset(response, 0, sizeof(*response));
    if (type_length == 0u || type_length >= sizeof(requested)) return -1;
    (void)memcpy(requested, query_type, type_length + 1u);
    for (size_t index = 0u; index < type_length; ++index) {
        requested[index] = (char)toupper((unsigned char)requested[index]);
    }
    current = canonical_query(reader, query_name);
    if (current == NULL || type_index(requested) < 0 || !inside_origin(reader, current)) {
        tracked_free(reader, current);
        return -1;
    }
    while (1) {
        char cut[255];
        int cut_result = 0;
        OwnerGroup explicit_group;
        int has_explicit = 0;
        int exists = 0;
        int seen_status = append_visited(reader, response, current);
        if (seen_status != 0) {
            tracked_free(reader, current);
            return -1;
        }
        cut_result = nearest_cut(reader, current, cut);
        if (cut_result < 0) {
            tracked_free(reader, current);
            return -1;
        }
        if (cut_result == 1) {
            /* Preserve CNAME chain already in ANSWER; attach cut NS. */
            int had_answer = response->answer_count != 0u;
            if (referral(reader, cut, response) != 0) {
                tracked_free(reader, current);
                return -1;
            }
            if (had_answer)
                response->aa = 1;
            tracked_free(reader, current);
            return 0;
        }
        if (lookup_group(reader, current, &explicit_group, &has_explicit) != 0 ||
            node_exists(reader, current, &exists) != 0) {
            free_group(reader, &explicit_group);
            tracked_free(reader, current);
            return -1;
        }
        if (exists) {
            RRset *selected = has_explicit ? group_get(&explicit_group, requested) : NULL;
            RRset *alias = has_explicit && strcmp(requested, "CNAME") != 0
                ? group_get(&explicit_group, "CNAME") : NULL;
            if (selected != NULL) {
                if (append_rrset(reader, &response->answer, &response->answer_count,
                                 selected, NULL) != 0) {
                    free_group(reader, &explicit_group);
                    tracked_free(reader, current);
                    return -1;
                }
                if (strcmp(requested, "NS") == 0) {
                    /* BIND-like in-bailiwick A/AAAA glue for AA NS answers. */
                    GlueItem *glue = NULL;
                    size_t glue_count = 0u;
                    size_t index = 0u;
                    for (index = 0u; index < selected->rdata_count; ++index) {
                        const char *target = selected->rdatas[index];
                        size_t target_length = strlen(target);
                        size_t origin_length = strlen(reader->origin);
                        int below = strcmp(target, reader->origin) == 0 ||
                            (target_length > origin_length + 1u &&
                             target[target_length - origin_length - 1u] == '.' &&
                             strcmp(target + target_length - origin_length,
                                    reader->origin) == 0);
                        OwnerGroup address;
                        int address_found = 0;
                        size_t address_index = 0u;
                        if (!below) continue;
                        if (lookup_group(reader, target, &address, &address_found) != 0) {
                            free_group(reader, &explicit_group);
                            tracked_free(reader, current);
                            return -1;
                        }
                        if (address_found) {
                            for (address_index = 0u; address_index < 2u; ++address_index) {
                                const char *type = address_index == 0u ? "A" : "AAAA";
                                RRset *addr = group_get(&address, type);
                                if (addr != NULL) {
                                    void *grown = tracked_realloc(
                                        reader, glue, (glue_count + 1u) * sizeof(GlueItem)
                                    );
                                    if (grown == NULL) {
                                        free_group(reader, &address);
                                        free_group(reader, &explicit_group);
                                        tracked_free(reader, current);
                                        return -1;
                                    }
                                    glue = (GlueItem *)grown;
                                    (void)memset(&glue[glue_count], 0, sizeof(GlueItem));
                                    glue[glue_count].reader = reader;
                                    if (clone_rrset(reader, addr, NULL,
                                                    &glue[glue_count].rrset) != 0) {
                                        free_group(reader, &address);
                                        free_group(reader, &explicit_group);
                                        tracked_free(reader, current);
                                        return -1;
                                    }
                                    glue_count += 1u;
                                }
                            }
                        }
                        free_group(reader, &address);
                    }
                    if (glue_count > 1u) {
                        qsort(glue, glue_count, sizeof(GlueItem), compare_glue);
                    }
                    if (glue_count > 0u) {
                        size_t g = 0u;
                        response->additional = (RRset *)tracked_malloc(
                            reader, glue_count * sizeof(RRset)
                        );
                        if (response->additional == NULL) {
                            for (g = 0u; g < glue_count; ++g) {
                                free_rrset(reader, &glue[g].rrset);
                            }
                            tracked_free(reader, glue);
                            free_group(reader, &explicit_group);
                            tracked_free(reader, current);
                            return -1;
                        }
                        for (g = 0u; g < glue_count; ++g) {
                            response->additional[g] = glue[g].rrset;
                            (void)memset(&glue[g].rrset, 0, sizeof(RRset));
                        }
                        response->additional_count = glue_count;
                    }
                    tracked_free(reader, glue);
                }
                response->rcode = "NOERROR";
                response->path = followed ? "cname" : "exact";
                response->aa = 1;
                free_group(reader, &explicit_group);
                tracked_free(reader, current);
                return 0;
            }
            if (alias != NULL) {
                char *next = NULL;
                if (append_rrset(reader, &response->answer, &response->answer_count,
                                 alias, NULL) != 0) {
                    free_group(reader, &explicit_group);
                    tracked_free(reader, current);
                    return -1;
                }
                next = tracked_strdup(reader, alias->rdatas[0]);
                free_group(reader, &explicit_group);
                if (next == NULL) {
                    tracked_free(reader, current);
                    return -1;
                }
                tracked_free(reader, current);
                current = next;
                followed = 1;
                if (!inside_origin(reader, current)) {
                    response->rcode = "NOERROR";
                    response->path = "cname";
                    response->aa = 1;
                    tracked_free(reader, current);
                    return 0;
                }
                continue;
            }
            free_group(reader, &explicit_group);
            if (finish_negative(reader, response, "NOERROR",
                                followed ? "cname" : "nodata") != 0) {
                tracked_free(reader, current);
                return -1;
            }
            tracked_free(reader, current);
            return 0;
        }
        free_group(reader, &explicit_group);
        {
            char closest[255];
            char wildcard[255];
            OwnerGroup wildcard_group;
            int has_wildcard = 0;
            if (closest_encloser(reader, current, closest) != 0 ||
                wildcard_name(closest, wildcard) != 0) {
                tracked_free(reader, current);
                return -1;
            }
            response->closest_encloser = tracked_strdup(reader, closest);
            if (response->closest_encloser == NULL ||
                lookup_group(reader, wildcard, &wildcard_group, &has_wildcard) != 0) {
                free_group(reader, &wildcard_group);
                tracked_free(reader, current);
                return -1;
            }
            if (has_wildcard) {
                RRset *selected = group_get(&wildcard_group, requested);
                RRset *alias = strcmp(requested, "CNAME") != 0
                    ? group_get(&wildcard_group, "CNAME") : NULL;
                tracked_free(reader, response->wildcard_owner);
                response->wildcard_owner = tracked_strdup(reader, wildcard);
                if (response->wildcard_owner == NULL) {
                    free_group(reader, &wildcard_group);
                    tracked_free(reader, current);
                    return -1;
                }
                if (selected != NULL) {
                    if (append_rrset(reader, &response->answer, &response->answer_count,
                                     selected, current) != 0) {
                        free_group(reader, &wildcard_group);
                        tracked_free(reader, current);
                        return -1;
                    }
                    response->rcode = "NOERROR";
                    response->path = followed ? "cname" : "wildcard";
                    response->aa = 1;
                    free_group(reader, &wildcard_group);
                    tracked_free(reader, current);
                    return 0;
                }
                if (alias != NULL) {
                    char *next = NULL;
                    if (append_rrset(reader, &response->answer, &response->answer_count,
                                     alias, current) != 0) {
                        free_group(reader, &wildcard_group);
                        tracked_free(reader, current);
                        return -1;
                    }
                    next = tracked_strdup(reader, alias->rdatas[0]);
                    free_group(reader, &wildcard_group);
                    if (next == NULL) {
                        tracked_free(reader, current);
                        return -1;
                    }
                    tracked_free(reader, current);
                    current = next;
                    followed = 1;
                    if (!inside_origin(reader, current)) {
                        response->rcode = "NOERROR";
                        response->path = "cname";
                        response->aa = 1;
                        tracked_free(reader, current);
                        return 0;
                    }
                    continue;
                }
                free_group(reader, &wildcard_group);
                if (finish_negative(reader, response, "NOERROR",
                                    "wildcard_nodata") != 0) {
                    tracked_free(reader, current);
                    return -1;
                }
                tracked_free(reader, current);
                return 0;
            }
            free_group(reader, &wildcard_group);
            {
                char higher[255];
                char parent[255];
                int higher_wildcard = 0;
                int closest_explicit = 0;
                OwnerGroup closest_group;
                int closest_found = 0;
                if (lookup_group(reader, closest, &closest_group, &closest_found) != 0) {
                    tracked_free(reader, current);
                    return -1;
                }
                closest_explicit = closest_found;
                free_group(reader, &closest_group);
                (void)memcpy(higher, closest, strlen(closest) + 1u);
                while (strcmp(higher, reader->origin) != 0) {
                    OwnerGroup higher_group;
                    int higher_found = 0;
                    char candidate[255];
                    if (parent_of(higher, reader->origin, parent) != 0) break;
                    (void)memcpy(higher, parent, strlen(parent) + 1u);
                    if (wildcard_name(higher, candidate) != 0) continue;
                    if (lookup_group(reader, candidate, &higher_group, &higher_found) != 0) {
                        tracked_free(reader, current);
                        return -1;
                    }
                    free_group(reader, &higher_group);
                    if (higher_found) {
                        higher_wildcard = 1;
                        break;
                    }
                }
                if (finish_negative(
                        reader, response, "NXDOMAIN",
                        followed ? "cname" :
                        (!closest_explicit && higher_wildcard)
                            ? "ent_blocked_wildcard" : "nxdomain"
                    ) != 0) {
                    tracked_free(reader, current);
                    return -1;
                }
                tracked_free(reader, current);
                return 0;
            }
        }
    }
}

static void response_trace_summary(Bogi23Reader *reader, const Response *response) {
    const RRset *sections[3] = {response->answer, response->authority, response->additional};
    size_t counts[3] = {response->answer_count, response->authority_count, response->additional_count};
    size_t section = 0u;
    for (section = 0u; section < 3u; ++section) {
        size_t rrset_index = 0u;
        for (rrset_index = 0u; rrset_index < counts[section]; ++rrset_index) {
            const RRset *rrset = &sections[section][rrset_index];
            size_t rdata_index = 0u;
            reader->active_trace->selected_rr_count += 1u;
            for (rdata_index = 0u; rdata_index < rrset->rdata_count; ++rdata_index) {
                reader->active_trace->selected_text_bytes +=
                    strlen(rrset->owner) + strlen(rrset->rdatas[rdata_index]);
            }
        }
    }
}

static void json_string(FILE *output, const char *text) {
    const unsigned char *cursor = (const unsigned char *)text;
    (void)fputc('"', output);
    while (*cursor != 0u) {
        unsigned char byte = *cursor++;
        if (byte == '"' || byte == '\\') {
            (void)fputc('\\', output);
            (void)fputc((int)byte, output);
        } else if (byte < 0x20u) {
            (void)fprintf(output, "\\u%04x", (unsigned int)byte);
        } else {
            (void)fputc((int)byte, output);
        }
    }
    (void)fputc('"', output);
}

static void json_optional_string(FILE *output, const char *text) {
    if (text == NULL) (void)fputs("null", output);
    else json_string(output, text);
}

static void emit_rrset(FILE *output, const RRset *rrset) {
    size_t index = 0u;
    (void)fputc('[', output);
    json_string(output, rrset->owner);
    (void)fputc(',', output);
    json_string(output, rrset->rrtype);
    (void)fprintf(output, ",%" PRIu64 ",[", rrset->ttl);
    for (index = 0u; index < rrset->rdata_count; ++index) {
        if (index > 0u) (void)fputc(',', output);
        json_string(output, rrset->rdatas[index]);
    }
    (void)fputs("]]", output);
}

static void emit_section(FILE *output, const RRset *rrsets, size_t count) {
    size_t index = 0u;
    (void)fputc('[', output);
    for (index = 0u; index < count; ++index) {
        if (index > 0u) (void)fputc(',', output);
        emit_rrset(output, &rrsets[index]);
    }
    (void)fputc(']', output);
}

static void emit_selection_section(
    FILE *output, const RRset *rrsets, size_t count
) {
    size_t index = 0u;
    (void)fputc('[', output);
    for (index = 0u; index < count; ++index) {
        const RRset *rrset = &rrsets[index];
        if (index > 0u) (void)fputc(',', output);
        (void)fputs("{\"source_owner\":", output);
        json_string(output, rrset->source_owner);
        (void)fputs(",\"presented_owner\":", output);
        json_string(output, rrset->owner);
        (void)fputs(",\"rrtype\":", output);
        json_string(output, rrset->rrtype);
        (void)fprintf(output,
            ",\"source_ttl\":%" PRIu64 ",\"effective_ttl\":%" PRIu64
            ",\"rdatas\":[", rrset->source_ttl, rrset->ttl);
        for (size_t rdata = 0u; rdata < rrset->rdata_count; ++rdata) {
            if (rdata > 0u) (void)fputc(',', output);
            json_string(output, rrset->rdatas[rdata]);
        }
        (void)fputs("]}", output);
    }
    (void)fputc(']', output);
}

static void emit_response(FILE *output, const Response *response) {
    size_t index = 0u;
    (void)fputs("{\"rcode\":", output);
    json_string(output, response->rcode == NULL ? "" : response->rcode);
    (void)fprintf(output, ",\"aa\":%s,\"tc\":%s,\"answer\":",
                  response->aa ? "true" : "false",
                  response->tc ? "true" : "false");
    emit_section(output, response->answer, response->answer_count);
    (void)fputs(",\"authority\":", output);
    emit_section(output, response->authority, response->authority_count);
    (void)fputs(",\"additional\":", output);
    emit_section(output, response->additional, response->additional_count);
    (void)fputs(",\"selection\":{\"answer\":", output);
    emit_selection_section(output, response->answer, response->answer_count);
    (void)fputs(",\"authority\":", output);
    emit_selection_section(output, response->authority, response->authority_count);
    (void)fputs(",\"additional\":", output);
    emit_selection_section(output, response->additional, response->additional_count);
    (void)fputc('}', output);
    (void)fputs(",\"path\":", output);
    json_string(output, response->path == NULL ? "" : response->path);
    (void)fputs(",\"visited_qnames\":[", output);
    for (index = 0u; index < response->visited_count; ++index) {
        if (index > 0u) (void)fputc(',', output);
        json_string(output, response->visited[index]);
    }
    (void)fputs("],\"delegation_cut_owner\":", output);
    json_optional_string(output, response->delegation_cut);
    (void)fputs(",\"wildcard_source_owner\":", output);
    json_optional_string(output, response->wildcard_owner);
    (void)fputs(",\"closest_encloser_owner\":", output);
    json_optional_string(output, response->closest_encloser);
    (void)fprintf(output, ",\"cname_loop\":%s}",
                  response->cname_loop ? "true" : "false");
}

static void emit_events(FILE *output, AccessTrace *trace) {
    size_t index = 0u;
    TraceEvent event;
    (void)fputc('[', output);
    if (!trace->fixed) {
        if (trace_flush_pending(trace) != 0 || fflush(trace->spill) != 0 ||
            fseek(trace->spill, 0L, SEEK_SET) != 0) {
            fail_process("cannot replay query trace spill");
        }
    }
    for (index = 0u; index < trace->count; ++index) {
        const TraceEvent *item = NULL;
        if (trace->fixed) item = &trace->events[index];
        else {
            if (fread(&event, sizeof(event), 1u, trace->spill) != 1u) {
                fail_process("cannot read query trace spill");
            }
            item = &event;
        }
        if (index > 0u) (void)fputc(',', output);
        (void)fprintf(output,
            "{\"offset\":%" PRIu64 ",\"length\":%" PRIu64 ",\"kind\":",
            item->offset, item->length);
        json_string(output, trace_kind_name(item->kind));
        (void)fputc('}', output);
    }
    (void)fputc(']', output);
}

static uint64_t saturated_allocation_limit(const AccessTrace *trace) {
    uint64_t result = 65536u;
    uint64_t value = 0u;
    if (checked_mul_u64(512u, trace->visited_owner_count, &value) != 0 ||
        checked_add_u64(result, value, &result) != 0 ||
        checked_mul_u64(256u, trace->selected_rr_count, &value) != 0 ||
        checked_add_u64(result, value, &result) != 0 ||
        checked_mul_u64(2u, trace->selected_text_bytes, &value) != 0 ||
        checked_add_u64(result, value, &result) != 0) return UINT64_MAX;
    return result;
}

static void emit_trace(
    FILE *output, AccessTrace *trace,
    uint64_t allocation_peak_delta,
    uint64_t allocation_current_delta,
    uint64_t allocation_requests,
    uint64_t allocation_frees
) {
    uint64_t limit = saturated_allocation_limit(trace);
    size_t index = 0u;
    (void)fputs("{\"source\":\"mmap-read_at\",\"events\":", output);
    emit_events(output, trace);
    (void)fprintf(output,
        ",\"owner_restart_probes_total\":%" PRIu64
        ",\"owner_restart_probes_max\":%" PRIu64
        ",\"owner_block_entries_total\":%" PRIu64
        ",\"owner_block_entries_max\":%" PRIu64
        ",\"pool_restart_reads\":%" PRIu64
        ",\"pool_items_probed\":%" PRIu64
        ",\"pool_items_probed_max_per_ref\":%" PRIu64,
        trace->owner_restart_probes_total,
        trace->owner_restart_probes_max,
        trace->owner_block_entries_total,
        trace->owner_block_entries_max,
        trace->pool_restart_reads,
        trace->pool_items_probed,
        trace->pool_items_probed_max_per_ref);
    (void)fputs(",\"result_ids\":[", output);
    for (index = 0u; index < trace->result_id_count; ++index) {
        if (index > 0u) (void)fputc(',', output);
        (void)fprintf(output, "%" PRIu64, trace->result_ids[index]);
    }
    (void)fprintf(output,
        "],\"visited_owner_count\":%" PRIu64
        ",\"selected_rr_count\":%" PRIu64
        ",\"selected_text_bytes\":%" PRIu64
        ",\"allocation_peak_bytes\":%" PRIu64
        ",\"allocation_current_bytes_before_release\":%" PRIu64
        ",\"allocation_requests\":%" PRIu64
        ",\"allocation_frees_before_release\":%" PRIu64
        ",\"allocation_limit_bytes\":%" PRIu64
        ",\"allocation_within_limit\":%s"
        ",\"fallback_full_scans\":0}",
        trace->visited_owner_count,
        trace->selected_rr_count,
        trace->selected_text_bytes,
        allocation_peak_delta,
        allocation_current_delta,
        allocation_requests,
        allocation_frees,
        limit,
        allocation_peak_delta <= limit ? "true" : "false");
}

static void emit_constructor_trace(FILE *output, Bogi23Reader *reader) {
    (void)fputs("{\"events\":", output);
    emit_events(output, &reader->constructor_trace);
    (void)fputs(
        ",\"startup_owner_items_scanned\":0"
        ",\"startup_pool_items_scanned\":0"
        ",\"startup_materialized_entries\":0"
        ",\"persistent_cache_entries\":0}", output);
}

static int start_query_trace(Bogi23Reader *reader, AccessTrace *trace) {
    (void)memset(trace, 0, sizeof(*trace));
    trace->spill = tmpfile();
    if (trace->spill == NULL) return -1;
    reader->query_alloc_base = reader->alloc_current;
    reader->query_alloc_peak = reader->alloc_current;
    reader->query_alloc_requests_base = reader->alloc_requests;
    reader->query_alloc_frees_base = reader->alloc_frees;
    reader->active_trace = trace;
    return 0;
}

static void run_one_query(
    Bogi23Reader *reader, const char *query_name, const char *query_type
) {
    AccessTrace trace;
    Response response;
    int status = 0;
    uint64_t peak_delta = 0u;
    uint64_t current_delta = 0u;
    uint64_t requests = 0u;
    uint64_t frees = 0u;
    uint64_t leak = 0u;
    if (start_query_trace(reader, &trace) != 0) fail_process("cannot create query trace spill");
    (void)memset(&response, 0, sizeof(response));
    status = resolve_query(reader, query_name, query_type, &response);
    if (status == 0) response_trace_summary(reader, &response);
    peak_delta = reader->query_alloc_peak - reader->query_alloc_base;
    current_delta = reader->alloc_current - reader->query_alloc_base;
    requests = reader->alloc_requests - reader->query_alloc_requests_base;
    frees = reader->alloc_frees - reader->query_alloc_frees_base;

    (void)fputs("{\"claim_bearing\":false,\"qname\":", stdout);
    json_string(stdout, query_name);
    (void)fputs(",\"qtype\":", stdout);
    json_string(stdout, query_type);
    (void)fprintf(stdout, ",\"ok\":%s,\"response\":",
                  status == 0 ? "true" : "false");
    if (status == 0) emit_response(stdout, &response);
    else (void)fputs("null", stdout);
    (void)fputs(",\"error\":", stdout);
    if (status == 0) (void)fputs("null", stdout);
    else json_string(stdout, "NATIVE_RESOLVE_FAILED");
    (void)fputs(",\"constructor_trace\":", stdout);
    emit_constructor_trace(stdout, reader);
    (void)fputs(",\"query_trace\":", stdout);
    emit_trace(stdout, &trace, peak_delta, current_delta, requests, frees);

    free_response(reader, &response);
    trace_release(reader, &trace);
    leak = reader->alloc_current - reader->query_alloc_base;
    reader->active_trace = NULL;
    (void)fprintf(stdout, ",\"post_query_leak_bytes\":%" PRIu64 "}\n", leak);
}


#include "bogi23_export.h"

int bogi23_foreach_owner(Bogi23Reader *reader, bogi23_owner_cb cb, void *arg) {
    AccessTrace quiet;
    TraceEvent events[8192];
    AccessTrace *saved;
    uint64_t block;
    if (reader == NULL || cb == NULL) {
        return -1;
    }
    (void)memset(&quiet, 0, sizeof(quiet));
    (void)memset(events, 0, sizeof(events));
    quiet.events = events;
    quiet.capacity = sizeof(events) / sizeof(events[0]);
    quiet.fixed = 1;
    saved = reader->active_trace;
    reader->active_trace = &quiet;
    for (block = 0u; block < reader->owner_restart_count; ++block) {
        uint64_t cursor = 0u;
        uint64_t ordinal = block * ZIR3_BLOCK_SIZE;
        uint64_t stop = reader->owner_count;
        uint8_t previous[ZIR3_MAX_KEY];
        size_t previous_length = 0u;
        if (ordinal + ZIR3_BLOCK_SIZE < stop) {
            stop = ordinal + ZIR3_BLOCK_SIZE;
        }
        if (restart_position(reader, block, &cursor) != 0) {
            reader->active_trace = saved;
            return -1;
        }
        while (ordinal < stop) {
            uint8_t key[ZIR3_MAX_KEY];
            size_t key_length = 0u;
            uint64_t body_length = 0u;
            uint64_t body_start = 0u;
            uint64_t after_body = 0u;
            OwnerGroup group;
            int cb_rc;
            if ((ordinal % ZIR3_BLOCK_SIZE) == 0u) {
                uint64_t full_length = 0u;
                if (read_uleb(reader, &cursor, reader->pool_restart_off,
                              TK_OWNER_META, &full_length) != 0 ||
                    full_length > ZIR3_MAX_KEY ||
                    read_at(reader, cursor, full_length, TK_OWNER_KEY, key) != 0) {
                    reader->active_trace = saved;
                    return -1;
                }
                cursor += full_length;
                key_length = (size_t)full_length;
            } else {
                uint64_t common = 0u;
                uint64_t suffix_length = 0u;
                if (read_uleb(reader, &cursor, reader->pool_restart_off,
                              TK_OWNER_META, &common) != 0 ||
                    read_uleb(reader, &cursor, reader->pool_restart_off,
                              TK_OWNER_META, &suffix_length) != 0 ||
                    common > previous_length || suffix_length > ZIR3_MAX_KEY ||
                    common + suffix_length > ZIR3_MAX_KEY) {
                    reader->active_trace = saved;
                    return -1;
                }
                (void)memcpy(key, previous, (size_t)common);
                if (read_at(reader, cursor, suffix_length, TK_OWNER_KEY,
                            key + (size_t)common) != 0) {
                    reader->active_trace = saved;
                    return -1;
                }
                cursor += suffix_length;
                key_length = (size_t)(common + suffix_length);
            }
            body_start = cursor;
            if (read_uleb(reader, &body_start, reader->pool_restart_off,
                          TK_OWNER_META, &body_length) != 0 ||
                checked_add_u64(body_start, body_length, &after_body) != 0 ||
                after_body > reader->pool_restart_off) {
                reader->active_trace = saved;
                return -1;
            }
            (void)memcpy(previous, key, key_length);
            previous_length = key_length;
            /* Reset fixed quiet buffer each owner — else AXFR/foreach dies
             * after ~8k events (createiterator → Transfer failed). */
            quiet.count = 0;
            quiet.has_pending = 0;
            (void)memset(&group, 0, sizeof(group));
            if (decode_body(reader, key, key_length, body_start, body_length,
                            &group) != 0) {
                reader->active_trace = saved;
                return -1;
            }
            cb_rc = cb(reader, &group, arg);
            free_group(reader, &group);
            if (cb_rc != 0) {
                reader->active_trace = saved;
                return cb_rc;
            }
            cursor = after_body;
            ordinal += 1u;
        }
    }
    reader->active_trace = saved;
    return 0;
}

/* --- mmap-direct BIND helpers --- */

typedef struct {
    AccessTrace quiet;
    TraceEvent events[4096];
    AccessTrace *saved;
    int active;
} Bogi23TraceGuard;

/* Per-thread quiet trace: BIND (and other multi-threaded auth servers)
 * call lookup_group concurrently; a process-global guard races and yields
 * SERVFAIL under parallel digs. */
static __thread Bogi23TraceGuard g_trace_guard;

int bogi23_trace_begin(Bogi23Reader *reader) {
    if (reader == NULL) {
        return -1;
    }
    if (g_trace_guard.active) {
        /*
         * Hot-path lookups re-enter without end. The quiet buffer is fixed at
         * 4096 events — without a reset, later queries fail with -1 once the
         * buffer fills (seen as find_zone_cut err / SERVFAIL after ~tens of
         * digs). Reset counters in place; keep the event array.
         */
        TraceEvent *ev = g_trace_guard.quiet.events;
        size_t cap = g_trace_guard.quiet.capacity;
        (void)memset(&g_trace_guard.quiet, 0, sizeof(g_trace_guard.quiet));
        g_trace_guard.quiet.events = ev;
        g_trace_guard.quiet.capacity = cap;
        g_trace_guard.quiet.fixed = 1;
        reader->active_trace = &g_trace_guard.quiet;
        return 0;
    }
    (void)memset(&g_trace_guard, 0, sizeof(g_trace_guard));
    g_trace_guard.quiet.events = g_trace_guard.events;
    g_trace_guard.quiet.capacity =
        sizeof(g_trace_guard.events) / sizeof(g_trace_guard.events[0]);
    g_trace_guard.quiet.fixed = 1;
    g_trace_guard.saved = reader->active_trace;
    reader->active_trace = &g_trace_guard.quiet;
    g_trace_guard.active = 1;
    return 0;
}

void bogi23_trace_end(Bogi23Reader *reader) {
    if (reader == NULL || !g_trace_guard.active) {
        return;
    }
    reader->active_trace = g_trace_guard.saved;
    g_trace_guard.active = 0;
}

int bogi23_lookup_group(Bogi23Reader *reader, const char *owner,
                        Bogi23OwnerGroup *group, int *found) {
    OwnerGroup internal;
    int rc;
    if (bogi23_trace_begin(reader) != 0) {
        return -1;
    }
    (void)memset(&internal, 0, sizeof(internal));
    rc = lookup_group(reader, owner, &internal, found);
    if (rc != 0) {
        return -1;
    }
    /* Layout-compatible copy into public typedef. */
    (void)memcpy(group, &internal, sizeof(internal));
    return 0;
}

void bogi23_free_group(Bogi23Reader *reader, Bogi23OwnerGroup *group) {
    OwnerGroup internal;
    if (group == NULL) {
        return;
    }
    (void)memcpy(&internal, group, sizeof(internal));
    free_group(reader, &internal);
    (void)memset(group, 0, sizeof(*group));
}

int bogi23_node_exists(Bogi23Reader *reader, const char *owner, int *exists) {
    if (bogi23_trace_begin(reader) != 0) {
        return -1;
    }
    return node_exists(reader, owner, exists);
}

#include "bogi23_dig.h"

int bogi23_dig_get_apex(Bogi23Reader *reader, char *out, size_t out_sz)
{
    size_t n;
    if (reader == NULL || out == NULL || out_sz == 0)
        return -1;
    n = strlen(reader->origin);
    if (n + 1 > out_sz)
        return -1;
    (void)memcpy(out, reader->origin, n + 1);
    return 0;
}

int bogi23_dig_lookup(Bogi23Reader *reader, const char *name,
                      Bogi23DigLookupKind *kind, char *succ_out, size_t succ_sz)
{
    uint8_t key[ZIR3_MAX_KEY];
    size_t key_length = 0u;
    ScanResult scan;
    char *owner = NULL;
    if (reader == NULL || name == NULL || kind == NULL)
        return -1;
    *kind = BOGI23_DIG_NONE;
    if (succ_out != NULL && succ_sz > 0)
        succ_out[0] = '\0';
    if (bogi23_trace_begin(reader) != 0)
        return -1;
    if (owner_to_key(reader, name, key, &key_length) != 0)
        return -1;
    (void)memset(&scan, 0, sizeof(scan));
    if (scan_owner(reader, key, key_length, 0, &scan) != 0)
        return -1;
    if (!scan.found) {
        free_scan(reader, &scan);
        *kind = BOGI23_DIG_NONE;
        return 0;
    }
    if (scan.relation == 0) {
        *kind = BOGI23_DIG_EXACT;
        free_scan(reader, &scan);
        return 0;
    }
    *kind = BOGI23_DIG_SUCCESSOR;
    owner = key_to_owner(reader, scan.key, scan.key_length);
    free_scan(reader, &scan);
    if (owner == NULL)
        return -1;
    if (succ_out != NULL && succ_sz > 0) {
        size_t n = strlen(owner);
        if (n + 1 > succ_sz) {
            tracked_free(reader, owner);
            return -1;
        }
        (void)memcpy(succ_out, owner, n + 1);
    }
    tracked_free(reader, owner);
    return 0;
}

int bogi23_dig_get_rrset(Bogi23Reader *reader, const char *owner,
                         const char *rrtype, Bogi23OwnerGroup *group, int *found)
{
    OwnerGroup internal;
    OwnerGroup filtered;
    size_t i, j;
    int own_found = 0;
    if (reader == NULL || owner == NULL || rrtype == NULL || group == NULL ||
        found == NULL)
        return -1;
    *found = 0;
    (void)memset(group, 0, sizeof(*group));
    if (bogi23_trace_begin(reader) != 0)
        return -1;
    (void)memset(&internal, 0, sizeof(internal));
    if (lookup_group(reader, owner, &internal, &own_found) != 0)
        return -1;
    if (!own_found)
        return 0;
    *found = 1;
    (void)memset(&filtered, 0, sizeof(filtered));
    filtered.owner = tracked_strdup(reader, internal.owner);
    if (filtered.owner == NULL) {
        free_group(reader, &internal);
        return -1;
    }
    for (i = 0; i < internal.count; ++i) {
        RRset *src = &internal.sets[i];
        RRset *dst;
        if (strcmp(src->rrtype, rrtype) != 0)
            continue;
        dst = &filtered.sets[filtered.count++];
        (void)memset(dst, 0, sizeof(*dst));
        dst->owner = tracked_strdup(reader, src->owner);
        dst->source_owner = tracked_strdup(reader, src->source_owner);
        dst->rrtype = tracked_strdup(reader, src->rrtype);
        dst->ttl = src->ttl;
        dst->source_ttl = src->source_ttl;
        dst->rdata_count = src->rdata_count;
        dst->rdatas = (char **)tracked_malloc(reader,
            (src->rdata_count ? src->rdata_count : 1u) * sizeof(char *));
        if (dst->owner == NULL || dst->source_owner == NULL ||
            dst->rrtype == NULL || dst->rdatas == NULL) {
            free_group(reader, &internal);
            free_group(reader, &filtered);
            return -1;
        }
        (void)memset(dst->rdatas, 0, src->rdata_count * sizeof(char *));
        for (j = 0; j < src->rdata_count; ++j) {
            dst->rdatas[j] = tracked_strdup(reader, src->rdatas[j]);
            if (dst->rdatas[j] == NULL) {
                free_group(reader, &internal);
                free_group(reader, &filtered);
                return -1;
            }
        }
        break;
    }
    free_group(reader, &internal);
    (void)memcpy(group, &filtered, sizeof(filtered));
    return 0;
}

int bogi23_dig_get_soa(Bogi23Reader *reader, Bogi23OwnerGroup *group, int *found)
{
    return bogi23_dig_get_rrset(reader, reader->origin, "SOA", group, found);
}

typedef struct {
    FILE *fp;
    int err;
} DigZoneDumpCtx;

static int dig_zone_dump_cb(Bogi23Reader *reader, const void *group_v, void *arg)
{
    const OwnerGroup *group = (const OwnerGroup *)group_v;
    DigZoneDumpCtx *ctx = (DigZoneDumpCtx *)arg;
    size_t i, j;
    (void)reader;
    if (ctx->err)
        return -1;
    for (i = 0; i < group->count; ++i) {
        const RRset *rr = &group->sets[i];
        for (j = 0; j < rr->rdata_count; ++j) {
            if (fprintf(ctx->fp, "%s\t%llu\tIN\t%s\t%s\n",
                        rr->owner ? rr->owner : ".",
                        (unsigned long long)rr->ttl,
                        rr->rrtype ? rr->rrtype : "A",
                        rr->rdatas[j] ? rr->rdatas[j] : "") < 0) {
                ctx->err = 1;
                return -1;
            }
        }
    }
    return 0;
}

int bogi23_dig_write_zonefile(Bogi23Reader *reader, const char *path)
{
    DigZoneDumpCtx ctx;
    FILE *fp;
    if (reader == NULL || path == NULL)
        return -1;
    fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    if (fprintf(fp, "$TTL 3600\n") < 0) {
        (void)fclose(fp);
        return -1;
    }
    ctx.fp = fp;
    ctx.err = 0;
    if (bogi23_foreach_owner(reader, dig_zone_dump_cb, &ctx) != 0 || ctx.err) {
        (void)fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    return 0;
}

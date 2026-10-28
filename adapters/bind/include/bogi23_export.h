#ifndef BOGI23_EXPORT_H
#define BOGI23_EXPORT_H

#include "bogi23_reader.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Must match RRset / OwnerGroup in bogi23_reader.c exactly. */
typedef struct Bogi23RRset {
	char *owner;
	char *source_owner;
	char *rrtype;
	uint64_t ttl;
	uint64_t source_ttl;
	char **rdatas;
	size_t rdata_count;
} Bogi23RRset;

typedef struct Bogi23OwnerGroup {
	Bogi23RRset sets[ZIR3_NTYPES_MAX];
	size_t count;
	char *owner;
} Bogi23OwnerGroup;

typedef int (*bogi23_owner_cb)(Bogi23Reader *reader, const void *group,
			       void *arg);

int bogi23_foreach_owner(Bogi23Reader *reader, bogi23_owner_cb cb, void *arg);

/* Lookup helpers for mmap-direct BIND db (require active_trace or use wrappers). */
int bogi23_trace_begin(Bogi23Reader *reader);
void bogi23_trace_end(Bogi23Reader *reader);

int bogi23_lookup_group(Bogi23Reader *reader, const char *owner,
			Bogi23OwnerGroup *group, int *found);
void bogi23_free_group(Bogi23Reader *reader, Bogi23OwnerGroup *group);
int bogi23_node_exists(Bogi23Reader *reader, const char *owner, int *exists);

#ifdef __cplusplus
}
#endif

#endif

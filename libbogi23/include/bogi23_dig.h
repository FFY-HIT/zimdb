#ifndef BOGI23_DIG_H
#define BOGI23_DIG_H

/*
 * Dig zone-data API (Model B): store lookups only — no Auth / wire assembly.
 *
 *   GetApex / GetSOA / Lookup(Exact|Successor|None) / GetRRset
 */

#include <stddef.h>

#include "bogi23_export.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	BOGI23_DIG_EXACT = 0,
	BOGI23_DIG_SUCCESSOR = 1,
	BOGI23_DIG_NONE = 2
} Bogi23DigLookupKind;

/* Absolute apex (origin) name into out (NUL-terminated). */
int bogi23_dig_get_apex(Bogi23Reader *reader, char *out, size_t out_sz);

/* Apex SOA RRset via GetRRset(apex, "SOA") into group; caller bogi23_free_group. */
int bogi23_dig_get_soa(Bogi23Reader *reader, Bogi23OwnerGroup *group, int *found);

/*
 * Lookup name in canonical order.
 * Exact: name stored; Successor: least stored owner >= name (succ_out filled);
 * None: no such owner.
 */
int bogi23_dig_lookup(Bogi23Reader *reader, const char *name,
		      Bogi23DigLookupKind *kind, char *succ_out, size_t succ_sz);

/*
 * Typed RRset at owner. On found, group holds a single set (or empty count=0
 * with found=1 if owner exists but type absent). On owner miss, found=0.
 * Caller must bogi23_free_group.
 */
int bogi23_dig_get_rrset(Bogi23Reader *reader, const char *owner,
			 const char *rrtype, Bogi23OwnerGroup *group, int *found);

/* Write RFC1035-ish zone text for the image (absolute owners). */
int bogi23_dig_write_zonefile(Bogi23Reader *reader, const char *path);

#ifdef __cplusplus
}
#endif

#endif

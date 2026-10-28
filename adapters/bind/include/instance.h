/*
 * BOGI dyndb instance: one origin + one .bogi path.
 */

#pragma once

#include <dns/dyndb.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/types.h>
#include <isc/loop.h>
#include <isc/mem.h>

typedef struct bogi_instance {
	isc_mem_t *mctx;
	char *db_name;
	char *bogi_path;
	dns_view_t *view;
	dns_zonemgr_t *zmgr;
	isc_loopmgr_t *loopmgr;
	dns_dbimplementation_t *db_imp;
	dns_fixedname_t zone_fn;
	dns_name_t *zone_name;
	dns_zone_t *zone;
} bogi_instance_t;

/* Compatibility with ISC sample zone helpers. */
typedef bogi_instance_t sample_instance_t;

isc_result_t
new_bogi_instance(isc_mem_t *mctx, const char *db_name, int argc, char **argv,
		  const dns_dyndbctx_t *dctx, bogi_instance_t **instp);

isc_result_t
load_bogi_instance_zone(bogi_instance_t *inst);

void
destroy_bogi_instance(bogi_instance_t **instp);

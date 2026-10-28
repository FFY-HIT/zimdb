
#include "instance.h"

#include <isc/util.h>
#include <dns/db.h>
#include <dns/dyndb.h>
#include <dns/view.h>
#include <dns/zone.h>

#include "db.h"
#include "log.h"
#include "zone.h"

static isc_result_t
parse_params(isc_mem_t *mctx, int argc, char **argv, dns_name_t *zone,
	     char **bogi_pathp) {
	isc_result_t result;

	REQUIRE(argv != NULL);
	REQUIRE(zone != NULL);
	REQUIRE(bogi_pathp != NULL && *bogi_pathp == NULL);

	if (argc != 2) {
		log_error("exactly two parameters required: <origin.> <path.bogi>");
		return ISC_R_FAILURE;
	}
	result = dns_name_fromstring(zone, argv[0], dns_rootname, 0, mctx);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	*bogi_pathp = isc_mem_strdup(mctx, argv[1]);
	return ISC_R_SUCCESS;
}

isc_result_t
new_bogi_instance(isc_mem_t *mctx, const char *db_name, int argc, char **argv,
		  const dns_dyndbctx_t *dctx, bogi_instance_t **instp) {
	isc_result_t result;
	bogi_instance_t *inst;

	REQUIRE(instp != NULL && *instp == NULL);

	inst = isc_mem_get(mctx, sizeof(*inst));
	*inst = (bogi_instance_t){ 0 };
	isc_mem_attach(mctx, &inst->mctx);
	inst->db_name = isc_mem_strdup(mctx, db_name);
	inst->zone_name = dns_fixedname_initname(&inst->zone_fn);

	result = parse_params(mctx, argc, argv, inst->zone_name, &inst->bogi_path);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	dns_view_attach(dctx->view, &inst->view);
	dns_zonemgr_attach(dctx->zmgr, &inst->zmgr);
	inst->loopmgr = dctx->loopmgr;

	result = dns_db_register(db_name, create_db, inst, mctx, &inst->db_imp);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	*instp = inst;
	return ISC_R_SUCCESS;

cleanup:
	destroy_bogi_instance(&inst);
	return result;
}

isc_result_t
load_bogi_instance_zone(bogi_instance_t *inst) {
	isc_result_t result;

	result = create_zone(inst, inst->zone_name, &inst->zone);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	return activate_zone(inst, inst->zone);
}

void
destroy_bogi_instance(bogi_instance_t **instp) {
	bogi_instance_t *inst;

	REQUIRE(instp != NULL);
	inst = *instp;
	*instp = NULL;
	if (inst == NULL) {
		return;
	}
	if (inst->db_name != NULL) {
		isc_mem_free(inst->mctx, inst->db_name);
	}
	if (inst->bogi_path != NULL) {
		isc_mem_free(inst->mctx, inst->bogi_path);
	}
	if (inst->zone != NULL) {
		dns_zone_detach(&inst->zone);
	}
	if (inst->db_imp != NULL) {
		dns_db_unregister(&inst->db_imp);
	}
	if (inst->view != NULL) {
		dns_view_detach(&inst->view);
	}
	if (inst->zmgr != NULL) {
		dns_zonemgr_detach(&inst->zmgr);
	}
	isc_mem_putanddetach(&inst->mctx, inst, sizeof(*inst));
}

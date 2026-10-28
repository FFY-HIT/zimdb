
#include <isc/commandline.h>
#include <isc/mem.h>
#include <isc/util.h>

#include <dns/dyndb.h>

#include "instance.h"
#include "log.h"

dns_dyndb_destroy_t dyndb_destroy;
dns_dyndb_register_t dyndb_init;
dns_dyndb_version_t dyndb_version;

const char *impname = "bogi_zonedb";

isc_result_t
dyndb_init(isc_mem_t *mctx, const char *name, const char *parameters,
	   const char *file, unsigned long line, const dns_dyndbctx_t *dctx,
	   void **instp) {
	isc_result_t result;
	unsigned int argc = 0;
	char **argv = NULL;
	char *s = NULL;
	bogi_instance_t *inst = NULL;

	REQUIRE(name != NULL);
	REQUIRE(dctx != NULL);

	s = isc_mem_strdup(mctx, parameters);
	result = isc_commandline_strtoargv(mctx, s, &argc, &argv, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	log_write(ISC_LOG_INFO, "loading bogi dyndb '%s' from %s:%lu", name, file,
		  line);

	result = new_bogi_instance(mctx, name, (int)argc, argv, dctx, &inst);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	result = load_bogi_instance_zone(inst);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	*instp = inst;
	inst = NULL;

cleanup:
	if (inst != NULL) {
		destroy_bogi_instance(&inst);
	}
	if (s != NULL) {
		isc_mem_free(mctx, s);
	}
	if (argv != NULL) {
		isc_mem_cput(mctx, argv, argc, sizeof(*argv));
	}
	return result;
}

void
dyndb_destroy(void **instp) {
	destroy_bogi_instance((bogi_instance_t **)instp);
}

int
dyndb_version(unsigned int *flags) {
	UNUSED(flags);
	return DNS_DYNDB_VERSION;
}

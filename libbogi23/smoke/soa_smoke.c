#include <stdio.h>
#include <string.h>

#include "bogi23_export.h"

int
main(int argc, char **argv)
{
	const char *path =
		argc > 1 ? argv[1]
			 : "/home/administrator/agentdns-czds/prepared/czds_page/"
			   "image.bogi";
	const char *owner = argc > 2 ? argv[2] : NULL;
	Bogi23Reader r;
	Bogi23OwnerGroup g;
	int found = 0;
	size_t i, j;

	memset(&r, 0, sizeof r);
	r.fd = -1;
	if (bogi23_open(&r, path) != 0) {
		fprintf(stderr, "open fail path=%s\n", path);
		return 1;
	}
	printf("origin=%s\n", r.origin);
	if (owner == NULL) {
		owner = r.origin;
	}
	bogi23_trace_begin(&r);
	if (bogi23_lookup_group(&r, owner, &g, &found) != 0 || !found) {
		printf("lookup miss owner=%s\n", owner);
		bogi23_close(&r);
		return 2;
	}
	for (i = 0; i < g.count; i++) {
		printf("type=%s ttl=%llu n=%zu\n", g.sets[i].rrtype,
		       (unsigned long long)g.sets[i].ttl,
		       g.sets[i].rdata_count);
		for (j = 0; j < g.sets[i].rdata_count; j++) {
			printf("  %s\n", g.sets[i].rdatas[j]);
		}
	}
	bogi23_free_group(&r, &g);
	bogi23_close(&r);
	return 0;
}

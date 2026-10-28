/* CLI: Dig dump image.bogi → zone text for native Auth hydrate. */
#include "bogi23_dig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	Bogi23Reader reader;
	const char *img;
	const char *out;
	if (argc != 3) {
		fprintf(stderr, "usage: %s image.bogi out.zone\n", argv[0]);
		return 2;
	}
	img = argv[1];
	out = argv[2];
	memset(&reader, 0, sizeof(reader));
	if (bogi23_open(&reader, img) != 0) {
		fprintf(stderr, "open failed: %s\n", img);
		return 1;
	}
	if (bogi23_dig_write_zonefile(&reader, out) != 0) {
		fprintf(stderr, "write failed: %s\n", out);
		bogi23_close(&reader);
		return 1;
	}
	bogi23_close(&reader);
	return 0;
}

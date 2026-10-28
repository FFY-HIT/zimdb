# ZimDB / BOGI-v2.3 encoder C accelerators (Pass A zone_scan + join_scatter).
CC ?= gcc
CFLAGS ?= -O3 -march=native -Wall -Wextra
LDFLAGS_SCATTER ?= -pthread

.PHONY: all clean

all: zone_scan join_scatter

zone_scan: zone_scan.c blake2b16.h
	$(CC) $(CFLAGS) -o $@ zone_scan.c

join_scatter: join_scatter.c
	$(CC) $(CFLAGS) $(LDFLAGS_SCATTER) -o $@ join_scatter.c

clean:
	rm -f zone_scan join_scatter

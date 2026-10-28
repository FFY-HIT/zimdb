# ZimDB

ZimDB (BOGI-v2.3) — zone image builder and authoritative-server adapters.

This repository contains **only** the code needed to:

1. **Build** a ZimDB image from a DNS zone file (the production encoder that builds full `.com`+DNSSEC in ~390 s on a 16-core / 123 GiB host).
2. **Serve** that image from NSD / Knot / Unbound / YADIFA / CoreDNS / BIND via thin product adapters + shared `libbogi23`.

## Quick start — build an image

Linux / WSL, Python 3.10+, `gcc`.

```bash
cd builder
make -j$(nproc)                          # zone_scan + join_scatter
# sample / any zone:
ZONE=/path/to/example.zone ORIGIN=example.com. \
  bash run_sample.sh "$ZONE" ./out_sample "$ORIGIN"

# full production encode (same path as the ~390s .com run):
ZONE=/path/to/com.zone OUT_DIR=./out_full ORIGIN=com. \
  BOGI_WORKERS=$(nproc) BOGI_PARALLEL_SCAN=1 \
  bash run_full.sh
```

Or call the encoder directly after `make`:

```bash
python3 -u encode_com_dnssec_zimdb.py \
  /path/to/zone /path/to/image.bogi /path/to/workdir origin.
```

Optional env: `BOGI_WORKERS`, `BOGI_PARALLEL_SCAN=1`, `BOGI_ZONE_SCAN`, `BOGI_JOIN_SCATTER`, `BOGI_RESUME=1`.

## Shared reader library

```bash
make -C libbogi23
# → libbogi23/build/libbogi23.so
```

## Product adapters

| Product | Path | Notes |
|---------|------|-------|
| NSD 4.14 | `adapters/nsd/` | glue + hook README |
| Knot 3.5 | `adapters/knot/` | glue + hook README |
| Unbound 1.24 | `adapters/unbound/` | glue + hook README |
| YADIFA 3.0.9 | `adapters/yadifa/` | glue + hook README |
| CoreDNS | `adapters/coredns/` | `bogi` plugin |
| BIND 9.20 | `adapters/bind/` | dyndb `bogi_zonedb.so` |

Vendor trees are **not** vendored here — copy the glue files into a stock checkout and apply the documented hooks, then link `-lbogi23` (BIND module embeds its own reader).

## Layout

```
builder/          # ZimDB encoder + C accelerators
libbogi23/        # shared mmap reader / auth-answer API
adapters/         # per-product glue
```

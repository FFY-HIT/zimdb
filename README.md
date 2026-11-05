# ZimDB

ZimDB (BOGI-v2.3) — zone image builder, authoritative-server adapters, and ops edit client.

This repository contains the code needed to:

1. **Build** a ZimDB image from a DNS zone file (the production encoder that builds full `.com`+DNSSEC in ~390 s on a 16-core / 123 GiB host).
2. **Serve** that image from NSD / Knot / Unbound / YADIFA / CoreDNS / BIND via thin product adapters + shared `libbogi23`.
3. **Edit** resource records in a desktop GUI and **Apply** changes into a binary zone image (ops path).

## Ops 编辑客户端（桌面 GUI）

运维场景：添加 / 修改 / 删除 RR → 点「提交」→ 本地二进制映像原子更新。

```powershell
# Windows（仓库根目录）
.\scripts\run_ops_gui.ps1
# 或
$env:PYTHONPATH = (Get-Location).Path
python -m ops_client
```

```bash
# Linux / WSL
bash scripts/run_ops_gui.sh
# 或
PYTHONPATH=. python3 -m ops_client
```

- 数据目录：`ops/data/zone.zimdb`（可用环境变量 `ZIMDB_OPS_DATA` 覆盖）
- 接口说明：[`ops/README.md`](ops/README.md)
- **当前 Apply 后端**：container 分片映像（可演示）。生产 DNSSEC `.bogi` Apply **尚未接通**，API 已预留 `ApplyBackend` 插槽。

## Quick start — build an image

Linux / WSL, Python 3.10+, `gcc`.

```bash
cd builder
make -j$(nproc)                          # zone_scan + join_scatter
ZONE=/path/to/example.zone ORIGIN=example.com. \
  bash run_sample.sh "$ZONE" ./out_sample "$ORIGIN"

ZONE=/path/to/com.zone OUT_DIR=./out_full ORIGIN=com. \
  BOGI_WORKERS=$(nproc) BOGI_PARALLEL_SCAN=1 \
  bash run_full.sh
```

Optional env: `BOGI_WORKERS`, `BOGI_PARALLEL_SCAN=1`, `BOGI_ZONE_SCAN`, `BOGI_JOIN_SCATTER`, `BOGI_RESUME=1`.

## Shared reader library

`libbogi23` / Zir memory-maps a BOGIP1 image and answers dig lookups via
binary search over owner restart keys (no open-time learned accelerator).

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
ops/              # ZoneEdit API + container Apply backend
ops_client/       # tkinter desktop GUI
scripts/          # run_ops_gui helpers
```

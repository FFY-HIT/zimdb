# ZimDB

ZimDB 将 DNS 区域文件构造成支持名称状态、ENT、closest encloser、通配来源、zone cut 和 RRset 查询的紧凑映像。

当前原生路径采用 ZIMDNS1 格式，提供有界工作空间构造、上下文 NS 模板、分块共享池、NSEC3 局部引用和世代更新。DNSRocks 集成提供该格式的权威查询服务。

## 构建与查询

Linux / WSL 需要 C++17、ldns、LZ4、Zstandard 和 OpenSSL 开发库。

```sh
make -C experiments/queryable_zone
experiments/queryable_zone/native_zone build \
  --zone /path/to/example.zone --origin example. \
  --out /path/to/example.zim --work /path/to/work \
  --memory-mib 64 --run-memory-mib 4 --sort-engine hierarchy \
  --sort-tuple body --codec zstd --pool none --front-code 1 \
  --index cow --key-codec compact --page-layout columnar \
  --ns-pool-entries 65536 --ns-templates 1 --nsec3-links 1
```

完整COM实测使用固定版本 SIMD parser，构建方式见 [原生构建说明](experiments/queryable_zone/BUILD_NOTE.md)。

[DNSRocks 接入说明](adapters/dnsrocks/README.zimdb.md) 给出 Go 权威程序的构建和运行入口。

## 完整COM实验

2026-09-19快照包含441,290,102条输入RR出现。ZimDB原生映像3,344,985,486字节，构建381.089秒，构建进程树采样峰值RSS31.125MiB。相同10万条计时查询下，平均RTT72.063微秒，查询峰值RSS89.9MiB。

完整配置、四组对比、测量口径与现有边界见 [实验汇总](docs/experiments/com-20260919-20261114.md)。这些数据来自一次固定负载测量。查询读取器优化按工程实现报告。

仓库同时保留 BOGIP1 构造器、libbogi23、运维客户端及对应适配器。下方为该工具链的使用说明。

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

## BOGIP1 builder

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

Default DNSSEC encode uses typed binary pool (`flags` bit `0x4`): pool
payloads store wire-oriented binary (A/AAAA, SOA/MX integers, RRSIG
times/signature, DS digest, DNSKEY key, NSEC3 next hash, etc.) and expand
to presentation on dig. The reader stays nolearn (restart-key binary search
only). Override with `BOGI_BINARY_POOL=0` is not wired yet — use an older
commit for presentation-pool images. Dedicated helper:

```bash
PYTHONPATH=. python3 builder/encode_binary_zone.py \
  --zone path/to/zone.gz --origin example. --out example.binary.bogi
```
NSEC3 *owner* hash labels remain in κ(ASCII+1) so lexicographic order is preserved.


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

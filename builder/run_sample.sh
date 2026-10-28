#!/usr/bin/env bash
# Encode a (small) zone into image.bogi — smoke / sample path.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ZONE="${1:?usage: $0 <zonefile> [out_dir] [origin]}"
OUT_DIR="${2:-$HERE/out_sample}"
ORIGIN="${3:-com.}"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/work"

make -C "$HERE" -j"$(nproc)"

export BOGI_WORKERS="${BOGI_WORKERS:-$(nproc)}"
export BOGI_PARALLEL_SCAN="${BOGI_PARALLEL_SCAN:-1}"
export BOGI_JOIN_SCATTER="${BOGI_JOIN_SCATTER:-$HERE/join_scatter}"
export BOGI_ZONE_SCAN="${BOGI_ZONE_SCAN:-$HERE/zone_scan}"

/usr/bin/time -f "elapsed_wall=%e" python3 -u "$HERE/encode_com_dnssec_zimdb.py" \
  "$ZONE" "$OUT_DIR/image.bogi" "$OUT_DIR/work" "$ORIGIN" \
  2>&1 | tee "$OUT_DIR/run.log"
ls -lh "$OUT_DIR/image.bogi" "$OUT_DIR/image.bogi.meta.json" 2>/dev/null || true

#!/usr/bin/env bash
# Full-zone ZimDB encode (production path used for ~390s .com+DNSSEC builds).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ZONE="${ZONE:?set ZONE=/path/to/zonefile}"
OUT_DIR="${OUT_DIR:-$HERE/out_full}"
ORIGIN="${ORIGIN:-com.}"
mkdir -p "$OUT_DIR"
WORK="$OUT_DIR/work_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$WORK"

make -C "$HERE" -j"$(nproc)"

export BOGI_WORKERS="${BOGI_WORKERS:-$(nproc)}"
export BOGI_PARALLEL_SCAN="${BOGI_PARALLEL_SCAN:-1}"
export BOGI_JOIN_SCATTER="${BOGI_JOIN_SCATTER:-$HERE/join_scatter}"
export BOGI_ZONE_SCAN="${BOGI_ZONE_SCAN:-$HERE/zone_scan}"

echo "WORK=$WORK" | tee "$OUT_DIR/latest_work.txt"
echo "start $(date -Is)" | tee "$OUT_DIR/run_full.log"
/usr/bin/time -f "elapsed_wall=%e" python3 -u "$HERE/encode_com_dnssec_zimdb.py" \
  "$ZONE" "$OUT_DIR/image.bogi" "$WORK" "$ORIGIN" \
  2>&1 | tee -a "$OUT_DIR/run_full.log"
echo "end $(date -Is)" | tee -a "$OUT_DIR/run_full.log"
cp -f "$WORK/encode.log" "$OUT_DIR/encode.log" 2>/dev/null || true
ls -lh "$OUT_DIR/image.bogi" "$OUT_DIR/image.bogi.meta.json" 2>/dev/null || true

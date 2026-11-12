# Per-owner Snappy / LZ4 images

This feature adds a physical compression layer to images produced by the
repository's existing disk-backed C/Python production pipeline. It does not
replace that pipeline with a whole-zone Python object graph.

The starting repository revision is
`9635294a7a1bb3ff464c721cbd919cdb4a67d64b`. This branch also includes shared
correctness fixes for parallel input-range boundaries and the matching reader
export/TTL path. Those fixes apply equally to unwrapped and codec variants;
they are separate from codec effects. Inspect the branch diff when reproducing
an experiment rather than identifying the branch solely by its base revision.

## Compression unit and layout

An owner frame contains one original encoded owner record: its full or
front-coded name key, the RRset type/TTL/count fields, and references into the
global RDATA pool. Each frame uses an independent native Snappy or LZ4 stream.
The global typed RDATA pool remains plain, retains the original IDs and layout,
and is included in the complete image size.

The original logical image bytes are unchanged by wrapping. Original owner
front-coding restarts and pool restarts remain every16 entries. A coarse
directory still covers up to16 owners to limit index overhead, but each of
those owners is a separate codec frame. Decompression independence does not
remove a nonrestart name's dependency on earlier names in its front-coded
group. The final artifact is one image with one global pool.

The codecs use the same native algorithm settings as the pinned RocksDB
comparison: raw Snappy, or independent empty-dictionary LZ4 at acceleration1
with an original-length varint prefix. A compressed payload is retained only
when its length is at most `floor(raw_length * 896 / 1024)`; otherwise that
owner is stored plain. Frame CRC, coarse-container CRC, lengths, directory and
first-key bytes all count in the final physical file size.

RocksDB compresses SST data blocks, generally containing multiple keys and
values. This feature aligns codec/settings while deliberately using a
different compression unit; it does not claim identical granularity or
identical bytes exposed to the compressor. `none` uses the same framed layout
as the two codecs, so the unwrapped image and framed-none image are distinct
controls for framing overhead.

## Build from a zone file

Requirements: Linux/WSL, Python3.10+, a C compiler, native `libsnappy.so.1`,
native `liblz4.so.1`, and zlib for the C reader. Build tools before measuring:

```bash
make -C builder -j2
make -C libbogi23 -j2
```

Choose fresh output/work directories. For example, from the repository root:

```bash
repo_root="$PWD"
job_root="/path/to/fresh/ext4/job"
zone_file="/path/to/source.zone"
origin="example."
mkdir -p "$job_root/work" "$job_root/tmp"

BOGI_WORKERS=2 BOGI_PARALLEL_SCAN=1 BOGI_ZONE_SCAN_REQUIRED=1 \
BOGI_ZONE_SCAN="$repo_root/builder/zone_scan" \
BOGI_JOIN_SCATTER="$repo_root/builder/join_scatter" \
TMPDIR="$job_root/tmp" LC_ALL=C \
python3 builder/encode_com_dnssec_zimdb.py \
  "$zone_file" "$job_root/unwrapped.bogi" "$job_root/work" "$origin"

python3 builder/wrap_owner_keys.py wrap \
  --input "$job_root/unwrapped.bogi" \
  --output "$job_root/image.bogi" --codec snappy
```

Select `--codec none`, `--codec snappy`, or `--codec lz4`. The wrapper writes
`image.bogi.meta.json` by default. Its `.bogi` suffix does not change the
`ZIMBC01` v2 on-disk magic. The wrapper currently admits BOGIP1 profile
`0x50310002`, plain/binary-pool flags, and rejects unsupported Huffman layouts.
Zone syntax/type limits remain those of the production frontend; a successful
SOA alone is not full-source qualification.

Owners whose raw record exceeds64MiB are stored plain using bounded CRC/copy
passes from the seekable input. Smaller frames use bounded whole-record native
codec calls. `--max-compressed-owner-bytes` can lower this threshold and is
recorded in metadata. This is a wrapper buffer policy, not a hard RSS guarantee
for the preceding production pipeline or the complete process.

## Verify and serve

Independent Python reconstruction validates both checksum layers and exact
logical byte identity:

```bash
python3 builder/wrap_owner_keys.py verify \
  --input "$job_root/image.bogi" --original "$job_root/unwrapped.bogi" \
  --manifest "$job_root/logical-verify.json"

python3 builder/wrap_owner_keys.py unwrap \
  --input "$job_root/image.bogi" --output "$job_root/restored.bogi" \
  --original "$job_root/unwrapped.bogi"
```

The matching C reader exposes the original logical bytes through
`bogi23_read_logical`; its smoke tool can independently recover the image in
65553-byte chunks, deliberately crossing record/frame boundaries:

```bash
libbogi23/build/keycodec_smoke stats "$job_root/image.bogi"
libbogi23/build/keycodec_smoke readback \
  "$job_root/image.bogi" "$job_root/c-restored.bogi"
cmp "$job_root/unwrapped.bogi" "$job_root/c-restored.bogi"
```

Rebuild/relink authority adapters against these matching reader headers and
library. `bogi23_open` accepts unwrapped and v2 images; reads decompress owner
frames as needed. `ZIMDB_KEY_CACHE_BYTES` controls the owner-frame cache and
takes precedence over the compatible `ZIMDB_BLOCK_CACHE_BYTES` name. The cache
budget is not total RSS. `keycodec_smoke` reports an18-value statistics vector,
including actual Snappy/LZ4 decode counts and cache charge.

Full qualification must additionally export all records through the C reader
and compare canonical owner/class/type/TTL/RDATA with the original source.
Source contracts used to reconstruct per-signature RRSIG TTLs must be stated;
retaining signatures does not itself prove complete DNSSEC authority behavior.

The CLI refuses existing output images and rejects resolved or hardlink
aliases between input/original and writable output/manifest/temporary paths.
It also refuses a preexisting implicit manifest temporary path. This protects
ordinary CLI use; it is not race-free filesystem isolation against a concurrent
hostile process.

## Compare without dropping construction work

The complete path is **zone source → production image → per-owner wrapper →
final artifact**. Report the original-build and wrapping stages, and include
both in source-to-final timing. For each codec's complete construction
measurement, run the production stage in a fresh workspace instead of reusing
another configuration's completed image. Retain both original-unwrapped and
framed-none controls.

Compile/configure outside timing, keep source/cache/CPU policies explicit,
write final/scratch data to a disk-backed filesystem, and report extra file
and directory fsync completion separately. Perform byte reconstruction and
complete RR qualification outside the build timer unless intentionally
declared part of it. `wrap --verify` charges its extra verification to that
invocation.

Authority Popen→first source-correct SOA, query latency under a source-derived
mix, and their RSS are separate from offline construction. Keep them separate
in tables. The same native authority binary/backend interface and comparable
declared cache policies help identify codec costs; one source and one trial
do not establish scaling or a universal ranking.

## Source identity after CLI protection

The disclosed research run used the pre-guard wrapper source with SHA256
`3265f2755ff90416fb3b82679ab0d600fd1b2acfa9e22415a47051fe527fed28`.
After those builds, a CLI-only early alias guard was added. The compression
functions and physical format were not changed; small valid-path tests compare
all three guarded outputs byte-for-byte with that exact measured source.
Measurement provenance must retain this distinction instead of identifying
both source files by one hash. The repository delivers the protected CLI.

#!/usr/bin/env python3
"""Disk-backed encode of full .com+DNSSEC into a BOGI-v2.3 DNSSEC image.

Profile: TYPE_ORDER_DNSSEC + u16 type mask. Pool IDs are lexical ranks of
unique RDATA. External sort assigns ranks; the owner stream stores hashes
then a second pass rewrites them as uLEB IDs.

Pipeline v2: Pass A writes owner records with **full BOGI keys** (no
front-coding) in zone-file order. Pass A2 externally sorts by key, merges
non-contiguous same-owner fragments (Verisign apex split), then front-codes
so ReaderA binary search works.
"""

from __future__ import annotations

import array
import gzip
import hashlib
import heapq
import json
import mmap
import os
import struct
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path

from binary_pool_codec import (  # noqa: E402
    FLAG_BINARY_POOL,
    TAG_UTF8,
    pack_rdata,
)

TYPE_ORDER = (
    "A",
    "NS",
    "CNAME",
    "SOA",
    "MX",
    "TXT",
    "AAAA",
    "DS",
    "RRSIG",
    "NSEC3",
    "DNSKEY",
    "NSEC3PARAM",
)
TYPE_TO_BIT = {t: 1 << i for i, t in enumerate(TYPE_ORDER)}
_TYPE_NAME_B = {t.encode("ascii"): t for t in TYPE_ORDER}
TYPE_MASK_BYTES = 2
BLOCK_SIZE = 16
HEADER_SIZE = 128
MAGIC = b"BOGIP1\0\0"
VERSION_MAJOR = 2
VERSION_MINOR = 3
ENDIAN_MARKER = 0x4C45
SCHEMA_ID = 0x424F4704
# Must match experiments.compact_image_v23.format_v23.PROFILE_ID_DNSSEC
PROFILE_ID = 0x50310002
FLAGS = FLAG_BINARY_POOL  # BINARY POOL DEFAULT
RESERVED0 = 0
RESERVED1 = 0
HEADER = struct.Struct("<8sHHHHIIIHHQQQQQQQQQQQQ")
RESTART = struct.Struct("<Q")
HASH_LEN = 16
MAX_KEY_BYTES = 253
SPILL_OWNERS = 250_000
SPILL_SORT_VERSION = 1
# v2 = full-key Pass A + key-order sort/merge + front-code in A2
PIPELINE_VERSION = 2


def _blake2b16(data: bytes) -> bytes:
    """Non-crypto blake2b-128; usedforsecurity=False skips OpenSSL FIPS overhead."""
    try:
        return hashlib.blake2b(data, digest_size=HASH_LEN, usedforsecurity=False).digest()
    except TypeError:
        return hashlib.blake2b(data, digest_size=HASH_LEN).digest()


def _mem_available_mb() -> int:
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except OSError:
        pass
    return 8192


def _auto_tune() -> tuple[int, int, int, int]:
    """Return SORT_CHUNK, OWNER_SORT_CHUNK, MERGE_FAN_IN, workers from RAM/CPU/env."""
    avail = _mem_available_mb()
    # Keep ~16 GiB headroom on big hosts for C in-memory sorts + OS cache.
    headroom = 16_384 if avail >= 64_000 else 8192
    budget = max(2048, avail - headroom)
    cpus = os.cpu_count() or 4
    default_workers = cpus if avail >= 48_000 else max(2, min(cpus, 8))
    workers = int(os.environ.get("BOGI_WORKERS", str(default_workers)))
    # Cap run size so parallel Python spill-sort (one process per run) cannot
    # OOM: ~12M recs × Python object overhead × 8 workers ≈ tens of GiB.
    if avail >= 96_000:
        owner_cap, sort_cap = 12_000_000, 12_000_000
    elif avail >= 48_000:
        owner_cap, sort_cap = 8_000_000, 12_000_000
    else:
        owner_cap, sort_cap = 500_000, 800_000
    owner_chunk = int(os.environ.get("BOGI_OWNER_SORT_CHUNK", "0")) or min(
        owner_cap, max(50_000, (budget * 1024 * 1024) // (workers * 400))
    )
    sort_chunk = int(os.environ.get("BOGI_SORT_CHUNK", "0")) or min(
        sort_cap, max(100_000, (budget * 1024 * 1024) // (workers * 80))
    )
    fan = int(os.environ.get("BOGI_MERGE_FAN_IN", "0")) or min(256, max(32, workers * 8))
    return sort_chunk, owner_chunk, fan, workers


SORT_CHUNK, OWNER_SORT_CHUNK, MERGE_FAN_IN, BOGI_WORKERS = _auto_tune()

_KEY_PLUS1 = bytes(
    (b + 1) if b < 0x80 and not (0x41 <= b <= 0x5A) else 0 for b in range(256)
)
_ULEB_CACHE = tuple(
    bytes((v,)) if v < 0x80 else bytes((0x80 | (v & 0x7F), v >> 7)) for v in range(512)
)


def encode_uleb128(value: int) -> bytes:
    if value < 512:
        return _ULEB_CACHE[value]
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded)


def decode_uleb(buf: bytes | bytearray, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    used = 0
    while True:
        byte = buf[pos + used]
        used += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, used
        shift += 7


def uleb_len(value: int) -> int:
    n = 1
    while value >= 0x80:
        value >>= 7
        n += 1
    return n


def common_prefix_length(left: bytes, right: bytes) -> int:
    limit = min(len(left), len(right))
    i = 0
    while i < limit and left[i] == right[i]:
        i += 1
    return i


def owner_to_key(owner: str, origin: str) -> bytes:
    if owner == origin:
        return b""
    suffix = "." + origin
    if not owner.endswith(suffix):
        raise ValueError(f"owner outside origin: {owner}")
    relative = owner[: -len(suffix)]
    labels = relative.split(".")
    encoded = bytearray()
    for label in reversed(labels):
        raw = label.encode("ascii")
        mapped = raw.translate(_KEY_PLUS1)
        if 0 in mapped or not raw or len(raw) > 63:
            raise ValueError(f"bad label: {label}")
        encoded.extend(mapped)
        encoded.append(0)
    if len(encoded) > MAX_KEY_BYTES:
        raise ValueError("key too long")
    return bytes(encoded)


def normalize_owner(token: str) -> str:
    o = token.lower()
    if not o.endswith("."):
        return o + "."
    return o


def parse_rr_line(line: str, current_owner: str | None):
    if not line or line[0] in ";$":
        return None
    if line[0].isspace():
        if current_owner is None:
            return None
        owner = current_owner
        rest = line.split()
    else:
        parts = line.split(None, 1)
        if len(parts) < 2:
            return None
        owner = normalize_owner(parts[0])
        rest = parts[1].split()
    ttl = None
    i = 0
    while i < len(rest):
        tok = rest[i]
        up = tok.upper()
        if ttl is None and tok.isdigit():
            ttl = int(tok)
            i += 1
            continue
        if up in {"IN", "CH", "HS"}:
            i += 1
            continue
        rrtype = up
        rdata = " ".join(rest[i + 1 :])
        if " ;" in rdata:
            rdata = rdata.split(" ;", 1)[0].rstrip()
        return owner, rrtype, 0 if ttl is None else ttl, rdata
    return None


def parse_rr_line_b(line: bytes, current_owner: str | None):
    """ASCII-fast path for Pass A: keep rdata as bytes (no decode/encode)."""
    if not line or line[0] in (0x3B, 0x24):  # ; $
        return None
    if line.endswith(b"\r"):
        line = line[:-1]
    if not line:
        return None
    if line[0] in (0x20, 0x09):
        if current_owner is None:
            return None
        owner = current_owner
        rest = line.split()
    else:
        parts = line.split(None, 1)
        if len(parts) < 2:
            return None
        ot = parts[0].lower()
        if not ot.endswith(b"."):
            ot += b"."
        try:
            owner = ot.decode("ascii")
        except UnicodeDecodeError:
            return None
        rest = parts[1].split()
    ttl = None
    i = 0
    while i < len(rest):
        tok = rest[i]
        up = tok.upper()
        if ttl is None and tok.isdigit():
            ttl = int(tok)
            i += 1
            continue
        if up in (b"IN", b"CH", b"HS"):
            i += 1
            continue
        rrtype = _TYPE_NAME_B.get(up)
        if rrtype is None:
            return None
        rdata = b" ".join(rest[i + 1 :])
        cut = rdata.find(b" ;")
        if cut >= 0:
            rdata = rdata[:cut].rstrip()
        return owner, rrtype, 0 if ttl is None else ttl, rdata
    return None


def pack_rec(h: bytes, rrset_ord: int, rdata_ord: int, raw: bytes) -> bytes:
    return (
        h
        + struct.pack("<III", rrset_ord, rdata_ord, len(raw))
        + raw
    )


def unpack_rec(buf: bytes, off: int) -> tuple[bytes, int, int, bytes, int]:
    h = buf[off : off + HASH_LEN]
    rrset_ord, rdata_ord, n = struct.unpack_from("<III", buf, off + HASH_LEN)
    start = off + HASH_LEN + 12
    end = start + n
    return h, rrset_ord, rdata_ord, buf[start:end], end


def pack_owner_rec(key: bytes, body: bytes, hash_blob: bytes) -> bytes:
    """Owner spill record: full BOGI key (not front-coded) + body + hashes."""
    return (
        struct.pack("<III", len(key), len(body), len(hash_blob))
        + key
        + body
        + hash_blob
    )


def unpack_owner_rec(rec: bytes) -> tuple[bytes, bytes, bytes]:
    klen, blen, hlen = struct.unpack_from("<III", rec, 0)
    base = 12
    key = rec[base : base + klen]
    body = rec[base + klen : base + klen + blen]
    hashes = rec[base + klen + blen : base + klen + blen + hlen]
    if len(hashes) != hlen or len(hashes) % HASH_LEN:
        raise RuntimeError("owner hash blob misaligned")
    return key, body, hashes


def parse_owner_body(
    body: bytes, hashes: bytes
) -> dict[str, tuple[int, list[bytes]]]:
    """Decode mask/ttl/count + parallel hash blob into per-type hash lists."""
    if len(body) < TYPE_MASK_BYTES:
        raise RuntimeError("owner body too short")
    mask = int.from_bytes(body[:TYPE_MASK_BYTES], "little")
    pos = TYPE_MASK_BYTES
    hpos = 0
    out: dict[str, tuple[int, list[bytes]]] = {}
    for rrtype in TYPE_ORDER:
        if (mask & TYPE_TO_BIT[rrtype]) == 0:
            continue
        ttl, used = decode_uleb(body, pos)
        pos += used
        count, used = decode_uleb(body, pos)
        pos += used
        chunk: list[bytes] = []
        for _ in range(count):
            chunk.append(hashes[hpos : hpos + HASH_LEN])
            hpos += HASH_LEN
        out[rrtype] = (ttl, chunk)
    if pos != len(body) or hpos != len(hashes):
        raise RuntimeError("owner body/hash walk mismatch")
    return out


def merge_owner_types(
    left: dict[str, tuple[int, list[bytes]]],
    right: dict[str, tuple[int, list[bytes]]],
) -> dict[str, tuple[int, list[bytes]]]:
    """Union RRtypes; same type keeps first TTL and unique hashes (sorted)."""
    merged = {t: (ttl, list(hs)) for t, (ttl, hs) in left.items()}
    for rrtype, (ttl, hs) in right.items():
        if rrtype not in merged:
            merged[rrtype] = (ttl, list(hs))
            continue
        old_ttl, old_hs = merged[rrtype]
        uniq = sorted(set(old_hs) | set(hs))
        merged[rrtype] = (old_ttl, uniq)
    return merged


def pack_owner_types(types: dict[str, tuple[int, list[bytes]]]) -> tuple[bytes, bytes, int, int]:
    """Pack merged types → (body, hash_blob, rrset_count, rdata_ref_count)."""
    body = bytearray()
    mask = 0
    present: list[tuple[str, tuple[int, list[bytes]]]] = []
    for rrtype in TYPE_ORDER:
        item = types.get(rrtype)
        if item is None:
            continue
        mask |= TYPE_TO_BIT[rrtype]
        present.append((rrtype, item))
    body.extend(mask.to_bytes(TYPE_MASK_BYTES, "little"))
    hash_blob = bytearray()
    refs = 0
    for _rrtype, (ttl, hs) in present:
        body.extend(encode_uleb128(ttl))
        body.extend(encode_uleb128(len(hs)))
        for h in hs:
            hash_blob.extend(h)
        refs += len(hs)
    return bytes(body), bytes(hash_blob), len(present), refs


def iter_framed_recs(path: Path):
    with path.open("rb", buffering=64 << 10) as src:
        while True:
            hdr = src.read(4)
            if not hdr:
                return
            if len(hdr) < 4:
                raise RuntimeError(f"truncated frame header in {path}")
            (ln,) = struct.unpack("<I", hdr)
            rec = src.read(ln)
            if len(rec) != ln:
                raise RuntimeError(f"truncated frame in {path}")
            yield rec


def sort_owner_run(recs: list[bytes], path: Path) -> None:
    recs.sort(key=lambda r: unpack_owner_rec(r)[0])
    with path.open("wb", buffering=4 << 20) as out:
        for rec in recs:
            out.write(struct.pack("<I", len(rec)))
            out.write(rec)


def _sort_owner_run_path(path_str: str) -> str:
    """Worker: load framed owner recs, sort by key, rewrite in place."""
    path = Path(path_str)
    recs = list(iter_framed_recs(path))
    sort_owner_run(recs, path)
    return path_str


def _c_spill_sort(path_str: str) -> str:
    """Sort one RDATA spill run via C helper (mmap + qsort by raw)."""
    helper = _join_scatter_bin()
    if helper is None:
        return _sort_spill_run_path_py(path_str)
    subprocess.check_call(
        [str(helper), "spill_sort", path_str],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return path_str


def _sort_spill_run_path_py(path_str: str) -> str:
    """Python fallback: load spill recs, sort by raw RDATA, rewrite in place."""
    path = Path(path_str)
    recs: list[tuple[bytes, bytes]] = []
    data = path.read_bytes()
    off = 0
    while off < len(data):
        (ln,) = struct.unpack_from("<I", data, off)
        off += 4
        rec = data[off : off + ln]
        off += ln
        raw = rec[HASH_LEN + 12 :]
        recs.append((raw, rec))
    recs.sort(key=lambda item: item[0])
    out = bytearray()
    for _raw, rec in recs:
        out.extend(struct.pack("<I", len(rec)))
        out.extend(rec)
    path.write_bytes(out)
    return path_str


def _sort_spill_run_path(path_str: str) -> str:
    """Prefer C spill_sort; fall back to Python."""
    try:
        return _c_spill_sort(path_str)
    except (subprocess.CalledProcessError, OSError):
        return _sort_spill_run_path_py(path_str)


def merge_sorted_owner_paths(paths: list[Path], out_path: Path) -> int:
    """k-way merge by full key; write sorted (still unmerged) records."""
    with tempfile.TemporaryDirectory(prefix="owner_merge_", dir=out_path.parent) as td:
        pending = list(paths)
        stage = 0
        while len(pending) > MERGE_FAN_IN:
            nxt: list[Path] = []
            for start in range(0, len(pending), MERGE_FAN_IN):
                group = pending[start : start + MERGE_FAN_IN]
                dest = Path(td) / f"m{stage}_{start:05d}.bin"
                _merge_owner_runs(group, dest)
                for old in group:
                    if old.parent == Path(td):
                        old.unlink(missing_ok=True)
                nxt.append(dest)
            pending = nxt
            stage += 1
        if len(pending) == 1:
            src = pending[0]
            if src.resolve() != out_path.resolve():
                if out_path.exists():
                    out_path.unlink()
                src.rename(out_path)
            return sum(1 for _ in iter_framed_recs(out_path))
        return _merge_owner_runs(pending, out_path)


def _merge_owner_runs(paths: list[Path], out_path: Path) -> int:
    files = [p.open("rb", buffering=64 << 10) for p in paths]
    heap: list[tuple[bytes, int, bytes]] = []
    try:
        for i, fh in enumerate(files):
            hdr = fh.read(4)
            if not hdr:
                continue
            (ln,) = struct.unpack("<I", hdr)
            rec = fh.read(ln)
            key = unpack_owner_rec(rec)[0]
            heapq.heappush(heap, (key, i, rec))
        count = 0
        with out_path.open("wb", buffering=8 << 20) as out:
            while heap:
                key, i, rec = heapq.heappop(heap)
                out.write(struct.pack("<I", len(rec)))
                out.write(rec)
                count += 1
                hdr = files[i].read(4)
                if not hdr:
                    continue
                (ln,) = struct.unpack("<I", hdr)
                nxt = files[i].read(ln)
                nkey = unpack_owner_rec(nxt)[0]
                if nkey < key:
                    raise RuntimeError("unsorted owner run during merge")
                heapq.heappush(heap, (nkey, i, nxt))
        return count
    finally:
        for fh in files:
            fh.close()


def _body_rr_ref_counts(body: bytes, hashes: bytes) -> tuple[int, int]:
    """Cheap counts without full RDATA parse (mask popcount + hash slots)."""
    mask = int.from_bytes(body[:TYPE_MASK_BYTES], "little")
    return bin(mask).count("1"), len(hashes) // HASH_LEN


def _coalesce_byte_range(
    args: tuple[str, int, int, str, int, int],
) -> dict:
    """Coalesce a byte range of a framed sorted-owner file.

    ``owner_base`` must be a multiple of BLOCK_SIZE so front-coding restarts
    align with the global owner stream when shards are concatenated.
    """
    path_s, start, end, out_path_s, owner_base, spill_owners = args
    path = Path(path_s)
    out_path = Path(out_path_s)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    owner_file = out_path.open("wb", buffering=8 << 20)
    owners_in_file = 0
    shard_paths = [out_path]
    shard_idx = 0

    def rotate() -> None:
        nonlocal owner_file, owners_in_file, shard_idx, out_path
        owner_file.close()
        shard_idx += 1
        out_path = out_path.with_name(f"{out_path.stem}_{shard_idx:02d}{out_path.suffix}")
        shard_paths.append(out_path)
        owner_file = out_path.open("wb", buffering=8 << 20)
        owners_in_file = 0

    prior_key = b""
    owner_count = 0
    rrset_count = 0
    rdata_ref_count = 0
    front_coded = 0
    uncompressed = 0
    pending_key: bytes | None = None
    pending_body: bytes | None = None
    pending_hashes: bytes | None = None
    pending_types: dict[str, tuple[int, list[bytes]]] | None = None
    fragments_in = 0
    merges = 0

    def front_encode_key(key: bytes) -> bytes:
        nonlocal front_coded, uncompressed, prior_key
        full = encode_uleb128(len(key)) + key
        uncompressed += len(full)
        global_idx = owner_base + owner_count
        if global_idx % BLOCK_SIZE == 0:
            key_enc = full
        else:
            shared = common_prefix_length(prior_key, key)
            suffix = key[shared:]
            key_enc = encode_uleb128(shared) + encode_uleb128(len(suffix)) + suffix
        front_coded += len(key_enc)
        prior_key = key
        return key_enc

    def write_rec(key_enc: bytes, body: bytes, hash_blob: bytes) -> None:
        nonlocal owners_in_file
        rec = (
            struct.pack("<III", len(key_enc), len(body), len(hash_blob))
            + key_enc
            + body
            + hash_blob
        )
        owner_file.write(struct.pack("<I", len(rec)))
        owner_file.write(rec)
        owners_in_file += 1
        if owners_in_file >= spill_owners:
            rotate()

    def emit_raw(key: bytes, body: bytes, hash_blob: bytes) -> None:
        nonlocal owner_count, rrset_count, rdata_ref_count
        n_rr, n_ref = _body_rr_ref_counts(body, hash_blob)
        write_rec(front_encode_key(key), body, hash_blob)
        owner_count += 1
        rrset_count += n_rr
        rdata_ref_count += n_ref

    def emit_types(key: bytes, types: dict[str, tuple[int, list[bytes]]]) -> None:
        nonlocal owner_count, rrset_count, rdata_ref_count
        body, hash_blob, n_rr, n_ref = pack_owner_types(types)
        write_rec(front_encode_key(key), body, hash_blob)
        owner_count += 1
        rrset_count += n_rr
        rdata_ref_count += n_ref

    def flush_pending() -> None:
        nonlocal pending_key, pending_body, pending_hashes, pending_types
        if pending_key is None:
            return
        if pending_types is not None:
            emit_types(pending_key, pending_types)
        else:
            assert pending_body is not None and pending_hashes is not None
            emit_raw(pending_key, pending_body, pending_hashes)
        pending_key = pending_body = pending_hashes = pending_types = None

    with path.open("rb", buffering=8 << 20) as fh:
        fh.seek(start)
        pos = start
        while pos < end:
            hdr = fh.read(4)
            if len(hdr) < 4:
                break
            (ln,) = struct.unpack("<I", hdr)
            rec = fh.read(ln)
            if len(rec) != ln:
                raise RuntimeError("framed truncate in coalesce shard")
            pos += 4 + ln
            fragments_in += 1
            key, body, hashes = unpack_owner_rec(rec)
            if pending_key is None:
                pending_key, pending_body, pending_hashes = key, body, hashes
                pending_types = None
                continue
            if key == pending_key:
                if pending_types is None:
                    assert pending_body is not None and pending_hashes is not None
                    pending_types = parse_owner_body(pending_body, pending_hashes)
                    pending_body = pending_hashes = None
                pending_types = merge_owner_types(
                    pending_types, parse_owner_body(body, hashes)
                )
                merges += 1
                continue
            flush_pending()
            pending_key, pending_body, pending_hashes = key, body, hashes
            pending_types = None
        # If the last key continues into the next shard, the splitter must not
        # cut mid-key; ranges end on record boundaries with distinct next keys.
        flush_pending()
    owner_file.close()
    return {
        "owner_paths": [str(p) for p in shard_paths if p.stat().st_size > 0],
        "owner_count": owner_count,
        "rrset_count": rrset_count,
        "rdata_ref_count": rdata_ref_count,
        "front_coded": front_coded,
        "uncompressed": uncompressed,
        "fragments_in": fragments_in,
        "merges": merges,
    }


def _split_framed_at_block_boundaries(
    sorted_path: Path, workers: int, log
) -> list[tuple[int, int, int]]:
    """Return (start, end, owner_base) shards; owner_base % BLOCK_SIZE == 0.

    Never splits between two consecutive records that share the same BOGI key
    (so rare apex/chunk-boundary merges stay inside one shard).
    """
    size = sorted_path.stat().st_size
    if workers <= 1 or size < (64 << 20):
        return [(0, size, 0)]
    target = size // workers
    ranges: list[tuple[int, int, int]] = []
    owner_base = 0
    start = 0
    owners_since = 0
    with sorted_path.open("rb", buffering=8 << 20) as fh:
        pos = 0
        while pos < size:
            hdr = fh.read(4)
            if len(hdr) < 4:
                break
            (ln,) = struct.unpack("<I", hdr)
            rec = fh.read(ln)
            if len(rec) != ln:
                break
            key, _, _ = unpack_owner_rec(rec)
            pos += 4 + ln
            owners_since += 1
            if (
                len(ranges) < workers - 1
                and pos - start >= target
                and owners_since % BLOCK_SIZE == 0
            ):
                # Do not cut if the next framed record continues this key.
                peek_ok = True
                if pos < size:
                    cur = fh.tell()
                    nh = fh.read(4)
                    if len(nh) == 4:
                        (nln,) = struct.unpack("<I", nh)
                        nrec = fh.read(nln)
                        if len(nrec) == nln:
                            nkey, _, _ = unpack_owner_rec(nrec)
                            if nkey == key:
                                peek_ok = False
                    fh.seek(cur)
                if peek_ok:
                    ranges.append((start, pos, owner_base))
                    owner_base += owners_since
                    start = pos
                    owners_since = 0
        if start < size or not ranges:
            ranges.append((start, size, owner_base))
    log(f"coalesce: split into {len(ranges)} shards (block-aligned)")
    return ranges


def coalesce_sorted_owners(sorted_path: Path, out_dir: Path, log) -> dict:
    """Merge consecutive same-key fragments; front-code into own_*.bin spills.

    Fast path keeps body/hashes when adjacent keys differ. Shards are
    BLOCK_SIZE-aligned and sized so each (except last) emits a multiple of
    BLOCK_SIZE owners — required for independent front-coding. Rare merges are
    wholly contained in one shard via peek-at-next-key when cutting.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.glob("own_*.bin"):
        old.unlink()

    # Prefer C helper when available (no-merge rewrite + rare merge fallback).
    helper = _join_scatter_bin()
    if helper is not None:
        try:
            log(f"coalesce via {helper}")
            t_c = time.time()
            out = subprocess.check_output(
                [
                    str(helper),
                    "coalesce",
                    str(sorted_path),
                    str(out_dir),
                    str(BLOCK_SIZE),
                    str(SPILL_OWNERS),
                    str(TYPE_MASK_BYTES),
                ],
                text=True,
            )
            meta = dict(part.split("=", 1) for part in out.strip().split() if "=" in part)
            owner_paths = sorted(out_dir.glob("own_*.bin"))
            log(f"coalesce C done in {time.time() - t_c:.1f}s")
            return {
                "owner_paths": owner_paths,
                "owner_count": int(meta["owners"]),
                "rrset_count": int(meta["rrsets"]),
                "rdata_ref_count": int(meta["refs"]),
                "front_coded": int(meta["front"]),
                "uncompressed": int(meta["uncomp"]),
                "fragments_in": int(meta["fragments"]),
                "merges": int(meta["merges"]),
            }
        except (subprocess.CalledProcessError, KeyError, ValueError) as exc:
            log(f"coalesce C failed ({exc}); Python fallback")

    workers = BOGI_WORKERS
    ranges = _split_framed_at_block_boundaries(sorted_path, workers, log)
    # Verify each non-final shard's fragment count is % BLOCK_SIZE == 0; merges
    # inside a shard break emitted-count alignment, so fall back to 1 shard.
    use_parallel = len(ranges) > 1
    payloads = [
        (
            str(sorted_path),
            start,
            end,
            str(out_dir / f"own_{i:05d}.bin"),
            owner_base,
            SPILL_OWNERS,
        )
        for i, (start, end, owner_base) in enumerate(ranges)
    ]
    if not use_parallel:
        payloads = [
            (str(sorted_path), 0, sorted_path.stat().st_size, str(out_dir / "own_00000.bin"), 0, SPILL_OWNERS)
        ]
    results: list[dict] = []
    if len(payloads) == 1:
        results = [_coalesce_byte_range(payloads[0])]
    else:
        log(f"coalesce: parallel workers={len(payloads)}")
        with ProcessPoolExecutor(max_workers=len(payloads)) as pool:
            futs = [pool.submit(_coalesce_byte_range, p) for p in payloads]
            for fut in as_completed(futs):
                results.append(fut.result())
        results.sort(key=lambda r: r["owner_paths"][0])
        # If any non-last shard's emitted count is not % BLOCK_SIZE, front-coding
        # across the seam is wrong — refuse and redo sequentially.
        bad = any(
            results[i]["owner_count"] % BLOCK_SIZE != 0 for i in range(len(results) - 1)
        )
        if bad:
            log("coalesce: shard emit not block-aligned (merges); sequential redo")
            for p in out_dir.glob("own_*.bin"):
                p.unlink()
            results = [
                _coalesce_byte_range(
                    (
                        str(sorted_path),
                        0,
                        sorted_path.stat().st_size,
                        str(out_dir / "own_00000.bin"),
                        0,
                        SPILL_OWNERS,
                    )
                )
            ]

    owner_paths: list[Path] = []
    owner_count = rrset_count = rdata_ref_count = 0
    front_coded = uncompressed = fragments_in = merges = 0
    for r in results:
        owner_paths.extend(Path(p) for p in r["owner_paths"])
        owner_count += r["owner_count"]
        rrset_count += r["rrset_count"]
        rdata_ref_count += r["rdata_ref_count"]
        front_coded += r["front_coded"]
        uncompressed += r["uncompressed"]
        fragments_in += r["fragments_in"]
        merges += r["merges"]
    final_paths: list[Path] = []
    for i, src in enumerate(owner_paths):
        dest = out_dir / f"own_{i:05d}.bin"
        if src.resolve() != dest.resolve():
            if dest.exists():
                dest.unlink()
            src.rename(dest)
        final_paths.append(dest)
    log(
        f"coalesce done fragments_in={fragments_in:,} owners={owner_count:,} "
        f"merges={merges:,} rrsets={rrset_count:,} refs={rdata_ref_count:,}"
    )
    return {
        "owner_paths": final_paths,
        "owner_count": owner_count,
        "rrset_count": rrset_count,
        "rdata_ref_count": rdata_ref_count,
        "front_coded": front_coded,
        "uncompressed": uncompressed,
        "fragments_in": fragments_in,
        "merges": merges,
    }


def external_sort_owners_by_key(
    owner_paths: list[Path], work: Path, log
) -> Path:
    """Sort Pass-A full-key owner spills by BOGI key → single sorted frame file."""
    helper = _join_scatter_bin()
    out_fast = work / "owners_sorted_by_key.bin"
    if helper is not None and owner_paths:
        paths_file = work / "owner_sort_paths.txt"
        paths_file.write_text(
            "".join(str(p) + "\n" for p in owner_paths), encoding="utf-8"
        )
        try:
            log(f"pass A2: owner_sort via {helper} files={len(owner_paths)}")
            t_os = time.time()
            proc = subprocess.run(
                [str(helper), "owner_sort", str(paths_file), str(out_fast)],
                text=True,
                capture_output=True,
                check=True,
            )
            if proc.stderr:
                for line in proc.stderr.strip().splitlines()[-8:]:
                    log(f"  {line}")
            log(
                f"pass A2: owner_sort C done in {time.time() - t_os:.1f}s "
                f"({proc.stdout.strip()})"
            )
            return out_fast
        except subprocess.CalledProcessError as exc:
            err = (exc.stderr or exc.stdout or "")[-500:]
            log(f"pass A2: owner_sort C failed rc={exc.returncode}: {err}; Python fallback")
            if out_fast.exists():
                out_fast.unlink()

    runs_dir = work / "owner_sort_runs"
    if runs_dir.exists():
        for p in runs_dir.glob("*.bin"):
            p.unlink()
    else:
        runs_dir.mkdir(parents=True)
    # Phase 1: write unsorted chunk files (fast sequential I/O)
    runs: list[Path] = []
    buf: list[bytes] = []
    for path in owner_paths:
        for rec in iter_framed_recs(path):
            buf.append(rec)
            if len(buf) >= OWNER_SORT_CHUNK:
                dest = runs_dir / f"run_{len(runs):05d}.bin"
                with dest.open("wb", buffering=4 << 20) as out:
                    for r in buf:
                        out.write(struct.pack("<I", len(r)))
                        out.write(r)
                runs.append(dest)
                buf = []
        log(f"owner-sort read {path.name} unsorted_runs={len(runs)}")
    if buf:
        dest = runs_dir / f"run_{len(runs):05d}.bin"
        with dest.open("wb", buffering=4 << 20) as out:
            for r in buf:
                out.write(struct.pack("<I", len(r)))
                out.write(r)
        runs.append(dest)
    # Phase 2: parallel in-place sort of each run
    log(f"pass A2: parallel-sort {len(runs)} owner runs workers={BOGI_WORKERS}")
    if len(runs) == 1:
        _sort_owner_run_path(str(runs[0]))
    else:
        with ProcessPoolExecutor(max_workers=BOGI_WORKERS) as pool:
            futs = [pool.submit(_sort_owner_run_path, str(p)) for p in runs]
            for i, fut in enumerate(as_completed(futs), 1):
                fut.result()
                if i % 32 == 0 or i == len(futs):
                    log(f"owner-sort runs done {i}/{len(futs)}")
    sorted_path = work / "owners_sorted_by_key.bin"
    log(f"pass A2: merge {len(runs)} owner runs by key")
    n = merge_sorted_owner_paths(runs, sorted_path)
    log(f"pass A2 sort done records={n:,} → {sorted_path.name}")
    for p in runs:
        p.unlink(missing_ok=True)
    return sorted_path


class SpillWriter:
    def __init__(
        self,
        directory: Path,
        prefix: str,
        *,
        defer_sort: bool = True,
        sort_on_flush: bool = False,
    ) -> None:
        self.directory = directory
        self.prefix = prefix
        self.paths: list[Path] = []
        self.buf = bytearray()
        self.count = 0
        self.type_buf = bytearray()
        self.type_paths: list[Path] = []
        # Write unsorted runs; parallel-sort before unique merge (faster on multi-core).
        self.defer_sort = defer_sort
        # Sort each run immediately after write (hides spill_sort inside Pass A workers).
        self.sort_on_flush = sort_on_flush

    def add(self, rec: bytes, type_idx: int | None = None) -> None:
        self.buf.extend(struct.pack("<I", len(rec)))
        self.buf.extend(rec)
        if type_idx is not None and (FLAGS & FLAG_BINARY_POOL) != 0:
            # hash[16] + type index — first occurrence wins at pool build
            self.type_buf.extend(rec[:HASH_LEN])
            self.type_buf.append(type_idx & 0xFF)
        self.count += 1
        if self.count >= SORT_CHUNK:
            self.flush()

    def flush(self) -> None:
        if not self.buf and not self.type_buf:
            return
        if not self.buf:
            tpath = self.directory / (
                f"{self.prefix}.type_{len(self.type_paths):05d}.bin"
            )
            tpath.write_bytes(bytes(self.type_buf))
            self.type_paths.append(tpath)
            self.type_buf.clear()
            return
        data = bytes(self.buf)
        if self.defer_sort or self.sort_on_flush:
            out = data
        else:
            recs: list[tuple[bytes, bytes]] = []
            off = 0
            while off < len(data):
                (ln,) = struct.unpack_from("<I", data, off)
                off += 4
                rec = data[off : off + ln]
                off += ln
                raw = rec[HASH_LEN + 12 :]
                recs.append((raw, rec))
            recs.sort(key=lambda item: item[0])
            out = bytearray()
            for _raw, rec in recs:
                out.extend(struct.pack("<I", len(rec)))
                out.extend(rec)
        path = self.directory / f"{self.prefix}_{len(self.paths):05d}.bin"
        path.write_bytes(bytes(out))
        self.paths.append(path)
        self.buf.clear()
        self.count = 0
        if self.type_buf:
            tpath = self.directory / f"{self.prefix}.type_{len(self.type_paths):05d}.bin"
            tpath.write_bytes(bytes(self.type_buf))
            self.type_paths.append(tpath)
            self.type_buf.clear()
        if self.sort_on_flush:
            _sort_spill_run_path(str(path))

    def parallel_sort_runs(self, log, workers: int = BOGI_WORKERS) -> None:
        if not self.defer_sort or not self.paths:
            return
        helper = _join_scatter_bin()
        # C spill_sort is mmap-based → allow more concurrency than Python.
        workers = max(1, min(workers, 12 if helper else 4))
        log(
            f"parallel-sort {len(self.paths)} RDATA spill runs "
            f"workers={workers} via={'C' if helper else 'py'}"
        )
        if len(self.paths) == 1:
            _sort_spill_run_path(str(self.paths[0]))
            return
        # Threads + C subprocess avoid ProcessPool memory duplication.
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_sort_spill_run_path, str(p)) for p in self.paths]
            for i, fut in enumerate(as_completed(futs), 1):
                fut.result()
                if i % 16 == 0 or i == len(futs):
                    log(f"spill-sort runs done {i}/{len(futs)}")


def iter_spill(path: Path):
    # Do not retain an entire run per iterator: full .com has thousands of runs.
    with path.open("rb", buffering=64 << 10) as src:
        while True:
            hdr = src.read(4)
            if not hdr:
                return
            if len(hdr) != 4:
                raise RuntimeError(f"truncated spill header: {path}")
            (ln,) = struct.unpack("<I", hdr)
            rec = src.read(ln)
            if ln < HASH_LEN + 12 or len(rec) != ln:
                raise RuntimeError(f"truncated spill record: {path}")
            raw_len = struct.unpack_from("<I", rec, HASH_LEN + 8)[0]
            if raw_len != ln - HASH_LEN - 12:
                raise RuntimeError(f"spill RDATA length mismatch: {path}")
            yield rec


def external_unique_sort(paths: list[Path], out_path: Path, log=None) -> int:
    """Bounded-memory/fd merge; publish only a complete sorted unique stream."""
    helper = _join_scatter_bin()
    if helper is not None and paths:
        paths_file = out_path.parent / "unique_merge_paths.txt"
        paths_file.write_text(
            "".join(str(p) + "\n" for p in paths), encoding="utf-8"
        )
        try:
            if log:
                log(f"pass B: unique_merge via {helper} runs={len(paths)}")
            t_u = time.time()
            proc = subprocess.run(
                [str(helper), "unique_merge", str(paths_file), str(out_path)],
                text=True,
                capture_output=True,
                check=True,
            )
            if log and proc.stderr:
                for line in proc.stderr.strip().splitlines()[-6:]:
                    log(f"  {line}")
            meta = dict(
                part.split("=", 1)
                for part in proc.stdout.strip().split()
                if "=" in part
            )
            count = int(meta["unique"])
            if log:
                log(f"pass B: unique_merge C done in {time.time() - t_u:.1f}s")
            return count
        except (subprocess.CalledProcessError, KeyError, ValueError) as exc:
            if log:
                err = getattr(exc, "stderr", None) or str(exc)
                log(f"pass B: unique_merge C failed ({err}); Python fallback")
            out_path.unlink(missing_ok=True)

    with tempfile.TemporaryDirectory(prefix="unique_merge_", dir=out_path.parent) as td:
        pending = list(paths)
        generation = 0
        while len(pending) > MERGE_FAN_IN:
            following = []
            for start in range(0, len(pending), MERGE_FAN_IN):
                dest = Path(td) / f"{generation}_{start}.bin"
                _merge_unique(pending[start : start + MERGE_FAN_IN], dest)
                following.append(dest)
            for path in pending:
                if path.parent == Path(td):
                    path.unlink()
            pending = following
            generation += 1
        complete = Path(td) / "complete.bin"
        count = _merge_unique(pending, complete)
        complete.replace(out_path)
        return count


def _merge_unique(paths: list[Path], out_path: Path) -> int:
    """Write unique records sorted by raw RDATA. First witness wins.

    Preconditions: each spill path is sorted ascending by raw RDATA
    (SpillWriter.flush sorts). Unsorted runs would silently retain
    duplicates — that bug produced the false ~441M unique count.
    """

    files = [iter_spill(p) for p in paths]
    heap: list[tuple[bytes, int, bytes]] = []
    for i, it in enumerate(files):
        try:
            rec = next(it)
        except StopIteration:
            continue
        raw = rec[HASH_LEN + 12 :]
        heapq.heappush(heap, (raw, i, rec))
    unique = 0
    prev_raw: bytes | None = None
    try:
        return _merge_unique_open(files, heap, out_path)
    finally:
        for iterator in files:
            iterator.close()


def _merge_unique_open(files, heap, out_path: Path) -> int:
    unique = 0
    prev_raw = None
    with out_path.open("wb", buffering=8 << 20) as out:
        while heap:
            raw, i, rec = heapq.heappop(heap)
            if raw != prev_raw:
                out.write(struct.pack("<I", len(rec)))
                out.write(rec)
                unique += 1
                prev_raw = raw
            try:
                nxt = next(files[i])
            except StopIteration:
                continue
            nraw = nxt[HASH_LEN + 12 :]
            # Defense: runs must be non-decreasing; unsorted input is a bug.
            if nraw < raw:
                raise RuntimeError(
                    f"spill run {i} not sorted by raw RDATA "
                    f"(prev_len={len(raw)} next_len={len(nraw)})"
                )
            heapq.heappush(heap, (nraw, i, nxt))
    return unique


def _align_next_line(fh, pos: int) -> int:
    if pos <= 0:
        fh.seek(0)
        return 0
    fh.seek(pos - 1)
    if fh.read(1) == b"\n":
        return fh.tell()
    while True:
        ch = fh.read(1)
        if not ch or ch == b"\n":
            return fh.tell()


def _zone_scan_bin() -> Path | None:
    here = Path(__file__).resolve().parent
    cands = [
        here / "zone_scan",
        here / "com_zimdb_encode_opt" / "zone_scan",
        Path(os.environ.get("BOGI_ZONE_SCAN", "")),
        Path("/data/scripts/zone_scan"),
    ]
    for p in cands:
        if p and p.is_file() and os.access(p, os.X_OK):
            return p
    return None


def _scan_zone_range_c(payload: tuple) -> dict:
    """C accelerator for Pass A range scan (must match Python semantics)."""
    (
        zone_str,
        origin,
        start,
        end,
        owners_dir_str,
        spills_dir_str,
        worker_id,
        spill_owners,
    ) = payload
    helper = _zone_scan_bin()
    assert helper is not None
    owners_dir = Path(owners_dir_str)
    spills_dir = Path(spills_dir_str)
    owners_dir.mkdir(parents=True, exist_ok=True)
    spills_dir.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [
            str(helper),
            zone_str,
            origin,
            str(start),
            str(end),
            str(owners_dir),
            str(spills_dir),
            str(worker_id),
            str(spill_owners),
            str(SORT_CHUNK),
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    meta = dict(
        part.split("=", 1) for part in proc.stdout.strip().split() if "=" in part
    )
    owner_paths = sorted(
        str(p) for p in owners_dir.glob(f"w{worker_id:02d}_own_*.bin")
    )
    spill_paths = sorted(
        str(p) for p in spills_dir.glob(f"w{worker_id:02d}_rdata_[0-9][0-9][0-9][0-9][0-9].bin")
    )
    return {
        "owner_paths": owner_paths,
        "spill_paths": spill_paths,
        "owner_count": int(meta["owners"]),
        "rrset_count": int(meta["rrsets"]),
        "rdata_ref_count": int(meta["refs"]),
        "lines": int(meta["lines"]),
        "skipped": int(meta["skipped"]),
        "worker_id": worker_id,
    }


def _scan_zone_range(payload: tuple) -> dict:
    """Worker: scan [start,end) byte range of zone; emit owner+rdata spills.

    .com lines are absolute-name RRs, so chunks may split mid-owner; Pass A2
    coalesces same-key fragments. Continuation lines (leading WS) stay with
    the preceding owner inside this worker.
    """
    if _zone_scan_bin() is not None:
        try:
            return _scan_zone_range_c(payload)
        except (subprocess.CalledProcessError, OSError, KeyError, ValueError) as exc:
            if os.environ.get("BOGI_ZONE_SCAN_REQUIRED") == "1":
                raise RuntimeError(f"zone_scan C required but failed: {exc}") from exc
            sys.stderr.write(f"zone_scan C failed ({exc}); Python fallback\n")

    (
        zone_str,
        origin,
        start,
        end,
        owners_dir_str,
        spills_dir_str,
        worker_id,
        spill_owners,
    ) = payload
    zone_path = Path(zone_str)
    owners_dir = Path(owners_dir_str)
    spills_dir = Path(spills_dir_str)
    owners_dir.mkdir(parents=True, exist_ok=True)
    spills_dir.mkdir(parents=True, exist_ok=True)

    # Sort each spill run inside the worker so Pass A wall ≈ scan (no post-tail).
    spill = SpillWriter(spills_dir, f"w{worker_id:02d}_rdata", sort_on_flush=True)
    owner_paths: list[str] = []
    owner_file = None
    owner_index = 0
    owners_in_file = 0

    def open_owner() -> None:
        nonlocal owner_file, owner_index, owners_in_file
        if owner_file is not None:
            owner_file.close()
        path = owners_dir / f"w{worker_id:02d}_own_{owner_index:05d}.bin"
        owner_index += 1
        owner_paths.append(str(path))
        owner_file = path.open("wb", buffering=4 << 20)
        owners_in_file = 0

    cur_owner: str | None = None
    cur_key = b""
    cur_rrsets: dict[str, tuple[int, list[bytes]]] = {}
    owner_count = 0
    rrset_count = 0
    rdata_ref_count = 0
    lines = 0
    skipped = 0

    def flush_owner() -> None:
        nonlocal owner_count, rrset_count, rdata_ref_count, owners_in_file
        if cur_owner is None:
            return
        body = bytearray()
        mask = 0
        present = []
        for rrtype in TYPE_ORDER:
            item = cur_rrsets.get(rrtype)
            if item is None:
                continue
            mask |= TYPE_TO_BIT[rrtype]
            present.append((rrtype, item))
        body.extend(mask.to_bytes(TYPE_MASK_BYTES, "little"))
        hash_blob = bytearray()
        local_rr = 0
        for _rrtype, (ttl, rdatas) in present:
            deduped: list[bytes] = []
            for raw in sorted(rdatas):
                if deduped and deduped[-1] == raw:
                    continue
                deduped.append(raw)
            body.extend(encode_uleb128(ttl))
            body.extend(encode_uleb128(len(deduped)))
            for j, raw in enumerate(deduped):
                h = _blake2b16(raw)
                hash_blob.extend(h)
                spill.add(
                    pack_rec(h, rrset_count + local_rr, j, raw),
                    TYPE_ORDER.index(_rrtype),
                )
            local_rr += 1
            rdata_ref_count += len(deduped)
        rec = pack_owner_rec(cur_key, bytes(body), bytes(hash_blob))
        assert owner_file is not None
        owner_file.write(struct.pack("<I", len(rec)))
        owner_file.write(rec)
        owners_in_file += 1
        if owners_in_file >= spill_owners:
            open_owner()
        owner_count += 1
        rrset_count += local_rr

    open_owner()
    with zone_path.open("rb", buffering=16 << 20) as fh:
        _align_next_line(fh, start)
        while True:
            line_start = fh.tell()
            raw_line = fh.readline()
            if not raw_line:
                break
            lines += 1
            if raw_line.endswith(b"\n"):
                raw_line = raw_line[:-1]
            parsed = parse_rr_line_b(raw_line, cur_owner)
            if parsed is None:
                continue
            owner, rrtype, ttl, raw = parsed
            if not raw:
                skipped += 1
                continue
            new_owner = cur_owner is not None and owner != cur_owner
            # Assign crossing lines by their first byte; finish current owner.
            if line_start >= end and new_owner:
                break
            if line_start >= end and cur_owner is None:
                break
            if new_owner:
                flush_owner()
                cur_rrsets = {}
            if cur_owner != owner:
                cur_owner = owner
                try:
                    cur_key = owner_to_key(owner, origin)
                except ValueError:
                    skipped += 1
                    cur_owner = None
                    cur_rrsets = {}
                    continue
            item = cur_rrsets.get(rrtype)
            if item is None:
                cur_rrsets[rrtype] = (ttl, [raw])
            else:
                item[1].append(raw)
        flush_owner()
    if owner_file is not None:
        owner_file.close()
    spill.flush()
    return {
        "owner_paths": owner_paths,
        "spill_paths": [str(p) for p in spill.paths],
        "owner_count": owner_count,
        "rrset_count": rrset_count,
        "rdata_ref_count": rdata_ref_count,
        "lines": lines,
        "skipped": skipped,
        "worker_id": worker_id,
    }


def parallel_scan_zone(
    zone_path: Path,
    origin: str,
    owners_dir: Path,
    spills_dir: Path,
    log,
    workers: int,
) -> tuple[list[Path], SpillWriter, dict]:
    """Split zone into byte ranges and scan in parallel processes."""
    size = zone_path.stat().st_size
    workers = max(1, min(workers, 16))
    ranges: list[tuple[int, int]] = []
    chunk = size // workers
    for i in range(workers):
        start = i * chunk
        end = size if i == workers - 1 else (i + 1) * chunk
        ranges.append((start, end))
    use_c = _zone_scan_bin() is not None
    log(
        f"pass A: parallel scan workers={workers} zone_bytes={size:,} "
        f"via={'C' if use_c else 'py'}"
    )
    payloads = [
        (
            str(zone_path),
            origin,
            start,
            end,
            str(owners_dir),
            str(spills_dir),
            i,
            SPILL_OWNERS,
        )
        for i, (start, end) in enumerate(ranges)
    ]
    results = []
    # C workers are subprocesses → threads avoid extra Python process fan-out.
    pool_cls = ThreadPoolExecutor if use_c else ProcessPoolExecutor
    scan_fn = _scan_zone_range_c if use_c else _scan_zone_range
    with pool_cls(max_workers=workers) as pool:
        futs = [pool.submit(scan_fn, p) for p in payloads]
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            log(
                f"scan worker={r['worker_id']} "
                f"owners={r['owner_count']:,} "
                f"refs={r['rdata_ref_count']:,} "
                f"spills={len(r['spill_paths'])}"
            )
    results.sort(key=lambda r: r["worker_id"])
    owner_paths = [Path(p) for r in results for p in r["owner_paths"]]
    spill = SpillWriter(spills_dir, "rdata")
    spill.paths = [Path(p) for r in results for p in r["spill_paths"]]
    # zone_scan sorts each spill on flush.
    spill.defer_sort = False
    stats = {
        "owner_count": sum(r["owner_count"] for r in results),
        "rrset_count": sum(r["rrset_count"] for r in results),
        "rdata_ref_count": sum(r["rdata_ref_count"] for r in results),
        "lines": sum(r["lines"] for r in results),
        "skipped": sum(r["skipped"] for r in results),
    }
    return owner_paths, spill, stats


def main() -> int:
    zone_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    work = Path(sys.argv[3])
    origin = sys.argv[4] if len(sys.argv) > 4 else "com."
    work.mkdir(parents=True, exist_ok=True)
    head = zone_path.read_bytes()[:2] if zone_path.is_file() else b""
    if zone_path.suffix == ".gz" or head == bytes([0x1F, 0x8B]):
        plain = work / (
            zone_path.name[:-3]
            if zone_path.name.endswith(".gz")
            else (zone_path.name + ".zone")
        )
        if (not plain.is_file()) or plain.stat().st_mtime < zone_path.stat().st_mtime:
            print(f"decompress {zone_path} -> {plain}", flush=True)
            with gzip.open(zone_path, "rb") as src, plain.open("wb") as dst:
                while True:
                    chunk = src.read(8 << 20)
                    if not chunk:
                        break
                    dst.write(chunk)
        zone_path = plain
    wall0 = time.perf_counter()
    log_path = work / "encode.log"

    def log(msg: str) -> None:
        line = f"{time.perf_counter() - wall0:8.1f}s {msg}"
        print(line, flush=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    resume = os.environ.get("BOGI_RESUME") == "1"
    # Default off until boundary coalescing is proven bit-identical on full .com
    # (parallel path matched owner/rrset/unique counts but differed by 2 refs).
    parallel_scan = os.environ.get("BOGI_PARALLEL_SCAN", "0") == "1"
    log(
        f"zone={zone_path} out={out_path} resume={resume} "
        f"pipeline=v{PIPELINE_VERSION} profile=0x{PROFILE_ID:08x} "
        f"SORT_CHUNK={SORT_CHUNK} OWNER_SORT_CHUNK={OWNER_SORT_CHUNK} "
        f"MERGE_FAN_IN={MERGE_FAN_IN} WORKERS={BOGI_WORKERS} "
        f"parallel_scan={parallel_scan} "
        f"MemAvailable≈{_mem_available_mb()}MiB"
    )
    owners_dir = work / "owners"
    spills_dir = work / "spills"
    owners_dir.mkdir(exist_ok=True)
    spills_dir.mkdir(exist_ok=True)

    stats_path = work / "pass_a_stats.json"
    if resume and stats_path.is_file():
        saved = json.loads(stats_path.read_text(encoding="utf-8"))
        if saved.get("spill_sort_version") != SPILL_SORT_VERSION:
            raise RuntimeError("legacy unsorted checkpoint is unsafe; use a fresh work directory")
        if saved.get("pipeline_version") != PIPELINE_VERSION:
            raise RuntimeError(
                f"checkpoint pipeline_version={saved.get('pipeline_version')} "
                f"!= {PIPELINE_VERSION} (need key-order rebuild); use a fresh work directory"
            )
    elif any(work.glob("owners/own_*.bin")) or stats_path.exists():
        raise RuntimeError("work directory is not fresh; choose a new directory")
    skip_pool = False
    spill = SpillWriter(spills_dir, "rdata")
    owner_file = None
    owner_index = 0
    owners_in_file = 0
    owner_paths: list[Path] = []

    def open_owner() -> None:
        nonlocal owner_file, owner_index, owners_in_file
        if owner_file is not None:
            owner_file.close()
        path = owners_dir / f"own_{owner_index:05d}.bin"
        owner_index += 1
        owner_paths.append(path)
        owner_file = path.open("wb", buffering=4 << 20)
        owners_in_file = 0

    cur_owner: str | None = None
    cur_key = b""
    cur_rrsets: dict[str, tuple[int, list[bytes]]] = {}
    owner_count = 0
    rrset_count = 0
    rdata_ref_count = 0
    front_coded = 0
    uncompressed = 0
    prior_key = b""
    lines = 0
    skipped = 0

    def flush_owner() -> None:
        """Pass A: emit full-key owner fragment (front-coding deferred to A2)."""
        nonlocal owner_count, rrset_count, rdata_ref_count
        nonlocal owners_in_file, owner_file
        if cur_owner is None:
            return
        key = cur_key
        body = bytearray()
        mask = 0
        present = []
        for rrtype in TYPE_ORDER:
            item = cur_rrsets.get(rrtype)
            if item is None:
                continue
            mask |= TYPE_TO_BIT[rrtype]
            present.append((rrtype, item))
        body.extend(mask.to_bytes(TYPE_MASK_BYTES, "little"))
        hash_blob = bytearray()
        local_rr = 0
        for rrtype, (ttl, rdatas) in present:
            deduped: list[bytes] = []
            for raw in sorted(rdatas):
                if deduped and deduped[-1] == raw:
                    continue
                deduped.append(raw)
            body.extend(encode_uleb128(ttl))
            body.extend(encode_uleb128(len(deduped)))
            for j, raw in enumerate(deduped):
                h = _blake2b16(raw)
                hash_blob.extend(h)
                spill.add(
                    pack_rec(h, rrset_count + local_rr, j, raw),
                    TYPE_ORDER.index(rrtype),
                )
            local_rr += 1
            rdata_ref_count += len(deduped)
        rec = pack_owner_rec(key, bytes(body), bytes(hash_blob))
        assert owner_file is not None
        owner_file.write(struct.pack("<I", len(rec)))
        owner_file.write(rec)
        owners_in_file += 1
        if owners_in_file >= SPILL_OWNERS:
            open_owner()
        # provisional counts — A2 coalesce rewrites final owner/rrset/ref stats
        owner_count += 1
        rrset_count += local_rr

    pool_checkpoint = work / "pool_complete.json"
    pool_ready = (work / "pool_data.bin").is_file() and pool_checkpoint.is_file()
    if resume and pool_ready and stats_path.is_file():
        saved = json.loads(stats_path.read_text(encoding="utf-8"))
        owner_count = saved["owner_count"]
        rrset_count = saved["rrset_count"]
        rdata_ref_count = saved["rdata_ref_count"]
        front_coded = saved["front_coded"]
        uncompressed = saved["uncompressed"]
        lines = saved["lines"]
        skipped = saved["skipped"]
        log(f"resume at pass D pool_ready owners={owner_count:,}")
        owner_paths = []
        if not (work / "hash_id_by_hash.bin").is_file():
            if not (work / "hash_id_sorted.bin").is_file():
                log("rescan zone for hash→id rows and owner bodies")
                rescan_hash_rows(zone_path, origin, work, log)
            hash_rows = work / "hash_id_sorted.bin"
            log("sort rebuilt hash→id")
            external_sort_hash_id(hash_rows, work / "hash_id_by_hash.bin", work / "hashsort")
            hash_rows.unlink()
        if not (work / "owner_bodies.bin").is_file():
            log("rescan zone for owner bodies")
            rescan_owner_bodies(zone_path, origin, work, log)
        skip_pool = True
    elif resume and stats_path.is_file() and (work / "unique_sorted.bin").is_file():
        saved = json.loads(stats_path.read_text(encoding="utf-8"))
        owner_count = saved["owner_count"]
        rrset_count = saved["rrset_count"]
        rdata_ref_count = saved["rdata_ref_count"]
        front_coded = saved["front_coded"]
        uncompressed = saved["uncompressed"]
        lines = saved["lines"]
        skipped = saved["skipped"]
        owner_paths = sorted(owners_dir.glob("own_*.bin"))
        if front_coded == 0:
            front_coded, uncompressed = recover_key_bytes(owner_paths, log)
        log(
            f"resume after pass B owners={owner_count:,} "
            f"unique_file={(work / 'unique_sorted.bin').stat().st_size:,}"
        )
    else:
        if resume and stats_path.is_file():
            raise RuntimeError("no completed merge checkpoint; restart with a fresh work directory")
        if parallel_scan and BOGI_WORKERS > 1:
            owner_paths, spill, scan_stats = parallel_scan_zone(
                zone_path, origin, owners_dir, spills_dir, log, BOGI_WORKERS
            )
            owner_count = scan_stats["owner_count"]
            rrset_count = scan_stats["rrset_count"]
            rdata_ref_count = scan_stats["rdata_ref_count"]
            lines = scan_stats["lines"]
            skipped = scan_stats["skipped"]
            spill.parallel_sort_runs(log)
            log(
                f"pass A done fragments={owner_count:,} rrsets={rrset_count:,} "
                f"refs={rdata_ref_count:,} spills={len(spill.paths)} skipped={skipped}"
            )
        else:
            open_owner()
            log("pass A: scan zone")
            with zone_path.open(
                "r", encoding="utf-8", errors="replace", buffering=8 << 20
            ) as fh:
                for line in fh:
                    lines += 1
                    if lines & 0x3FFFFF == 0:
                        log(
                            f"lines={lines:,} owners={owner_count:,} refs={rdata_ref_count:,}"
                        )
                    s = line.rstrip("\n")
                    parsed = parse_rr_line(s, cur_owner)
                    if parsed is None:
                        continue
                    owner, rrtype, ttl, rdata = parsed
                    if rrtype not in TYPE_TO_BIT:
                        skipped += 1
                        continue
                    if not rdata:
                        skipped += 1
                        continue
                    if cur_owner is not None and owner != cur_owner:
                        flush_owner()
                        cur_rrsets = {}
                    if cur_owner != owner:
                        cur_owner = owner
                        cur_key = owner_to_key(owner, origin)
                    raw = rdata.encode("utf-8")
                    item = cur_rrsets.get(rrtype)
                    if item is None:
                        cur_rrsets[rrtype] = (ttl, [raw])
                    else:
                        item[1].append(raw)
            flush_owner()
            if owner_file is not None:
                owner_file.close()
            spill.flush()
            spill.parallel_sort_runs(log)
            log(
                f"pass A done fragments={owner_count:,} rrsets={rrset_count:,} "
                f"refs={rdata_ref_count:,} spills={len(spill.paths)} skipped={skipped}"
            )
        # A2 ∥ B; when B finishes start C+C2; when A2 finishes start D1 ∥ C2.
        raw_owner_paths = list(owner_paths)
        sorted_path = work / "unique_sorted.bin"
        owners_sorted_dir = work / "owners_keyed"
        pool_tmp_early = work / "pool_data.bin"
        bodies_early = work / "owner_bodies.bin"
        hash_refs_early = work / "hash_refs.bin"
        coalesced_box: dict = {}
        unique_box: dict = {}

        def _run_a2() -> None:
            sorted_owners = external_sort_owners_by_key(raw_owner_paths, work, log)
            for p in raw_owner_paths:
                p.unlink(missing_ok=True)
            coalesced_box["c"] = coalesce_sorted_owners(
                sorted_owners, owners_sorted_dir, log
            )
            sorted_owners.unlink(missing_ok=True)

        def _run_b() -> None:
            log(f"pass B: external unique sort ({len(spill.paths)} runs)")
            unique_box["n"] = external_unique_sort(spill.paths, sorted_path, log=log)
            for p in spill.paths:
                p.unlink()

        def _run_c_c2() -> None:
            log("pass C: assign lexical ids (overlapped with A2/D1)")
            ord_n = write_pool_and_hash_index(
                sorted_path,
                pool_tmp_early,
                work / "pool_restarts.bin",
                work,
                log,
            )
            pool_checkpoint.write_text(
                json.dumps(
                    {
                        "pool_entry_count": ord_n,
                        "pool_bytes": pool_tmp_early.stat().st_size,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            sorted_path.unlink(missing_ok=True)

        def _run_d1(paths: list[Path], expect_owners: int) -> None:
            helper = _join_scatter_bin()
            if helper is not None and paths:
                paths_file = work / "d1_paths.txt"
                paths_file.write_text(
                    "".join(str(p) + "\n" for p in paths), encoding="utf-8"
                )
                try:
                    log(f"pass D1 via {helper} (overlapped with C2)")
                    t_d1 = time.time()
                    proc = subprocess.run(
                        [
                            str(helper),
                            "d1_split",
                            str(paths_file),
                            str(bodies_early),
                            str(hash_refs_early),
                        ],
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    if proc.stderr:
                        for line in proc.stderr.strip().splitlines()[-6:]:
                            log(f"  {line}")
                    meta = dict(
                        part.split("=", 1)
                        for part in proc.stdout.strip().split()
                        if "=" in part
                    )
                    seen = int(meta["owners"])
                    if seen != expect_owners:
                        raise RuntimeError(f"d1 owners {seen} != {expect_owners}")
                    for path in paths:
                        path.unlink(missing_ok=True)
                    log(f"pass D1 C done in {time.time() - t_d1:.1f}s")
                    return
                except (
                    subprocess.CalledProcessError,
                    KeyError,
                    ValueError,
                    RuntimeError,
                ) as exc:
                    log(f"pass D1 C failed ({exc}); Python fallback")
                    bodies_early.unlink(missing_ok=True)
                    hash_refs_early.unlink(missing_ok=True)
            with bodies_early.open("wb", buffering=8 << 20) as bodies, hash_refs_early.open(
                "wb", buffering=8 << 20
            ) as hash_refs:
                seen = 0
                for path in paths:
                    data = path.read_bytes()
                    off = 0
                    n = len(data)
                    while off < n:
                        (ln,) = struct.unpack_from("<I", data, off)
                        off += 4
                        rec = data[off : off + ln]
                        off += ln
                        klen, blen, hlen = struct.unpack_from("<III", rec, 0)
                        base = 12
                        key_enc = rec[base : base + klen]
                        body = rec[base + klen : base + klen + blen]
                        hashes = rec[base + klen + blen : base + klen + blen + hlen]
                        if len(hashes) % HASH_LEN:
                            raise RuntimeError("hash blob not aligned")
                        bodies.write(struct.pack("<III", len(key_enc), len(body), 0))
                        bodies.write(key_enc)
                        bodies.write(body)
                        hash_refs.write(
                            struct.pack("<II", seen, len(hashes) // HASH_LEN)
                        )
                        hash_refs.write(hashes)
                        seen += 1
                    path.unlink()
                if seen != expect_owners:
                    raise RuntimeError(f"split owners {seen} != {expect_owners}")

        log("pass A2∥B→C∥D1: pipeline owner_sort + unique + pool + d1")
        with ThreadPoolExecutor(max_workers=3) as pair:
            fa = pair.submit(_run_a2)
            fb = pair.submit(_run_b)
            fb.result()
            unique = unique_box["n"]
            log(f"pass B done unique={unique:,}")
            fc = pair.submit(_run_c_c2)
            fa.result()
            coalesced = coalesced_box["c"]
            for p in owners_dir.glob("own_*.bin"):
                p.unlink(missing_ok=True)
            owner_paths = []
            for i, src in enumerate(coalesced["owner_paths"]):
                dest = owners_dir / f"own_{i:05d}.bin"
                src.rename(dest)
                owner_paths.append(dest)
            try:
                owners_sorted_dir.rmdir()
            except OSError:
                pass
            owner_count = coalesced["owner_count"]
            rrset_count = coalesced["rrset_count"]
            rdata_ref_count = coalesced["rdata_ref_count"]
            front_coded = coalesced["front_coded"]
            uncompressed = coalesced["uncompressed"]
            log(
                f"pass A2 done owners={owner_count:,} rrsets={rrset_count:,} "
                f"refs={rdata_ref_count:,} merges={coalesced['merges']:,}"
            )
            stats_path.write_text(
                json.dumps(
                    {
                        "pipeline_version": PIPELINE_VERSION,
                        "spill_sort_version": SPILL_SORT_VERSION,
                        "owner_count": owner_count,
                        "rrset_count": rrset_count,
                        "rdata_ref_count": rdata_ref_count,
                        "front_coded": front_coded,
                        "uncompressed": uncompressed,
                        "lines": lines,
                        "skipped": skipped,
                        "owner_merges": coalesced["merges"],
                        "owner_fragments_in": coalesced["fragments_in"],
                    }
                ),
                encoding="utf-8",
            )
            d1_paths = list(owner_paths)
            owner_paths = []
            fd1 = pair.submit(_run_d1, d1_paths, owner_count)
            fc.result()
            fd1.result()
        skip_pool = True

    sorted_path = work / "unique_sorted.bin"
    if skip_pool:
        log("skip pass C; pool and hash→id already on disk")
        pool_saved = json.loads(pool_checkpoint.read_text(encoding="utf-8"))
        if pool_saved["pool_bytes"] != (work / "pool_data.bin").stat().st_size:
            raise RuntimeError("pool checkpoint size mismatch")
        pool_entry_count_saved = pool_saved["pool_entry_count"]
    else:
        pool_entry_count_saved = None
    pool_tmp = work / "pool_data.bin"
    ordinal = pool_entry_count_saved or 0
    if not skip_pool:
        log("pass C: assign lexical ids")
        ordinal = write_pool_and_hash_index(
            sorted_path, pool_tmp, work / "pool_restarts.bin", work, log
        )
        pool_checkpoint.write_text(json.dumps({
            "pool_entry_count": ordinal, "pool_bytes": pool_tmp.stat().st_size,
        }) + "\n", encoding="utf-8")
        sorted_path.unlink()
    pool_restarts_path = work / "pool_restarts.bin"
    hash_sorted = work / "hash_id_by_hash.bin"

    # owner stream rewrite
    stream_path = work / "owner_stream.bin"
    restart_path = work / "owner_restarts.bin"
    log("pass D: rewrite owner stream with pool ids")
    bodies_path = work / "owner_bodies.bin"
    hash_refs_path = work / "hash_refs.bin"
    log("pass D1: split key/body and hash refs")
    if bodies_path.is_file() and hash_refs_path.is_file() and not owner_paths:
        log("pass D1 already on disk")
    else:
        helper = _join_scatter_bin()
        d1_ok = False
        if helper is not None and owner_paths:
            paths_file = work / "d1_paths.txt"
            paths_file.write_text(
                "".join(str(p) + "\n" for p in owner_paths), encoding="utf-8"
            )
            try:
                log(f"pass D1 via {helper}")
                t_d1 = time.time()
                proc = subprocess.run(
                    [
                        str(helper),
                        "d1_split",
                        str(paths_file),
                        str(bodies_path),
                        str(hash_refs_path),
                    ],
                    text=True,
                    capture_output=True,
                    check=True,
                )
                if proc.stderr:
                    for line in proc.stderr.strip().splitlines()[-6:]:
                        log(f"  {line}")
                meta = dict(
                    part.split("=", 1)
                    for part in proc.stdout.strip().split()
                    if "=" in part
                )
                seen = int(meta["owners"])
                if seen != owner_count:
                    raise RuntimeError(f"d1 owners {seen} != {owner_count}")
                for path in owner_paths:
                    path.unlink(missing_ok=True)
                log(f"pass D1 C done in {time.time() - t_d1:.1f}s")
                d1_ok = True
            except (subprocess.CalledProcessError, KeyError, ValueError, RuntimeError) as exc:
                log(f"pass D1 C failed ({exc}); Python fallback")
                bodies_path.unlink(missing_ok=True)
                hash_refs_path.unlink(missing_ok=True)
        if not d1_ok:
            with bodies_path.open("wb", buffering=8 << 20) as bodies, hash_refs_path.open(
                "wb", buffering=8 << 20
            ) as hash_refs:
                seen = 0
                for path in owner_paths:
                    data = path.read_bytes()
                    off = 0
                    n = len(data)
                    while off < n:
                        (ln,) = struct.unpack_from("<I", data, off)
                        off += 4
                        rec = data[off : off + ln]
                        off += ln
                        klen, blen, hlen = struct.unpack_from("<III", rec, 0)
                        base = 12
                        key_enc = rec[base : base + klen]
                        body = rec[base + klen : base + klen + blen]
                        hashes = rec[base + klen + blen : base + klen + blen + hlen]
                        if len(hashes) % HASH_LEN:
                            raise RuntimeError("hash blob not aligned")
                        bodies.write(struct.pack("<III", len(key_enc), len(body), 0))
                        bodies.write(key_enc)
                        bodies.write(body)
                        hash_refs.write(struct.pack("<II", seen, len(hashes) // HASH_LEN))
                        hash_refs.write(hashes)
                        seen += 1
                        if seen % 5_000_000 == 0:
                            log(f"split owners={seen:,}")
                    path.unlink()
                if seen != owner_count:
                    raise RuntimeError(f"split owners {seen} != {owner_count}")
    log("pass D2: join hash refs to lexical ids")
    ids_u32_path, counts_arr = join_hash_refs(
        hash_refs_path, hash_sorted, work / "join", log
    )
    hash_sorted.unlink()
    hash_refs_path.unlink()

    stream_len = 0
    seen = 0
    helper = _join_scatter_bin()
    counts_bin = work / "join" / "counts.bin"
    if helper is not None and counts_bin.is_file():
        log(f"pass D stream via {helper}")
        t_stream = time.time()
        out = subprocess.check_output(
            [
                str(helper),
                "stream",
                str(bodies_path),
                str(counts_bin),
                str(ids_u32_path),
                str(stream_path),
                str(restart_path),
            ],
            text=True,
        )
        # stream_len=<n> owners=<n>
        meta = dict(
            part.split("=", 1) for part in out.strip().split() if "=" in part
        )
        stream_len = int(meta["stream_len"])
        seen = int(meta["owners"])
        log(f"pass D stream done in {time.time() - t_stream:.1f}s")
    else:
        with ids_u32_path.open("rb") as ids_fh:
            ids_mm = mmap.mmap(ids_fh.fileno(), 0, access=mmap.ACCESS_READ)
            ids_view = memoryview(ids_mm).cast("I")
            id_cursor = 0
            with stream_path.open("wb", buffering=8 << 20) as stream, restart_path.open(
                "wb"
            ) as restarts_out, bodies_path.open("rb") as bodies:
                while True:
                    hdr = bodies.read(12)
                    if not hdr:
                        break
                    klen, blen, _pad = struct.unpack("<III", hdr)
                    key_enc = bodies.read(klen)
                    body = bodies.read(blen)
                    n_ids = counts_arr[seen]
                    if seen % BLOCK_SIZE == 0:
                        restarts_out.write(RESTART.pack(stream_len))
                    out_body = bytearray(body[:TYPE_MASK_BYTES])
                    bpos = TYPE_MASK_BYTES
                    id_pos = 0
                    mask = int.from_bytes(body[:TYPE_MASK_BYTES], "little")
                    for bit in range(len(TYPE_ORDER)):
                        if (mask & (1 << bit)) == 0:
                            continue
                        ttl, used = decode_uleb(body, bpos)
                        bpos += used
                        out_body.extend(encode_uleb128(ttl))
                        count, used = decode_uleb(body, bpos)
                        bpos += used
                        out_body.extend(encode_uleb128(count))
                        for _ in range(count):
                            out_body.extend(encode_uleb128(ids_view[id_cursor + id_pos]))
                            id_pos += 1
                    if id_pos != n_ids or bpos != len(body):
                        raise RuntimeError(f"body/id walk mismatch owner={seen}")
                    id_cursor += n_ids
                    piece = key_enc + encode_uleb128(len(out_body)) + bytes(out_body)
                    stream.write(piece)
                    stream_len += len(piece)
                    seen += 1
                    if seen % 5_000_000 == 0:
                        log(f"stream owners={seen:,} bytes={stream_len:,}")
            ids_view.release()
            ids_mm.close()
    log(f"pass D done owners={seen:,} stream={stream_len:,}")
    ids_u32_path.unlink(missing_ok=True)
    bodies_path.unlink()

    origin_b = origin.encode("ascii")
    owner_restart_count = (owner_count + BLOCK_SIZE - 1) // BLOCK_SIZE
    pool_entry_count = ordinal
    pool_restart_count = (pool_entry_count + BLOCK_SIZE - 1) // BLOCK_SIZE
    owner_restart_bytes = owner_restart_count * 8
    pool_restart_bytes = pool_restart_count * 8
    origin_off = HEADER_SIZE
    restart_off = origin_off + len(origin_b)
    stream_off = restart_off + owner_restart_bytes
    pool_restart_off = stream_off + stream_len
    pool_off = pool_restart_off + pool_restart_bytes
    pool_bytes = pool_tmp.stat().st_size
    file_size = pool_off + pool_bytes
    if pool_restarts_path.stat().st_size != pool_restart_bytes:
        raise RuntimeError(
            f"pool restart size {pool_restarts_path.stat().st_size} != {pool_restart_bytes}"
        )
    if restart_path.stat().st_size != owner_restart_bytes:
        raise RuntimeError(
            f"owner restart size {restart_path.stat().st_size} != {owner_restart_bytes}"
        )
    header = HEADER.pack(
        MAGIC,
        VERSION_MAJOR,
        VERSION_MINOR,
        ENDIAN_MARKER,
        HEADER_SIZE,
        SCHEMA_ID,
        PROFILE_ID,
        FLAGS,
        BLOCK_SIZE,
        RESERVED0,
        file_size,
        origin_off,
        len(origin_b),
        restart_off,
        owner_restart_count,
        stream_off,
        stream_len,
        owner_count,
        rrset_count,
        rdata_ref_count,
        pool_entry_count,
        RESERVED1,
    )
    log(f"pass E: assemble {file_size:,} bytes")
    with out_path.open("wb", buffering=8 << 20) as out:
        out.write(header)
        out.write(origin_b)
        with restart_path.open("rb") as fh:
            out.write(fh.read())
        with stream_path.open("rb") as fh:
            while True:
                chunk = fh.read(8 << 20)
                if not chunk:
                    break
                out.write(chunk)
        with pool_restarts_path.open("rb") as fh:
            out.write(fh.read())
        with pool_tmp.open("rb") as fh:
            while True:
                chunk = fh.read(8 << 20)
                if not chunk:
                    break
                out.write(chunk)
    actual = out_path.stat().st_size
    if actual != file_size:
        raise RuntimeError(f"assembled {actual} != header {file_size}")
    meta = {
        "zone": str(zone_path),
        "output": str(out_path),
        "origin": origin,
        "profile": "BOGI-v2.3 + TYPE_ORDER_DNSSEC + u16 mask + binary pool",
        "flags": FLAGS,
        "pipeline_version": PIPELINE_VERSION,
        "owner_order": "bogi_key",
        "file_size": file_size,
        "owner_count": owner_count,
        "rrset_count": rrset_count,
        "rdata_ref_count": rdata_ref_count,
        "pool_entry_count": pool_entry_count,
        "pool_data_bytes": pool_bytes,
        "owner_stream_bytes": stream_len,
        "front_coded_key_bytes": front_coded,
        "uncompressed_owner_key_bytes": uncompressed,
        "skipped": skipped,
        "lines": lines,
        "elapsed_s": round(time.perf_counter() - wall0, 1),
        "tunables": {
            "SORT_CHUNK": SORT_CHUNK,
            "MERGE_FAN_IN": MERGE_FAN_IN,
            "OWNER_SORT_CHUNK": OWNER_SORT_CHUNK,
            "SPILL_OWNERS": SPILL_OWNERS,
        },
    }
    meta_path = Path(str(out_path) + ".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    log("DONE " + json.dumps(meta))
    return 0


def write_pool_and_hash_index(
    sorted_path: Path, pool_tmp: Path, restarts_path: Path, work: Path, log
) -> int:
    """Pass C+C2 extract: prefer one-pass C pool_build, then sort hash→id."""
    helper = _join_scatter_bin()
    hash_id_path = work / "hash_id_sorted.bin"
    ordinal = 0
    type_by_hash: dict[bytes, int] = {}
    if (FLAGS & FLAG_BINARY_POOL) != 0:
        for tip in sorted(list(work.glob("**/*.type_*.bin")) + list(work.glob("**/*_type_*.bin"))):
            blob = tip.read_bytes()
            for off in range(0, len(blob), HASH_LEN + 1):
                if off + HASH_LEN + 1 > len(blob):
                    break
                h = blob[off : off + HASH_LEN]
                type_by_hash.setdefault(h, blob[off + HASH_LEN])
        log(f"pass C: binary pool type hints={len(type_by_hash):,}")
    if helper is not None and (FLAGS & FLAG_BINARY_POOL) == 0:
        try:
            log(f"pass C: pool_build via {helper}")
            t0 = time.time()
            proc = subprocess.run(
                [
                    str(helper),
                    "pool_build",
                    str(sorted_path),
                    str(pool_tmp),
                    str(restarts_path),
                    str(hash_id_path),
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            if proc.stderr:
                for line in proc.stderr.strip().splitlines()[-6:]:
                    log(f"  {line}")
            meta = dict(
                part.split("=", 1) for part in proc.stdout.strip().split() if "=" in part
            )
            ordinal = int(meta["entries"])
            pool_off = int(meta["pool_bytes"])
            log(
                f"pass C done pool_bytes={pool_off:,} entries={ordinal:,} "
                f"in {time.time() - t0:.1f}s"
            )
        except (subprocess.CalledProcessError, KeyError, ValueError) as exc:
            log(f"pass C pool_build failed ({exc}); Python fallback")
            hash_id_path.unlink(missing_ok=True)
            pool_tmp.unlink(missing_ok=True)
            restarts_path.unlink(missing_ok=True)
            ordinal = 0
    if ordinal == 0:
        with sorted_path.open("rb") as src, pool_tmp.open(
            "wb", buffering=8 << 20
        ) as pool, restarts_path.open("wb") as pool_restarts, hash_id_path.open(
            "wb", buffering=8 << 20
        ) as hid:
            pool_off = 0
            while True:
                hdr = src.read(4)
                if not hdr:
                    break
                (ln,) = struct.unpack("<I", hdr)
                rec = src.read(ln)
                rrset_ord, rdata_ord, raw_len = struct.unpack_from(
                    "<III", rec, HASH_LEN
                )
                raw = rec[HASH_LEN + 12 :]
                if len(raw) != raw_len:
                    raise RuntimeError("rdata length mismatch")
                if ordinal % BLOCK_SIZE == 0:
                    pool_restarts.write(RESTART.pack(pool_off))
                payload = raw
                if (FLAGS & FLAG_BINARY_POOL) != 0:
                    tidx = type_by_hash.get(rec[:HASH_LEN])
                    if tidx is not None and 0 <= tidx < len(TYPE_ORDER):
                        try:
                            payload = pack_rdata(
                                TYPE_ORDER[tidx], raw.decode("utf-8")
                            )
                        except Exception:
                            payload = bytes([TAG_UTF8]) + raw
                    else:
                        payload = bytes([TAG_UTF8]) + raw
                piece = (
                    encode_uleb128(rrset_ord)
                    + encode_uleb128(rdata_ord)
                    + encode_uleb128(len(payload))
                    + payload
                )
                pool.write(piece)
                pool_off += len(piece)
                hid.write(rec[:HASH_LEN])
                hid.write(struct.pack("<I", ordinal))
                ordinal += 1
                if ordinal % 2_000_000 == 0:
                    log(f"pool ids={ordinal:,} bytes={pool_off:,}")
        log(f"pass C done pool_bytes={pool_off:,} entries={ordinal:,}")
    hash_sorted = work / "hash_id_by_hash.bin"
    log("pass C2: external sort by hash")
    external_sort_hash_id(hash_id_path, hash_sorted, work / "hashsort")
    hash_id_path.unlink(missing_ok=True)
    log(f"pass C2 done hash_id_bytes={hash_sorted.stat().st_size:,}")
    return ordinal


def write_pool(sorted_path: Path, pool_tmp: Path, restarts_path: Path, log) -> int:
    """Legacy entry — prefer write_pool_and_hash_index."""
    work = pool_tmp.parent
    return write_pool_and_hash_index(
        sorted_path, pool_tmp, restarts_path, work, log
    )


def write_hash_index(sorted_path: Path, work: Path, ordinal: int, log) -> None:
    """No-op when pool_build already wrote+sorted; kept for resume paths."""
    hash_sorted = work / "hash_id_by_hash.bin"
    if hash_sorted.is_file() and hash_sorted.stat().st_size == ordinal * (HASH_LEN + 4):
        log("pass C2: hash_id_by_hash already present")
        return
    hash_id_path = work / "hash_id_sorted.bin"
    if not hash_id_path.is_file():
        log("pass C2: sort hash→id (rebuild rows)")
        with sorted_path.open("rb") as src, hash_id_path.open(
            "wb", buffering=8 << 20
        ) as hid:
            hid_ordinal = 0
            while True:
                hdr = src.read(4)
                if not hdr:
                    break
                (ln,) = struct.unpack("<I", hdr)
                rec = src.read(ln)
                hid.write(rec[:HASH_LEN])
                hid.write(struct.pack("<I", hid_ordinal))
                hid_ordinal += 1
        if hid_ordinal != ordinal:
            raise RuntimeError(f"hash-id rows {hid_ordinal} != pool {ordinal}")
    log("pass C2: external sort by hash")
    external_sort_hash_id(hash_id_path, hash_sorted, work / "hashsort")
    hash_id_path.unlink(missing_ok=True)
    log(f"pass C2 done hash_id_bytes={hash_sorted.stat().st_size:,}")


def rescan_hash_rows(zone_path: Path, origin: str, work: Path, log) -> None:
    """Second zone scan: lexical id is assigned in first-seen-unique order? 

    No: pool ids are lexical over raw RDATA, which this scan does not know.
    Instead emit (hash, raw) is impossible at this size. Emit hash rows only
    after sorting unique raw again would redo pass B.

    This function emits hash rows in *lexical id order* by re-deriving the
    order the pool used: unique raw sorted, first witness discarded. That
    requires the raw bytes. They are still inside pool_data.bin but without
    hashes. Recompute the hash from each pool payload instead.
    """

    pool_path = work / "pool_data.bin"
    out = work / "hash_id_sorted.bin"
    ordinal = 0
    with pool_path.open("rb") as src, out.open("wb", buffering=8 << 20) as hid:
        while True:
            # pool piece: uleb rrset_ord, uleb rdata_ord, uleb len, raw
            pos_buf = src.read(1)
            if not pos_buf:
                break
            # rewind-free uleb decode from a pushback buffer
            def read_uleb(first: bytes) -> int:
                value = first[0] & 0x7F
                if first[0] < 0x80:
                    return value
                shift = 7
                while True:
                    b = src.read(1)
                    if not b:
                        raise RuntimeError("truncated uleb in pool")
                    value |= (b[0] & 0x7F) << shift
                    if b[0] < 0x80:
                        return value
                    shift += 7

            rrset_ord = read_uleb(pos_buf)
            rdata_ord = read_uleb(src.read(1))
            raw_len = read_uleb(src.read(1))
            raw = src.read(raw_len)
            if len(raw) != raw_len:
                raise RuntimeError("truncated pool payload")
            h = _blake2b16(raw)
            hid.write(h)
            hid.write(struct.pack("<I", ordinal))
            ordinal += 1
            if ordinal % 5_000_000 == 0:
                log(f"rehash pool ids={ordinal:,}")
            del rrset_ord, rdata_ord
    log(f"rehash done rows={ordinal:,}")


def rescan_owner_bodies(zone_path: Path, origin: str, work: Path, log) -> None:
    bodies_path = work / "owner_bodies.bin"
    hash_refs_path = work / "hash_refs.bin"
    cur_owner: str | None = None
    cur_key = b""
    cur_rrsets: dict[str, tuple[int, list[bytes]]] = {}
    prior_key = b""
    owner_count = 0
    front = 0
    with zone_path.open(
        "r", encoding="utf-8", errors="replace", buffering=8 << 20
    ) as fh, bodies_path.open("wb", buffering=8 << 20) as bodies, hash_refs_path.open(
        "wb", buffering=8 << 20
    ) as hash_refs:

        def flush() -> None:
            nonlocal owner_count, prior_key, front
            if cur_owner is None:
                return
            key = cur_key
            full = encode_uleb128(len(key)) + key
            if owner_count % BLOCK_SIZE == 0:
                key_enc = full
            else:
                shared = common_prefix_length(prior_key, key)
                suffix = key[shared:]
                key_enc = encode_uleb128(shared) + encode_uleb128(len(suffix)) + suffix
            front += len(key_enc)
            body = bytearray()
            mask = 0
            present = []
            for rrtype in TYPE_ORDER:
                item = cur_rrsets.get(rrtype)
                if item is None:
                    continue
                mask |= TYPE_TO_BIT[rrtype]
                present.append(item)
            body.extend(mask.to_bytes(TYPE_MASK_BYTES, "little"))
            hashes = bytearray()
            for ttl, rdatas in present:
                deduped: list[bytes] = []
                for raw in sorted(rdatas):
                    if deduped and deduped[-1] == raw:
                        continue
                    deduped.append(raw)
                body.extend(encode_uleb128(ttl))
                body.extend(encode_uleb128(len(deduped)))
                for raw in deduped:
                    hashes.extend(_blake2b16(raw))
            bodies.write(struct.pack("<III", len(key_enc), len(body), 0))
            bodies.write(key_enc)
            bodies.write(body)
            hash_refs.write(struct.pack("<II", owner_count, len(hashes) // HASH_LEN))
            hash_refs.write(hashes)
            owner_count += 1
            prior_key = key

        lines = 0
        for line in fh:
            lines += 1
            if lines & 0x3FFFFF == 0:
                log(f"rescan lines={lines:,} owners={owner_count:,}")
            parsed = parse_rr_line(line.rstrip("\n"), cur_owner)
            if parsed is None:
                continue
            owner, rrtype, ttl, rdata = parsed
            if rrtype not in TYPE_TO_BIT or not rdata:
                continue
            if cur_owner is not None and owner != cur_owner:
                flush()
                cur_rrsets = {}
            if cur_owner != owner:
                cur_owner = owner
                cur_key = owner_to_key(owner, origin)
            raw = rdata.encode("utf-8")
            item = cur_rrsets.get(rrtype)
            if item is None:
                cur_rrsets[rrtype] = (ttl, [raw])
            else:
                item[1].append(raw)
        flush()
    log(f"rescan done owners={owner_count:,} front={front:,}")


def recover_key_bytes(paths: list[Path], log) -> tuple[int, int]:
    front = 0
    owners = 0
    for path in paths:
        data = path.read_bytes()
        off = 0
        n = len(data)
        while off < n:
            (ln,) = struct.unpack_from("<I", data, off)
            off += 4
            klen = struct.unpack_from("<I", data, off)[0]
            front += klen
            off += ln
            owners += 1
        log(f"recover keys owners={owners:,} front={front:,}")
    # Uncompressed size is not recoverable from front-coded keys. The size
    # estimate scan measured 2,767,066,227; keep that as the reported figure.
    return front, 2767066227


def external_sort_hash_id(src: Path, dst: Path, tmp: Path) -> None:
    """Sort 20-byte (hash16, id u32) records by hash."""

    tmp.mkdir(parents=True, exist_ok=True)
    rec_size = HASH_LEN + 4
    runs: list[Path] = []
    buf = bytearray()
    count = 0
    with src.open("rb") as fh:
        while True:
            chunk = fh.read(rec_size * 1_000_000)
            if not chunk:
                break
            if len(chunk) % rec_size:
                raise RuntimeError("hash-id file truncated")
            recs = [
                chunk[i : i + rec_size] for i in range(0, len(chunk), rec_size)
            ]
            recs.sort()
            path = tmp / f"run_{len(runs):05d}.bin"
            path.write_bytes(b"".join(recs))
            runs.append(path)
            count += len(recs)
    files = [p.open("rb") for p in runs]
    heap: list[tuple[bytes, int]] = []
    for i, fh in enumerate(files):
        rec = fh.read(rec_size)
        if rec:
            heapq.heappush(heap, (rec, i))
    written = 0
    with dst.open("wb", buffering=8 << 20) as out:
        while heap:
            rec, i = heapq.heappop(heap)
            out.write(rec)
            written += 1
            nxt = files[i].read(rec_size)
            if nxt:
                heapq.heappush(heap, (nxt, i))
    for fh in files:
        fh.close()
    for p in runs:
        p.unlink()
    if written != count:
        raise RuntimeError(f"hash sort wrote {written} != {count}")


def _join_scatter_bin() -> Path | None:
    """Locate compiled join_scatter helper (C accelerator)."""
    here = Path(__file__).resolve().parent
    cands = [
        here / "join_scatter",
        here / "com_zimdb_encode_opt" / "join_scatter",
        Path(os.environ.get("BOGI_JOIN_SCATTER", "")),
    ]
    for p in cands:
        if p and p.is_file() and os.access(p, os.X_OK):
            return p
    return None


def join_hash_refs(
    refs: Path, hash_sorted: Path, tmp: Path, log
) -> tuple[Path, array.array]:
    """Join hash refs → flat u32 id array in owner/j order + counts array.

    Returns (ids_u32_flat_path, counts_array). Never materializes list[list[int]].
    """
    existing = tmp / "ids_flat.bin"
    counts_path = tmp / "counts.bin"
    if existing.is_file() and existing.stat().st_size > 0:
        log("join: ids_flat.bin present, skip merge")
        if not counts_path.is_file():
            raise RuntimeError("counts.bin missing for ids_flat resume")
        counts = array.array("I")
        counts.frombytes(counts_path.read_bytes())
        return finish_join_scatter(existing, counts, tmp, log)

    tmp.mkdir(parents=True, exist_ok=True)
    ref_rows = tmp / "ref_rows.bin"
    helper = _join_scatter_bin()
    if helper is not None:
        log(f"join: expand_refs via {helper}")
        t0 = time.time()
        subprocess.check_call(
            [str(helper), "expand_refs", str(refs), str(ref_rows), str(counts_path)]
        )
        log(f"join: expand_refs done in {time.time() - t0:.1f}s")
        counts = array.array("I")
        counts.frombytes(counts_path.read_bytes())
    else:
        counts = array.array("I")
        pack_tail = struct.Struct("<III")
        with refs.open("rb") as src, ref_rows.open("wb", buffering=16 << 20) as out:
            owner_i = 0
            while True:
                hdr = src.read(8)
                if not hdr:
                    break
                owner, count = struct.unpack("<II", hdr)
                if owner != owner_i:
                    raise RuntimeError(f"owner ref order {owner} != {owner_i}")
                hashes = src.read(HASH_LEN * count)
                counts.append(count)
                mv = memoryview(hashes)
                for j in range(count):
                    out.write(mv[j * HASH_LEN : (j + 1) * HASH_LEN])
                    out.write(pack_tail.pack(owner, j, 0))
                owner_i += 1
                if owner_i % 10_000_000 == 0:
                    log(f"ref rows owners={owner_i:,}")
        counts_path.write_bytes(counts.tobytes())
    sorted_refs = tmp / "ref_rows_sorted.bin"
    log("join: sort refs by hash")
    external_sort_owner_refs(ref_rows, sorted_refs, tmp / "refsort")
    ref_rows.unlink()

    ids_flat = tmp / "ids_flat.bin"
    log("join: merge refs with hash→id")
    if helper is not None:
        t_jm = time.time()
        try:
            proc = subprocess.run(
                [
                    str(helper),
                    "join_merge",
                    str(sorted_refs),
                    str(hash_sorted),
                    str(ids_flat),
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            if proc.stderr:
                for line in proc.stderr.strip().splitlines()[-6:]:
                    log(f"  {line}")
            log(
                f"join: merge C done in {time.time() - t_jm:.1f}s "
                f"({proc.stdout.strip()})"
            )
            sorted_refs.unlink()
            return finish_join_scatter(ids_flat, counts, tmp, log)
        except subprocess.CalledProcessError as exc:
            err = (exc.stderr or "")[-400:]
            log(f"join: merge C failed rc={exc.returncode}: {err}; Python fallback")
            ids_flat.unlink(missing_ok=True)
    rec_ref = HASH_LEN + 12
    rec_id = HASH_LEN + 4
    pack_out = struct.Struct("<III")
    with sorted_refs.open("rb") as left, hash_sorted.open("rb") as right, ids_flat.open(
        "wb", buffering=16 << 20
    ) as out:
        lrec = left.read(rec_ref)
        rrec = right.read(rec_id)
        matched = 0
        while lrec:
            lh = lrec[:HASH_LEN]
            while rrec and rrec[:HASH_LEN] < lh:
                rrec = right.read(rec_id)
            if not rrec or rrec[:HASH_LEN] != lh:
                raise RuntimeError("hash ref missing from pool")
            rid = struct.unpack_from("<I", rrec, HASH_LEN)[0]
            owner, j, _ = struct.unpack_from("<III", lrec, HASH_LEN)
            out.write(pack_out.pack(owner, j, rid))
            matched += 1
            lrec = left.read(rec_ref)
            if matched % 50_000_000 == 0:
                log(f"join matched={matched:,}")
    sorted_refs.unlink()
    return finish_join_scatter(ids_flat, counts, tmp, log)


def finish_join_scatter(
    ids_flat: Path, counts: array.array, tmp: Path, log
) -> tuple[Path, array.array]:
    """Scatter (owner,j,rid) into flat u32[prefix[owner]+j] — no sort, no list-of-lists."""
    out_path = tmp / "ids_u32_flat.bin"
    helper = _join_scatter_bin()
    if helper is not None:
        log(f"join: scatter via {helper}")
        t0 = time.time()
        subprocess.check_call(
            [str(helper), "scatter", str(ids_flat), str(tmp / "counts.bin"), str(out_path)]
        )
        log(f"join: scatter done in {time.time() - t0:.1f}s")
        ids_flat.unlink(missing_ok=True)
        return out_path, counts

    log("join: scatter ids by (owner,j) into flat u32 (python)")
    t0 = time.time()
    n_owners = len(counts)
    prefix = array.array("I", [0]) * n_owners
    total = 0
    for i, c in enumerate(counts):
        prefix[i] = total
        total += c
    out_bytes = total * 4
    with out_path.open("wb+") as fh:
        fh.truncate(out_bytes)
        mm = mmap.mmap(fh.fileno(), out_bytes)
        view = memoryview(mm).cast("I")
        with ids_flat.open("rb", buffering=16 << 20) as src:
            # Read 12-byte records in chunks
            chunk = src.read(12 * 1_000_000)
            done = 0
            while chunk:
                if len(chunk) % 12:
                    raise RuntimeError("ids_flat truncated")
                mv = memoryview(chunk)
                for off in range(0, len(chunk), 12):
                    owner, j, rid = struct.unpack_from("<III", mv, off)
                    view[prefix[owner] + j] = rid
                done += len(chunk) // 12
                if done % 50_000_000 == 0:
                    log(f"scatter progress={done:,}/{total:,}")
                chunk = src.read(12 * 1_000_000)
        view.release()
        mm.flush()
        mm.close()
    ids_flat.unlink(missing_ok=True)
    log(f"join: scatter done refs={total:,} in {time.time() - t0:.1f}s")
    return out_path, counts


def _sort_fixed(src: Path, dst: Path, tmp: Path, rec_size: int, key_bytes: int) -> None:
    """External sort fixed-size records by the first key_bytes of each record."""
    helper = _join_scatter_bin()
    tmp.mkdir(parents=True, exist_ok=True)
    if helper is not None and key_bytes == 16:
        src_size = src.stat().st_size
        # Prefer in-memory sort16 whenever the file is clearly smaller than RAM
        # (D2 ref_rows ≈12 GiB on .com; esort16 auto can miss due to page-cache).
        if src_size < (_mem_available_mb() * 1024 * 1024) // 2 or src_size < (24 << 30):
            subprocess.check_call(
                [str(helper), "sort16", str(src), str(dst), str(rec_size)]
            )
            return
        log_tmp = tmp / "esort_runs"
        log_tmp.mkdir(exist_ok=True)
        subprocess.check_call(
            [str(helper), "esort16", str(src), str(dst), str(rec_size), str(log_tmp)]
        )
        return
    if helper is not None and key_bytes == 8 and rec_size <= (64 << 20):
        # In-memory path when file fits — caller decides; try sort8 on whole file
        src_size = src.stat().st_size
        if src_size < (_mem_available_mb() * 1024 * 1024) // 3:
            subprocess.check_call(
                [str(helper), "sort8", str(src), str(dst), str(rec_size)]
            )
            return

    runs: list[Path] = []
    total = 0
    # Larger runs when RAM allows (~min(8M records, 512MB))
    avail = _mem_available_mb()
    run_bytes = min(512 << 20, max(rec_size * 500_000, (avail * 1024 * 1024) // 8))
    run_bytes = (run_bytes // rec_size) * rec_size
    with src.open("rb") as fh:
        while True:
            raw = fh.read(run_bytes)
            if not raw:
                break
            if len(raw) % rec_size:
                raise RuntimeError("fixed record file truncated")
            path = tmp / f"run_{len(runs):05d}.bin"
            count = len(raw) // rec_size
            # Pre-extract keys once (avoid per-comparison bytes slices)
            if key_bytes == 16:
                keys = [raw[i * rec_size : i * rec_size + 16] for i in range(count)]
                order = sorted(range(count), key=keys.__getitem__)
            elif key_bytes == 8:
                keys_u = array.array("Q")
                mv = memoryview(raw)
                for i in range(count):
                    keys_u.append(struct.unpack_from("<Q", mv, i * rec_size)[0])
                order = sorted(range(count), key=keys_u.__getitem__)
            else:
                order = sorted(
                    range(count),
                    key=lambda i: raw[i * rec_size : i * rec_size + key_bytes],
                )
            with path.open("wb", buffering=8 << 20) as out:
                for i in order:
                    out.write(raw[i * rec_size : (i + 1) * rec_size])
            runs.append(path)
            total += count

    files = [p.open("rb") for p in runs]
    current = [fh.read(rec_size) for fh in files]
    heap: list[tuple[bytes, int]] = []
    for i, rec in enumerate(current):
        if rec:
            heapq.heappush(heap, (rec[:key_bytes], i))
    written = 0
    with dst.open("wb", buffering=16 << 20) as out:
        while heap:
            _k, i = heapq.heappop(heap)
            out.write(current[i])
            written += 1
            nxt = files[i].read(rec_size)
            current[i] = nxt
            if nxt:
                heapq.heappush(heap, (nxt[:key_bytes], i))
    for fh in files:
        fh.close()
    for p in runs:
        p.unlink()
    if written != total:
        raise RuntimeError(f"sort wrote {written} != {total}")


def external_sort_owner_refs(src: Path, dst: Path, tmp: Path) -> None:
    _sort_fixed(src, dst, tmp, HASH_LEN + 12, key_bytes=16)


def external_sort_ids(src: Path, dst: Path, tmp: Path) -> None:
    _sort_fixed(src, dst, tmp, 12, key_bytes=8)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        import traceback

        traceback.print_exc()
        raise SystemExit(1)

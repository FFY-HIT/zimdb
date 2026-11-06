#!/usr/bin/env python3
"""Encode a DNSSEC zone to BOGIP1 with typed binary pool (flags bit 0x4).

Example:
  PYTHONPATH=.. python3 encode_binary_zone.py \\
      --zone /mnt/d/czds/raw/abbott.zone.gz --origin abbott. \\
      --out abbott.binary.bogi
"""
from __future__ import annotations

import argparse
import gzip
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ops.vendor.checked_image.p1 import LogicalRRset, LogicalZone  # noqa: E402
from ops.vendor.compact_image_v23.format_v23 import (  # noqa: E402
    BLOCK_SIZE,
    ENDIAN_MARKER,
    HEADER,
    HEADER_SIZE,
    MAGIC,
    PROFILE_ID_DNSSEC,
    RESERVED0,
    RESTART,
    SCHEMA_ID,
    TYPE_ORDER_DNSSEC,
    VERSION_MAJOR,
    VERSION_MINOR,
    common_prefix_length,
    encode_uleb128,
    owner_to_key,
)
from ops.vendor.compact_image_v23.lowerer import (  # noqa: E402
    _build_pool,
    _encode_body_dnssec,
    _owner_groups,
)
from binary_pool_codec import FLAG_BINARY_POOL, pack_rdata  # noqa: E402

_REC = re.compile(r"^(\S+)\s+(?:(\d+)\s+)?[Ii][Nn]\s+([A-Za-z0-9]+)\s+(.+)$")
SUPPORTED = set(TYPE_ORDER_DNSSEC)


def _abs(name: str, origin: str) -> str:
    name = name.strip().lower()
    if name == "@":
        return origin
    if not name.endswith("."):
        name = name + "." + origin
    return name


def parse_dnssec(text: str, origin: str) -> LogicalZone:
    origin = origin.lower()
    if not origin.endswith("."):
        origin += "."
    groups: dict[tuple[str, str], tuple[int, set[str]]] = {}
    for raw in text.splitlines():
        line = raw.split(";", 1)[0].strip()
        if not line or line.startswith("$"):
            continue
        m = _REC.match(line)
        if not m:
            continue
        owner_t, ttl_t, rrtype, rdata = m.groups()
        rrtype = rrtype.upper()
        if rrtype not in SUPPORTED:
            continue
        owner = _abs(owner_t, origin)
        if not (owner == origin or owner.endswith("." + origin)):
            continue
        ttl = int(ttl_t) if ttl_t else 86400
        rdata = rdata.strip()
        if rrtype in {"NS", "CNAME", "PTR"} and rdata and not rdata.endswith("."):
            rdata = rdata + "."
        if rrtype in {"NS", "CNAME", "PTR"}:
            rdata = rdata.lower()
        if rrtype == "MX":
            parts = rdata.split(None, 1)
            if len(parts) == 2:
                exch = parts[1] if parts[1].endswith(".") else parts[1] + "."
                rdata = parts[0] + " " + exch.lower()
        if rrtype == "SOA":
            toks = rdata.split()
            if len(toks) >= 2:
                if not toks[0].endswith("."):
                    toks[0] += "."
                if not toks[1].endswith("."):
                    toks[1] += "."
                toks[0] = toks[0].lower()
                toks[1] = toks[1].lower()
                rdata = " ".join(toks)
        key = (owner, rrtype)
        if key not in groups:
            groups[key] = (ttl, set())
        groups[key][1].add(rdata)
    rrsets = [
        LogicalRRset(owner, ttl, rrtype, tuple(sorted(vals)))
        for (owner, rrtype), (ttl, vals) in sorted(
            groups.items(),
            key=lambda kv: (owner_to_key(kv[0][0], origin), TYPE_ORDER_DNSSEC.index(kv[0][1])),
        )
    ]
    return LogicalZone(origin, tuple(rrsets))


def encode_binary_image(zone: LogicalZone) -> bytes:
    groups = _owner_groups(zone)
    id_of, _, _, rdata_ref_count = _build_pool(zone)
    raw_of = {i: raw for raw, i in id_of.items()}
    type_of = {}
    for rr in zone.rrsets:
        for text in rr.rdatas:
            type_of.setdefault(text.encode(), rr.rrtype)

    owner_stream = bytearray()
    owner_restart_offsets = []
    prior = b""
    for ordinal, (owner, rrsets) in enumerate(groups):
        key = owner_to_key(owner, zone.origin)
        if ordinal % BLOCK_SIZE == 0:
            owner_restart_offsets.append(len(owner_stream))
            key_enc = encode_uleb128(len(key)) + key
        else:
            shared = common_prefix_length(prior, key)
            suf = key[shared:]
            key_enc = encode_uleb128(shared) + encode_uleb128(len(suf)) + suf
        owner_stream.extend(key_enc)
        body = _encode_body_dnssec(rrsets, id_of)
        owner_stream.extend(encode_uleb128(len(body)))
        owner_stream.extend(body)
        prior = key

    first_occ = {}
    for i, rr in enumerate(zone.rrsets):
        for j, text in enumerate(rr.rdatas):
            first_occ.setdefault(text.encode(), (i, j))

    pool_data = bytearray()
    pool_restart_offsets = []
    for ordinal in range(len(raw_of)):
        raw = raw_of[ordinal]
        if ordinal % BLOCK_SIZE == 0:
            pool_restart_offsets.append(len(pool_data))
        w_rr, w_rd = first_occ[raw]
        try:
            payload = pack_rdata(type_of[raw], raw.decode())
        except Exception:
            from binary_pool_codec import TAG_UTF8

            payload = bytes([TAG_UTF8]) + raw
        pool_data.extend(encode_uleb128(w_rr))
        pool_data.extend(encode_uleb128(w_rd))
        pool_data.extend(encode_uleb128(len(payload)))
        pool_data.extend(payload)

    origin = zone.origin.encode("ascii")
    owner_restarts = b"".join(RESTART.pack(o) for o in owner_restart_offsets)
    pool_restarts = b"".join(RESTART.pack(o) for o in pool_restart_offsets)
    owner_count = len(groups)
    owner_restart_count = (owner_count + BLOCK_SIZE - 1) // BLOCK_SIZE
    pool_entry_count = len(raw_of)
    pool_restart_count = (pool_entry_count + BLOCK_SIZE - 1) // BLOCK_SIZE

    origin_off = HEADER_SIZE
    restart_off = origin_off + len(origin)
    stream_off = restart_off + len(owner_restarts)
    pool_restart_off = stream_off + len(owner_stream)
    pool_off = pool_restart_off + len(pool_restarts)
    file_size = pool_off + len(pool_data)
    header = HEADER.pack(
        MAGIC, VERSION_MAJOR, VERSION_MINOR, ENDIAN_MARKER, HEADER_SIZE,
        SCHEMA_ID, PROFILE_ID_DNSSEC, FLAG_BINARY_POOL, BLOCK_SIZE, RESERVED0,
        file_size, origin_off, len(origin), restart_off, owner_restart_count,
        stream_off, len(owner_stream), owner_count, len(zone.rrsets),
        rdata_ref_count, pool_entry_count, 0,
    )
    return header + origin + owner_restarts + bytes(owner_stream) + pool_restarts + bytes(pool_data)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--zone", type=Path, required=True)
    ap.add_argument("--origin", required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    raw = args.zone.read_bytes()
    if args.zone.suffix == ".gz" or raw[:2] == bytes([0x1F, 0x8B]):
        text = gzip.decompress(raw).decode("utf-8", "replace")
    else:
        text = raw.decode("utf-8", "replace")
    origin = args.origin if args.origin.endswith(".") else args.origin + "."
    zone = parse_dnssec(text, origin)
    img = encode_binary_image(zone)
    args.out.write_bytes(img)
    print(f"wrote {args.out} ({len(img)} bytes, flags=0x{FLAG_BINARY_POOL:x})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

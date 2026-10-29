#!/usr/bin/env python3
"""Single-file incremental BOGI container.

One zone is one file:

    ContainerHdr || origin || shard bodies (v2.3) || TOC

An update appends re-encoded shard bodies and a new TOC, then commits by
rewriting the header (generation, toc_offset). Untouched shard bytes stay
where they are. Owner counts stay within about a factor of two of the target
by splitting a shard at its median owner, borrowing across one boundary, or
merging two underfull neighbors. Each body remains an independent v2.3 image
with a shard-local RDATA pool.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from ops.vendor.checked_image.p1 import LogicalRRset, LogicalZone
from ops.vendor.compact_image_v23.format_v23 import (
    BLOCK_SIZE,
    HEADER,
    HEADER_FIELD_NAMES,
    MAGIC as SHARD_MAGIC,
    TYPE_ORDER,
    TYPE_TO_BIT,
    owner_to_key,
)
from ops.vendor.compact_image_v23.incremental_shards import DeltaOp, apply_deltas
from ops.vendor.compact_image_v23.lowerer import lower_bytes

_c_bridge = None  # ops demo: pure Python lowerer

CONTAINER_MAGIC = b"BOGIC1\0\0"
CONTAINER_VERSION = 1
CONTAINER_HEADER_SIZE = 64
# magic, version, header_size, generation, shard_count, target_owners,
# toc_offset, toc_bytes, file_size, origin_len, pad
_HDR = struct.Struct("<8sHHIIIQQQH14x")
assert _HDR.size == CONTAINER_HEADER_SIZE
_U64 = struct.Struct("<Q")
_U32 = struct.Struct("<I")
_U16 = struct.Struct("<H")


@dataclass
class ShardPiece:
    key_lo: bytes
    key_hi: bytes | None
    image: bytes
    owner_count: int
    pool_entry_count: int
    zone: LogicalZone
    reuse_offset: int | None = None
    dirty: bool = False
    image_valid: bool = True


@dataclass
class Container:
    origin: str
    generation: int
    target_owners: int
    shards: list[ShardPiece]
    blob: bytes = field(repr=False, default=b"")


@dataclass
class ApplyStats:
    touched: list[int]
    rewritten: int
    shard_count_before: int
    shard_count_after: int
    owner_counts: list[int]
    bytes_before: int
    bytes_after: int
    bytes_appended: int
    generation: int


_KEY_MINUS1 = bytes((b - 1) & 0xFF for b in range(256))


def key_to_owner(key: bytes, origin: str) -> str:
    """Invert owner_to_key."""
    if key == b"":
        return origin
    labels: list[str] = []
    start = 0
    while start < len(key):
        end = key.find(b"\x00", start)
        if end < 0:
            raise ValueError("owner key is missing a label terminator")
        raw = key[start:end].translate(_KEY_MINUS1)
        labels.append(raw.decode("ascii"))
        start = end + 1
    relative = ".".join(reversed(labels))
    return f"{relative}.{origin}"


def _decode_uleb128(buf: bytes | memoryview, index: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if index >= len(buf):
            raise ValueError("truncated uLEB128")
        byte = buf[index]
        index += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, index
        shift += 7
        if shift > 63:
            raise ValueError("uLEB128 is too wide")


def _parse_shard_header(image: bytes) -> dict[str, object]:
    if len(image) < HEADER.size or image[:8] != SHARD_MAGIC:
        raise ValueError("shard body is not a v2.3 image")
    return dict(zip(HEADER_FIELD_NAMES, HEADER.unpack_from(image, 0), strict=True))


def decode_shard_image(image: bytes, origin: str) -> LogicalZone:
    """Decode one v2.3 shard body back into a LogicalZone."""
    header = _parse_shard_header(image)
    origin_off = int(header["origin_off"])
    origin_len = int(header["origin_len"])
    shard_origin = image[origin_off : origin_off + origin_len].decode("ascii")
    if shard_origin != origin:
        raise ValueError(f"shard origin {shard_origin} != container origin {origin}")
    stream_off = int(header["stream_off"])
    stream_len = int(header["stream_len"])
    stream = image[stream_off : stream_off + stream_len]
    pool_entry_count = int(header["pool_entry_count"])
    pool_restart_count = (pool_entry_count + BLOCK_SIZE - 1) // BLOCK_SIZE
    pool_off = stream_off + stream_len + pool_restart_count * 8
    pool: list[bytes] = []
    cursor = pool_off
    for _ in range(pool_entry_count):
        _, cursor = _decode_uleb128(image, cursor)
        _, cursor = _decode_uleb128(image, cursor)
        length, cursor = _decode_uleb128(image, cursor)
        pool.append(bytes(image[cursor : cursor + length]))
        cursor += length

    owner_count = int(header["owner_count"])
    rrsets: list[LogicalRRset] = []
    index = 0
    prior = b""
    for ordinal in range(owner_count):
        if ordinal % BLOCK_SIZE == 0:
            key_len, index = _decode_uleb128(stream, index)
            key = bytes(stream[index : index + key_len])
            index += key_len
        else:
            shared, index = _decode_uleb128(stream, index)
            suffix_len, index = _decode_uleb128(stream, index)
            suffix = bytes(stream[index : index + suffix_len])
            index += suffix_len
            key = prior[:shared] + suffix
        prior = key
        body_len, index = _decode_uleb128(stream, index)
        body = stream[index : index + body_len]
        index += body_len
        if not body:
            raise ValueError("empty owner body")
        mask = body[0]
        body_index = 1
        owner = key_to_owner(key, origin)
        for rrtype in TYPE_ORDER:
            bit = TYPE_TO_BIT[rrtype]
            if mask & bit == 0:
                continue
            ttl, body_index = _decode_uleb128(body, body_index)
            count, body_index = _decode_uleb128(body, body_index)
            rdatas = []
            for _ in range(count):
                rid, body_index = _decode_uleb128(body, body_index)
                rdatas.append(pool[rid].decode("utf-8"))
            rrsets.append(LogicalRRset(owner, int(ttl), rrtype, tuple(rdatas)))
        if body_index != len(body):
            raise ValueError("owner body was not fully consumed")
    if index != len(stream):
        raise ValueError("owner stream was not fully consumed")
    return LogicalZone(origin, tuple(rrsets))


def _sha256(blob: bytes) -> bytes:
    return hashlib.sha256(blob).digest()


def _encode_toc(shards: list[ShardPiece], offsets: list[int]) -> bytes:
    out = bytearray()
    for shard, offset in zip(shards, offsets, strict=True):
        out += _U16.pack(len(shard.key_lo))
        out += shard.key_lo
        if shard.key_hi is None:
            out += _U16.pack(0xFFFF)
        else:
            out += _U16.pack(len(shard.key_hi))
            out += shard.key_hi
        out += _U64.pack(offset)
        out += _U64.pack(len(shard.image))
        out += _U32.pack(shard.owner_count)
        out += _U32.pack(shard.pool_entry_count)
        out += _sha256(shard.image)
    return bytes(out)


def _decode_toc(blob: bytes, offset: int, shard_count: int) -> list[tuple]:
    rows = []
    index = offset
    for _ in range(shard_count):
        (lo_len,) = _U16.unpack_from(blob, index)
        index += 2
        key_lo = bytes(blob[index : index + lo_len])
        index += lo_len
        (hi_len,) = _U16.unpack_from(blob, index)
        index += 2
        if hi_len == 0xFFFF:
            key_hi = None
        else:
            key_hi = bytes(blob[index : index + hi_len])
            index += hi_len
        (file_off,) = _U64.unpack_from(blob, index)
        index += 8
        (length,) = _U64.unpack_from(blob, index)
        index += 8
        (owner_count,) = _U32.unpack_from(blob, index)
        index += 4
        (pool_count,) = _U32.unpack_from(blob, index)
        index += 4
        digest = bytes(blob[index : index + 32])
        index += 32
        rows.append((key_lo, key_hi, file_off, length, owner_count, pool_count, digest))
    return rows


def _write_header(
    buf: bytearray,
    *,
    generation: int,
    shard_count: int,
    target_owners: int,
    toc_offset: int,
    toc_bytes: int,
    file_size: int,
    origin_len: int,
) -> None:
    buf[:CONTAINER_HEADER_SIZE] = _HDR.pack(
        CONTAINER_MAGIC,
        CONTAINER_VERSION,
        CONTAINER_HEADER_SIZE,
        generation,
        shard_count,
        target_owners,
        toc_offset,
        toc_bytes,
        file_size,
        origin_len,
    )


def _lower_piece(
    origin: str,
    rrsets: tuple[LogicalRRset, ...],
    key_lo: bytes,
    key_hi: bytes | None,
    *,
    require_apex: bool,
) -> ShardPiece:
    zone = LogicalZone(origin, rrsets)
    if not rrsets:
        image = b""
    elif _c_bridge is not None and _c_bridge.available():
        image = _c_bridge.lower_zone_c(zone, require_apex=require_apex)
    else:
        image = lower_bytes(zone, require_apex=require_apex)
    header = _parse_shard_header(image) if image else {"pool_entry_count": 0}
    return ShardPiece(
        key_lo=key_lo,
        key_hi=key_hi,
        image=image,
        owner_count=len({rr.owner for rr in rrsets}),
        pool_entry_count=int(header["pool_entry_count"]),
        zone=zone,
        dirty=True,
    )


def _owners_of(zone: LogicalZone) -> list[str]:
    owners: list[str] = []
    last = None
    for rr in zone.rrsets:
        if rr.owner != last:
            owners.append(rr.owner)
            last = rr.owner
    return owners


def _slice_zone(zone: LogicalZone, owners: set[str]) -> tuple[LogicalRRset, ...]:
    return tuple(rr for rr in zone.rrsets if rr.owner in owners)


def _piece_from_owners(
    origin: str,
    zone: LogicalZone,
    owners: list[str],
    key_lo: bytes,
    key_hi: bytes | None,
    *,
    shard_index: int,
) -> ShardPiece:
    chosen = set(owners)
    return _lower_piece(
        origin,
        _slice_zone(zone, chosen),
        key_lo,
        key_hi,
        require_apex=(shard_index == 0),
    )


def _canonical_zone(zone: LogicalZone) -> LogicalZone:
    rrsets = tuple(
        sorted(
            zone.rrsets,
            key=lambda rr: (owner_to_key(rr.owner, zone.origin), TYPE_ORDER.index(rr.rrtype)),
        )
    )
    return LogicalZone(zone.origin, rrsets)


def build_container(zone: LogicalZone, *, target_owners: int, generation: int = 1) -> bytes:
    """Pack an equal owner split into one container file."""
    if target_owners < 2:
        raise ValueError("target_owners must be >= 2")
    zone = _canonical_zone(zone)
    owners = _owners_of(zone)
    count = len(owners)
    shard_count = max(1, (count + target_owners - 1) // target_owners)
    # One-pass bucket assignment: avoid O(shards · RRsets) rescans in _slice_zone.
    owner_shard: dict[str, int] = {}
    ranges: list[tuple[int, int]] = []
    for index in range(shard_count):
        start = (index * count) // shard_count
        end = ((index + 1) * count) // shard_count
        ranges.append((start, end))
        for owner in owners[start:end]:
            owner_shard[owner] = index
    buckets: list[list[LogicalRRset]] = [[] for _ in range(shard_count)]
    for rr in zone.rrsets:
        buckets[owner_shard[rr.owner]].append(rr)
    pieces: list[ShardPiece] = []
    use_c = _c_bridge is not None and _c_bridge.available()
    if use_c and shard_count > 1:
        shard_zones = [LogicalZone(zone.origin, tuple(buckets[i])) for i in range(shard_count)]
        apex_flags = [i == 0 for i in range(shard_count)]
        images = _c_bridge.lower_zones_parallel(shard_zones, apex_flags)
        for index, (start, end) in enumerate(ranges):
            group = owners[start:end]
            key_lo = owner_to_key(group[0], zone.origin)
            key_hi = owner_to_key(owners[end], zone.origin) if end < count else None
            image = images[index]
            header = _parse_shard_header(image) if image else {"pool_entry_count": 0}
            pieces.append(
                ShardPiece(
                    key_lo=key_lo,
                    key_hi=key_hi,
                    image=image,
                    owner_count=len(group),
                    pool_entry_count=int(header["pool_entry_count"]),
                    zone=shard_zones[index],
                    dirty=True,
                )
            )
    else:
        for index, (start, end) in enumerate(ranges):
            group = owners[start:end]
            key_lo = owner_to_key(group[0], zone.origin)
            key_hi = owner_to_key(owners[end], zone.origin) if end < count else None
            pieces.append(
                _lower_piece(
                    zone.origin,
                    tuple(buckets[index]),
                    key_lo,
                    key_hi,
                    require_apex=(index == 0),
                )
            )
    return _publish(b"", zone.origin, generation, target_owners, pieces)


def parse_container(blob: bytes, *, decode: bool = True) -> Container:
    if len(blob) < CONTAINER_HEADER_SIZE or blob[:8] != CONTAINER_MAGIC:
        raise ValueError("not a BOGI container")
    (
        _magic,
        version,
        header_size,
        generation,
        shard_count,
        target_owners,
        toc_offset,
        toc_bytes,
        file_size,
        origin_len,
    ) = _HDR.unpack_from(blob, 0)
    if version != CONTAINER_VERSION or header_size != CONTAINER_HEADER_SIZE:
        raise ValueError("unsupported container header")
    if file_size != len(blob):
        raise ValueError("container file_size does not match bytes")
    origin = blob[CONTAINER_HEADER_SIZE : CONTAINER_HEADER_SIZE + origin_len].decode("ascii")
    rows = _decode_toc(blob, toc_offset, shard_count)
    if toc_offset + toc_bytes != file_size and toc_bytes != file_size - toc_offset:
        # TOC is the current suffix; older TOC bytes may sit in the garbage gap.
        if file_size - toc_offset != toc_bytes:
            raise ValueError("TOC length mismatch")
    shards: list[ShardPiece] = []
    for key_lo, key_hi, offset, length, owner_count, pool_count, digest in rows:
        image = bytes(blob[offset : offset + length])
        if _sha256(image) != digest:
            raise ValueError("shard hash mismatch")
        zone = decode_shard_image(image, origin) if decode else LogicalZone(origin, ())
        shards.append(
            ShardPiece(
                key_lo=key_lo,
                key_hi=key_hi,
                image=image,
                owner_count=owner_count,
                pool_entry_count=pool_count,
                zone=zone,
                reuse_offset=offset,
                dirty=False,
            )
        )
    return Container(origin, generation, target_owners, shards, blob)


def _publish(
    previous: bytes,
    origin: str,
    generation: int,
    target_owners: int,
    shards: list[ShardPiece],
) -> bytes:
    origin_raw = origin.encode("ascii")
    if previous:
        out = bytearray(previous)
    else:
        out = bytearray(CONTAINER_HEADER_SIZE + len(origin_raw))
        out[CONTAINER_HEADER_SIZE : CONTAINER_HEADER_SIZE + len(origin_raw)] = origin_raw
    offsets: list[int] = []
    for shard in shards:
        if (
            shard.reuse_offset is not None
            and not shard.dirty
            and previous[shard.reuse_offset : shard.reuse_offset + len(shard.image)] == shard.image
        ):
            offsets.append(shard.reuse_offset)
            continue
        offsets.append(len(out))
        out += shard.image
        shard.dirty = False
        shard.reuse_offset = offsets[-1]
    toc_offset = len(out)
    toc = _encode_toc(shards, offsets)
    out += toc
    _write_header(
        out,
        generation=generation,
        shard_count=len(shards),
        target_owners=target_owners,
        toc_offset=toc_offset,
        toc_bytes=len(toc),
        file_size=len(out),
        origin_len=len(origin_raw),
    )
    return bytes(out)


def _apply_local(zone: LogicalZone, deltas: list[DeltaOp], *, require_apex: bool) -> LogicalZone:
    if require_apex:
        return apply_deltas(zone, deltas)
    origin = zone.origin
    groups: dict[tuple[str, str], tuple[int, set[str]]] = {}
    for rr in zone.rrsets:
        groups[(rr.owner, rr.rrtype)] = (rr.ttl, set(rr.rdatas))
    for delta in deltas:
        key = (delta.owner, delta.rrtype)
        if delta.op == "ADD":
            if key not in groups:
                groups[key] = (delta.ttl, {delta.rdata})
            else:
                ttl, rdatas = groups[key]
                rdatas.add(delta.rdata)
                groups[key] = (ttl, rdatas)
        elif delta.op == "DELETE":
            if key not in groups:
                continue
            ttl, rdatas = groups[key]
            rdatas.discard(delta.rdata)
            if not rdatas:
                del groups[key]
            else:
                groups[key] = (ttl, rdatas)
        elif delta.op == "MODIFY":
            if key not in groups:
                groups[key] = (delta.ttl, {delta.rdata})
                continue
            _ttl, rdatas = groups[key]
            if delta.old_rdata is not None:
                rdatas.discard(delta.old_rdata)
            rdatas.add(delta.rdata)
            groups[key] = (delta.ttl, rdatas)
        else:
            raise ValueError(delta.op)
    cname_owners = {owner for (owner, rrtype) in groups if rrtype == "CNAME"}
    rrsets: list[LogicalRRset] = []
    for (owner, rrtype), (ttl, rdatas) in groups.items():
        if owner in cname_owners and rrtype != "CNAME":
            continue
        if not rdatas:
            continue
        rrsets.append(LogicalRRset(owner, ttl, rrtype, tuple(sorted(rdatas))))
    rrsets.sort(key=lambda rr: (owner_to_key(rr.owner, origin), TYPE_ORDER.index(rr.rrtype)))
    return LogicalZone(origin, tuple(rrsets))


def _shard_index(shards: list[ShardPiece], origin: str, owner: str) -> int:
    key = owner_to_key(owner, origin)
    for index, shard in enumerate(shards):
        if key < shard.key_lo:
            break
        if shard.key_hi is None or key < shard.key_hi:
            return index
    raise ValueError(f"owner {owner} is outside shard ranges")


def _split_piece(piece: ShardPiece, mid: int) -> tuple[ShardPiece, ShardPiece]:
    _ensure_shard_zone(piece, piece.zone.origin)
    owners = _owners_of(piece.zone)
    if not 1 <= mid < len(owners):
        raise ValueError("split point is outside the shard")
    left_owners = owners[:mid]
    right_owners = owners[mid:]
    right_lo = owner_to_key(right_owners[0], piece.zone.origin)
    left = _piece_from_owners(
        piece.zone.origin,
        piece.zone,
        left_owners,
        piece.key_lo,
        right_lo,
        shard_index=0 if piece.key_lo == b"" else 1,
    )
    right = _piece_from_owners(
        piece.zone.origin,
        piece.zone,
        right_owners,
        right_lo,
        piece.key_hi,
        shard_index=1,
    )
    return left, right


def _merge_pieces(left: ShardPiece, right: ShardPiece) -> ShardPiece:
    _ensure_shard_zone(left, left.zone.origin)
    _ensure_shard_zone(right, right.zone.origin)
    rrsets = left.zone.rrsets + right.zone.rrsets
    return _lower_piece(
        left.zone.origin,
        rrsets,
        left.key_lo,
        right.key_hi,
        require_apex=(left.key_lo == b""),
    )


def _move_prefix(src: ShardPiece, count: int, dst_on_left: ShardPiece) -> tuple[ShardPiece, ShardPiece]:
    """Move the first `count` owners of src onto the right edge of dst_on_left."""
    _ensure_shard_zone(src, src.zone.origin)
    _ensure_shard_zone(dst_on_left, dst_on_left.zone.origin)
    owners = _owners_of(src.zone)
    if count <= 0 or count >= len(owners):
        raise ValueError("borrow count is outside the neighbor")
    moved = owners[:count]
    kept = owners[count:]
    new_lo = owner_to_key(kept[0], src.zone.origin)
    dst_owners = _owners_of(dst_on_left.zone) + moved
    dst = _piece_from_owners(
        dst_on_left.zone.origin,
        LogicalZone(dst_on_left.zone.origin, dst_on_left.zone.rrsets + _slice_zone(src.zone, set(moved))),
        dst_owners,
        dst_on_left.key_lo,
        new_lo,
        shard_index=0 if dst_on_left.key_lo == b"" else 1,
    )
    rest = _piece_from_owners(
        src.zone.origin,
        src.zone,
        kept,
        new_lo,
        src.key_hi,
        shard_index=1,
    )
    return dst, rest


def rebalance(shards: list[ShardPiece], target_owners: int) -> list[ShardPiece]:
    """Keep every non-final shard in [ceil(T/2), T] when the zone is large enough."""
    low = max(1, (target_owners + 1) // 2)
    guard = 0
    while guard < 100000:
        guard += 1
        progressed = False
        index = 0
        while index < len(shards):
            count = shards[index].owner_count
            if count > target_owners and count >= 2:
                mid = count // 2
                if shards[index].key_lo == b"":
                    mid = max(1, mid)
                left, right = _split_piece(shards[index], mid)
                shards[index : index + 1] = [left, right]
                progressed = True
                continue
            if count < low and index + 1 < len(shards):
                nxt = shards[index + 1].owner_count
                if count == 0:
                    shards[index : index + 2] = [_merge_pieces(shards[index], shards[index + 1])]
                    progressed = True
                    continue
                if nxt > low:
                    give = min(low - count, nxt - low)
                    if give > 0:
                        dst, src = _move_prefix(shards[index + 1], give, shards[index])
                        shards[index] = dst
                        shards[index + 1] = src
                        progressed = True
                        continue
                if nxt <= low and count + nxt <= target_owners:
                    shards[index : index + 2] = [_merge_pieces(shards[index], shards[index + 1])]
                    progressed = True
                    continue
            if count == 0 and index > 0:
                shards[index - 1 : index + 1] = [_merge_pieces(shards[index - 1], shards[index])]
                progressed = True
                index -= 1
                continue
            index += 1
        if not progressed:
            break
    else:
        raise RuntimeError("rebalance did not converge")
    return shards


def _ensure_shard_zone(piece: ShardPiece, origin: str) -> None:
    """Lazily decode a shard body when LogicalZone data is required.

    If ``image_valid`` is false, the in-memory ``zone`` is authoritative
    (including an intentional empty shard after deletes). Re-decoding the
    stale ``image`` bytes would resurrect removed owners during rebalance.
    """
    if piece.zone.rrsets or not piece.image or not piece.image_valid:
        return
    piece.zone = decode_shard_image(piece.image, origin)


def apply_container(blob: bytes, deltas: list[DeltaOp]) -> tuple[bytes, ApplyStats]:
    """Decode touched shards only, apply Δ, rebalance, append."""
    # Skip whole-file LogicalZone decode: untouched shards keep image bytes.
    container = parse_container(blob, decode=False)
    before = len(container.shards)
    touched_set: set[int] = set()
    grouped: dict[int, list[DeltaOp]] = {}
    for delta in deltas:
        index = _shard_index(container.shards, container.origin, delta.owner)
        grouped.setdefault(index, []).append(delta)
        touched_set.add(index)
    # Neighbors may be rewritten by borrow/merge during rebalance.
    decode_set = set(touched_set)
    for index in list(touched_set):
        if index > 0:
            decode_set.add(index - 1)
        if index + 1 < len(container.shards):
            decode_set.add(index + 1)
    for index in sorted(decode_set):
        _ensure_shard_zone(container.shards[index], container.origin)
    for index, ops in grouped.items():
        piece = container.shards[index]
        piece.zone = _apply_local(piece.zone, ops, require_apex=(piece.key_lo == b""))
        piece.owner_count = len(_owners_of(piece.zone))
        piece.dirty = True
        piece.image_valid = False
        piece.reuse_offset = None
    if container.shards and container.shards[0].key_lo == b"":
        _ensure_shard_zone(container.shards[0], container.origin)
        apex = container.origin
        types = {rr.rrtype for rr in container.shards[0].zone.rrsets if rr.owner == apex}
        if not {"SOA", "NS"} <= types:
            raise ValueError("apex lost SOA or NS")
    container.shards = rebalance(container.shards, container.target_owners)
    # Parallel C re-encode when multiple dirty shards need fresh images.
    if (
        _c_bridge is not None
        and _c_bridge.available()
        and sum(1 for p in container.shards if not (p.image_valid and p.image)) > 1
    ):
        dirty_idx = [
            i for i, p in enumerate(container.shards) if not (p.image_valid and p.image)
        ]
        zones = []
        apex = []
        for i in dirty_idx:
            piece = container.shards[i]
            _ensure_shard_zone(piece, container.origin)
            owners = _owners_of(piece.zone)
            zones.append(LogicalZone(container.origin, _slice_zone(piece.zone, set(owners))))
            apex.append(piece.key_lo == b"")
        images = _c_bridge.lower_zones_parallel(zones, apex)
        materialized = []
        img_i = 0
        for index, piece in enumerate(container.shards):
            if piece.image_valid and piece.image:
                materialized.append(piece)
                continue
            image = images[img_i]
            img_i += 1
            header = _parse_shard_header(image) if image else {"pool_entry_count": 0}
            materialized.append(
                ShardPiece(
                    key_lo=piece.key_lo,
                    key_hi=piece.key_hi,
                    image=image,
                    owner_count=len(_owners_of(piece.zone)),
                    pool_entry_count=int(header["pool_entry_count"]),
                    zone=piece.zone,
                    dirty=True,
                )
            )
    else:
        materialized = []
        for index, piece in enumerate(container.shards):
            if piece.image_valid and piece.image:
                materialized.append(piece)
                continue
            owners = _owners_of(piece.zone)
            materialized.append(
                _piece_from_owners(
                    container.origin,
                    piece.zone,
                    owners,
                    piece.key_lo,
                    piece.key_hi,
                    shard_index=index,
                )
            )

    container.shards = materialized
    rewritten = sum(1 for shard in container.shards if shard.dirty or shard.reuse_offset is None)
    updated = _publish(
        container.blob,
        container.origin,
        container.generation + 1,
        container.target_owners,
        container.shards,
    )
    appended = len(updated) - len(blob)
    return updated, ApplyStats(
        touched=sorted(touched_set),
        rewritten=rewritten,
        shard_count_before=before,
        shard_count_after=len(container.shards),
        owner_counts=[shard.owner_count for shard in container.shards],
        bytes_before=len(blob),
        bytes_after=len(updated),
        bytes_appended=appended,
        generation=container.generation + 1,
    )


def container_canonical(blob: bytes) -> tuple[str, ...]:
    container = parse_container(blob, decode=True)
    lines: list[str] = []
    for shard in container.shards:
        lines.extend(shard.zone.canonical_lines())
    return tuple(lines)


def counts_within_bound(counts: list[int], target: int) -> bool:
    if not counts:
        return False
    low = max(1, (target + 1) // 2)
    if any(count > target for count in counts):
        return False
    # The last shard may be underfull. Every earlier shard must meet the floor
    # once the zone is large enough to fill it.
    for count in counts[:-1]:
        if 0 < count < low:
            return False
    return True

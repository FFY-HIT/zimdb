"""Untrusted BOGI-v2.3 lowerer.

BOGI-v2.3 keeps the v2 owner-group stream and replaces the eager v2.2 pool
with a source-first-occurrence witnessed pool plus one restart per 16 entries.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ops.vendor.checked_image.p1 import LogicalRRset, LogicalZone

from .format_v23 import (
    BLOCK_SIZE,
    ENDIAN_MARKER,
    FLAGS,
    HEADER,
    HEADER_SIZE,
    MAGIC,
    PROFILE_ID,
    PROFILE_ID_DNSSEC,
    RESERVED0,
    RESERVED1,
    RESTART,
    SCHEMA_ID,
    TYPE_MASK_BYTES_DNSSEC,
    TYPE_ORDER,
    TYPE_ORDER_DNSSEC,
    TYPE_TO_BIT,
    TYPE_TO_BIT_DNSSEC,
    U32_MAX,
    VERSION_MAJOR,
    VERSION_MINOR,
    common_prefix_length,
    encode_uleb128,
    owner_to_key,
)


@dataclass(frozen=True)
class SectionAttribution:
    header_bytes: int
    origin_bytes: int
    owner_restart_bytes: int
    owner_stream_bytes: int
    pool_restart_bytes: int
    pool_data_bytes: int
    whole_file_bytes: int
    uncompressed_owner_key_bytes: int
    front_coded_key_bytes: int
    unique_rdata_count: int
    rdata_ref_count: int

    def as_dict(self) -> dict[str, int]:
        return {
            "header_bytes": self.header_bytes,
            "origin_bytes": self.origin_bytes,
            "owner_restart_bytes": self.owner_restart_bytes,
            "owner_stream_bytes": self.owner_stream_bytes,
            "pool_restart_bytes": self.pool_restart_bytes,
            "pool_data_bytes": self.pool_data_bytes,
            "whole_file_bytes": self.whole_file_bytes,
            "uncompressed_owner_key_bytes": self.uncompressed_owner_key_bytes,
            "front_coded_key_bytes": self.front_coded_key_bytes,
            "unique_rdata_count": self.unique_rdata_count,
            "rdata_ref_count": self.rdata_ref_count,
        }


@dataclass(frozen=True)
class LoweredImage:
    image: bytes
    attribution: SectionAttribution


def _owner_groups(
    zone: LogicalZone,
) -> tuple[tuple[str, tuple[LogicalRRset, ...]], ...]:
    groups: list[tuple[str, tuple[LogicalRRset, ...]]] = []
    cursor = 0
    while cursor < len(zone.rrsets):
        owner = zone.rrsets[cursor].owner
        end = cursor + 1
        while end < len(zone.rrsets) and zone.rrsets[end].owner == owner:
            end += 1
        groups.append((owner, zone.rrsets[cursor:end]))
        cursor = end
    return tuple(groups)


def _build_pool(
    zone: LogicalZone,
) -> tuple[dict[bytes, int], bytes, bytes, int]:
    first_occurrence: dict[bytes, tuple[int, int]] = {}
    rdata_ref_count = 0
    for rrset_ordinal, rrset in enumerate(zone.rrsets):
        for rdata_ordinal, text in enumerate(rrset.rdatas):
            raw = text.encode("utf-8")
            if not raw:
                raise ValueError("canonical P1 RDATA must be non-empty")
            first_occurrence.setdefault(raw, (rrset_ordinal, rdata_ordinal))
            rdata_ref_count += 1

    ordered = sorted(first_occurrence)
    if not ordered:
        raise ValueError("BOGI requires at least one RDATA pool entry")
    id_of = {raw: ordinal for ordinal, raw in enumerate(ordered)}
    pool_data = bytearray()
    pool_restart_offsets: list[int] = []
    for ordinal, raw in enumerate(ordered):
        if ordinal % BLOCK_SIZE == 0:
            pool_restart_offsets.append(len(pool_data))
        rrset_ordinal, rdata_ordinal = first_occurrence[raw]
        pool_data.extend(encode_uleb128(rrset_ordinal))
        pool_data.extend(encode_uleb128(rdata_ordinal))
        pool_data.extend(encode_uleb128(len(raw)))
        pool_data.extend(raw)
    pool_restarts = b"".join(
        RESTART.pack(offset) for offset in pool_restart_offsets
    )
    return id_of, pool_restarts, bytes(pool_data), rdata_ref_count


def _encode_body(
    rrsets: tuple[LogicalRRset, ...], id_of: dict[bytes, int]
) -> bytes:
    if not rrsets:
        raise ValueError("an owner group must contain at least one RRset")
    by_type: dict[str, LogicalRRset] = {}
    for rrset in rrsets:
        if rrset.rrtype not in TYPE_TO_BIT:
            raise ValueError(f"RR type is outside frozen P1: {rrset.rrtype}")
        if rrset.rrtype in by_type:
            raise ValueError(f"duplicate RRset type at owner: {rrset.rrtype}")
        if not 0 <= rrset.ttl <= U32_MAX:
            raise ValueError("TTL is outside uint32")
        if not rrset.rdatas:
            raise ValueError("RRset must contain at least one RDATA")
        raw_rdatas = tuple(text.encode("utf-8") for text in rrset.rdatas)
        if any(not raw for raw in raw_rdatas):
            raise ValueError("canonical P1 RDATA must be non-empty")
        if any(left >= right for left, right in zip(raw_rdatas, raw_rdatas[1:])):
            raise ValueError("RDATA must be strictly ordered without duplicates")
        by_type[rrset.rrtype] = rrset

    mask = sum(TYPE_TO_BIT[rrtype] for rrtype in by_type)
    body = bytearray((mask,))
    for rrtype in TYPE_ORDER:
        rrset = by_type.get(rrtype)
        if rrset is None:
            continue
        body.extend(encode_uleb128(rrset.ttl))
        body.extend(encode_uleb128(len(rrset.rdatas)))
        prior_id: int | None = None
        for text in rrset.rdatas:
            rid = id_of[text.encode("utf-8")]
            if prior_id is not None and rid <= prior_id:
                raise ValueError("RDATA IDs must be strictly increasing within an RRset")
            body.extend(encode_uleb128(rid))
            prior_id = rid
    return bytes(body)


def _encode_body_dnssec(
    rrsets: tuple[LogicalRRset, ...], id_of: dict[bytes, int]
) -> bytes:
    """Owner-body encoder for the DNSSEC-capable type profile (u16 mask)."""

    if not rrsets:
        raise ValueError("an owner group must contain at least one RRset")
    by_type: dict[str, LogicalRRset] = {}
    for rrset in rrsets:
        if rrset.rrtype not in TYPE_TO_BIT_DNSSEC:
            raise ValueError(f"RR type is outside DNSSEC profile: {rrset.rrtype}")
        if rrset.rrtype in by_type:
            raise ValueError(f"duplicate RRset type at owner: {rrset.rrtype}")
        if not 0 <= rrset.ttl <= U32_MAX:
            raise ValueError("TTL is outside uint32")
        if not rrset.rdatas:
            raise ValueError("RRset must contain at least one RDATA")
        raw_rdatas = tuple(text.encode("utf-8") for text in rrset.rdatas)
        if any(not raw for raw in raw_rdatas):
            raise ValueError("canonical RDATA must be non-empty")
        if any(left >= right for left, right in zip(raw_rdatas, raw_rdatas[1:])):
            raise ValueError("RDATA must be strictly ordered without duplicates")
        by_type[rrset.rrtype] = rrset

    mask = sum(TYPE_TO_BIT_DNSSEC[rrtype] for rrtype in by_type)
    body = bytearray(mask.to_bytes(TYPE_MASK_BYTES_DNSSEC, "little"))
    for rrtype in TYPE_ORDER_DNSSEC:
        rrset = by_type.get(rrtype)
        if rrset is None:
            continue
        body.extend(encode_uleb128(rrset.ttl))
        body.extend(encode_uleb128(len(rrset.rdatas)))
        prior_id: int | None = None
        for text in rrset.rdatas:
            rid = id_of[text.encode("utf-8")]
            if prior_id is not None and rid <= prior_id:
                raise ValueError("RDATA IDs must be strictly increasing within an RRset")
            body.extend(encode_uleb128(rid))
            prior_id = rid
    return bytes(body)


def lower_bytes_with_attribution(
    zone: LogicalZone,
    *,
    require_apex: bool = True,
    profile: str = "p1",
) -> LoweredImage:
    """Lower a LogicalZone to BOGI-v2.3.

    profile:
      - \"p1\": seven types, 1-byte mask, PROFILE_ID
      - \"dnssec\": TYPE_ORDER_DNSSEC, u16 mask, PROFILE_ID_DNSSEC
    """
    if profile not in {"p1", "dnssec"}:
        raise ValueError(f"unknown profile {profile!r}")
    dnssec = profile == "dnssec"
    profile_id = PROFILE_ID_DNSSEC if dnssec else PROFILE_ID
    encode_body = _encode_body_dnssec if dnssec else _encode_body

    try:
        origin = zone.origin.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("origin must be ASCII") from exc
    if (
        not 1 <= len(origin) <= 254
        or not zone.origin.endswith(".")
        or any(0x41 <= byte <= 0x5A for byte in origin)
    ):
        raise ValueError("origin is outside the frozen P1 header grammar")

    groups = _owner_groups(zone)
    if not groups:
        raise ValueError("BOGI requires at least one owner")
    if require_apex:
        if groups[0][0] != zone.origin:
            raise ValueError("owner zero must be the apex")
        apex_types = {rrset.rrtype for rrset in groups[0][1]}
        if not {"SOA", "NS"} <= apex_types:
            raise ValueError("apex must contain SOA and NS")

    id_of, pool_restarts, pool_data, rdata_ref_count = _build_pool(zone)

    owner_stream = bytearray()
    owner_restart_offsets: list[int] = []
    prior_key = b""
    uncompressed_key_bytes = 0
    front_coded_key_bytes = 0
    for ordinal, (owner, rrsets) in enumerate(groups):
        key = owner_to_key(owner, zone.origin)
        if ordinal and key <= prior_key:
            raise ValueError("owner groups are not in canonical strict order")
        full_key_encoding = encode_uleb128(len(key)) + key
        uncompressed_key_bytes += len(full_key_encoding)
        if ordinal % BLOCK_SIZE == 0:
            owner_restart_offsets.append(len(owner_stream))
            key_encoding = full_key_encoding
        else:
            shared = common_prefix_length(prior_key, key)
            suffix = key[shared:]
            key_encoding = (
                encode_uleb128(shared)
                + encode_uleb128(len(suffix))
                + suffix
            )
        front_coded_key_bytes += len(key_encoding)
        owner_stream.extend(key_encoding)
        body = encode_body(rrsets, id_of)
        owner_stream.extend(encode_uleb128(len(body)))
        owner_stream.extend(body)
        prior_key = key

    owner_restarts = b"".join(
        RESTART.pack(offset) for offset in owner_restart_offsets
    )
    owner_count = len(groups)
    owner_restart_count = (owner_count + BLOCK_SIZE - 1) // BLOCK_SIZE
    pool_entry_count = len(id_of)
    pool_restart_count = (pool_entry_count + BLOCK_SIZE - 1) // BLOCK_SIZE
    if len(owner_restarts) != owner_restart_count * RESTART.size:
        raise AssertionError("internal owner restart-count mismatch")
    if len(pool_restarts) != pool_restart_count * RESTART.size:
        raise AssertionError("internal pool restart-count mismatch")

    origin_off = HEADER_SIZE
    restart_off = origin_off + len(origin)
    stream_off = restart_off + len(owner_restarts)
    pool_restart_off = stream_off + len(owner_stream)
    pool_off = pool_restart_off + len(pool_restarts)
    file_size = pool_off + len(pool_data)
    header = HEADER.pack(
        MAGIC,
        VERSION_MAJOR,
        VERSION_MINOR,
        ENDIAN_MARKER,
        HEADER_SIZE,
        SCHEMA_ID,
        profile_id,
        FLAGS,
        BLOCK_SIZE,
        RESERVED0,
        file_size,
        origin_off,
        len(origin),
        restart_off,
        owner_restart_count,
        stream_off,
        len(owner_stream),
        owner_count,
        len(zone.rrsets),
        rdata_ref_count,
        pool_entry_count,
        RESERVED1,
    )
    image = (
        header
        + origin
        + owner_restarts
        + bytes(owner_stream)
        + pool_restarts
        + pool_data
    )
    if len(image) != file_size:
        raise AssertionError("internal file-size mismatch")
    return LoweredImage(
        image,
        SectionAttribution(
            header_bytes=HEADER_SIZE,
            origin_bytes=len(origin),
            owner_restart_bytes=len(owner_restarts),
            owner_stream_bytes=len(owner_stream),
            pool_restart_bytes=len(pool_restarts),
            pool_data_bytes=len(pool_data),
            whole_file_bytes=file_size,
            uncompressed_owner_key_bytes=uncompressed_key_bytes,
            front_coded_key_bytes=front_coded_key_bytes,
            unique_rdata_count=pool_entry_count,
            rdata_ref_count=rdata_ref_count,
        ),
    )


def lower_bytes(
    zone: LogicalZone, *, require_apex: bool = True, profile: str = "p1"
) -> bytes:
    return lower_bytes_with_attribution(
        zone, require_apex=require_apex, profile=profile
    ).image


def lower_file(
    zone: LogicalZone, output: str | Path, *, profile: str = "p1"
) -> Path:
    path = Path(output)
    path.write_bytes(lower_bytes(zone, profile=profile))
    return path


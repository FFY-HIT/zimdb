"""Declarative constants and encoding helpers for BOGI-v2.3.

The checker and readers are expected to implement their own trust-boundary
parsing.  This module deliberately contains only the physical-format constants
and deterministic helpers needed by an untrusted lowerer.
"""

from __future__ import annotations

import struct


MAGIC = b"BOGIP1\0\0"
VERSION_MAJOR = 2
VERSION_MINOR = 3
ENDIAN_MARKER = 0x4C45
HEADER_SIZE = 128
SCHEMA_ID = 0x424F4704
PROFILE_ID = 0x50310001  # P1 seven types, 1-byte mask
PROFILE_ID_DNSSEC = 0x50310002  # P1+DNSSEC, u16 mask (TYPE_ORDER_DNSSEC)
FLAGS = 0
BLOCK_SIZE = 16
RESERVED0 = 0
RESERVED1 = 0
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1
MAX_KEY_BYTES = 253
MAX_ULEB_BYTES = 10

TYPE_ORDER = ("A", "NS", "CNAME", "SOA", "MX", "TXT", "AAAA")
TYPE_TO_BIT = {rrtype: 1 << index for index, rrtype in enumerate(TYPE_ORDER)}
BIT_TO_TYPE = {bit: rrtype for rrtype, bit in TYPE_TO_BIT.items()}
KNOWN_TYPE_MASK = sum(TYPE_TO_BIT.values())

# DNSSEC-capable profile (opt-in): same layout as v2.3 but with a u16 type
# mask and the following types appended after the P1 seven.  Used by the
# .com+DNSSEC size experiment; not the default P1 wire profile.
TYPE_ORDER_DNSSEC = TYPE_ORDER + (
    "DS",
    "RRSIG",
    "NSEC3",
    "DNSKEY",
    "NSEC3PARAM",
)
TYPE_TO_BIT_DNSSEC = {
    rrtype: 1 << index for index, rrtype in enumerate(TYPE_ORDER_DNSSEC)
}
TYPE_MASK_BYTES_DNSSEC = (len(TYPE_ORDER_DNSSEC) + 7) // 8  # 2
assert TYPE_MASK_BYTES_DNSSEC == 2

# Bytes 0..111 retain the v2.2 header meanings.  Offset 112 is the number of
# unique lexical pool entries; offset 120 is a reserved-zero uint64.  Pool
# section positions are derived from stream_off, stream_len, U, and K=16.
HEADER = struct.Struct("<8sHHHHIIIHHQQQQQQQQQQQQ")
RESTART = struct.Struct("<Q")

HEADER_FIELD_NAMES = (
    "magic",
    "version_major",
    "version_minor",
    "endian",
    "header_size",
    "schema_id",
    "profile_id",
    "flags",
    "block_size",
    "reserved0",
    "file_size",
    "origin_off",
    "origin_len",
    "restart_off",
    "restart_count",
    "stream_off",
    "stream_len",
    "owner_count",
    "rrset_count",
    "rdata_count",
    "pool_entry_count",
    "reserved1",
)

assert HEADER.size == HEADER_SIZE
assert RESTART.size == 8


def parse_header(buffer: bytes | bytearray | memoryview) -> dict[str, object]:
    """Unpack a complete header without applying trust checks."""

    return dict(zip(HEADER_FIELD_NAMES, HEADER.unpack_from(buffer, 0), strict=True))


# Small-value cache: hot path in lowerer/pool encoding.
_ULEB_CACHE = tuple(
    bytes((v,)) if v < 0x80 else bytes((0x80 | (v & 0x7F), v >> 7)) for v in range(512)
)


def encode_uleb128(value: int) -> bytes:
    """Return the unique shortest-form unsigned LEB128 encoding."""

    if value.__class__ is not int or not 0 <= value <= U64_MAX:
        raise ValueError("uLEB128 value is outside uint64")
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


def common_prefix_length(left: bytes, right: bytes) -> int:
    """Return the bytewise maximal common-prefix length."""

    limit = min(len(left), len(right))
    position = 0
    while position < limit and left[position] == right[position]:
        position += 1
    return position


# Map ASCII bytes to BOGI key bytes (byte+1); invalid bytes stay 0 for a fast reject.
_KEY_PLUS1 = bytes((b + 1) if b < 0x80 and not (0x41 <= b <= 0x5A) else 0 for b in range(256))


def owner_to_key(owner: str, origin: str) -> bytes:
    """Encode a canonical absolute owner as a control-safe BOGI key."""

    if owner == origin:
        return b""
    suffix = "." + origin
    if not owner.endswith(suffix):
        raise ValueError("owner is outside origin")
    relative = owner[: -len(suffix)]
    labels = relative.split(".")
    if not labels or any(not label for label in labels):
        raise ValueError("owner contains an empty relative label")
    encoded = bytearray()
    for label in reversed(labels):
        try:
            raw = label.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("owner labels must be ASCII") from exc
        if not 1 <= len(raw) <= 63:
            raise ValueError("owner label is outside the BOGI key grammar")
        mapped = raw.translate(_KEY_PLUS1)
        if 0 in mapped:
            raise ValueError("owner label is outside the BOGI key grammar")
        encoded.extend(mapped)
        encoded.append(0)
    if len(encoded) > MAX_KEY_BYTES:
        raise ValueError("encoded owner key exceeds 253 bytes")
    return bytes(encoded)


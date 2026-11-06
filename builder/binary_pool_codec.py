#!/usr/bin/env python3
"""Typed binary pool codec for BOGIP1 DNSSEC images (header flags bit 0x4)."""
from __future__ import annotations

import base64
import binascii
import ipaddress
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ops.vendor.compact_image_v23.format_v23 import (  # noqa: E402
    TYPE_ORDER_DNSSEC,
    encode_uleb128,
)

FLAG_BINARY_POOL = 0x4

TAG_UTF8 = 0
TAG_A = 1
TAG_AAAA = 2
TAG_SOA = 3
TAG_MX = 4
TAG_DS = 5
TAG_DNSKEY = 6
TAG_RRSIG = 7
TAG_NSEC3 = 8
TAG_NSEC3PARAM = 9
TAG_NS = 10
TAG_TXT = 11

TYPE_INDEX = {t: i for i, t in enumerate(TYPE_ORDER_DNSSEC)}
RRTYPE_NUM = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "DS": 43, "RRSIG": 46, "NSEC": 47,
    "DNSKEY": 48, "NSEC3": 50, "NSEC3PARAM": 51,
}
NUM_RRTYPE = {v: k for k, v in RRTYPE_NUM.items()}


def _uleb_read(buf, off: int):
    val = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        val |= (b & 0x7F) << shift
        if b < 0x80:
            return val, off
        shift += 7


def _put_name(name: str) -> bytes:
    raw = name.encode("ascii")
    return encode_uleb128(len(raw)) + raw


def _get_name(buf, off: int):
    n, off = _uleb_read(buf, off)
    return bytes(buf[off : off + n]).decode("ascii"), off + n


def b32hex_decode(label: str) -> bytes:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    s = "".join(c for c in label.strip().upper() if c in alphabet)
    bits = "".join(f"{alphabet.index(c):05b}" for c in s)
    cut = len(bits) - (len(bits) % 8)
    bits = bits[:cut]
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def b32hex_encode(raw: bytes) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    bits = "".join(f"{b:08b}" for b in raw)
    while len(bits) % 5:
        bits += "0"
    return "".join(alphabet[int(bits[i : i + 5], 2)] for i in range(0, len(bits), 5))


def _types_mask(types):
    m = 0
    for t in types:
        if t in TYPE_INDEX:
            m |= 1 << TYPE_INDEX[t]
    return m


def _types_from_mask(m: int):
    return [t for i, t in enumerate(TYPE_ORDER_DNSSEC) if m & (1 << i)]


def pack_rdata(rrtype: str, text: str) -> bytes:
    if rrtype == "A":
        return bytes([TAG_A]) + ipaddress.IPv4Address(text.strip()).packed
    if rrtype == "AAAA":
        return bytes([TAG_AAAA]) + ipaddress.IPv6Address(text.strip()).packed
    if rrtype == "SOA":
        toks = text.split()
        return (
            bytes([TAG_SOA])
            + _put_name(toks[0].lower())
            + _put_name(toks[1].lower())
            + struct.pack("!5I", *[int(x) for x in toks[2:7]])
        )
    if rrtype == "MX":
        toks = text.split(None, 1)
        return bytes([TAG_MX]) + struct.pack("!H", int(toks[0])) + _put_name(toks[1].lower())
    if rrtype == "DS":
        toks = text.split()
        return (
            bytes([TAG_DS])
            + struct.pack("!HBB", int(toks[0]), int(toks[1]), int(toks[2]))
            + binascii.unhexlify(toks[3])
        )
    if rrtype == "DNSKEY":
        toks = text.split()
        return (
            bytes([TAG_DNSKEY])
            + struct.pack("!HBB", int(toks[0]), int(toks[1]), int(toks[2]))
            + base64.b64decode("".join(toks[3:]), validate=False)
        )
    if rrtype == "RRSIG":
        toks = text.split()
        covered = toks[0].upper()
        alg, labels, orig_ttl = int(toks[1]), int(toks[2]), int(toks[3])
        expire, inception = int(toks[4]), int(toks[5])
        keytag = int(toks[6])
        signer = toks[7].lower()
        if not signer.endswith("."):
            signer += "."
        sig = base64.b64decode("".join(toks[8:]), validate=False)
        if covered in RRTYPE_NUM:
            cov_num, cov_extra = RRTYPE_NUM[covered], bytes([0])
        elif covered.startswith("TYPE") and covered[4:].isdigit():
            cov_num, cov_extra = int(covered[4:]) & 0xFFFF, bytes([0])
        else:
            cov_num, cov_extra = 0, bytes([1]) + _put_name(covered)
        return (
            bytes([TAG_RRSIG])
            + struct.pack("!H", cov_num)
            + cov_extra
            + struct.pack("!BB", alg & 0xFF, labels & 0xFF)
            + struct.pack("!I", orig_ttl)
            + struct.pack("!QQ", expire, inception)
            + struct.pack("!H", keytag)
            + _put_name(signer)
            + encode_uleb128(len(sig))
            + sig
        )
    if rrtype == "NSEC3":
        toks = text.split()
        alg, flags, iters = int(toks[0]), int(toks[1]), int(toks[2])
        salt_s, next_lab = toks[3], toks[4]
        type_names = [t.upper() for t in toks[5:]]
        salt = b"" if salt_s == "-" else binascii.unhexlify(salt_s)
        nxt = b32hex_decode(next_lab)
        mask = _types_mask(type_names)
        body = bytearray(
            bytes([TAG_NSEC3])
            + struct.pack("!BBH", alg, flags, iters)
            + bytes([len(salt)])
            + salt
            + encode_uleb128(len(nxt))
            + nxt
            + struct.pack("!H", mask)
        )
        if b32hex_encode(nxt) == next_lab.upper():
            body.append(0)
        else:
            body.append(1)
            body.extend(_put_name(next_lab))
        if _types_from_mask(mask) == type_names:
            body.append(0)
        else:
            body.append(1)
            body.extend(_put_name(" ".join(type_names)))
        return bytes(body)
    if rrtype == "NSEC3PARAM":
        toks = text.split()
        salt_s = toks[3] if len(toks) > 3 else "-"
        salt = b"" if salt_s == "-" else binascii.unhexlify(salt_s)
        return (
            bytes([TAG_NSEC3PARAM])
            + struct.pack("!BBH", int(toks[0]), int(toks[1]), int(toks[2]))
            + bytes([len(salt)])
            + salt
        )
    if rrtype in {"NS", "CNAME", "PTR"}:
        return bytes([TAG_NS]) + _put_name(text.strip().lower())
    if rrtype == "TXT":
        raw = text.encode("utf-8")
        return bytes([TAG_TXT]) + encode_uleb128(len(raw)) + raw
    return bytes([TAG_UTF8]) + text.encode("utf-8")


def unpack_rdata(payload: bytes) -> str:
    if not payload:
        return ""
    tag, b = payload[0], payload[1:]
    if tag == TAG_UTF8:
        return b.decode("utf-8")
    if tag == TAG_A:
        return str(ipaddress.IPv4Address(b))
    if tag == TAG_AAAA:
        return str(ipaddress.IPv6Address(b))
    if tag == TAG_SOA:
        off = 0
        mname, off = _get_name(b, off)
        rname, off = _get_name(b, off)
        nums = struct.unpack_from("!5I", b, off)
        return f"{mname} {rname} {nums[0]} {nums[1]} {nums[2]} {nums[3]} {nums[4]}"
    if tag == TAG_MX:
        pref = struct.unpack_from("!H", b, 0)[0]
        exch, _ = _get_name(b, 2)
        return f"{pref} {exch}"
    if tag == TAG_DS:
        keytag, alg, digt = struct.unpack_from("!HBB", b, 0)
        return f"{keytag} {alg} {digt} {binascii.hexlify(b[4:]).decode()}"
    if tag == TAG_DNSKEY:
        flags, proto, alg = struct.unpack_from("!HBB", b, 0)
        return f"{flags} {proto} {alg} {base64.b64encode(b[4:]).decode()}"
    if tag == TAG_RRSIG:
        off = 0
        cov_num = struct.unpack_from("!H", b, off)[0]
        off += 2
        if b[off] == 0:
            off += 1
            covered = NUM_RRTYPE.get(cov_num, f"TYPE{cov_num}")
        else:
            off += 1
            covered, off = _get_name(b, off)
        alg, labels = struct.unpack_from("!BB", b, off)
        off += 2
        orig_ttl = struct.unpack_from("!I", b, off)[0]
        off += 4
        expire, inception = struct.unpack_from("!QQ", b, off)
        off += 16
        keytag = struct.unpack_from("!H", b, off)[0]
        off += 2
        signer, off = _get_name(b, off)
        slen, off = _uleb_read(b, off)
        sig = base64.b64encode(b[off : off + slen]).decode()
        return (
            f"{covered} {alg} {labels} {orig_ttl} {expire} {inception} "
            f"{keytag} {signer} {sig}"
        )
    if tag == TAG_NSEC3:
        off = 0
        alg, flags, iters = struct.unpack_from("!BBH", b, off)
        off += 4
        sl = b[off]
        off += 1
        salt_b = b[off : off + sl]
        off += sl
        nl, off = _uleb_read(b, off)
        nxt = b[off : off + nl]
        off += nl
        mask = struct.unpack_from("!H", b, off)[0]
        off += 2
        if b[off] == 0:
            next_lab = b32hex_encode(nxt)
            off += 1
        else:
            off += 1
            next_lab, off = _get_name(b, off)
        if b[off] == 0:
            types = " ".join(_types_from_mask(mask))
            off += 1
        else:
            off += 1
            types, off = _get_name(b, off)
        salt = "-" if not salt_b else binascii.hexlify(salt_b).decode()
        return f"{alg} {flags} {iters} {salt} {next_lab} {types}"
    if tag == TAG_NSEC3PARAM:
        alg, flags, iters = struct.unpack_from("!BBH", b, 0)
        sl = b[4]
        salt_b = b[5 : 5 + sl]
        salt = "-" if not salt_b else binascii.hexlify(salt_b).decode()
        return f"{alg} {flags} {iters} {salt}"
    if tag == TAG_NS:
        return _get_name(b, 0)[0]
    if tag == TAG_TXT:
        n, off = _uleb_read(b, 0)
        return bytes(b[off : off + n]).decode("utf-8")
    return b.decode("utf-8", "replace")

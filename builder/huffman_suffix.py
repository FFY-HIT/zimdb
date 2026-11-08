#!/usr/bin/env python3
"""Huffman coding for BOGI front-coded owner-key suffixes."""
from __future__ import annotations

import heapq
from collections import Counter


class _HNode:
    __slots__ = ("freq", "byte", "left", "right")

    def __init__(self, freq, byte=None, left=None, right=None):
        self.freq = freq
        self.byte = byte
        self.left = left
        self.right = right

    def __lt__(self, other):
        return self.freq < other.freq


def build_codes(corpus: list[bytes]) -> dict[int, str]:
    freq: Counter[int] = Counter()
    for s in corpus:
        freq.update(s)
    if not freq:
        return {}
    heap: list[tuple[int, int, _HNode]] = []
    uid = 0
    for b, c in freq.items():
        heapq.heappush(heap, (c, uid, _HNode(c, byte=b)))
        uid += 1
    if len(heap) == 1:
        return {heap[0][2].byte: "0"}
    while len(heap) > 1:
        c1, _, a = heapq.heappop(heap)
        c2, _, b = heapq.heappop(heap)
        parent = _HNode(c1 + c2, left=a, right=b)
        heapq.heappush(heap, (parent.freq, uid, parent))
        uid += 1
    root = heap[0][2]
    codes: dict[int, str] = {}

    def walk(n: _HNode, pref: str) -> None:
        if n.byte is not None:
            codes[n.byte] = pref or "0"
            return
        walk(n.left, pref + "0")
        walk(n.right, pref + "1")

    walk(root, "")
    return codes


def table_wire(codes: dict[int, str]) -> bytes:
    """u16 n; then (u8 symbol, u8 bitlen, packed MSB-first code bits)."""
    out = bytearray()
    out.extend(len(codes).to_bytes(2, "little"))
    for b, code in sorted(codes.items()):
        out.append(b & 0xFF)
        out.append(len(code) & 0xFF)
        acc = 0
        bits = 0
        packed = bytearray()
        for ch in code:
            acc = (acc << 1) | (1 if ch == "1" else 0)
            bits += 1
            if bits == 8:
                packed.append(acc)
                acc = 0
                bits = 0
        if bits:
            packed.append(acc << (8 - bits))
        out.extend(packed)
    return bytes(out)


def table_from_wire(buf: bytes, off: int = 0) -> tuple[dict[str, int], int]:
    """Return inverse map code_bits->symbol and new offset."""
    n = int.from_bytes(buf[off : off + 2], "little")
    off += 2
    inv: dict[str, int] = {}
    for _ in range(n):
        sym = buf[off]
        off += 1
        bitlen = buf[off]
        off += 1
        nbytes = (bitlen + 7) // 8
        packed = buf[off : off + nbytes]
        off += nbytes
        bits = []
        for byte in packed:
            for i in range(7, -1, -1):
                bits.append("1" if (byte >> i) & 1 else "0")
        code = "".join(bits[:bitlen])
        inv[code] = sym
    return inv, off


def encode_uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def encode_suffix(plain: bytes, codes: dict[int, str]) -> bytes:
    """uleb(plain_len) + bit-packed Huffman codes (MSB first)."""
    if not plain:
        return encode_uleb(0)
    if not codes:
        return encode_uleb(len(plain)) + plain
    bits = 0
    acc = 0
    out = bytearray()
    for b in plain:
        for ch in codes[b]:
            acc = (acc << 1) | (1 if ch == "1" else 0)
            bits += 1
            if bits == 8:
                out.append(acc)
                acc = 0
                bits = 0
    if bits:
        out.append(acc << (8 - bits))
    return encode_uleb(len(plain)) + bytes(out)


def decode_suffix(blob: bytes, inv: dict[str, int]) -> bytes:
    # read uleb plain len
    shift = 0
    val = 0
    off = 0
    while True:
        b = blob[off]
        off += 1
        val |= (b & 0x7F) << shift
        if b < 0x80:
            break
        shift += 7
    plain_len = val
    if plain_len == 0:
        return b""
    if not inv:
        return blob[off : off + plain_len]
    bitstr = []
    for byte in blob[off:]:
        for i in range(7, -1, -1):
            bitstr.append("1" if (byte >> i) & 1 else "0")
    out = bytearray()
    i = 0
    while len(out) < plain_len:
        matched = False
        for L in range(1, 64):
            if i + L > len(bitstr):
                break
            frag = "".join(bitstr[i : i + L])
            if frag in inv:
                out.append(inv[frag])
                i += L
                matched = True
                break
        if not matched:
            raise ValueError("huffman decode stuck")
    return bytes(out)

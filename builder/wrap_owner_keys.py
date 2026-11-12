#!/usr/bin/env python3
"""Streaming physical per-owner compression for original BOGIP1 images.

The production zone builder is unchanged. This tool preserves every logical
input byte, front-coding restart and pool ID. See FORMAT_SPEC.json for v2.
"""
from __future__ import annotations

import argparse
from collections import Counter
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
import zlib

INNER = struct.Struct('<8sHHHHIIIHH12Q')
OUTER = struct.Struct('<8sHHI14Q')
DESC = struct.Struct('<6Q4I')
MAGIC = b'ZIMBC01\0'
PROFILE = 0x50310002
CODECS = {'none': 0, 'snappy': 1, 'lz4': 4}
NAMES = {value: key for key, value in CODECS.items()}
STRIDE = 16
MAX_KEY = 253
MAX_COMPRESSED_RAW = 64 << 20
COPY_BYTES = 1 << 20


class FormatError(ValueError):
    pass


def uleb(value):
    if not 0 <= value <= (1 << 64)-1:
        raise FormatError('unsigned LEB128 value outside uint64')
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def exact(handle, length):
    if length < 0:
        raise FormatError('negative read length')
    data = handle.read(length)
    if len(data) != length:
        raise FormatError('truncated input')
    return data


def varint(handle, end):
    out = bytearray()
    value = 0
    for number in range(10):
        if handle.tell() >= end:
            raise FormatError('truncated unsigned LEB128')
        raw = exact(handle, 1)[0]
        out.append(raw)
        if number == 9 and raw > 1:
            raise FormatError('overflowing unsigned LEB128')
        value |= (raw & 127) << (number*7)
        if raw < 128:
            if bytes(out) != uleb(value):
                raise FormatError('noncanonical unsigned LEB128')
            return value
    raise FormatError('overflowing unsigned LEB128')


def sha(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def save(path, document):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(document, indent=2) + '\n')
    temporary.replace(path)


def copy_range(source, target, offset, length, digest=None, crc=0):
    source.seek(offset)
    left = length
    while left:
        chunk = exact(source, min(COPY_BYTES, left))
        if target is not None:
            target.write(chunk)
        if digest is not None:
            digest.update(chunk)
        crc = zlib.crc32(chunk, crc)
        left -= len(chunk)
    return crc & 0xffffffff


def inner_metadata(raw, actual_size=None):
    if len(raw) != INNER.size:
        raise FormatError('truncated original header')
    h = INNER.unpack(raw)
    if (h[0] != b'BOGIP1\0\0' or h[1:6] != (2, 3, 0x4c45, 128, 0x424f4704)
            or h[6] != PROFILE or h[7] not in (0, 4) or h[8:10] != (16, 0) or h[21]):
        raise FormatError('unsupported original BOGIP1 header/profile/flags')
    size, origin, origin_len, restarts, groups, stream, stream_len, owners = h[10:18]
    if (size < 128 or (actual_size is not None and size != actual_size)
            or origin != 128 or not 1 <= origin_len <= 254
            or restarts != origin + origin_len or groups != (owners+15)//16
            or stream != restarts + 8*groups or stream > size or stream_len > size-stream):
        raise FormatError('invalid original region boundaries')
    suffix = stream + stream_len
    pool_restarts = (h[20]+15)//16
    if size-suffix < pool_restarts*8:
        raise FormatError('truncated original pool restart directory')
    if (owners == 0) != (stream_len == 0):
        raise FormatError('owner count and owner-stream length disagree')
    return {'header': h, 'logical_size': size, 'owner_stream_off': stream,
            'owner_stream_len': stream_len, 'owner_count': owners,
            'restart_off': restarts, 'restart_count': groups,
            'suffix_off': suffix, 'suffix_len': size-suffix,
            'rrset_count': h[18], 'rdata_references': h[19], 'pool_entries': h[20],
            'profile': h[6], 'flags': h[7]}


def owner_header(handle, end, ordinal, previous):
    """Read only the bounded key/header; do not materialize the owner body."""
    begin = handle.tell()
    if ordinal % STRIDE == 0:
        count = varint(handle, end)
        if count > MAX_KEY or count > end-handle.tell():
            raise FormatError('invalid full owner key length')
        key = exact(handle, count)
    else:
        shared = varint(handle, end)
        count = varint(handle, end)
        if (previous is None or shared > len(previous) or shared+count > MAX_KEY
                or count > end-handle.tell()):
            raise FormatError('invalid front-coded owner key')
        key = previous[:shared] + exact(handle, count)
    if previous is not None and key <= previous:
        raise FormatError('owner keys are not strictly increasing')
    body_length = varint(handle, end)
    if body_length < 2 or body_length > end-handle.tell():
        raise FormatError('invalid owner body length')
    finish = handle.tell() + body_length
    return begin, finish, key


class NativeCodecs:
    def __init__(self):
        self._snappy = None
        self._lz4 = None
        self._stream = None

    def snappy(self):
        if self._snappy is None:
            lib = ctypes.CDLL('libsnappy.so.1')
            lib.snappy_max_compressed_length.argtypes = [ctypes.c_size_t]
            lib.snappy_max_compressed_length.restype = ctypes.c_size_t
            lib.snappy_compress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
            lib.snappy_compress.restype = ctypes.c_int
            lib.snappy_uncompressed_length.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
            lib.snappy_uncompressed_length.restype = ctypes.c_int
            lib.snappy_uncompress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
            lib.snappy_uncompress.restype = ctypes.c_int
            self._snappy = lib
        return self._snappy

    def lz4(self):
        if self._lz4 is None:
            lib = ctypes.CDLL('liblz4.so.1')
            lib.LZ4_compressBound.argtypes = [ctypes.c_int]
            lib.LZ4_compressBound.restype = ctypes.c_int
            lib.LZ4_createStream.restype = ctypes.c_void_p
            lib.LZ4_freeStream.argtypes = [ctypes.c_void_p]
            lib.LZ4_resetStream_fast.argtypes = [ctypes.c_void_p]
            lib.LZ4_compress_fast_continue.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                                       ctypes.c_int, ctypes.c_int, ctypes.c_int]
            lib.LZ4_compress_fast_continue.restype = ctypes.c_int
            lib.LZ4_decompress_safe.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
            lib.LZ4_decompress_safe.restype = ctypes.c_int
            self._lz4 = lib
        return self._lz4

    def compress(self, raw, codec):
        if not raw or len(raw) > MAX_COMPRESSED_RAW:
            raise FormatError('invalid compressed-frame raw length')
        source = ctypes.create_string_buffer(raw)
        if codec == 1:
            lib = self.snappy()
            length = ctypes.c_size_t(lib.snappy_max_compressed_length(len(raw)))
            output = ctypes.create_string_buffer(length.value)
            if lib.snappy_compress(source, len(raw), output, ctypes.byref(length)):
                raise FormatError('native Snappy compression failed')
            return output.raw[:length.value]
        if codec == 4:
            lib = self.lz4()
            if self._stream is None:
                self._stream = lib.LZ4_createStream()
                if not self._stream:
                    raise MemoryError('LZ4 stream allocation failed')
            # Reuse fixed scratch only; clear all dictionary/history per owner.
            lib.LZ4_resetStream_fast(self._stream)
            bound = lib.LZ4_compressBound(len(raw))
            output = ctypes.create_string_buffer(bound)
            size = lib.LZ4_compress_fast_continue(self._stream, source, output, len(raw), bound, 1)
            if size <= 0:
                raise FormatError('native LZ4 compression failed')
            return uleb(len(raw)) + output.raw[:size]
        raise FormatError('unsupported requested codec')

    def decompress(self, payload, codec, expected):
        if not 0 < expected <= MAX_COMPRESSED_RAW:
            raise FormatError('compressed frame exceeds decoded-length limit')
        if codec == 1:
            lib = self.snappy()
            source = ctypes.create_string_buffer(payload)
            length = ctypes.c_size_t()
            if lib.snappy_uncompressed_length(source, len(payload), ctypes.byref(length)) or length.value != expected:
                raise FormatError('Snappy raw length disagrees with frame')
            output = ctypes.create_string_buffer(expected)
            if lib.snappy_uncompress(source, len(payload), output, ctypes.byref(length)) or length.value != expected:
                raise FormatError('native Snappy decompression failed')
            return output.raw[:expected]
        if codec == 4:
            stream = io.BytesIO(payload)
            declared = varint(stream, len(payload))
            if declared != expected or stream.tell() == len(payload):
                raise FormatError('LZ4-v2 raw length disagrees with frame')
            compressed = payload[stream.tell():]
            source = ctypes.create_string_buffer(compressed)
            output = ctypes.create_string_buffer(expected)
            if self.lz4().LZ4_decompress_safe(source, output, len(compressed), expected) != expected:
                raise FormatError('native LZ4 decompression failed')
            return output.raw[:expected]
        raise FormatError('unsupported compressed-frame codec')

    def close(self):
        if self._stream is not None:
            self._lz4.LZ4_freeStream(self._stream)
            self._stream = None


def wrap_image(source_path, output_path, codec, max_compress=MAX_COMPRESSED_RAW):
    started = time.monotonic()
    source_path, output_path = Path(source_path), Path(output_path)
    if codec not in NAMES or not 1 <= max_compress <= MAX_COMPRESSED_RAW:
        raise ValueError('unsupported codec or compression limit')
    if source_path.resolve() == output_path.resolve():
        raise ValueError('input and output must differ')
    output_path.parent.mkdir(parents=True, exist_ok=True)
    original_sha = sha(source_path)
    counts = Counter()
    logical_hash = hashlib.sha256()
    native = NativeCodecs()
    try:
        with source_path.open('rb') as source, source_path.open('rb') as lookup:
            meta = inner_metadata(exact(source, 128), source_path.stat().st_size)
            with tempfile.TemporaryDirectory(prefix='owner-key-wrap-', dir=output_path.parent) as td:
                desc_path, keys_path = Path(td)/'directory.bin', Path(td)/'firstkeys.bin'
                with output_path.open('xb+') as out, desc_path.open('wb') as descs, keys_path.open('wb') as keys:
                    out.write(bytes(128))
                    copy_range(source, out, 0, meta['owner_stream_off'], logical_hash)
                    containers_off = out.tell()
                    source.seek(meta['owner_stream_off'])
                    previous = None
                    key_bytes = 0
                    logical_cursor = meta['owner_stream_off']
                    for group in range(meta['restart_count']):
                        lookup.seek(meta['restart_off']+group*8)
                        relative = struct.unpack('<Q', exact(lookup, 8))[0]
                        if logical_cursor != meta['owner_stream_off']+relative:
                            raise FormatError('original restart does not match owner boundary')
                        physical_start, logical_start, crc = out.tell(), logical_cursor, 0
                        group_owners = min(16, meta['owner_count']-group*16)
                        first_key = None
                        for member in range(group_owners):
                            ordinal = group*16+member
                            begin, finish, key = owner_header(source, meta['suffix_off'], ordinal, previous)
                            if begin != logical_cursor:
                                raise FormatError('noncontiguous original owner records')
                            if first_key is None:
                                first_key = key
                            raw_length = finish-begin
                            actual_codec = 0
                            if raw_length > max_compress:
                                raw_crc = copy_range(source, None, begin, raw_length)
                                counts['large_plain_frames'] += 1
                                if codec:
                                    counts['forced_large_plain_fallbacks'] += 1
                                stored_length = raw_length
                                frame_header = uleb(raw_length)+uleb(stored_length)+bytes([0])+struct.pack('<I', raw_crc)
                                out.write(frame_header)
                                crc = zlib.crc32(frame_header, crc)
                                crc = copy_range(source, out, begin, raw_length, logical_hash, crc)
                            else:
                                source.seek(begin)
                                raw = exact(source, raw_length)
                                raw_crc = zlib.crc32(raw) & 0xffffffff
                                logical_hash.update(raw)
                                stored = raw
                                if codec:
                                    counts['compression_attempts'] += 1
                                    compressed = native.compress(raw, codec)
                                    if len(compressed) <= raw_length*896//1024:
                                        stored, actual_codec = compressed, codec
                                        counts['compressed_frames'] += 1
                                    else:
                                        counts['incompressible_fallbacks'] += 1
                                stored_length = len(stored)
                                frame_header = uleb(raw_length)+uleb(stored_length)+bytes([actual_codec])+struct.pack('<I', raw_crc)
                                out.write(frame_header)
                                out.write(stored)
                                crc = zlib.crc32(frame_header, crc)
                                crc = zlib.crc32(stored, crc)
                                del raw, stored
                                if codec:
                                    del compressed
                            counts['frames'] += 1
                            counts['actual_codec_'+str(actual_codec)] += 1
                            counts['raw_owner_bytes'] += raw_length
                            counts['stored_payload_bytes'] += stored_length
                            counts['frame_header_bytes'] += len(frame_header)
                            logical_cursor = finish
                            previous = key
                            source.seek(finish)
                        assert first_key is not None
                        descs.write(DESC.pack(logical_start, physical_start, out.tell()-physical_start,
                                              logical_cursor-logical_start, key_bytes, group*16,
                                              len(first_key), codec, group_owners, crc & 0xffffffff))
                        keys.write(first_key)
                        key_bytes += len(first_key)
                    if logical_cursor != meta['suffix_off'] or counts['frames'] != meta['owner_count']:
                        raise FormatError('owner stream count or endpoint mismatch')
                    directory_off = out.tell()
                    keys_off = directory_off+meta['restart_count']*DESC.size
                    descs.flush()
                    keys.flush()
                    with desc_path.open('rb') as sidecar:
                        for _ in range(meta['restart_count']):
                            row = list(DESC.unpack(exact(sidecar, DESC.size)))
                            row[4] += keys_off
                            out.write(DESC.pack(*row))
                        if sidecar.read(1):
                            raise FormatError('unexpected directory sidecar tail')
                    with keys_path.open('rb') as sidecar:
                        copy_range(sidecar, out, 0, key_bytes)
                    suffix_physical = out.tell()
                    if suffix_physical != keys_off+key_bytes:
                        raise FormatError('first-key directory endpoint mismatch')
                    copy_range(source, out, meta['suffix_off'], meta['suffix_len'], logical_hash)
                    physical_size = out.tell()
                    header = OUTER.pack(MAGIC, 2, 128, codec, meta['logical_size'], meta['owner_stream_off'],
                                        meta['suffix_off'], meta['suffix_len'], 128, containers_off,
                                        directory_off, meta['restart_count'], keys_off, key_bytes,
                                        suffix_physical, physical_size, meta['profile'], 1)
                    out.seek(0)
                    out.write(header)
        if logical_hash.hexdigest() != original_sha:
            raise FormatError('streamed logical bytes differ from original input hash')
        document = {'status': 'BUILT_PENDING_INDEPENDENT_VERIFY', 'format': 'ZIMBC01-v2-per-owner',
                    'input': str(source_path), 'input_bytes': meta['logical_size'], 'input_sha256': original_sha,
                    'logical_sha256': logical_hash.hexdigest(), 'output': str(output_path),
                    'output_bytes': physical_size, 'output_sha256': sha(output_path),
                    'codec': NAMES[codec], 'default_codec': codec, 'inner_profile': meta['profile'],
                    'owner_count': meta['owner_count'], 'coarse_group_count': meta['restart_count'],
                    'owners_per_codec_frame': 1, 'max_owners_per_coarse_group': 16,
                    'prefix_bytes': meta['owner_stream_off'], 'suffix_bytes': meta['suffix_len'],
                    'directory_bytes': meta['restart_count']*64, 'first_key_bytes': key_bytes,
                    'outer_header_bytes': 128, 'counts': dict(counts),
                    'framing_and_directory_overhead_bytes': 128+meta['restart_count']*64+key_bytes+counts['frame_header_bytes'],
                    'payload_savings_bytes': counts['raw_owner_bytes']-counts['stored_payload_bytes'],
                    'net_size_change_bytes': physical_size-meta['logical_size'],
                    'max_compressed_owner_raw_bytes': max_compress,
                    'large_owner_policy': 'force plain; bounded CRC pass and bounded copy from seekable original',
                    'codec_policy': 'native independent Snappy / reset empty LZ4 stream accel1 with original-length ULEB; store iff payload<=floor(raw*896/1024)',
                    'logical_scope': 'exact original bytes, front-coded names and one global pool; no runtime zone shards',
                    'elapsed_seconds': time.monotonic()-started}
        return document
    finally:
        native.close()


def wrapped_metadata(handle):
    physical_size = os.fstat(handle.fileno()).st_size
    handle.seek(0)
    raw = exact(handle, 128)
    head = OUTER.unpack(raw)
    if head[:3] != (MAGIC, 2, 128) or head[3] not in NAMES:
        raise FormatError('not a supported per-owner v2 image')
    q = head[4:]
    logical, prefix, suffix_logical, suffix_len, prefix_phys, containers, directory, groups, keys, keys_len, suffix_phys, size, profile, flag = q
    if (flag != 1 or profile != PROFILE or prefix_phys != 128 or containers != 128+prefix
            or directory < containers or keys != directory+groups*64 or suffix_phys != keys+keys_len
            or size != physical_size or suffix_phys > size or suffix_len != size-suffix_phys
            or suffix_logical > logical or suffix_len != logical-suffix_logical):
        raise FormatError('invalid outer region boundaries')
    handle.seek(prefix_phys)
    original = inner_metadata(exact(handle, 128), logical)
    if (prefix != original['owner_stream_off'] or suffix_logical != original['suffix_off']
            or suffix_len != original['suffix_len'] or groups != original['restart_count']):
        raise FormatError('outer and original logical header disagree')
    return {**original, 'physical_size': size, 'default_codec': head[3], 'prefix_physical': prefix_phys,
            'containers_off': containers, 'directory_off': directory, 'keys_off': keys,
            'keys_len': keys_len, 'suffix_physical': suffix_phys}


def reconstruct(wrapped_path, target=None):
    """Validate v2 and stream the byte-identical logical image to target/hash."""
    native = NativeCodecs()
    digest = hashlib.sha256()
    frames = 0
    codec_counts = Counter()
    try:
        with Path(wrapped_path).open('rb') as source, Path(wrapped_path).open('rb') as lookup:
            meta = wrapped_metadata(source)
            copy_range(source, target, meta['prefix_physical'], meta['owner_stream_off'], digest)
            logical_cursor, physical_cursor, key_cursor = meta['owner_stream_off'], meta['containers_off'], meta['keys_off']
            previous = None
            for group in range(meta['restart_count']):
                lookup.seek(meta['directory_off']+group*64)
                row = DESC.unpack(exact(lookup, 64))
                logical, physical, stored_length, raw_length, key_offset, ordinal, key_length, default, owners, container_crc = row
                expected_owners = min(16, meta['owner_count']-group*16)
                lookup.seek(meta['prefix_physical']+meta['restart_off']+group*8)
                restart = struct.unpack('<Q', exact(lookup, 8))[0]
                if (logical != logical_cursor or logical != meta['owner_stream_off']+restart
                        or physical != physical_cursor or not stored_length or not raw_length
                        or physical > meta['directory_off'] or stored_length > meta['directory_off']-physical
                        or key_offset != key_cursor or key_length > MAX_KEY
                        or key_offset > meta['suffix_physical'] or key_length > meta['suffix_physical']-key_offset
                        or ordinal != group*16 or owners != expected_owners or default != meta['default_codec']):
                    raise FormatError('invalid coarse descriptor')
                lookup.seek(key_offset)
                first_key = exact(lookup, key_length)
                if copy_range(source, None, physical, stored_length) != container_crc:
                    raise FormatError('stored container CRC mismatch')
                container_end = physical+stored_length
                source.seek(physical)
                sum_raw = 0
                for member in range(owners):
                    raw_len = varint(source, container_end)
                    stored_len = varint(source, container_end)
                    if source.tell()+5 > container_end:
                        raise FormatError('truncated owner frame header')
                    actual = exact(source, 1)[0]
                    expected_crc = struct.unpack('<I', exact(source, 4))[0]
                    payload_start = source.tell()
                    if (not raw_len or not stored_len or stored_len > container_end-payload_start
                            or actual not in (0, meta['default_codec'])):
                        raise FormatError('invalid owner frame lengths/codec')
                    if actual == 0:
                        if stored_len != raw_len:
                            raise FormatError('plain frame raw/stored length mismatch')
                        _, finish, key = owner_header(source, payload_start+raw_len, ordinal+member, previous)
                        if finish != payload_start+raw_len:
                            raise FormatError('plain frame does not contain exactly one owner')
                        checksum = copy_range(source, target, payload_start, raw_len, digest)
                    else:
                        if raw_len > MAX_COMPRESSED_RAW or stored_len > raw_len*896//1024:
                            raise FormatError('compressed frame length exceeds format limit/policy')
                        payload = exact(source, stored_len)
                        raw = native.decompress(payload, actual, raw_len)
                        reader = io.BytesIO(raw)
                        _, finish, key = owner_header(reader, raw_len, ordinal+member, previous)
                        if finish != raw_len:
                            raise FormatError('compressed frame does not contain exactly one owner')
                        checksum = zlib.crc32(raw) & 0xffffffff
                        digest.update(raw)
                        if target is not None:
                            target.write(raw)
                    if checksum != expected_crc:
                        raise FormatError('raw owner CRC mismatch')
                    if member == 0 and key != first_key:
                        raise FormatError('plaintext first key does not match raw owner')
                    previous = key
                    source.seek(payload_start+stored_len)
                    sum_raw += raw_len
                    frames += 1
                    codec_counts[str(actual)] += 1
                if source.tell() != container_end or sum_raw != raw_length:
                    raise FormatError('coarse container frame count/length mismatch')
                logical_cursor += raw_length
                physical_cursor += stored_length
                key_cursor += key_length
            if (logical_cursor != meta['suffix_off'] or physical_cursor != meta['directory_off']
                    or key_cursor != meta['suffix_physical'] or frames != meta['owner_count']):
                raise FormatError('final owner/directory/first-key endpoint mismatch')
            copy_range(source, target, meta['suffix_physical'], meta['suffix_len'], digest)
        return {'status': 'PASS_LOGICAL_RECONSTRUCTION', 'format': 'ZIMBC01-v2-per-owner',
                'input': str(wrapped_path), 'physical_bytes': meta['physical_size'],
                'logical_bytes': meta['logical_size'], 'logical_sha256': digest.hexdigest(),
                'owner_count': frames, 'coarse_group_count': meta['restart_count'],
                'actual_frame_codec_counts': dict(codec_counts)}
    finally:
        native.close()


def guard_cli_paths(args):
    """Reject destructive aliases before hashing, creating dirs or opening output.

    resolve covers lexical aliases and symlinked parents; samefile additionally
    covers existing hardlinks. This is a CLI misuse guard, not a claim of
    race-free filesystem isolation against a concurrent hostile process.
    """
    protected = [('input', args.input)]
    original = getattr(args, 'original', None)
    if original is not None:
        protected.append(('original', original))
    writable = []
    output = getattr(args, 'output', None)
    if output is not None:
        writable.append(('output', output))
    manifest = args.manifest
    if args.command == 'wrap' and manifest is None:
        manifest = Path(str(output)+'.meta.json')
    temporary = None
    if manifest is not None:
        temporary = manifest.with_name(manifest.name+'.tmp')
        writable.extend([('manifest', manifest), ('manifest temporary', temporary)])

    def alias(left, right):
        try:
            if left.resolve() == right.resolve():
                return True
            return left.exists() and right.exists() and left.samefile(right)
        except (OSError, RuntimeError) as error:
            raise ValueError('Cannot safely resolve CLI paths: '+str(error)) from error

    for name, path in writable:
        for source_name, source_path in protected:
            if alias(path, source_path):
                raise ValueError(f'{name} aliases protected {source_name}: {path}')
    for index, (name, path) in enumerate(writable):
        for other_name, other in writable[index+1:]:
            if alias(path, other):
                raise ValueError(f'{name} aliases {other_name}: {path}')
        if path.is_dir():
            raise ValueError(f'{name} must name a file, not a directory: {path}')
    # An implicit temporary filename is not permission to overwrite a preexisting
    # file/symlink, even if it is unrelated to the explicit protected inputs.
    if temporary is not None and os.path.lexists(temporary):
        raise ValueError('Manifest temporary path already exists: '+str(temporary))
    if output is not None and os.path.lexists(output):
        raise ValueError('Output already exists: '+str(output))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    wrap = commands.add_parser('wrap')
    wrap.add_argument('--input', type=Path, required=True)
    wrap.add_argument('--output', type=Path, required=True)
    wrap.add_argument('--codec', choices=CODECS, required=True)
    wrap.add_argument('--manifest', type=Path)
    wrap.add_argument('--max-compressed-owner-bytes', type=int, default=MAX_COMPRESSED_RAW)
    wrap.add_argument('--verify', action='store_true', help='independent logical reconstruction after writing; charged to invocation')
    for name in ('verify', 'unwrap'):
        command = commands.add_parser(name)
        command.add_argument('--input', type=Path, required=True)
        command.add_argument('--original', type=Path, help='require reconstructed SHA256 and length to match this original image')
        command.add_argument('--manifest', type=Path)
        if name == 'unwrap':
            command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    guard_cli_paths(args)
    if args.command == 'wrap':
        document = wrap_image(args.input, args.output, CODECS[args.codec], args.max_compressed_owner_bytes)
        if args.verify:
            verification = reconstruct(args.output)
            if (verification['logical_sha256'] != document['input_sha256']
                    or verification['logical_bytes'] != document['input_bytes']):
                raise FormatError('independent logical reconstruction differs from original')
            document['verification'] = verification
            document['status'] = 'PASS_LOGICAL_BYTE_IDENTITY'
        save(args.manifest or Path(str(args.output)+'.meta.json'), document)
    else:
        if args.command == 'unwrap':
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open('xb') as target:
                document = reconstruct(args.input, target)
            document['output'] = str(args.output)
            document['output_sha256'] = sha(args.output)
        else:
            document = reconstruct(args.input)
        if args.original:
            expected = sha(args.original)
            if expected != document['logical_sha256'] or args.original.stat().st_size != document['logical_bytes']:
                raise FormatError('reconstructed logical image differs from --original')
            document['original'] = str(args.original)
            document['original_sha256'] = expected
            document['status'] = 'PASS_LOGICAL_BYTE_IDENTITY'
        if args.manifest:
            save(args.manifest, document)
    print(json.dumps(document, separators=(',', ':')), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (FormatError, OSError, ValueError) as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        raise SystemExit(2)

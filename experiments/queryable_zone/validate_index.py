#!/usr/bin/env python3
"""Packed/fixed index compatibility, restart and malformed-index qualification."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import struct
import subprocess

import dns.name

from validate import (audit_g1, audit_queries, build_fixture, canonical_name,
                      file_sha256, fixture_cases, save_json)


def inspect(binary, image):
    process = subprocess.run([str(binary), 'inspect', '--image', str(image)],
                             check=True, capture_output=True, text=True)
    return json.loads(process.stdout)


def fnv64(data):
    value = 14695981039346656037
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return value


def audit_image(binary, source, image, output, extra_cases=()):
    origin = canonical_name('example.', dns.name.root)
    g1 = audit_g1(binary, source, origin, image, output)
    semantics = audit_queries(binary, image, source, origin,
                              fixture_cases() + list(extra_cases), output)
    return {'status': 'PASS', 'g1': g1, 'semantics': semantics,
            'inspection': inspect(binary, image)}


def build_large(binary, output):
    source = output / 'source.zone'
    image = output / 'image.zim'
    text = (Path(__file__).with_name('fixtures') / 'semantics.zone').read_text()
    with source.open('w', encoding='ascii') as target:
        target.write(text)
        for number in range(12000):
            target.write(f'huge.example. 300 IN TXT "value-{number:05d}-' + ('x' * 160) + '"\n')
        for number in range(4000):
            target.write(f'n{number:05d}.range.example. 300 IN TXT "range-' + ('y' * 160) + '"\n')
        for number in range(600):
            target.write(f'directory.example. 300 IN TYPE{64000 + number} \\# 4 {number:08x}\n')
    work = output / 'work'
    work.mkdir()
    command = [str(binary), 'build', '--zone', str(source), '--origin', 'example.',
               '--out', str(image), '--work', str(work), '--memory-mib', '16',
               '--codec', 'none', '--pool', 'none', '--front-code', '1',
               '--index', 'packed', '--stats', str(output / 'build_stats.json')]
    with (output / 'build.log').open('wb') as log:
        subprocess.run(command, stdout=log, stderr=log, check=True, timeout=600)
    information = inspect(binary, image)
    if information['page_count'] <= 32:
        raise AssertionError('Large fixture does not span three index restart groups')
    save_json(output / 'BUILD_COMMAND.json', {'command': command, 'inspection': information})
    return source, image


def malformed_index_cases(binary, image, output):
    original = image.read_bytes()
    page_count, index_offset = struct.unpack_from('<QQ', original, 16)
    data_bytes, restart_offset, restart_count = struct.unpack_from('<QQQ', original, 328)
    if restart_count != (page_count + 15) // 16:
        raise AssertionError('Unexpected packed-index fixture layout')
    table = index_offset + restart_offset
    group_end = struct.unpack_from('<Q', original, table + 16)[0] if restart_count > 1 else data_bytes

    def repair_table(raw):
        struct.pack_into('<Q', raw, 352, fnv64(raw[table:table + restart_count * 16]))

    def repair_group(raw):
        struct.pack_into('<Q', raw, table + 8, fnv64(raw[index_offset:index_offset + group_end]))
        repair_table(raw)

    cases = []
    damaged = bytearray(original)
    damaged[table] ^= 1
    cases.append(('restart_crc', damaged, 'packed restart table checksum mismatch'))
    damaged = bytearray(original)
    damaged[index_offset] ^= 1
    cases.append(('group_crc', damaged, 'packed index group checksum mismatch'))
    damaged = bytearray(original)
    struct.pack_into('<Q', damaged, 336, restart_offset + 1)
    cases.append(('metadata_bounds', damaged, 'invalid packed index metadata'))
    damaged = bytearray(original)
    struct.pack_into('<Q', damaged, table, (1 << 64) - 1)
    repair_table(damaged)
    cases.append(('restart_bounds_with_valid_crc', damaged, 'packed restart offset out of range'))
    damaged = bytearray(original)
    if damaged[index_offset] != 0:
        raise AssertionError('First packed index prefix is not canonical zero')
    damaged[index_offset] = 1
    repair_group(damaged)
    cases.append(('front_code_bounds_with_valid_crc', damaged, 'invalid packed directory front code'))
    damaged = bytearray(original)
    # First page starts at apex, so its key and both key varints are empty/zero.
    if damaged[index_offset:index_offset + 2] != b'\0\0':
        raise AssertionError('Expected apex first fence key in fixture')
    struct.pack_into('<Q', damaged, index_offset + 2, index_offset + 1)
    repair_group(damaged)
    cases.append(('page_reference_bounds_with_valid_crc', damaged, 'invalid page descriptor'))
    cases.append(('truncated_restart_table', original[:-1], 'invalid index range'))
    results = []
    for name, raw, expected_error in cases:
        path = output / (name + '.zim')
        path.write_bytes(raw)
        command = [str(binary), 'wire', '--image', str(path)]
        process = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                 text=True, timeout=60)
        result = {'name': name, 'command': command, 'returncode': process.returncode,
                  'stderr': process.stderr, 'expected_error': expected_error,
                  'sha256': file_sha256(path)}
        if process.returncode <= 0 or expected_error not in process.stderr:
            raise AssertionError('Malformed index was accepted or failed unexpectedly: ' + str(result))
        result['status'] = 'PASS_REJECTED'
        results.append(result)
    save_json(output / 'SUMMARY.json', {'status': 'PASS', 'checks': results})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--old-fixed-image', type=Path, required=True)
    parser.add_argument('--old-fixed-source', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {'kind': 'SUMMARY', 'status': 'RUNNING',
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'binary': str(args.binary), 'binary_sha256': file_sha256(args.binary),
              'qualification_outside_performance_timing': True}
    try:
        matrix = []
        for index_format, front_code in (('fixed', 1), ('packed', 1), ('packed', 0)):
            case = output / f'{index_format}_front{front_code}'
            case.mkdir()
            source, image = build_fixture(args.binary, case, 16, 'none', 'none', front_code,
                                           index_format)
            matrix.append(audit_image(args.binary, source, image, case))
        result['matrix'] = matrix
        compatibility = output / 'old_fixed_compatibility'
        compatibility.mkdir()
        result['old_fixed'] = audit_image(args.binary, args.old_fixed_source,
                                          args.old_fixed_image, compatibility)
        large = output / 'large_restart_groups'
        large.mkdir()
        source, image = build_large(args.binary, large)
        cases = [('index_first', 'n00000.range.example.', 'TXT'),
                 ('index_middle', 'n02000.range.example.', 'TXT'),
                 ('index_last', 'n03999.range.example.', 'TXT'),
                 ('index_ent', 'range.example.', 'A'),
                 ('index_negative_between', 'n02000x.range.example.', 'TXT')]
        result['large'] = audit_image(args.binary, source, image, large, cases)
        corrupt = output / 'malformed_index'
        corrupt.mkdir()
        result['corruption_checks'] = malformed_index_cases(args.binary, image, corrupt)
        result['status'] = 'PASS'
    except BaseException as error:
        result.update(status='FAIL', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        result['completed_utc'] = datetime.now(timezone.utc).isoformat()
        save_json(output / 'SUMMARY.json', result)
        print(json.dumps({'status': result['status'], 'summary': str(output / 'SUMMARY.json')}), flush=True)


if __name__ == '__main__':
    main()

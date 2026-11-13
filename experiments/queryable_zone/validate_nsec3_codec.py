#!/usr/bin/env python3
"""Independent full-wire and update qualification for NSEC3 next-key coding."""

import argparse
import base64
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess

import dns.name

from validate import (audit_g1, audit_queries, canonical_name, file_sha256,
                      read_source, save_json, unpack_wire)
from validate_key_codec import make_source, queries as key_queries
from validate_owner_order import owner_ordered_file
from validate_updates import (assert_current, assert_snapshot_retained,
                              inspect_snapshot, make_wire, rewritten_ttl,
                              run_update, write_delta)


def hash_text(length, seed):
    raw = bytes((seed + number * 37) % 256 for number in range(length))
    return base64.b32hexencode(raw).decode('ascii').rstrip('=')


def source_with_nsec3(original, output):
    source = make_source(original, output)
    text = source.read_text(encoding='ascii')
    for length in (1, 10, 19, 20, 21, 31):
        owner = f'next{length}.example.'
        # Unknown hash algorithm/flag bits are opaque payloads, never normalized.
        wire = make_wire(owner, 'NSEC3', 555,
                         '255 3 65535 A1B2C3 ' + hash_text(length, length) +
                         ' A NS AAAA RRSIG NSEC3 TYPE65534')
        _, owner_length = dns.name.from_wire(wire, 0)
        rdata = wire[owner_length + 10:]
        # RFC3597 form also admits lengths rejected by ldns's NSEC3 text grammar.
        row = owner + f' 555 IN TYPE50 \\# {len(rdata)} {rdata.hex()}\n'
        text += row
        if length == 20:
            text += row
    text += ('next20.example. 556 IN NSEC3 1 0 0 - ' + hash_text(20, 99) +
             ' SOA DNSKEY NSEC3PARAM\n')
    source.write_text(text, encoding='ascii')
    return source


def queries():
    return key_queries() + [(f'next_length_{length}', f'next{length}.example.', 'NSEC3')
                            for length in (1, 10, 19, 20, 21, 31)]


def check(binary, source, oracle, image, output, delta=None, index=None):
    output.mkdir()
    result = {'status': 'PASS',
              'g1': audit_g1(binary, source, oracle.origin, image, output, delta,
                             source_oracle=oracle),
              'semantics': audit_queries(binary, image, source, oracle.origin,
                                         queries(), output, delta, source_oracle=oracle)}
    if index == 'cow':
        inspected = json.loads(subprocess.check_output(
            [str(binary), 'inspect', '--image', str(image), '--check-index', '1'], text=True))
        if inspected['index_check']['status'] != 'PASS':
            raise AssertionError('NSEC3-mode COW index is invalid')
        result['index_check'] = inspected['index_check']
    return result


def update(args, source, oracle, image, folder, index):
    data = folder / 'data.zim'
    shutil.copy2(image, data)
    current = folder / 'CURRENT'
    current.write_text('data.zim\n', encoding='ascii')
    before = inspect_snapshot(args.binary, data)
    remove = Counter()
    for rows in oracle.records.values():
        for wire, count in rows.items():
            owner, rrtype, _, _ = unpack_wire(wire)
            if rrtype == 50 and owner in {canonical_name(f'next{length}.example.', oracle.origin)
                                         for length in (10, 20, 21)}:
                remove[wire] = count
    add = Counter({rewritten_ttl(wire, 3): count for wire, count in remove.items()})
    # New encoded 20-byte next hash and a literal fallback in the same generation.
    add[make_wire('added20.example.', 'NSEC3', 888,
                  '1 1 12 AABB ' + hash_text(20, 201) + ' A AAAA TYPE65534')] += 2
    add[make_wire('added19.example.', 'NSEC3', 889,
                  '2 0 13 - ' + hash_text(19, 202) + ' SOA NS')] += 1
    native_delta, json_delta = write_delta(folder, 'changes', remove, add)
    owner_ordered_file(native_delta, remove, add)
    generation = folder / 'generation.zgen'
    run_update(args.binary, current, native_delta, generation, folder / 'work',
               folder / 'stats.json', current, folder / 'update', delta_order='owner')
    assert_current(current, generation)
    assert_snapshot_retained(before, inspect_snapshot(args.binary, data))
    return {'status': 'PASS',
            'new': check(args.binary, source, oracle, current, folder / 'new', json_delta, index),
            'old': check(args.binary, source, oracle, data, folder / 'old', index=index),
            'retained_before': before, 'retained_after': inspect_snapshot(args.binary, data)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {'kind': 'SUMMARY', 'status': 'RUNNING', 'cases': [],
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'binary': str(args.binary), 'binary_sha256': file_sha256(args.binary),
              'qualification_outside_performance_timing': True}
    try:
        source = source_with_nsec3(args.source, output)
        oracle = read_source(source, canonical_name('example.', dns.name.root), keep_records=True)
        result.update(source=str(source), source_sha256=file_sha256(source))
        matrix = [('cow', 'nibble', 0, 'none'), ('cow', 'compact', 0, 'none'),
                  ('cow', 'nibble', 1, 'none'), ('cow', 'compact', 1, 'none'),
                  ('fixed', 'compact', 1, 'none'), ('packed', 'compact', 1, 'none'),
                  ('cow', 'compact', 1, 'local')]
        for index, key_codec, next_key, pool in matrix:
            name = f'{index}_{key_codec}_next{next_key}_{pool}'
            folder = output / name
            folder.mkdir()
            image = folder / 'image.zim'
            command = [str(args.binary), 'build', '--zone', str(source), '--origin', 'example.',
                       '--out', str(image), '--work', str(folder / 'build_work'),
                       '--memory-mib', '16', '--codec', 'zstd', '--pool', pool,
                       '--front-code', '1', '--index', index, '--key-codec', key_codec,
                       '--nsec3-next-key', str(next_key), '--stats', str(folder / 'build_stats.json')]
            with (folder / 'build.log').open('wb') as log:
                subprocess.run(command, stdout=log, stderr=log, check=True)
            save_json(folder / 'BUILD_COMMAND.json', {'command': command})
            case = {'name': name, 'status': 'PASS',
                    'base': check(args.binary, source, oracle, image, folder / 'base', index=index)}
            if next_key:
                update_folder = folder / 'update'
                update_folder.mkdir()
                case['update'] = update(args, source, oracle, image, update_folder, index)
            result['cases'].append(case)
        result['status'] = 'PASS'
    except BaseException as error:
        result.update(status='FAIL', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        result['completed_utc'] = datetime.now(timezone.utc).isoformat()
        save_json(output / 'SUMMARY.json', result)
        print(json.dumps({'status': result['status'], 'summary': str(output / 'SUMMARY.json')}))


if __name__ == '__main__':
    main()

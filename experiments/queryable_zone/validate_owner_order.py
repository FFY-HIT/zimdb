#!/usr/bin/env python3
"""Qualify owner-ordered deltas against the unordered update implementation."""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import random
import shutil
import subprocess

import dns.name

from validate import (audit_g1, audit_queries, canonical_name, file_sha256,
                      fixture_cases, read_source, save_json, unpack_wire)
from validate_updates import (assert_current, assert_snapshot_retained, inspect_snapshot,
                              make_wire, rewritten_ttl, run_update, write_delta)


def owner_ordered_file(path, remove, add, reverse=False):
    by_owner = defaultdict(list)
    for sign, records in (('-', remove), ('+', add)):
        for wire, count in records.items():
            owner = unpack_wire(wire)[0]
            by_owner[owner].extend((sign, wire) for _ in range(count))
    rng = random.Random(17)
    with path.open('w', encoding='ascii', newline='\n') as output:
        for owner in sorted(by_owner, reverse=reverse):
            rows = by_owner[owner]
            rng.shuffle(rows)  # Only owner order is promised to the consumer.
            for sign, wire in rows:
                output.write(sign + '\t' + wire.hex() + '\n')
    return {'path': str(path), 'sha256': file_sha256(path),
            'operation_count': sum(len(rows) for rows in by_owner.values()),
            'owner_count': len(by_owner), 'reverse_owner_order': reverse}


def source_selection(oracle, owner, rrtype):
    name = canonical_name(owner, oracle.origin)
    return Counter({wire: count for wire, count in oracle.records[name].items()
                    if unpack_wire(wire)[1] == rrtype})


def changes(oracle):
    ns = source_selection(oracle, 'deleg.example.', 2)
    opaque = source_selection(oracle, 'opaque.example.', 65534)
    dup = next(wire for wire, count in source_selection(oracle, 'dup.example.', 1).items()
               if count == 2)
    small_remove = ns + opaque + Counter({dup: 1})
    small_add = Counter({rewritten_ttl(wire, 1): count for wire, count in (ns + opaque).items()})
    small_add[rewritten_ttl(dup, 2)] += 1
    small_add[make_wire('dup.example.', 'TXT', 444, '"newtype"')] += 1
    huge = source_selection(oracle, 'huge.example.', 16)
    www = source_selection(oracle, 'www.example.', 1)
    giant_remove = huge + opaque + www
    giant_add = Counter({rewritten_ttl(wire, 1): count for wire, count in giant_remove.items()})
    return [('mixed_and_gaps', small_remove, small_add),
            ('giant_then_small_owners', giant_remove, giant_add)]


def queries():
    return fixture_cases() + [
        ('range_first', 'n00000.range.example.', 'TXT'),
        ('range_middle', 'n02000.range.example.', 'TXT'),
        ('range_last', 'n03999.range.example.', 'TXT'),
        ('mixed_new_type', 'dup.example.', 'TXT'),
    ]


def check_generation(binary, source, oracle, image, output, delta=None):
    output.mkdir()
    g1 = audit_g1(binary, source, oracle.origin, image, output, delta, source_oracle=oracle)
    semantics = audit_queries(binary, image, source, oracle.origin, queries(), output,
                              delta, source_oracle=oracle)
    tree = json.loads(subprocess.check_output([str(binary), 'inspect', '--image', str(image),
                                               '--check-index', '1'], text=True))
    if tree['index_check']['status'] != 'PASS':
        raise AssertionError('Index check failed after owner-ordered update')
    return {'status': 'PASS', 'g1': g1, 'semantics': semantics, 'index_check': tree['index_check']}


def assert_physical_identity(first, second):
    for key in ('data', 'generation'):
        left, right = first[key], second[key]
        if left.stat().st_size != right.stat().st_size or file_sha256(left) != file_sha256(right):
            raise AssertionError('Owner-ordered and unordered outputs differ: ' + key)
    return {key: {'bytes': first[key].stat().st_size, 'sha256': file_sha256(first[key])}
            for key in ('data', 'generation')}


def negative_checks(args, source, oracle, folder, owner_case, remove, add):
    current = owner_case['current']
    current_bytes = current.read_bytes()
    before = inspect_snapshot(args.binary, current)
    checks = []
    disordered = folder / 'disordered'
    disordered.mkdir()
    reversed_path = disordered / 'inverse_reversed.delta'
    owner_ordered_file(reversed_path, add, remove, reverse=True)
    run_update(args.binary, current, reversed_path, disordered / 'candidate.zgen',
               disordered / 'work', disordered / 'stats.json', current, disordered / 'update',
               expected_failure=True, delta_order='owner')
    after = inspect_snapshot(args.binary, current)
    if current.read_bytes() != current_bytes or before['dependencies'] != after['dependencies']:
        raise AssertionError('Owner-order validation was not completed before append/publication')
    checks.append({'name': 'owner_disorder_rejected_before_append', 'status': 'PASS'})

    absent = make_wire('totally-missing.example.', 'A', 300, '192.0.2.250')
    for mode in ('unordered', 'owner'):
        case = folder / ('invalid_netzero_' + mode)
        case.mkdir()
        native_path = case / 'change.delta'
        owner_ordered_file(native_path, Counter({absent: 1}), Counter({absent: 1}))
        candidate = case / 'candidate.zgen'
        run_update(args.binary, current, native_path, candidate, case / 'work',
                   case / 'stats.json', current, case / 'update',
                   expected_failure=True, delta_order=mode)
        if current.read_bytes() != current_bytes or candidate.exists():
            raise AssertionError('Unavailable removal canceled by addition was accepted')
        assert_snapshot_retained(before, inspect_snapshot(args.binary, current))
        checks.append({'name': 'strict_absent_remove_plus_identical_add_' + mode, 'status': 'PASS'})

    inverse = folder / 'inverse_owner.delta'
    owner_ordered_file(inverse, add, remove)
    for label, flag in (('before_descriptor', '--fail-before-publish'),
                        ('before_current', '--fail-before-current')):
        case = folder / label
        case.mkdir()
        candidate = case / 'candidate.zgen'
        run_update(args.binary, current, inverse, candidate, case / 'work',
                   case / 'stats.json', current, case / 'update', failure_flag=flag,
                   expected_failure=True, delta_order='owner')
        if current.read_bytes() != current_bytes:
            raise AssertionError('Owner-ordered failure changed CURRENT')
        assert_snapshot_retained(before, inspect_snapshot(args.binary, current))
        if label == 'before_descriptor' and candidate.exists():
            raise AssertionError('Pre-descriptor owner update published a descriptor')
        if label == 'before_current':
            if not candidate.exists():
                raise AssertionError('Pre-CURRENT owner update did not reach the descriptor stage')
            check_generation(args.binary, source, oracle, candidate, case / 'prepared_original')
        checks.append({'name': 'owner_order_' + label, 'status': 'PASS'})
    return checks


def run_suite(args, output):
    source = args.source.resolve()
    origin = canonical_name('example.', dns.name.root)
    oracle = read_source(source, origin, keep_records=True)
    initial = output / 'initial'
    initial.mkdir()
    image = initial / 'image.zim'
    work = initial / 'work'
    work.mkdir()
    command = [str(args.binary), 'build', '--zone', str(source), '--origin', 'example.',
               '--out', str(image), '--work', str(work), '--memory-mib', '16',
               '--codec', 'zstd', '--pool', 'none', '--front-code', '1', '--index', 'cow',
               '--stats', str(initial / 'stats.json')]
    with (initial / 'build.log').open('wb') as log:
        subprocess.run(command, stdout=log, stderr=log, check=True, timeout=600)
    check_generation(args.binary, source, oracle, image, initial / 'verification')
    results = []
    for name, remove, add in changes(oracle):
        folder = output / name
        folder.mkdir()
        ordered_delta = folder / 'owner.delta'
        delta_identity = owner_ordered_file(ordered_delta, remove, add)
        _, json_delta = write_delta(folder, 'expected', remove, add)
        runs = {}
        for mode in ('unordered', 'owner'):
            case = folder / mode
            case.mkdir()
            data = case / 'data.zim'
            shutil.copy2(image, data)
            old = inspect_snapshot(args.binary, data)
            generation, current = case / 'generation.zgen', case / 'CURRENT'
            run_update(args.binary, data, ordered_delta, generation, case / 'work',
                       case / 'stats.json', current, case / 'update', delta_order=mode)
            assert_current(current, generation)
            assert_snapshot_retained(old, inspect_snapshot(args.binary, data))
            runs[mode] = {'data': data, 'generation': generation, 'current': current,
                          'stats': json.loads((case / 'stats.json').read_text())}
        physical_identity = assert_physical_identity(runs['unordered'], runs['owner'])
        stats = runs['owner']['stats']
        if (stats['delta_order'] != 'owner' or stats['delta_file_passes'] != 2 or
                not stats['delta_pass_identity_verified'] or
                stats['delta_source_sha256'] != delta_identity['sha256']):
            raise AssertionError('Owner delta input-pass identity telemetry mismatch')
        if name == 'mixed_and_gaps':
            if stats['generated_delta_runs'] != 0 or stats['spilled_sorted_owners'] != 0:
                raise AssertionError('Small owner groups unexpectedly spilled')
        else:
            if (stats['generated_delta_runs'] < 1 or stats['spilled_sorted_owners'] != 1 or
                    stats['in_memory_sorted_owners'] < 2 or stats['maximum_owner_operations'] < 24000):
                raise AssertionError('Giant-owner bounded fallback/reset was not exercised')
        verification = check_generation(args.binary, source, oracle, runs['owner']['current'],
                                          folder / 'verification', json_delta)
        check_generation(args.binary, source, oracle, runs['owner']['data'],
                          folder / 'retained_initial')
        row = {'name': name, 'status': 'PASS', 'delta_identity': delta_identity,
               'physical_output_identity': physical_identity,
               'owner_stats': stats, 'unordered_stats': runs['unordered']['stats'],
               'verification': verification}
        if name == 'mixed_and_gaps':
            row['negative_and_failure_checks'] = negative_checks(
                args, source, oracle, folder, runs['owner'], remove, add)
        save_json(folder / 'SUMMARY.json', row)
        results.append(row)
    return {'status': 'PASS', 'cases': results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {'kind': 'SUMMARY', 'status': 'RUNNING', 'binary': str(args.binary),
              'binary_sha256': file_sha256(args.binary), 'source': str(args.source),
              'source_sha256': file_sha256(args.source),
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'qualification_outside_performance_timing': True}
    try:
        result['verification'] = run_suite(args, output)
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

#!/usr/bin/env python3
"""Untimed independent qualification of reversible compact owner keys."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess

import dns.name

from validate import (audit_g1, audit_queries, canonical_name, file_sha256,
                      fixture_cases, read_source, save_json)
from validate_owner_order import owner_ordered_file
from validate_updates import (assert_current, assert_snapshot_retained,
                              inspect_snapshot, make_wire, rewritten_ttl,
                              run_update, write_delta)


OCTETS = (0, 1, 127, 128, 252, 253, 254, 255)


def escaped(octet):
    return 'k\\' + f'{octet:03d}' + '.example.'


def make_source(original, output):
    source = output / 'source.zone'
    text = original.read_text(encoding='ascii')
    text += '\nk.example. 300 IN A 192.0.2.33\n'
    for value in OCTETS:
        text += escaped(value) + f' 300 IN A 192.0.2.{value % 200 + 1}\n'
        text += 'leaf.branch\\' + f'{value:03d}' + '.example. 300 IN TXT "ent-child"\n'
    # Preserve multiplicity across an escaped-owner update as well.
    text += escaped(255) + ' 300 IN A 192.0.2.56\n'
    source.write_text(text, encoding='ascii')
    return source


def queries():
    cases = fixture_cases() + [('key_prefix', 'k.example.', 'A')]
    for value in OCTETS:
        cases += [(f'octet_{value}', escaped(value), 'A'),
                  (f'octet_{value}_missing_type', escaped(value), 'TXT'),
                  (f'ent_{value}', 'branch\\' + f'{value:03d}' + '.example.', 'TXT')]
    cases += [('new_zero_child', 'new.' + escaped(0), 'A'),
              ('new_wildcard_ent', 'missing.wild\\255.example.', 'A')]
    return cases


def check(binary, source, oracle, image, output, delta=None, index=None):
    output.mkdir()
    g1 = audit_g1(binary, source, oracle.origin, image, output, delta,
                  source_oracle=oracle)
    semantics = audit_queries(binary, image, source, oracle.origin, queries(), output,
                              delta, source_oracle=oracle)
    result = {'status': 'PASS', 'g1': g1, 'semantics': semantics}
    if index == 'cow':
        tree = json.loads(subprocess.check_output(
            [str(binary), 'inspect', '--image', str(image), '--check-index', '1'], text=True))
        if tree['index_check']['status'] != 'PASS':
            raise AssertionError('Compact COW index is invalid')
        result['index_check'] = tree['index_check']
    return result


def update_compact(args, source, oracle, image, folder, index):
    # The old root stays readable while the shared data grows.
    data = folder / 'data.zim'
    shutil.copy2(image, data)
    current = folder / 'CURRENT'
    current.write_text('data.zim\n', encoding='ascii')
    before = inspect_snapshot(args.binary, data)
    remove = Counter()
    for owner in (escaped(254), escaped(255), 'leaf.branch\\253.example.'):
        remove += oracle.records[canonical_name(owner, oracle.origin)]
    add = Counter({rewritten_ttl(wire, 1): count for wire, count in remove.items()
                   if canonical_name('leaf.branch\\253.example.', oracle.origin) !=
                   dns.name.from_wire(wire, 0)[0]})
    add[make_wire('new.' + escaped(0), 'A', 301, '192.0.2.199')] += 1
    add[make_wire('leaf.*.wild\\255.example.', 'TXT', 302, '"wildcard-ent"')] += 1
    native_delta, json_delta = write_delta(folder, 'changes', remove, add)
    owner_ordered_file(native_delta, remove, add)
    generation = folder / 'generation.zgen'
    run_update(args.binary, current, native_delta, generation, folder / 'work',
               folder / 'stats.json', current, folder / 'update', delta_order='owner')
    assert_current(current, generation)
    assert_snapshot_retained(before, inspect_snapshot(args.binary, data))
    result = check(args.binary, source, oracle, current, folder / 'new', json_delta, index)
    old = check(args.binary, source, oracle, data, folder / 'old', index=index)
    return {'status': 'PASS', 'new': result, 'retained_old': old,
            'before': before, 'after_old': inspect_snapshot(args.binary, data)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True,
                        help='Existing large generic example. source fixture')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {'kind': 'SUMMARY', 'status': 'RUNNING',
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'binary': str(args.binary), 'binary_sha256': file_sha256(args.binary),
              'qualification_outside_performance_timing': True, 'cases': []}
    try:
        source = make_source(args.source, output)
        oracle = read_source(source, canonical_name('example.', dns.name.root), keep_records=True)
        result.update(source=str(source), source_sha256=file_sha256(source))
        for index in ('fixed', 'packed', 'cow'):
            for key_codec in ('nibble', 'compact'):
                folder = output / (index + '_' + key_codec)
                folder.mkdir()
                image = folder / 'image.zim'
                command = [str(args.binary), 'build', '--zone', str(source),
                           '--origin', 'example.', '--out', str(image),
                           '--work', str(folder / 'build_work'), '--memory-mib', '16',
                           '--codec', 'zstd', '--pool', 'none', '--front-code', '1',
                           '--index', index, '--key-codec', key_codec,
                           '--stats', str(folder / 'build_stats.json')]
                with (folder / 'build.log').open('wb') as log:
                    subprocess.run(command, stdout=log, stderr=log, check=True)
                save_json(folder / 'BUILD_COMMAND.json', {'command': command})
                case = {'name': folder.name, 'status': 'PASS',
                        'base': check(args.binary, source, oracle, image,
                                      folder / 'base', index=index)}
                if key_codec == 'compact':
                    update_folder = folder / 'update'
                    update_folder.mkdir()
                    case['update'] = update_compact(args, source, oracle, image,
                                                    update_folder, index)
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

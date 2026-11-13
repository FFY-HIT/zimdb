#!/usr/bin/env python3
"""Untimed persistent page-index splice and generation regressions."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess

import dns.name

from validate import (audit_g1, audit_queries, canonical_name, file_sha256,
                      fixture_cases, read_source, save_json, unpack_wire)
from validate_updates import (assert_current, assert_snapshot_retained, inspect_snapshot,
                              make_wire, rewritten_ttl, run_update, write_delta)


def root_shape(snapshot):
    inspection = snapshot['inspection']
    root = inspection['cow_root']
    pages = int(inspection['page_count'])
    height = int(root['height'])
    if int(root['pages']) != pages:
        raise AssertionError('COW root page count mismatch')
    if pages == 0:
        if height != 0 or int(root['offset']) != 0:
            raise AssertionError('Empty index has a nonempty root')
    else:
        if not 1 <= height <= 128 or int(root['offset']) == 0:
            raise AssertionError('Nonempty index has an empty root')
        minimum_previous, minimum_current = 1, 1
        for _ in range(1, height):
            minimum_previous, minimum_current = minimum_current, minimum_previous + minimum_current
        if not (minimum_current <= pages <= (1 << (height - 1))):
            raise AssertionError('Root height is incompatible with a balanced binary index')
    return {'pages': pages, 'height': height}


def txt_members(owner, count):
    return Counter({make_wire(owner, 'TXT', 300, '"value-' + str(number).zfill(4) +
                              '-' + 'z' * 160 + '"'): 1 for number in range(count)})


def cases_for_source(collector):
    origin = collector.origin
    records = collector.records
    all_records = Counter()
    for values in records.values():
        all_records.update(values)
    huge = records[canonical_name('huge.example.', origin)]
    non_apex = Counter()
    for name, values in records.items():
        if name != origin:
            non_apex.update(values)
    ns = Counter({wire: count for wire, count in records[canonical_name('deleg.example.', origin)].items()
                  if unpack_wire(wire)[1] == 2})
    return [
        ('delete_huge_owner', huge.copy(), Counter()),
        ('insert_first_owner', Counter(), txt_members('!.example.', 400)),
        ('insert_middle_owner', Counter(), txt_members('middle.example.', 400)),
        ('insert_last_owner', Counter(), txt_members('zzzzzz.example.', 400)),
        ('collapse_to_apex', non_apex, Counter()),
        ('empty_index', all_records, Counter()),
        ('ns_ttl_and_conflicts', ns,
         Counter({rewritten_ttl(wire, 1): count for wire, count in ns.items()})),
    ]


def query_cases():
    return fixture_cases() + [
        ('range_first', 'n00000.range.example.', 'TXT'),
        ('range_middle', 'n02000.range.example.', 'TXT'),
        ('range_last', 'n03999.range.example.', 'TXT'),
        ('range_ent', 'range.example.', 'A'),
        ('insert_first_lookup', '!.example.', 'TXT'),
        ('insert_middle_lookup', 'middle.example.', 'TXT'),
        ('insert_last_lookup', 'zzzzzz.example.', 'TXT'),
    ]


def check_generation(binary, source, oracle, image, folder, delta):
    folder.mkdir()
    g1 = audit_g1(binary, source, oracle.origin, image, folder, delta, source_oracle=oracle)
    semantics = audit_queries(binary, image, source, oracle.origin, query_cases(), folder,
                              delta, source_oracle=oracle)
    snapshot = inspect_snapshot(binary, image)
    shape = root_shape(snapshot)
    process = subprocess.run([str(binary), 'inspect', '--image', str(image), '--check-index', '1'],
                             capture_output=True, text=True, check=True, timeout=60)
    checked = json.loads(process.stdout)['index_check']
    if (checked['status'] != 'PASS' or checked['verified_leaves'] != shape['pages'] or
            checked['maximum_height'] != shape['height'] or checked['maximum_balance'] > 1 or
            checked['verified_nodes'] != max(0, 2 * shape['pages'] - 1)):
        raise AssertionError('Full COW index traversal failed AVL/count invariants')
    return {'status': 'PASS', 'g1': g1, 'semantics': semantics,
            'snapshot': snapshot, 'shape': shape, 'index_check': checked}


def check_conflicts_and_faults(binary, source, oracle, folder, base, gen1, current, remove, add):
    inverse_text, _ = write_delta(folder, 'inverse', add, remove)
    gen2 = folder / 'gen2.zgen'
    run_update(binary, current, inverse_text, gen2, folder / 'restore_work',
               folder / 'restore.stats.json', current, folder / 'restore')
    assert_current(current, gen2)
    check_generation(binary, source, oracle, current, folder / 'restored_current', None)
    current_bytes = current.read_bytes()
    old1 = inspect_snapshot(binary, gen1)
    old2 = inspect_snapshot(binary, gen2)
    stale = folder / 'stale'
    stale.mkdir()
    run_update(binary, gen1, inverse_text, stale / 'candidate.zgen', stale / 'work',
               stale / 'stats.json', current, stale / 'update', expected_failure=True)
    if current.read_bytes() != current_bytes or (stale / 'candidate.zgen').exists():
        raise AssertionError('Stale generation update changed publication')
    assert_snapshot_retained(old1, inspect_snapshot(binary, gen1))
    assert_snapshot_retained(old2, inspect_snapshot(binary, gen2))
    checks = [{'name': 'stale_generation_rejected', 'status': 'PASS'}]
    positive_text, positive_json = write_delta(folder, 'positive_again', remove, add)
    for label, flag in (('before_descriptor', '--fail-before-publish'),
                        ('before_current', '--fail-before-current')):
        case = folder / label
        case.mkdir()
        candidate = case / 'candidate.zgen'
        run_update(binary, current, positive_text, candidate, case / 'work',
                   case / 'stats.json', current, case / 'update',
                   failure_flag=flag, expected_failure=True)
        if current.read_bytes() != current_bytes:
            raise AssertionError('Failed COW update published CURRENT')
        assert_snapshot_retained(old1, inspect_snapshot(binary, gen1))
        assert_snapshot_retained(old2, inspect_snapshot(binary, gen2))
        if label == 'before_descriptor' and candidate.exists():
            raise AssertionError('Pre-descriptor failure published a generation')
        if label == 'before_current':
            if not candidate.exists():
                raise AssertionError('Pre-CURRENT failure did not reach generation publication')
            check_generation(binary, source, oracle, candidate, case / 'prepared_generation', positive_json)
        checks.append({'name': label, 'status': 'PASS'})
    check_generation(binary, source, oracle, gen2, folder / 'retained_gen2', None)
    check_generation(binary, source, oracle, base, folder / 'retained_initial_after_conflicts', None)
    return checks


def run_suite(args, output):
    origin = canonical_name('example.', dns.name.root)
    source = args.source.resolve()
    oracle = read_source(source, origin, keep_records=True)
    base_folder = output / 'initial'
    base_folder.mkdir()
    base_image = base_folder / 'image.zim'
    work = base_folder / 'work'
    work.mkdir()
    command = [str(args.binary), 'build', '--zone', str(source), '--origin', 'example.',
               '--out', str(base_image), '--work', str(work), '--memory-mib', '16',
               '--codec', 'zstd', '--pool', 'none', '--front-code', '1', '--index', 'cow',
               '--stats', str(base_folder / 'build.stats.json')]
    with (base_folder / 'build.log').open('wb') as log:
        subprocess.run(command, stdout=log, stderr=log, check=True, timeout=600)
    initial = check_generation(args.binary, source, oracle, base_image,
                                base_folder / 'verification', None)
    if initial['shape']['pages'] <= 32:
        raise AssertionError('COW splice fixture must contain more than32 page leaves')
    results = []
    for name, remove, add in cases_for_source(oracle):
        case = output / name
        case.mkdir()
        base = case / 'base.zim'
        shutil.copy2(base_image, base)
        before = inspect_snapshot(args.binary, base)
        native_delta, json_delta = write_delta(case, 'change', remove, add)
        generation, current = case / 'gen1.zgen', case / 'CURRENT'
        run_update(args.binary, base, native_delta, generation, case / 'work',
                   case / 'stats.json', current, case / 'update')
        assert_current(current, generation)
        result = check_generation(args.binary, source, oracle, generation,
                                    case / 'verification', json_delta)
        published = inspect_snapshot(args.binary, current)
        if published['inspection'] != result['snapshot']['inspection']:
            raise AssertionError('CURRENT and COW generation inspection differ')
        retained = inspect_snapshot(args.binary, base)
        assert_snapshot_retained(before, retained)
        old = check_generation(args.binary, source, oracle, base,
                                 case / 'retained_initial', None)
        pages = result['shape']['pages']
        original_pages = initial['shape']['pages']
        if name == 'delete_huge_owner' and pages >= original_pages:
            raise AssertionError('Deleting the huge owner did not remove leaves')
        if name.startswith('insert_') and pages <= original_pages:
            raise AssertionError('Insertion did not shift page ordinals')
        if name == 'collapse_to_apex' and result['shape'] != {'pages': 1, 'height': 1}:
            raise AssertionError('Index did not collapse to a single leaf')
        if name == 'empty_index':
            if result['shape'] != {'pages': 0, 'height': 0}:
                raise AssertionError('Full deletion did not produce an empty index')
            repopulate = Counter({
                make_wire('example.', 'SOA', 300,
                          'ns.example. hostmaster.example. 2 3600 600 86400 300'): 1,
                make_wire('example.', 'NS', 300, 'ns.example.'): 1,
                make_wire('ns.example.', 'A', 300, '192.0.2.44'): 1,
            })
            text, _ = write_delta(case, 'repopulate', Counter(), repopulate)
            _, combined_json = write_delta(case, 'repopulate_combined', remove, repopulate)
            gen2 = case / 'gen2.zgen'
            run_update(args.binary, current, text, gen2, case / 'repopulate_work',
                       case / 'repopulate.stats.json', current, case / 'repopulate')
            assert_current(current, gen2)
            result['repopulate'] = check_generation(args.binary, source, oracle, current,
                                                     case / 'repopulated', combined_json)
            if result['repopulate']['shape'] != {'pages': 1, 'height': 1}:
                raise AssertionError('Repopulation of an empty index did not create one leaf')
        if name == 'ns_ttl_and_conflicts':
            result['conflict_and_failure_checks'] = check_conflicts_and_faults(
                args.binary, source, oracle, case, base, generation, current, remove, add)
        result.update(name=name, retained_initial=old, publication_current=str(current))
        save_json(case / 'SUMMARY.json', result)
        results.append(result)
    return {'status': 'PASS', 'initial': initial, 'case_count': len(results), 'cases': results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True,
                        help='Existing example. large_restart_groups/source.zone fixture')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {'kind': 'SUMMARY', 'status': 'RUNNING',
              'binary': str(args.binary), 'binary_sha256': file_sha256(args.binary),
              'source': str(args.source), 'source_sha256': file_sha256(args.source),
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

#!/usr/bin/env python3
"""Untimed generation-update qualification using the independent RR oracle."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype

from validate import (audit_g1, audit_queries, build_fixture, canonical_name,
                      canonical_wire, file_sha256, fixture_cases, get_source_oracle,
                      read_delta_wires, read_source, save_json, unpack_wire)


def prefix_sha256(path, length):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        remaining = length
        while remaining:
            chunk = source.read(min(remaining, 1 << 20))
            if not chunk:
                raise ValueError('Referenced committed prefix exceeds file length')
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def inspect_snapshot(binary, image):
    process = subprocess.run([str(binary), 'inspect', '--image', str(image)],
                             capture_output=True, text=True, check=True, timeout=60)
    inspection = json.loads(process.stdout)
    dependencies = []
    for dependency in inspection['dependencies']:
        path = Path(dependency['path']).resolve()
        committed = int(dependency['committed_bytes'])
        dependencies.append({'path': str(path), 'committed_bytes': committed,
                             'committed_prefix_sha256': prefix_sha256(path, committed),
                             'actual_bytes': path.stat().st_size,
                             'actual_file_sha256': file_sha256(path)})
    return {'root': {'path': str(image.resolve()), 'bytes': image.stat().st_size,
                     'sha256': file_sha256(image)},
            'inspection': inspection, 'dependencies': dependencies}


def assert_snapshot_retained(before, after):
    old = {row['path']: row for row in before['dependencies']}
    new = {row['path']: row for row in after['dependencies']}
    if old.keys() != new.keys():
        raise AssertionError('Retained snapshot dependency paths changed')
    for path, row in old.items():
        if (new[path]['committed_bytes'] != row['committed_bytes'] or
                new[path]['committed_prefix_sha256'] != row['committed_prefix_sha256']):
            raise AssertionError('Retained snapshot committed bytes changed')
    # A direct base image is also its append-only data file. Generation
    # descriptors are distinct immutable roots and must remain byte-identical.
    if before['root']['path'] not in old and before['root'] != after['root']:
        raise AssertionError('Immutable generation descriptor changed')


def write_delta(folder, name, remove, add):
    text_path = folder / (name + '.delta')
    json_path = folder / (name + '.json')
    document = {}
    with text_path.open('w', encoding='ascii', newline='\n') as target:
        for operation, sign, rows in (('remove', '-', remove), ('add', '+', add)):
            document[operation] = []
            for wire, multiplicity in sorted(rows.items()):
                document[operation].append({'wire_hex': wire.hex(), 'multiplicity': multiplicity})
                for _ in range(multiplicity):
                    target.write(sign + '\t' + wire.hex() + '\n')
    save_json(json_path, document)
    return text_path, json_path


def rewritten_ttl(wire, increment):
    _, owner_length = dns.name.from_wire(wire, 0)
    output = bytearray(wire)
    old = struct.unpack_from('!I', wire, owner_length + 4)[0]
    struct.pack_into('!I', output, owner_length + 4, old + increment)
    return bytes(output)


def make_wire(owner, rrtype, ttl, text):
    name = canonical_name(owner, dns.name.root)
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rrtype),
                               text, origin=dns.name.root, relativize=False)
    return canonical_wire(name, ttl, rdata)


def fixture_deltas(source, origin):
    records = read_source(source, origin, keep_records=True).records

    def select(owner, rrtype):
        selected = Counter()
        for wire, count in records[canonical_name(owner, origin)].items():
            if unpack_wire(wire)[1] == int(dns.rdatatype.from_text(rrtype)):
                selected[wire] = count
        return selected

    small = select('deleg.example.', 'NS')
    huge = select('huge.example.', 'TXT')
    huge_keys = sorted(huge)
    huge_partial = Counter({huge_keys[0]: 1, huge_keys[-1]: 1})
    directory = select('directory.example.', 'TYPE64599')
    duplicate = next(wire for wire, count in select('dup.example.', 'A').items()
                     if count == 2)
    topology_remove = (select('leaf.entblock.wildbase.example.', 'TXT') +
                       select('leaf.*.emptywild.example.', 'TXT') +
                       select('deleg.example.', 'NS'))
    topology_add = Counter({
        make_wire('leaf.fresh.wildbase.example.', 'TXT', 300, '"new ENT"'): 1,
        make_wire('newcut.wildbase.example.', 'NS', 300, 'ns.newcut.wildbase.example.'): 1,
    })
    return [
        ('ns_ttl', small, Counter({rewritten_ttl(wire, 1): count for wire, count in small.items()})),
        ('huge_partial', huge_partial,
         Counter({rewritten_ttl(wire, 1): count for wire, count in huge_partial.items()})),
        ('huge_complete', huge,
         Counter({rewritten_ttl(wire, 1): count for wire, count in huge.items()})),
        ('many_types_partial', directory,
         Counter({rewritten_ttl(wire, 1): count for wire, count in directory.items()})),
        ('duplicate_delete_one', Counter({duplicate: 1}), Counter({rewritten_ttl(duplicate, 2): 1})),
        ('ent_wildcard_cut_topology', topology_remove, topology_add),
    ]


def run_update(binary, image, native_delta, generation, work, stats, current, log_prefix,
               failure_flag=None, expected_failure=False, delta_order=None):
    work.mkdir()
    command = [str(binary), 'update', '--image', str(image), '--delta', str(native_delta),
               '--out', str(generation), '--work', str(work), '--stats', str(stats),
               '--memory-mib', '16', '--current', str(current)]
    if failure_flag:
        command += [failure_flag, '1']
    if delta_order is not None:
        command += ['--delta-order', delta_order]
    with log_prefix.with_suffix('.stdout.log').open('wb') as stdout, \
            log_prefix.with_suffix('.stderr.log').open('wb') as stderr:
        process = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=600)
    row = {'command': command, 'returncode': process.returncode,
           'expected_failure': expected_failure,
           'scope': 'Untimed correctness fixture, excluded from W measurements'}
    save_json(log_prefix.with_suffix('.command.json'), row)
    if expected_failure:
        if process.returncode <= 0:
            raise AssertionError('Expected a handled nonzero update failure')
    elif process.returncode:
        raise RuntimeError('Update fixture command failed')
    return row


def assert_current(current, generation):
    lines = current.read_text(encoding='utf-8').splitlines()
    if len(lines) != 1 or Path(lines[0]).is_absolute():
        raise AssertionError('CURRENT must contain one relative generation path')
    if (current.parent / lines[0]).resolve() != generation.resolve():
        raise AssertionError('CURRENT did not publish the requested generation')


def audit_fixture_updates(args, output):
    base_folder = output / 'base'
    base_folder.mkdir()
    source, frozen_base = build_fixture(args.binary, base_folder, 16, 'none', 'none', 1,
                                        args.index)
    origin = canonical_name('example.', dns.name.root)
    base_g1_folder = base_folder / 'g1'
    base_g1_folder.mkdir()
    audit_g1(args.binary, source, origin, frozen_base, base_g1_folder)
    results = []
    for name, remove, add in fixture_deltas(source, origin):
        case = output / name
        case.mkdir()
        base = case / 'base.zim'
        shutil.copy2(frozen_base, base)
        old = inspect_snapshot(args.binary, base)
        native_delta, json_delta = write_delta(case, 'change', remove, add)
        generation, current = case / 'gen1.zgen', case / 'CURRENT'
        command = run_update(args.binary, base, native_delta, generation, case / 'work',
                             case / 'update.stats.json', current, case / 'update')
        assert_current(current, generation)
        retained = inspect_snapshot(args.binary, base)
        assert_snapshot_retained(old, retained)
        new = inspect_snapshot(args.binary, generation)
        verification = case / 'new_generation'
        verification.mkdir()
        g1 = audit_g1(args.binary, source, origin, generation, verification, json_delta)
        semantics = audit_queries(args.binary, generation, source, origin, fixture_cases(),
                                  verification, json_delta)
        published = inspect_snapshot(args.binary, current)
        if published['inspection'] != new['inspection']:
            raise AssertionError('CURRENT resolves a different generation')
        published_verification = case / 'current_entrypoint'
        published_verification.mkdir()
        audit_g1(args.binary, source, origin, current, published_verification, json_delta)
        audit_queries(args.binary, current, source, origin, fixture_cases(),
                      published_verification, json_delta)
        old_verification = case / 'retained_generation'
        old_verification.mkdir()
        audit_g1(args.binary, source, origin, base, old_verification)
        audit_queries(args.binary, base, source, origin, fixture_cases(), old_verification)
        row = {'name': name, 'status': 'PASS', 'command': command,
               'before': old, 'retained_after': retained, 'new_generation': new,
               'current_entrypoint_identity': published,
               'g1': g1, 'semantics': semantics}
        if name == 'ns_ttl':
            row['publication_failures'] = audit_publication_failures(
                args.binary, source, origin, generation, current, case, remove, add)
        save_json(case / 'SUMMARY.json', row)
        results.append(row)
    return {'status': 'PASS', 'case_count': len(results), 'cases': results}


def audit_publication_failures(binary, source, origin, old_generation, current, folder, remove, add):
    current_before = current.read_bytes()
    retained_before = inspect_snapshot(binary, old_generation)
    cases = [
        ('invalid_removal', Counter({make_wire('absent.example.', 'A', 300, '192.0.2.250'): 1}),
         Counter(), None),
        ('before_descriptor', add, remove, '--fail-before-publish'),
        ('before_current', add, remove, '--fail-before-current'),
    ]
    result = []
    for name, to_remove, to_add, failure_flag in cases:
        case = folder / name
        case.mkdir()
        native_delta, _ = write_delta(case, 'change', to_remove, to_add)
        candidate = case / 'candidate.zgen'
        command = run_update(binary, current, native_delta, candidate, case / 'work',
                             case / 'update.stats.json', current, case / 'update',
                             failure_flag=failure_flag, expected_failure=True)
        if current.read_bytes() != current_before:
            raise AssertionError('Failed update changed CURRENT')
        after = inspect_snapshot(binary, old_generation)
        assert_snapshot_retained(retained_before, after)
        if name in ('invalid_removal', 'before_descriptor') and candidate.exists():
            raise AssertionError('Uncommitted descriptor unexpectedly published')
        if name == 'before_current' and not candidate.exists():
            raise AssertionError('Pre-CURRENT injection did not reach durable descriptor stage')
        if name == 'before_current':
            prepared = case / 'prepared_generation'
            prepared.mkdir()
            audit_g1(binary, source, origin, candidate, prepared)
        if name == 'before_descriptor' and (
                after['dependencies'][0]['actual_bytes'] <= retained_before['dependencies'][0]['actual_bytes']):
            raise AssertionError('Pre-descriptor injection did not reach append stage')
        result.append({'name': name, 'status': 'PASS', 'command': command,
                       'current_unchanged': True, 'old_snapshot_retained': True,
                       'candidate_exists': candidate.exists(), 'physical_after': after})
    return result


def assert_ns_ttl_only(delta_path):
    changes = read_delta_wires(delta_path)
    expected_add = Counter()
    for wire, multiplicity in changes['remove'].items():
        if unpack_wire(wire)[1] != int(dns.rdatatype.NS):
            raise AssertionError('Campaign delta contains a non-NS removal')
        expected_add[rewritten_ttl(wire, 1)] += multiplicity
    if expected_add != changes['add']:
        raise AssertionError('Campaign delta changes more than complete NS wire TTL+1')
    return {'changed_rr_occurrences': sum(expected_add.values()),
            'changed_types': [int(dns.rdatatype.NS)],
            'dnssec_preservation_basis': 'Complete expected RR multiset changes NS TTL only; all other full RR wire occurrences unchanged'}


def audit_existing_generations(args, output):
    origin = canonical_name(args.origin, dns.name.root)
    oracle = get_source_oracle(args.source, origin, args.oracle_cache)
    base = inspect_snapshot(args.binary, args.base)
    if args.base_g1:
        previous = json.loads(args.base_g1.read_text())
        if (previous['status'] != 'PASS' or not previous['multiset_equal'] or
                previous['source_sha256'] != oracle.source_identity['sha256'] or
                previous['image_sha256'] != base['root']['sha256']):
            raise AssertionError('Base G1 reuse identity mismatch')
        base_g1 = {'status': 'PASS_BYTE_IDENTITY_REUSE', 'receipt': str(args.base_g1)}
    else:
        base_folder = output / 'base_g1'
        base_folder.mkdir()
        base_g1 = audit_g1(args.binary, args.source, origin, args.base, base_folder,
                           source_oracle=oracle)
    results = []
    for name, generation_text, delta_text in args.case:
        folder = output / name
        folder.mkdir()
        generation, delta = Path(generation_text), Path(delta_text)
        invariant = assert_ns_ttl_only(delta)
        snapshot = inspect_snapshot(args.binary, generation)
        old_data = Path(snapshot['inspection']['data_file'])
        old_snapshot = inspect_snapshot(args.binary, old_data)
        if (old_snapshot['dependencies'][0]['committed_bytes'] != base['dependencies'][0]['committed_bytes'] or
                old_snapshot['dependencies'][0]['committed_prefix_sha256'] != base['dependencies'][0]['committed_prefix_sha256']):
            raise AssertionError('Retained original root differs from qualified base')
        g1 = audit_g1(args.binary, args.source, origin, generation, folder, delta,
                      source_oracle=oracle)
        row = {'name': name, 'status': 'PASS', 'g1': g1, 'delta_invariant': invariant,
               'generation_identity': snapshot, 'retained_base_identity': old_snapshot,
               'retained_base_logical_status': 'PASS_BYTE_IDENTITY_REUSE',
               'base_g1': base_g1}
        save_json(folder / 'SUMMARY.json', row)
        results.append(row)
    return {'status': 'PASS', 'cases': results, 'base_identity': base, 'base_g1': base_g1,
            'source_oracle_cache': oracle.oracle_cache_metadata}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--run-fixture', action='store_true')
    parser.add_argument('--index', choices=('fixed', 'packed', 'cow'))
    parser.add_argument('--source', type=Path)
    parser.add_argument('--origin', default='agency.')
    parser.add_argument('--base', type=Path)
    parser.add_argument('--base-g1', type=Path)
    parser.add_argument('--oracle-cache', type=Path)
    parser.add_argument('--case', nargs=3, action='append', metavar=('NAME', 'GENERATION', 'DELTA_JSON'))
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {'kind': 'SUMMARY', 'status': 'RUNNING',
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'binary': str(args.binary.resolve()), 'binary_sha256': file_sha256(args.binary),
              'qualification_outside_performance_timing': True}
    try:
        if args.run_fixture:
            result['verification'] = audit_fixture_updates(args, output)
        else:
            if not all((args.source, args.base, args.oracle_cache, args.case)):
                raise ValueError('Existing generation audit requires --source --base --oracle-cache and --case')
            result['verification'] = audit_existing_generations(args, output)
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

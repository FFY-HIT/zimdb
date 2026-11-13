#!/usr/bin/env python3
"""Independent source-wire multiset and query-semantic checks.

Qualification runs outside performance timing. The source oracle uses
dnspython's parser and captures each parsed RR before RRset merging. Its
explicit name/ancestor sets exist only in this validation process.
"""

from __future__ import annotations

import argparse
import bisect
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.tokenizer
import dns.zonefile


def save_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def file_sha256(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def canonical_wire(name, ttl, rdata):
    payload = rdata.to_digestable(dns.name.root)
    return (name.canonicalize().to_wire() +
            struct.pack('!HHIH', int(rdata.rdtype), int(rdata.rdclass), ttl,
                        len(payload)) + payload)


def unpack_wire(wire):
    # Native's wire command promises uncompressed standalone canonical RRs.
    position = 0
    while True:
        if position >= len(wire):
            raise ValueError('Truncated owner name')
        length = wire[position]
        if length & 0xc0:
            raise ValueError('Compressed owner in standalone RR wire')
        position += 1
        if length == 0:
            break
        position += length
    owner, used = dns.name.from_wire(wire, 0)
    if used != position or position + 10 > len(wire):
        raise ValueError('Malformed RR owner/header')
    rdtype, rdclass, ttl, rdlength = struct.unpack_from('!HHIH', wire, position)
    position += 10
    if position + rdlength != len(wire):
        raise ValueError('RDLENGTH differs from standalone wire length')
    rdata = dns.rdata.from_wire(rdclass, rdtype, wire, position, rdlength,
                               origin=dns.name.root)
    if canonical_wire(owner, ttl, rdata) != wire:
        raise ValueError('Native wire is not canonical uncompressed RR wire')
    return owner.canonicalize(), rdtype, rdclass, ttl


class RecordCollector:
    """Minimal parser transaction retaining every occurrence and each TTL."""

    def __init__(self, origin, keep_records):
        self.origin = origin
        self.manager = self
        self.keep_records = keep_records
        self.hashes = Counter()
        self.type_counts = Counter()
        self.records = defaultdict(Counter)
        self.count = 0
        self.wire_bytes = 0

    def origin_information(self):
        return self.origin, False, self.origin

    def check_put_rdataset(self, check):
        # Reader adds this RRset-level check for zone construction. This
        # collector records the parser's RR events without constructing a zone.
        pass

    def _set_origin(self, origin):
        # $ORIGIN changes the parser's current origin, not the fixed zone apex.
        pass

    def add(self, name, ttl, rdata):
        name = name.canonicalize()
        wire = canonical_wire(name, ttl, rdata)
        digest = hashlib.sha256(wire).digest()
        self.hashes[digest] += 1
        self.count += 1
        self.wire_bytes += len(wire)
        self.type_counts[int(rdata.rdtype)] += 1
        if self.keep_records:
            self.records[name][wire] += 1


def read_source(path, origin, keep_records=False):
    collector = RecordCollector(origin, keep_records)
    with Path(path).open(encoding='utf-8') as source:
        tokenizer = dns.tokenizer.Tokenizer(source, str(path))
        parser = dns.zonefile.Reader(tokenizer, dns.rdataclass.IN, collector,
                                     allow_include=False)
        parser.read()
    return collector


def get_source_oracle(source_path, origin, cache_directory):
    """Cache independently parsed RR digests with content and checksum binding."""
    source_path = Path(source_path)
    cache_directory = Path(cache_directory)
    metadata_path = cache_directory / 'SOURCE_ORACLE.json'
    digest_path = cache_directory / 'digests.tsv.gz'
    source_id = {'path': str(source_path.resolve()), 'bytes': source_path.stat().st_size,
                 'sha256': file_sha256(source_path), 'origin': origin.to_text()}
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text())
        for field in ('bytes', 'sha256', 'origin'):
            if metadata['source'][field] != source_id[field]:
                raise ValueError('Source oracle cache identity mismatch: ' + field)
        if file_sha256(digest_path) != metadata['digest_file_sha256']:
            raise ValueError('Source oracle cache checksum mismatch')
        collector = RecordCollector(origin, keep_records=False)
        with gzip.open(digest_path, 'rt', encoding='ascii') as source:
            for line in source:
                digest, count = line.rstrip('\n').split('\t')
                if len(digest) != 64 or int(count) < 1:
                    raise ValueError('Malformed cached source digest')
                key = bytes.fromhex(digest)
                if key in collector.hashes:
                    raise ValueError('Repeated digest key in source cache')
                collector.hashes[key] = int(count)
        if digest_summary(collector.hashes) != metadata['summary']:
            raise ValueError('Source cache summary mismatch')
        collector.count = metadata['summary']['rr_occurrences']
        collector.type_counts.update({int(key): value for key, value in metadata['type_counts'].items()})
        collector.wire_bytes = metadata['wire_bytes']
    else:
        cache_directory.mkdir(parents=True, exist_ok=False)
        collector = read_source(source_path, origin)
        if file_sha256(source_path) != source_id['sha256']:
            raise ValueError('Source changed during oracle capture')
        temporary = digest_path.with_name(digest_path.name + '.tmp')
        with gzip.open(temporary, 'wt', encoding='ascii', compresslevel=1, newline='\n') as target:
            for digest, count in collector.hashes.items():
                target.write(digest.hex() + '\t' + str(count) + '\n')
        temporary.replace(digest_path)
        metadata = {'schema': 1, 'source': source_id,
                    'oracle': 'dnspython per-RR events, TTL and multiplicity preserved',
                    'dnspython_version': __import__('dns').__version__,
                    'digest_file_sha256': file_sha256(digest_path),
                    'summary': digest_summary(collector.hashes),
                    'type_counts': dict(collector.type_counts), 'wire_bytes': collector.wire_bytes}
        save_json(metadata_path, metadata)
    collector.source_identity = source_id
    collector.oracle_cache_metadata = str(metadata_path)
    return collector


def digest_summary(hashes):
    unique_digest = hashlib.sha256()
    multiset_digest = hashlib.sha256()
    for digest, count in sorted(hashes.items()):
        line = digest.hex().encode('ascii') + b'\n'
        unique_digest.update(line)
        for _ in range(count):
            multiset_digest.update(line)
    return {'rr_occurrences': sum(hashes.values()), 'unique_rrs': len(hashes),
            'sorted_unique_rr_sha256': unique_digest.hexdigest(),
            'sorted_multiset_rr_sha256': multiset_digest.hexdigest()}


def read_image_wire(binary, image, output):
    hashes = Counter()
    type_counts = Counter()
    count = 0
    wire_bytes = 0
    command = [str(binary), 'wire', '--image', str(image)]
    with (output / 'wire.stderr.log').open('wb') as error:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=error,
                                   text=True, encoding='ascii')
        try:
            for number, line in enumerate(process.stdout, 1):
                text = line.rstrip('\n')
                if not text or text != text.lower() or any(c not in '0123456789abcdef' for c in text):
                    raise ValueError(f'Malformed lowercase hex RR at output line {number}')
                wire = bytes.fromhex(text)
                _, rdtype, _, _ = unpack_wire(wire)
                hashes[hashlib.sha256(wire).digest()] += 1
                type_counts[rdtype] += 1
                count += 1
                wire_bytes += len(wire)
            returncode = process.wait(timeout=60)
            if returncode:
                raise RuntimeError(f'Native wire command exited {returncode}')
        except BaseException:
            process.terminate()
            process.wait(timeout=10)
            raise
    return hashes, {'command': command, 'rr_occurrences': count,
                    'wire_bytes': wire_bytes, 'type_counts': dict(type_counts)}


def read_delta_wires(delta_path):
    delta = json.loads(delta_path.read_text(encoding='utf-8'))
    changes = {}
    for operation in ('remove', 'add'):
        changes[operation] = Counter()
        for row in delta.get(operation, []):
            if isinstance(row, str):
                wire, multiplicity = bytes.fromhex(row), 1
            else:
                wire = bytes.fromhex(row['wire_hex'])
                multiplicity = row['multiplicity']
            if not isinstance(multiplicity, int) or multiplicity < 1:
                raise ValueError('Delta multiplicity must be a positive integer')
            unpack_wire(wire)
            changes[operation][wire] += multiplicity
    return changes


def apply_delta(hashes, delta_path):
    wire_changes = read_delta_wires(delta_path)
    changes = {operation: Counter() for operation in ('remove', 'add')}
    for operation, records in wire_changes.items():
        for wire, multiplicity in records.items():
            changes[operation][hashlib.sha256(wire).digest()] += multiplicity
    if changes['remove'] - hashes:
        raise ValueError('Delta removes an unavailable RR occurrence')
    hashes.subtract(changes['remove'])
    hashes.update(changes['add'])
    hashes += Counter()  # Drop only zero counts after strict removals.
    return {'path': str(delta_path), 'sha256': file_sha256(delta_path),
            'removed_occurrences': sum(changes['remove'].values()),
            'added_occurrences': sum(changes['add'].values())}


def audit_g1(binary, source_path, origin, image, output, delta_path=None, source_oracle=None):
    source = source_oracle if source_oracle is not None else read_source(source_path, origin)
    source_sha = file_sha256(source_path)
    if hasattr(source, 'source_identity') and source.source_identity['sha256'] != source_sha:
        raise ValueError('Shared source oracle does not match source content')
    expected_hashes = source.hashes.copy()
    base_summary = digest_summary(expected_hashes)
    delta = apply_delta(expected_hashes, delta_path) if delta_path else None
    actual, native = read_image_wire(binary, image, output)
    set_equal = actual.keys() == expected_hashes.keys()
    multiset_equal = actual == expected_hashes
    missing = expected_hashes - actual
    extra = actual - expected_hashes
    result = {'status': 'PASS' if multiset_equal else 'FAIL',
              'source_path': str(source_path), 'source_sha256': source_sha,
              'image_path': str(image), 'image_sha256': file_sha256(image),
              'oracle': 'dnspython zonefile RR events, no RRset merging',
              'source_oracle_cache': getattr(source, 'oracle_cache_metadata', None),
              'canonical_protocol': 'SHA256 of full canonical uncompressed RR wire including TTL; sorted lowercase hex LF',
              'set_equal': set_equal, 'multiset_equal': multiset_equal,
              'base_source': base_summary, 'delta': delta,
              'source': digest_summary(expected_hashes), 'actual': digest_summary(actual),
              'source_type_counts': dict(source.type_counts), 'native_wire': native,
              'missing_occurrences': sum(missing.values()),
              'unexpected_occurrences': sum(extra.values()),
              'missing_digest_examples': [d.hex() for d in list(missing)[:8]],
              'unexpected_digest_examples': [d.hex() for d in list(extra)[:8]]}
    save_json(output / 'G1.json', result)
    if not multiset_equal:
        raise AssertionError('Full canonical RR multiset differs from source')
    return result


def canonical_name(text, origin):
    return dns.name.from_text(text, origin=origin).canonicalize()


class SemanticOracle:
    def __init__(self, collector):
        self.origin = collector.origin
        self.records = collector.records
        self.owners = sorted(self.records)
        self.nodes = {self.origin}
        self.typed = defaultdict(lambda: defaultdict(Counter))
        for name, records in self.records.items():
            for wire, multiplicity in records.items():
                _, rdtype, _, _ = unpack_wire(wire)
                self.typed[name][rdtype][wire] += multiplicity
            ancestor = name
            while ancestor.is_subdomain(self.origin):
                self.nodes.add(ancestor)
                if ancestor == self.origin:
                    break
                ancestor = ancestor.parent()

    def query(self, name, rdtype):
        index = bisect.bisect_left(self.owners, name)
        lookup_owner = self.owners[index] if index < len(self.owners) else None
        lookup = ('exact' if lookup_owner == name else
                  'successor' if lookup_owner is not None else 'none')
        if name in self.records:
            state = 'explicit'
        elif name in self.nodes:
            state = 'ent'
        else:
            state = 'absent'
        closest = name
        while closest not in self.nodes:
            closest = closest.parent()
        ancestors = []
        current = name
        while current != self.origin:
            ancestors.append(current)
            current = current.parent()
        cut = next((ancestor for ancestor in reversed(ancestors)
                    if self.typed.get(ancestor, {}).get(int(dns.rdatatype.NS))), None)
        wildcard = None
        exact = self.typed.get(name, {}).get(rdtype, Counter())
        if cut is not None:
            resolved = exact if name == cut and rdtype == int(dns.rdatatype.DS) else self.typed[cut][int(dns.rdatatype.NS)]
        elif state == 'absent':
            candidate = dns.name.from_text('*', closest).canonicalize()
            if candidate in self.nodes:
                wildcard = candidate
                sets = self.typed[candidate]
                resolved = sets.get(rdtype, Counter())
                if not resolved and rdtype != int(dns.rdatatype.CNAME):
                    resolved = sets.get(int(dns.rdatatype.CNAME), Counter())
            else:
                resolved = Counter()
            if wildcard is not None:
                synthesized = Counter()
                for wire, multiplicity in resolved.items():
                    source_owner, _, _, _ = unpack_wire(wire)
                    rewritten = name.to_wire() + wire[len(source_owner.to_wire()):]
                    synthesized[rewritten] += multiplicity
                resolved = synthesized
        else:
            resolved = exact
            if not resolved and state == 'explicit' and rdtype != int(dns.rdatatype.CNAME):
                resolved = self.typed[name].get(int(dns.rdatatype.CNAME), Counter())
        if cut is not None and not (name == cut and rdtype == int(dns.rdatatype.DS)):
            status = 'referral'
        elif resolved:
            selected_type = unpack_wire(next(iter(resolved)))[1]
            status = ('cname' if wildcard is None and
                      selected_type == int(dns.rdatatype.CNAME) and rdtype != selected_type
                      else 'answer')
        elif state == 'absent' and wildcard is None:
            status = 'nxdomain'
        else:
            status = 'nodata'
        return {'origin': self.origin, 'name_state': state,
                'lookup': lookup, 'lookup_owner': lookup_owner, 'status': status,
                'closest_encloser': closest, 'wildcard_source': wildcard,
                'zone_cut': cut, 'exact_records': exact, 'records': resolved}


def query_record_counter(rows, origin):
    result = Counter()
    for row in rows:
        wire = bytes.fromhex(row['wire_hex'])
        owner, rdtype, rdclass, ttl = unpack_wire(wire)
        if canonical_name(row['owner'], origin) != owner:
            raise AssertionError('Record owner field differs from wire')
        if (int(row['type']), int(row['class']), int(row['ttl'])) != (rdtype, rdclass, ttl):
            raise AssertionError('Record type/class/TTL fields differ from wire')
        multiplicity = row['multiplicity']
        if not isinstance(multiplicity, int) or multiplicity < 1:
            raise AssertionError('Record multiplicity must be a positive integer')
        result[wire] += multiplicity
    return result


def audit_queries(binary, image, source_path, origin, cases, output, delta_path=None,
                  source_oracle=None):
    if source_oracle is None:
        source = read_source(source_path, origin, keep_records=True)
    else:
        source = RecordCollector(origin, keep_records=True)
        source.records.update({owner: records.copy()
                               for owner, records in source_oracle.records.items()})
    if delta_path:
        changes = read_delta_wires(delta_path)
        for wire, multiplicity in changes['remove'].items():
            owner = unpack_wire(wire)[0]
            if source.records.get(owner, Counter())[wire] < multiplicity:
                raise ValueError('Semantic delta removes unavailable RR occurrences')
            source.records[owner][wire] -= multiplicity
            if source.records[owner][wire] == 0:
                del source.records[owner][wire]
            if not source.records[owner]:
                del source.records[owner]
        for wire, multiplicity in changes['add'].items():
            source.records[unpack_wire(wire)[0]][wire] += multiplicity
    oracle = SemanticOracle(source)
    checks = []
    for number, (label, name, type_text) in enumerate(cases):
        rdtype = int(dns.rdatatype.from_text(type_text))
        expected = oracle.query(canonical_name(name, origin), rdtype)
        command = [str(binary), 'query', '--image', str(image), '--name', name,
                   '--type', type_text]
        process = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if process.returncode:
            raise RuntimeError(f'Query failed {label}: {process.stderr}')
        actual = json.loads(process.stdout)
        save_json(output / f'query_{number:02d}.json', actual)
        failures = []
        for key in ('origin', 'lookup_owner', 'closest_encloser', 'wildcard_source', 'zone_cut'):
            got = None if actual[key] is None else canonical_name(actual[key], origin)
            if got != expected[key]:
                failures.append(key)
        for key in ('name_state', 'lookup', 'status'):
            if actual[key] != expected[key]:
                failures.append(key)
        for key in ('exact_records', 'records'):
            if query_record_counter(actual[key], origin) != expected[key]:
                failures.append(key)
        if expected['wildcard_source'] is not None:
            for record in actual['records']:
                if canonical_name(record['source_owner'], origin) != expected['wildcard_source']:
                    failures.append('record_source_owner')
        checks.append({'label': label, 'name': name, 'type': type_text,
                       'status': 'PASS' if not failures else 'FAIL',
                       'failed_fields': failures, 'command': command,
                       'expected': {key: (value.to_text() if isinstance(value, dns.name.Name) else value)
                                    for key, value in expected.items() if key not in ('exact_records', 'records')},
                       'exact_rr_occurrences': sum(expected['exact_records'].values()),
                       'resolved_rr_occurrences': sum(expected['records'].values())})
    result = {'status': 'PASS' if all(c['status'] == 'PASS' for c in checks) else 'FAIL',
              'oracle': 'independent dnspython source records and ancestor sets, qualification only',
              'checks': checks}
    save_json(output / 'SEMANTICS.json', result)
    if result['status'] != 'PASS':
        raise AssertionError('Name/query semantics differ from independent source oracle')
    return result


def fixture_cases():
    return [
        ('origin', 'example.', 'SOA'),
        ('apex_ns', 'example.', 'NS'),
        ('explicit', 'www.example.', 'A'),
        ('explicit_missing_type', 'www.example.', 'AAAA'),
        ('ent', 'entblock.wildbase.example.', 'A'),
        ('ent_blocks_wildcard', 'missing.entblock.wildbase.example.', 'A'),
        ('wildcard', 'unmatched.wildbase.example.', 'A'),
        ('wildcard_missing_type', 'unmatched.wildbase.example.', 'MX'),
        ('wildcard_ent_source', 'missing.emptywild.example.', 'A'),
        ('new_ent_blocks_wildcard', 'missing.fresh.wildbase.example.', 'A'),
        ('new_cut_blocks_wildcard', 'host.newcut.wildbase.example.', 'A'),
        ('wildcard_cname', 'missing.aliasbase.example.', 'A'),
        ('absent', 'missing.www.example.', 'A'),
        ('referral', 'host.deleg.example.', 'A'),
        ('highest_cut', 'host.deep.deleg.example.', 'A'),
        ('cut_ds', 'deleg.example.', 'DS'),
        ('cut_without_ds', 'deep.deleg.example.', 'DS'),
        ('cname', 'alias.example.', 'A'),
        ('mixed_ttl_and_duplicates', 'dup.example.', 'A'),
        ('mixed_rrsig_ttl', 'example.', 'RRSIG'),
        ('nsec', 'www.example.', 'NSEC'),
        ('unknown', 'opaque.example.', 'TYPE65534'),
        ('casefold', 'MiXeD.ExAmPlE.', 'A'),
        ('escaped_dot', r'x\046dot.example.', 'A'),
        ('escaped_octet', r'oct\128et.example.', 'A'),
        ('escaped_zero', r'nul\000label.example.', 'A'),
        ('prefix_boundary', 'far.example.', 'A'),
        ('before_first_child', '!.example.', 'A'),
        ('after_last_child', 'zzzzzz.example.', 'A'),
        ('huge_rrset', 'huge.example.', 'TXT'),
        ('many_types', 'directory.example.', 'TYPE64599'),
    ]


def build_fixture(binary, output, memory_mib, codec, pool, front_code, index_format=None):
    fixture = Path(__file__).with_name('fixtures') / 'semantics.zone'
    source_path = output / 'semantics.zone'
    text = fixture.read_text(encoding='ascii')
    for number in range(1200):
        text += f'huge.example. 300 IN TXT "value-{number:04d}-' + ('x' * 160) + '"\n'
    for number in range(600):
        text += f'directory.example. 300 IN TYPE{64000 + number} \\# 4 {number:08x}\n'
    source_path.write_text(text, encoding='ascii')
    image = output / 'image.zim'
    work = output / 'work'
    work.mkdir()
    command = [str(binary), 'build', '--zone', str(source_path), '--origin', 'example.',
               '--out', str(image), '--work', str(work), '--memory-mib', str(memory_mib),
               '--codec', codec, '--pool', pool, '--front-code', str(front_code),
               '--stats', str(output / 'build_stats.json')]
    if index_format is not None:
        command += ['--index', index_format]
    with (output / 'build.stdout.log').open('wb') as stdout, (output / 'build.stderr.log').open('wb') as stderr:
        process = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=600)
    if process.returncode:
        raise RuntimeError(f'Fixture build failed, exit {process.returncode}')
    save_json(output / 'BUILD_COMMAND.json', {'command': command, 'returncode': process.returncode,
                                             'scope': 'qualification fixture, outside performance timing'})
    return source_path, image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--image', type=Path)
    parser.add_argument('--origin', default='agency.')
    parser.add_argument('--delta', type=Path)
    parser.add_argument('--oracle-cache', type=Path)
    parser.add_argument('--check-fixture', action='store_true',
                        help='Check standard example. query cases on an existing image')
    parser.add_argument('--run-fixture', action='store_true')
    parser.add_argument('--memory-mib', type=int, default=16)
    parser.add_argument('--codec', default='none')
    parser.add_argument('--pool', default='none')
    parser.add_argument('--front-code', type=int, choices=(0, 1), default=1)
    parser.add_argument('--index', choices=('fixed', 'packed', 'cow'))
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {'kind': 'SUMMARY', 'status': 'RUNNING', 'started_utc': datetime.now(timezone.utc).isoformat(),
              'binary': str(args.binary.resolve()), 'binary_sha256': file_sha256(args.binary),
              'qualification_outside_performance_timing': True,
              'fixture': args.run_fixture, 'dnspython_version': __import__('dns').__version__}
    try:
        if args.run_fixture:
            if args.source or args.image:
                raise ValueError('Fixture mode creates its own source and image')
            source, image = build_fixture(args.binary, output, args.memory_mib, args.codec,
                                          args.pool, args.front_code, args.index)
            origin = canonical_name('example.', dns.name.root)
        else:
            if not args.source or not args.image:
                raise ValueError('--source and --image are required for full-source G1')
            source, image = args.source, args.image
            origin = canonical_name(args.origin, dns.name.root)
        oracle = get_source_oracle(source, origin, args.oracle_cache) if args.oracle_cache else None
        result['g1'] = audit_g1(args.binary, source, origin, image, output, args.delta, oracle)
        if args.run_fixture or args.check_fixture:
            if origin != canonical_name('example.', dns.name.root):
                raise ValueError('Standard semantic fixture queries require example. origin')
            result['semantics'] = audit_queries(args.binary, image, source, origin,
                                                fixture_cases(), output, args.delta)
        result['status'] = 'PASS'
    except BaseException as error:
        result['status'] = 'FAIL'
        result['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        result['completed_utc'] = datetime.now(timezone.utc).isoformat()
        save_json(output / 'SUMMARY.json', result)
        print(json.dumps({'status': result['status'], 'summary': str(output / 'SUMMARY.json')}), flush=True)


if __name__ == '__main__':
    main()

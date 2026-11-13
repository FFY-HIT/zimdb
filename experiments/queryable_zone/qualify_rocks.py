#!/usr/bin/env python3
"""Qualify native DNSRocks storage against the independent source RR multiset."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

import dns.name

import validate


def inventory(database):
    rows = []
    for path in sorted(database.iterdir()):
        if not path.is_file():
            continue
        if path.name in {'LOG', 'LOCK'} or path.name.startswith('LOG.old.'):
            continue
        stat = path.stat()
        rows.append({'name': path.name, 'bytes': stat.st_size,
                     'sha256': validate.file_sha256(path),
                     'allocated_bytes': stat.st_blocks * 512,
                     'device': stat.st_dev, 'inode': stat.st_ino})
    return rows


def read_database(binary, database, output):
    command = [str(binary), 'wire', '--db', str(database)]
    hashes = Counter()
    types = Counter()
    wire_bytes = 0
    with (output / 'wire.stderr.log').open('wb') as error:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=error,
                                   text=True, encoding='ascii')
        try:
            for number, line in enumerate(process.stdout, 1):
                text = line.rstrip('\n')
                if (not text or text != text.lower() or len(text) > 2 * 65800 or
                        any(character not in '0123456789abcdef' for character in text)):
                    raise ValueError(f'Malformed canonical wire hex at native RR {number}')
                wire = bytes.fromhex(text)
                _, record_type, _, _ = validate.unpack_wire(wire)
                hashes[hashlib.sha256(wire).digest()] += 1
                types[record_type] += 1
                wire_bytes += len(wire)
            returncode = process.wait(timeout=60)
            if returncode:
                raise RuntimeError(f'Native DNSRocks export exited {returncode}')
        except BaseException:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
            raise
    return hashes, {'command': command, 'rr_occurrences': sum(hashes.values()),
                    'wire_bytes': wire_bytes, 'type_counts': dict(types)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--origin', required=True)
    parser.add_argument('--oracle-cache', type=Path, required=True)
    parser.add_argument('--delta', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--properties', type=Path, default=Path(
        '/home/administrator/zimdb_block_codec_20261112/bin/sst_properties'))
    parser.add_argument('--expected-codec', help='Optional exact SST compression name, case insensitive')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve()
    database = args.db.resolve()
    result = {'kind': 'SUMMARY', 'status': 'RUNNING',
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'binary': str(binary), 'binary_sha256': validate.file_sha256(binary),
              'qualifier_sha256': validate.file_sha256(Path(__file__)),
              'source_oracle_code_sha256': validate.file_sha256(Path(validate.__file__)),
              'sst_properties_binary_sha256': validate.file_sha256(args.properties),
              'database': str(database),
              'qualification_outside_performance_timing': True,
              'semantic_scope': 'Full canonical RR multiset; name-query semantics require separate fixtures'}
    try:
        origin = dns.name.from_text(args.origin, dns.name.root).canonicalize()
        source = validate.get_source_oracle(args.source, origin, args.oracle_cache)
        expected = source.hashes.copy()
        base_summary = validate.digest_summary(expected)
        delta = validate.apply_delta(expected, args.delta) if args.delta else None
        before = inventory(database)
        validate.save_json(output / 'payload_before.json', before)
        actual, exported = read_database(binary, database, output)
        command = [str(args.properties.resolve()), str(database)]
        completed = subprocess.run(command, capture_output=True, text=True)
        (output / 'sst_properties.stdout.json').write_text(completed.stdout)
        (output / 'sst_properties.stderr.log').write_text(completed.stderr)
        if completed.returncode:
            raise RuntimeError(f'SST property inspection exited {completed.returncode}')
        properties = json.loads(completed.stdout)
        validate.save_json(output / 'SST_PROPERTIES.json', properties)
        if (properties.get('status') != 'PASS' or properties.get('failures') != 0 or
                not properties.get('files')):
            raise ValueError('SST properties did not qualify every observed file')
        native_sst = {row['name'] for row in before if row['name'].endswith('.sst')}
        if {row['name'] for row in properties['files']} != native_sst:
            raise ValueError('SST property inventory differs from native payload')
        codecs = sorted({row['compression_name'] for row in properties['files']})
        if args.expected_codec and {codec.lower() for codec in codecs} != {args.expected_codec.lower()}:
            raise ValueError('Observed SST compression differs from the declared codec')
        after = inventory(database)
        validate.save_json(output / 'payload_after.json', after)
        missing = expected - actual
        extra = actual - expected
        g1 = {'status': 'PASS' if actual == expected and before == after else 'FAIL',
              'source_path': str(args.source.resolve()),
              'source_sha256': source.source_identity['sha256'],
              'source_oracle_cache': source.oracle_cache_metadata,
              'oracle': 'Independent dnspython per-RR source events with cached digest identity binding',
              'base_source': base_summary, 'delta': delta,
              'source': validate.digest_summary(expected),
              'actual': validate.digest_summary(actual),
              'set_equal': actual.keys() == expected.keys(),
              'multiset_equal': actual == expected,
              'native_payload_unchanged': before == after,
              'native_payload_bytes': sum(row['bytes'] for row in before),
              'missing_occurrences': sum(missing.values()),
              'unexpected_occurrences': sum(extra.values()),
              'missing_digest_examples': [digest.hex() for digest in list(missing)[:8]],
              'unexpected_digest_examples': [digest.hex() for digest in list(extra)[:8]],
              'native_wire': exported,
              'payload_inventory_scope': 'All native files; excludes diagnostic LOG, LOG.old.* and LOCK only',
              'actual_sst_codecs': codecs,
              'sst_properties_command': command}
        validate.save_json(output / 'G1.json', g1)
        result['g1'] = g1
        if g1['status'] != 'PASS':
            raise AssertionError('Native DNSRocks RR multiset or stored payload identity differs')
        result['status'] = 'PASS'
    except BaseException as error:
        result['status'] = 'FAIL'
        result['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        result['completed_utc'] = datetime.now(timezone.utc).isoformat()
        validate.save_json(output / 'SUMMARY.json', result)
        print(json.dumps({'status': result['status'], 'summary': str(output / 'SUMMARY.json')}), flush=True)


if __name__ == '__main__':
    main()

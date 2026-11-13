#!/usr/bin/env python3
"""Independent full RR-multiset qualification of a legacy-format image.

The unmodified legacy reader exports every stored pool-reference occurrence to
zone text. dnspython independently canonicalizes that export before comparison
with the source-event oracle. Qualification runs outside all performance timing.
"""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import json
import subprocess

import dns.name

from validate import (canonical_name, digest_summary, file_sha256,
                      get_source_oracle, read_source, save_json)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dumper', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--origin', default='agency.')
    parser.add_argument('--oracle-cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {'kind': 'SUMMARY', 'status': 'RUNNING',
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'qualification_outside_performance_timing': True,
              'qualifier_sha256': file_sha256(Path(__file__)),
              'oracle_code_sha256': file_sha256(Path(__file__).with_name('validate.py')),
              'dumper': str(args.dumper.resolve()),
              'dumper_sha256': file_sha256(args.dumper),
              'semantic_scope': 'Complete RR multiset; this does not establish general legacy name-query invariants'}
    try:
        origin = canonical_name(args.origin, dns.name.root)
        expected = get_source_oracle(args.source, origin, args.oracle_cache)
        before = {'bytes': args.image.stat().st_size, 'sha256': file_sha256(args.image)}
        exported = output / 'stored_occurrences.zone'
        command = [str(args.dumper), str(args.image), str(exported)]
        with (output/'dump.stdout.log').open('wb') as stdout, (output/'dump.stderr.log').open('wb') as stderr:
            subprocess.run(command, stdout=stdout, stderr=stderr, check=True, timeout=600)
        actual = read_source(exported, origin)
        after = {'bytes': args.image.stat().st_size, 'sha256': file_sha256(args.image)}
        if before != after:
            raise AssertionError('Legacy image changed during read-only qualification')
        missing = expected.hashes - actual.hashes
        extra = actual.hashes - expected.hashes
        equal = actual.hashes == expected.hashes
        result['g1'] = {'status': 'PASS' if equal else 'FAIL',
                        'source': expected.source_identity,
                        'source_oracle_cache': expected.oracle_cache_metadata,
                        'source_summary': digest_summary(expected.hashes),
                        'actual_summary': digest_summary(actual.hashes),
                        'source_type_counts': dict(expected.type_counts),
                        'actual_type_counts': dict(actual.type_counts),
                        'source_wire_bytes': expected.wire_bytes,
                        'actual_wire_bytes': actual.wire_bytes,
                        'set_equal': actual.hashes.keys() == expected.hashes.keys(),
                        'multiset_equal': equal,
                        'missing_occurrences': sum(missing.values()),
                        'unexpected_occurrences': sum(extra.values()),
                        'missing_digest_examples': [d.hex() for d in list(missing)[:8]],
                        'unexpected_digest_examples': [d.hex() for d in list(extra)[:8]],
                        'image_identity': before, 'image_unchanged': True,
                        'export_command': command,
                        'export_bytes': exported.stat().st_size,
                        'export_sha256': file_sha256(exported),
                        'canonical_protocol': 'SHA256 full canonical standalone DNS RR wire including TTL, with every occurrence',
                        'admission_scope': 'Exact equality with the existing IN-only, one-TTL-per-owner/type decoded image proves representability of this fixed source; no general mixed-TTL admission claim'}
        save_json(output/'G1.json', result['g1'])
        if not equal:
            raise AssertionError('Full canonical RR multiset differs from source')
        result['status'] = 'PASS'
    except BaseException as error:
        result['status'] = 'FAIL'
        result['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        result['completed_utc'] = datetime.now(timezone.utc).isoformat()
        save_json(output/'SUMMARY.json', result)
        print(json.dumps({'status': result['status'], 'summary': str(output/'SUMMARY.json')}), flush=True)


if __name__ == '__main__':
    main()

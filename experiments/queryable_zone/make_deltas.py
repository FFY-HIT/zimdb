#!/usr/bin/env python3
"""Prepare complete unsigned-delegation NS TTL replacements outside W timing."""

from collections import Counter, defaultdict
from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import struct

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.tokenizer
import dns.zonefile

from validate import RecordCollector, canonical_name, canonical_wire, file_sha256, save_json


class NSCollector(RecordCollector):
    def __init__(self, origin):
        super().__init__(origin, keep_records=False)
        self.ns = defaultdict(Counter)
        self.ns_signed_owners = set()

    def add(self, name, ttl, rdata):
        self.count += 1
        self.type_counts[int(rdata.rdtype)] += 1
        name = name.canonicalize()
        if rdata.rdtype == dns.rdatatype.NS:
            self.ns[name][canonical_wire(name, ttl, rdata)] += 1
        elif (rdata.rdtype == dns.rdatatype.RRSIG and
              rdata.type_covered == dns.rdatatype.NS):
            self.ns_signed_owners.add(name)


def read_ns_source(path, origin):
    collector = NSCollector(origin)
    with path.open(encoding='utf-8') as source:
        tokenizer = dns.tokenizer.Tokenizer(source, str(path))
        parser = dns.zonefile.Reader(tokenizer, dns.rdataclass.IN, collector,
                                     allow_include=False)
        parser.read()
    return collector


def increment_ttl(wire):
    _, owner_length = dns.name.from_wire(wire, 0)
    ttl_offset = owner_length + 4
    ttl = struct.unpack_from('!I', wire, ttl_offset)[0]
    if ttl >= 0x7fffffff:
        raise ValueError('Cannot increment TTL within RFC2181 unsigned31-bit range')
    updated = bytearray(wire)
    struct.pack_into('!I', updated, ttl_offset, ttl + 1)
    return bytes(updated), ttl


def write_delta(output, name, owners, collector, source_id, requested_count):
    text_path = output / (name + '.delta')
    json_path = output / (name + '.json')
    record_count = 0
    ttl_min = None
    ttl_max = None
    # Both formats remove complete NS RRsets, then add their TTL+1 versions.
    # Multiplicity is expanded in the native text format and counted in JSON.
    with text_path.open('w', encoding='ascii', newline='\n') as text_file, \
            json_path.open('w', encoding='ascii', newline='\n') as json_file:
        json_file.write('{\n')
        for operation_index, (operation, sign) in enumerate((('remove', '-'), ('add', '+'))):
            if operation_index:
                json_file.write(',\n')
            json_file.write('"' + operation + '":[\n')
            first = True
            for owner in owners:
                for wire, multiplicity in sorted(collector.ns[owner].items()):
                    rewritten, original_ttl = increment_ttl(wire)
                    selected = wire if operation == 'remove' else rewritten
                    if operation == 'remove':
                        record_count += multiplicity
                        ttl_min = original_ttl if ttl_min is None else min(ttl_min, original_ttl)
                        ttl_max = original_ttl if ttl_max is None else max(ttl_max, original_ttl)
                    hex_wire = selected.hex()
                    for _ in range(multiplicity):
                        text_file.write(sign + '\t' + hex_wire + '\n')
                    if not first:
                        json_file.write(',\n')
                    json_file.write(json.dumps({'wire_hex': hex_wire, 'multiplicity': multiplicity}))
                    first = False
            json_file.write('\n]')
        json_file.write('\n}\n')
    metadata = {
        'kind': 'DELTA', 'name': name, 'source': source_id,
        'prepared_outside_update_timer': True,
        'selection': 'First N eligible delegation owners in DNS canonical order',
        'eligibility': 'Non-apex NS owner with no RRSIG covering NS at that owner',
        'requested_owner_count': requested_count, 'changed_owner_count': len(owners),
        'changed_complete_rrset_count': len(owners),
        'removed_rr_occurrences': record_count, 'added_rr_occurrences': record_count,
        'original_ttl_min': ttl_min, 'original_ttl_max': ttl_max, 'ttl_increment': 1,
        'canonical_owner_range': {
            'first': owners[0].to_text() if owners else None,
            'last': owners[-1].to_text() if owners else None,
            'comparator': 'RFC4034 canonical DNS name order, dnspython Name comparison',
        },
        'native_delta': {'path': str(text_path), 'bytes': text_path.stat().st_size,
                         'sha256': file_sha256(text_path), 'line_count': record_count * 2,
                         'format': 'One -TABhex or +TABhex full canonical RR occurrence per line'},
        'validation_delta': {'path': str(json_path), 'bytes': json_path.stat().st_size,
                             'sha256': file_sha256(json_path),
                             'format': 'remove/add arrays of wire_hex and positive multiplicity'},
    }
    save_json(output / (name + '.metadata.json'), metadata)
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--origin', default='agency.')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--medium-owners', type=int, default=256)
    args = parser.parse_args()
    if args.medium_owners < 1:
        raise ValueError('--medium-owners must be positive')
    source = args.source.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    origin = canonical_name(args.origin, dns.name.root)
    source_id = {'path': str(source), 'bytes': source.stat().st_size,
                 'sha256': file_sha256(source)}
    collector = read_ns_source(source, origin)
    if file_sha256(source) != source_id['sha256']:
        raise RuntimeError('Source content changed during delta preparation')
    eligible = sorted(owner for owner in collector.ns
                      if owner != origin and owner not in collector.ns_signed_owners)
    if not eligible:
        raise ValueError('No unsigned non-apex NS RRsets are eligible')
    results = []
    for name, count in (('small', 1), ('medium', args.medium_owners), ('whole', len(eligible))):
        results.append(write_delta(output, name, eligible[:count], collector, source_id, count))
    summary = {
        'kind': 'SUMMARY', 'status': 'PASS',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'source': source_id, 'origin': origin.to_text(),
        'source_rr_occurrences': collector.count,
        'source_type_counts': dict(collector.type_counts),
        'ns_owner_count': len(collector.ns),
        'ns_occurrences': sum(sum(values.values()) for values in collector.ns.values()),
        'ns_signed_owner_count': len(collector.ns_signed_owners),
        'excluded_apex_ns_owner_count': int(origin in collector.ns),
        'excluded_signed_delegation_ns_owner_count': sum(owner != origin and owner in collector.ns
                                                         for owner in collector.ns_signed_owners),
        'eligible_owner_count': len(eligible),
        'whole_scope': 'All eligible unsigned delegation NS RRsets, not every RR in the zone',
        'dnssec_rule': 'All RRSIG, DS, NSEC/NSEC3, DNSKEY and parameters remain byte-identical',
        'preparation_outside_update_timing': True, 'deltas': results,
    }
    save_json(output / 'SUMMARY.json', summary)
    print(json.dumps({'status': 'PASS', 'eligible_owners': len(eligible),
                      'source_rr_occurrences': collector.count,
                      'summary': str(output / 'SUMMARY.json')}), flush=True)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Read-only exact DS functional-dependency census for qualified flattened CZDS."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import time

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype


def key_tag(wire):
    value = sum(byte << (8 if index % 2 == 0 else 0) for index, byte in enumerate(wire))
    return (value + (value >> 16)) & 65535


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--zone', type=Path, required=True)
    parser.add_argument('--dictionary', type=Path, default=Path(__file__).with_name('dnskey_dictionary.json'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    dictionary = json.loads(args.dictionary.read_text())
    keys = []
    for row in dictionary['keys']:
        record = dns.rdata.from_text(dns.rdataclass.IN,dns.rdatatype.DNSKEY,row['dnskey_rdata'])
        wire = record.to_wire()
        keys.append({'wire':wire,'tag':key_tag(wire),'algorithm':record.algorithm,
                     'matches':0,'digest_bytes':0,'name':row['name']})
    before = args.zone.stat()
    source_digest = hashlib.sha256()
    total = matched = digest_bytes = matched_digest_bytes = 0
    start = time.monotonic()
    with args.zone.open('rb') as source:
        for raw in source:
            source_digest.update(raw)
            if b'DS' not in raw and b'ds' not in raw:
                continue
            tokens = raw.split()
            if len(tokens) < 4 or tokens[3].upper() != b'DS':
                continue
            if len(tokens) != 8 or tokens[2].upper() != b'IN' or not tokens[0].endswith(b'.'):
                raise ValueError('Source is outside the declared flattened CZDS DS syntax')
            owner = dns.name.from_text(tokens[0].decode('ascii')).canonicalize().to_wire()
            record = dns.rdata.from_text(dns.rdataclass.IN,dns.rdatatype.DS,
                                        b' '.join(tokens[4:]).decode('ascii'))
            total += 1
            digest_bytes += len(record.digest)
            algorithm = {1:'sha1',2:'sha256',4:'sha384'}.get(record.digest_type)
            if not algorithm:
                continue
            for key in keys:
                if record.key_tag != key['tag'] or record.algorithm != key['algorithm']:
                    continue
                generated = hashlib.new(algorithm,owner+key['wire']).digest()
                expected = struct.pack('!HBB',key['tag'],key['algorithm'],record.digest_type)+generated
                if generated == record.digest and expected == record.to_wire():
                    matched += 1
                    matched_digest_bytes += len(generated)
                    key['matches'] += 1
                    key['digest_bytes'] += len(generated)
                    break
    after = args.zone.stat()
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) != (
            after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
        raise RuntimeError('Source changed during census')
    result = {'kind':'SUMMARY','status':'PASS_EXACT_FUNCTIONAL_CENSUS','source':str(args.zone),
              'source_bytes':before.st_size,'source_sha256':source_digest.hexdigest(),
              'dictionary_path':str(args.dictionary),'dictionary_file_bytes':args.dictionary.stat().st_size,
              'dictionary_rdata_bytes':sum(len(key['wire']) for key in keys),
              'ds_records':total,'digest_payload_bytes':digest_bytes,'matched_records':matched,
              'matched_digest_payload_bytes':matched_digest_bytes,
              'keys':[{k:v for k,v in key.items() if k != 'wire'} for key in keys],
              'elapsed_seconds':time.monotonic()-start,
              'scope':'Component feasibility; literal fallback required; full image size and build benefits remain unmeasured'}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result),flush=True)


if __name__ == '__main__':
    main()

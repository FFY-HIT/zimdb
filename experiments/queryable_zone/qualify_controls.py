#!/usr/bin/env python3
"""Revalidate fresh controls and disclose set versus multiset preservation."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess

ROOT = Path('/home/administrator/zimdb_queryable_20261113/rounds/r00_controls')
WORKSPACE = Path('/mnt/c/Users/Administrator/Desktop/BOGI_loop')
TOOLS = Path('/home/administrator/zimdb_block_codec_20261112/bin')
SOURCE = Path('/home/administrator/zimdb_block_codec_20261112/artifacts/agency/source.zone')


def digest_lines(path, directory, env):
    sorted_path = directory/'sorted.lines'
    subprocess.run(['/usr/bin/sort','-S16M','--parallel=1','-T',str(directory),str(path),'-o',str(sorted_path)],
                   check=True, env=env)
    total = unique = 0
    previous = None
    multiset_digest = hashlib.sha256()
    set_digest = hashlib.sha256()
    with sorted_path.open('rb') as stream:
        for line in stream:
            if len(line) != 65:
                raise RuntimeError('Malformed RR digest line')
            total += 1
            multiset_digest.update(line)
            if line != previous:
                unique += 1
                set_digest.update(line)
                previous = line
    return {'rr_occurrences':total,'unique_rrs':unique,'multiset_sha256':multiset_digest.hexdigest(),
            'set_sha256':set_digest.hexdigest()}


def main():
    os.sched_setaffinity(0,{6,7})
    output = ROOT/'qualification'
    output.mkdir(exist_ok=False)
    env = {**os.environ,'LC_ALL':'C','GOMAXPROCS':'2','TMPDIR':str(output)}
    native = TOOLS/'tasknative'
    identities = {}
    for label in ['source','repo_materialized','dnsrocks_lz4']:
        folder = output/label
        folder.mkdir()
        if label == 'source':
            argv = [str(native),'--mode','digests','--zone',str(SOURCE),'--origin','agency.',
                    '--stats',str(folder/'reader.json'),'--digests',str(folder/'raw.lines')]
            with (folder/'command.log').open('wb') as log:
                subprocess.run(argv,stdout=log,stderr=log,check=True,env=env)
        elif label == 'repo_materialized':
            helper_path = WORKSPACE/'notes/repo_key_codec_20261112/qualify_matrix.py'
            spec = importlib.util.spec_from_file_location('qualified_g1',helper_path)
            helper = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(helper)
            helper.zim_g1(ROOT/'artifacts/repo_materialized/image.bogi',folder,
                          Path('/home/administrator/zimdb_repo_keycodec_20261112/source/libbogi23/build/dump_zone'),
                          native,env)
        else:
            argv = [str(native),'--mode','verify-rdb','--db',str(ROOT/'artifacts/dnsrocks_lz4/payload'),
                    '--origin','agency.','--stats',str(folder/'reader.json'),'--digests',str(folder/'raw.lines')]
            with (folder/'command.log').open('wb') as log:
                subprocess.run(argv,stdout=log,stderr=log,check=True,env=env)
        identities[label] = digest_lines(folder/'raw.lines',folder,env)
        if label != 'source':
            identities[label]['set_pass'] = identities[label]['set_sha256'] == identities['source']['set_sha256']
            identities[label]['multiset_pass'] = identities[label]['multiset_sha256'] == identities['source']['multiset_sha256']
        (output/'SUMMARY.json').write_text(json.dumps({'kind':'SUMMARY','g1':identities},indent=2)+'\n')
        print(json.dumps({'case':label,**identities[label]}),flush=True)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""P3 forced full-reencoding controls using the verified post-delta RR multiset."""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess

from measure_updates import CAMPAIGN, HERE, DELTAS, save, measurement, directory_size, native_base, rocks_base


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--round', required=True)
    parser.add_argument('--after', type=Path, required=True)
    args = parser.parse_args()
    root = CAMPAIGN/'rounds'/args.round
    root.mkdir(parents=True, exist_ok=False)
    (root/'bin').mkdir()
    (root/'source_snapshot').mkdir()
    for filename in ['native_zone','native_zone.cpp','Makefile','ASSUMPTIONS.md']:
        destination = root/'bin/native_zone' if filename == 'native_zone' else root/'source_snapshot'/filename
        shutil.copy2(HERE/filename,destination)
    shutil.copy2(CAMPAIGN/'rocks_control',root/'bin/rocks_control')
    shutil.copy2(HERE/'rocks_control.go',root/'source_snapshot/rocks_control.go')
    os.sched_setaffinity(0,{4})
    measure = measurement(root)
    wire = root/'post_delta.wire.hex'
    with wire.open('wb') as output, (root/'wire.stderr.log').open('wb') as error:
        subprocess.run([str(root/'bin/native_zone'),'wire','--image',str(args.after)],
                       stdout=output,stderr=error,check=True)
    wire_sha = measure.sha(wire)
    save(root/'PLAN.json',{'kind':'PLAN','problem':'P3','round':args.round,
         'control':'Forced full reencoding, distinct from native incremental DNSRocks update',
         'after_generation':str(args.after),'delta':str(DELTAS/'whole.json'),
         'wire':str(wire),'wire_sha256':wire_sha,'wire_bytes':wire.stat().st_size,
         'preparation':'Canonical full post-delta RR stream prepared before W timer',
         'W_primary':'Linux process_io_delta.write_bytes through full image/database fsync',
         'history':'One complete previous generation retained before timing',
         'tuple_time_and_rss':'Original source build values, full-reencode duration stored separately',
         'binary_sha256':{p.name:measure.sha(p) for p in (root/'bin').iterdir()}})
    results = []
    for backend in ['native','dnsrocks']:
        label = backend+'_full_reencode'
        artifact = root/'artifacts'/label
        artifact.mkdir(parents=True)
        payload = artifact/'payload'
        payload.mkdir()
        stats = artifact/'operation_stats.json'
        if backend == 'native':
            base, base_tuple = native_base('native_whole')
            shutil.copy2(base,payload/'previous.zim')
            command = [str(root/'bin/native_zone'),'build','--input-wire-hex',str(wire),
                       '--origin','agency.','--out',str(payload/'current.zim'),
                       '--work',str(artifact/'work'),'--memory-mib','16','--codec','zstd',
                       '--pool','none','--front-code','1','--index','packed','--stats',str(stats)]
        else:
            base, base_tuple = rocks_base()
            shutil.copytree(base,payload/'previous')
            command = [str(root/'bin/rocks_control'),'build','--input-wire-hex',str(wire),
                       '--origin','agency.','--out',str(payload/'live'),'--codec','zstd','--stats',str(stats)]
        measure.sync_payload(payload)
        if measure.sha(wire) != wire_sha:
            raise RuntimeError('Prepared post-delta RR stream changed')
        result = measure.run_case({'id':label,'backend':backend,'payload':str(payload),'argv':command,
                                   'problem':'P3','control':'forced full reencode','input_wire_sha256':wire_sha})
        internal = json.loads(stats.read_text())
        retained = directory_size(payload)
        row = {'id':label,'problem':'P3','control':'forced_full_reencode',
               'tuple':{'image_bytes':retained['unique_inode_bytes'],
                        'build_durable_seconds':base_tuple['build_durable_seconds'],
                        'peak_tree_rss_kib':base_tuple['peak_tree_rss_kib'],
                        'rewrite_bytes':internal['process_io_delta']['write_bytes'],
                        'reencoded_owners':internal.get('owners')},
               'operation_durable_seconds':result['durable_wall_seconds'],
               'operation_sampled_tree_rss_kib':result['sampled_tree_peak_rss_kib'],
               'stats':internal,'measurement':result,'retained_size':retained,
               'correctness':'PENDING_EXTERNAL_G1'}
        results.append(row)
        save(root/'SUMMARY.json',{'kind':'SUMMARY','round':args.round,'problem':'P3',
             'status':'FULL_REENCODE_CONTROLS_PENDING_CORRECTNESS','results':results})
        print(json.dumps({'kind':'SUMMARY','case':label,'tuple':row['tuple']}),flush=True)
    save(root/'STAGE.json',{'kind':'STAGE','round':args.round,
         'cases':[{'id':r['id'],'internal':r['stats'],'observer_events':r['measurement']['events']} for r in results]})


if __name__ == '__main__':
    main()

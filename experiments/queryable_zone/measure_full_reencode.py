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
    parser.add_argument('--reference-round', help='Qualified initial-build cohort with one native and one RocksDB case')
    parser.add_argument('--after-g1', type=Path)
    args = parser.parse_args()
    reference = None
    if args.reference_round:
        if not args.after_g1:
            parser.error('A matched current control requires the independent after-G1 receipt')
        rows = json.loads((CAMPAIGN/'rounds'/args.reference_round/'SUMMARY.json').read_text())['results']
        reference = {}
        for backend in ['zimdb_native','dnsrocks']:
            matches = [row for row in rows if row['configuration']['backend'] == backend]
            if len(matches) != 1:
                raise ValueError('Reference round must contain exactly one native and one RocksDB configuration')
            reference[backend] = matches[0]
    root = CAMPAIGN/'rounds'/args.round
    root.mkdir(parents=True, exist_ok=False)
    (root/'bin').mkdir()
    (root/'source_snapshot').mkdir()
    frozen = CAMPAIGN/'rounds'/args.reference_round if reference else None
    for filename in ['native_zone','native_zone.cpp','Makefile','ASSUMPTIONS.md']:
        destination = root/'bin/native_zone' if filename == 'native_zone' else root/'source_snapshot'/filename
        source = frozen/('bin' if filename == 'native_zone' else 'source_snapshot')/filename if frozen else HERE/filename
        shutil.copy2(source,destination)
    shutil.copy2(frozen/'bin/rocks_control' if frozen else CAMPAIGN/'rocks_control',root/'bin/rocks_control')
    shutil.copy2(frozen/'source_snapshot/rocks_control.go' if frozen else HERE/'rocks_control.go',root/'source_snapshot/rocks_control.go')
    for binary in (root/'bin').iterdir():
        binary.chmod(0o755)
    shutil.copy2(Path(__file__),root/'source_snapshot/measure_full_reencode.py')
    shutil.copy2(HERE/'measure_updates.py',root/'source_snapshot/measure_updates.py')
    shutil.copy2(HERE/'ASSUMPTIONS.md',root/'source_snapshot/PROTOCOL_ASSUMPTIONS.md')
    if frozen and (frozen/'source_snapshot/CONTROL_BINDING.patch').exists():
        shutil.copy2(frozen/'source_snapshot/CONTROL_BINDING.patch',root/'source_snapshot/CONTROL_BINDING.patch')
    os.sched_setaffinity(0,{4})
    measure = measurement(root)
    if args.after_g1:
        qualified = json.loads(args.after_g1.read_text())
        if not (qualified['status'] == 'PASS' and qualified['set_equal'] and qualified['multiset_equal']
                and qualified['image_sha256'] == measure.sha(args.after)):
            raise ValueError('Post-delta image does not match its independent full-G1 receipt')
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
         'independent_after_g1':str(args.after_g1) if args.after_g1 else None,
         'reference_round':args.reference_round,
         'operation_scope':'Full encoding core through payload sync; prepared-wire creation and CURRENT cutover excluded',
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
            current = reference['zimdb_native'] if reference else None
            configuration = current['configuration'] if current else {}
            index = (configuration.get('index') or current.get('internal_stats',{}).get('index_format','fixed')) if current else 'packed'
            base, base_tuple = (Path(current['configuration']['payload']),current['tuple']) if current else native_base('native_whole')
            shutil.copy2(base,payload/'previous.zim')
            command = [str(root/'bin/native_zone'),'build','--input-wire-hex',str(wire),
                       '--origin','agency.','--out',str(payload/'current.zim'),
                       '--work',str(artifact/'work'),'--memory-mib','16',
                       '--codec',configuration.get('codec','zstd'),
                       '--pool',configuration.get('pool','none'),
                       '--front-code',str(int(configuration.get('front_code',True))), '--index',index,
                       '--stats',str(stats)]
            if current and current['configuration'].get('key_codec'):
                command += ['--key-codec',current['configuration']['key_codec'],
                            '--nsec3-next-key',str(int(current['configuration']['nsec3_next_key']))]
        else:
            current = reference['dnsrocks'] if reference else None
            configuration = current['configuration'] if current else {}
            base, base_tuple = (Path(current['configuration']['payload']),current['tuple']) if current else rocks_base()
            shutil.copytree(base,payload/'previous')
            command = [str(root/'bin/rocks_control'),'build','--input-wire-hex',str(wire),
                       '--origin','agency.','--out',str(payload/'live'),
                       '--codec',configuration.get('codec','zstd'),'--stats',str(stats)]
            if current and current['configuration'].get('block_bytes'):
                command += ['--block-bytes',str(current['configuration']['block_bytes'])]
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

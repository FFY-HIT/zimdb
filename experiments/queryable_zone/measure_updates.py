#!/usr/bin/env python3
"""Measure generation updates with one retained previous generation per backend."""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import shutil
import subprocess

CAMPAIGN = Path('/home/administrator/zimdb_queryable_20261113')
HERE = CAMPAIGN/'source/experiments/queryable_zone'
WORKSPACE = Path('/mnt/c/Users/Administrator/Desktop/BOGI_loop')
DELTAS = CAMPAIGN/'deltas/agency_ns_ttl'


def save(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(document, indent=2)+'\n')
    temporary.replace(path)


def directory_size(path, diagnostic=False):
    seen = set()
    logical = allocated = 0
    rows = []
    for item in sorted(p for p in path.rglob('*') if p.is_file()):
        if not diagnostic and (item.name in ('LOCK','LOG') or item.name.startswith('LOG.old.')):
            continue
        stat = item.stat()
        identity = (stat.st_dev, stat.st_ino)
        rows.append({'path':str(item),'bytes':stat.st_size,'allocated_bytes':stat.st_blocks*512,
                     'device':stat.st_dev,'inode':stat.st_ino,'links':stat.st_nlink})
        if identity not in seen:
            seen.add(identity)
            logical += stat.st_size
            allocated += stat.st_blocks*512
    return {'unique_inode_bytes':logical,'unique_inode_allocated_bytes':allocated,'files':rows}


def measurement(root):
    file = WORKSPACE/'notes/agency_load_compare_20261112/measure_builds.py'
    spec = importlib.util.spec_from_file_location('qualified_measurement', file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = root
    return module


def native_base(case, round_name='r05_packed_directory', primary_label='native_packed_zstd'):
    label = 'native_fixed_zstd' if case == 'native_fixed_small' else primary_label
    summary = json.loads((CAMPAIGN/'rounds'/round_name/'SUMMARY.json').read_text())
    row = next(row for row in summary['results'] if row['id'] == label)
    return Path(row['configuration']['payload']), row['tuple']


def rocks_base(round_name='r04_pool_representation', label='dnsrocks_control_zstd'):
    summary = json.loads((CAMPAIGN/'rounds'/round_name/'SUMMARY.json').read_text())
    row = next(row for row in summary['results'] if row['id'] == label)
    return Path(row['configuration']['payload']), row['tuple']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--round', required=True)
    parser.add_argument('--cases', nargs='+', default=['native_small','dnsrocks_small','native_medium',
                        'dnsrocks_medium','native_whole','dnsrocks_whole','native_fixed_small'])
    parser.add_argument('--native-round', default='r05_packed_directory')
    parser.add_argument('--native-label', default='native_packed_zstd')
    parser.add_argument('--native-version', type=Path,
                        help='Frozen directory containing native_zone, native_zone.cpp, Makefile and ledger')
    parser.add_argument('--delta-order', choices=['unordered','owner'], default='unordered')
    parser.add_argument('--rocks-round')
    parser.add_argument('--rocks-label', default='dnsrocks_control_zstd')
    args = parser.parse_args()
    root = CAMPAIGN/'rounds'/args.round
    root.mkdir(parents=True, exist_ok=False)
    (root/'bin').mkdir()
    (root/'source_snapshot').mkdir()
    native_version = args.native_version or CAMPAIGN/'rounds'/args.native_round
    frozen_native = native_version/'native_zone' if args.native_version else native_version/'bin/native_zone'
    frozen_sources = native_version if args.native_version else native_version/'source_snapshot'
    shutil.copy2(frozen_native, root/'bin/native_zone')
    (root/'bin/native_zone').chmod(0o755)
    if any(label.startswith('dnsrocks_') for label in args.cases):
        rocks_binary = CAMPAIGN/'rounds'/args.rocks_round/'bin/rocks_control' if args.rocks_round else CAMPAIGN/'rocks_control'
        shutil.copy2(rocks_binary, root/'bin/rocks_control')
        (root/'bin/rocks_control').chmod(0o755)
    for filename in ['native_zone.cpp','Makefile','ASSUMPTIONS.md']:
        shutil.copy2(frozen_sources/filename, root/'source_snapshot'/filename)
    shutil.copy2(Path(__file__), root/'source_snapshot/measure_updates.py')
    shutil.copy2(HERE/'ASSUMPTIONS.md', root/'source_snapshot/PROTOCOL_ASSUMPTIONS.md')
    if any(label.startswith('dnsrocks_') for label in args.cases):
        rocks_sources = CAMPAIGN/'rounds'/args.rocks_round/'source_snapshot' if args.rocks_round else HERE
        shutil.copy2(rocks_sources/'rocks_control.go', root/'source_snapshot/rocks_control.go')
        binding_patch = rocks_sources/'CONTROL_BINDING.patch'
        if binding_patch.exists():
            shutil.copy2(binding_patch, root/'source_snapshot/CONTROL_BINDING.patch')
    os.sched_setaffinity(0,{4})
    measure = measurement(root)
    plan = {'kind':'PLAN','round':args.round,'problem':'P3', 'cases':args.cases,
            'native_version':str(native_version),'native_base_round':args.native_round,
            'rocks_base_round':args.rocks_round or 'r04_pool_representation','rocks_base_label':args.rocks_label,
            'delta_order':args.delta_order,
            'previous_generations_retained':1,
            'update': 'Complete NS RRsets, TTL+1, unsigned delegations, all DNSSEC payloads retained',
            'W_primary':'Linux writer process_io_delta.write_bytes including temporary ordering/index work',
            'W_secondary':'Exact image append+directory+generation+CURRENT bytes for native; changed-live-SST bytes for RocksDB',
            'size':'All retained payload bytes, deduplicated by inode across checkpoint hardlinks, diagnostics separate',
            'tuple_time_and_rss':'Original source-to-image build values copied from frozen base rows; update latency/RSS separately labeled',
            'initialization':'Copy base and create previous checkpoint before update timer, save prep receipt separately',
            'binary_sha256':{p.name:measure.sha(p) for p in (root/'bin').iterdir()}}
    save(root/'PLAN.json', plan)
    results = []
    try:
        for label in args.cases:
            artifact = root/'artifacts'/label
            artifact.mkdir(parents=True, exist_ok=False)
            payload = artifact/'payload'
            payload.mkdir()
            size_name = label.rsplit('_',1)[1]
            delta = DELTAS/(size_name+'.delta')
            stats_path = artifact/'update_stats.json'
            prep = {'delta':str(delta),'delta_sha256':measure.sha(delta)}
            if label.startswith('native_'):
                base, base_tuple = native_base(label,args.native_round,args.native_label)
                shutil.copy2(base,payload/'data.zim')
                (payload/'CURRENT').write_text('data.zim\n')
                command = [str(root/'bin/native_zone'),'update','--image',str(payload/'CURRENT'),
                           '--delta',str(delta),'--out',str(payload/'generation0001.zg'),
                           '--current',str(payload/'CURRENT'),'--work',str(artifact/'work'),
                           '--memory-mib','16','--stats',str(stats_path)]
                if args.delta_order == 'owner':
                    command.extend(['--delta-order','owner'])
                prep['source_base'] = str(base)
                backend = 'zimdb'
            else:
                base, base_tuple = rocks_base(args.rocks_round or 'r04_pool_representation',args.rocks_label)
                shutil.copytree(base,payload/'live')
                checkpoint = [str(root/'bin/rocks_control'),'checkpoint','--db',str(payload/'live'),
                              '--out',str(payload/'previous'),'--stats',str(artifact/'checkpoint_stats.json')]
                with (artifact/'checkpoint.log').open('wb') as log:
                    subprocess.run(checkpoint,stdout=log,stderr=log,check=True)
                prep['checkpoint'] = json.loads((artifact/'checkpoint_stats.json').read_text())
                prep['source_base'] = str(base)
                command = [str(root/'bin/rocks_control'),'update','--db',str(payload/'live'),
                           '--delta',str(delta),'--retained-checkpoint',str(payload/'previous'),
                           '--stats',str(stats_path)]
                backend = 'dnsrocks'
            prep['fsync'] = measure.sync_payload(payload)
            prep['payload_before'] = directory_size(payload)
            save(artifact/'PREPARATION.json',prep)
            spec = {'id':label,'backend':backend,'payload':str(payload),'argv':command,
                    'delta':str(delta),'problem':'P3','base_build_tuple':base_tuple}
            measured = measure.run_case(spec)
            stats = json.loads(stats_path.read_text())
            retained = directory_size(payload)
            io_writes = stats['process_io_delta']['write_bytes']
            row = {'id':label,'backend':backend,'delta':size_name,
                   'tuple':{'image_bytes':retained['unique_inode_bytes'],
                            'build_durable_seconds':base_tuple['build_durable_seconds'],
                            'peak_tree_rss_kib':base_tuple['peak_tree_rss_kib'],
                            'rewrite_bytes':io_writes,
                            'reencoded_owners':stats.get('reencoded_owners')},
                   'W_io_write_bytes':io_writes,
                   'W_image_bytes':stats.get('rewrite_bytes'),
                   'W_changed_live_sst_bytes':stats.get('new_or_changed_live_sst_bytes'),
                   'retained_size':retained,'diagnostic_inclusive_size':directory_size(payload,True),
                   'update_durable_seconds':measured['durable_wall_seconds'],
                   'update_sampled_tree_rss_kib':measured['sampled_tree_peak_rss_kib'],
                   'native_stats':stats,'measurement':measured,
                   'payload':str(payload),'correctness':'PENDING_EXTERNAL_G1'}
            results.append(row)
            save(root/'SUMMARY.json',{'kind':'SUMMARY','round':args.round,'problem':'P3',
                 'status':'UPDATES_PENDING_CORRECTNESS','results':results})
            print(json.dumps({'kind':'SUMMARY','case':label,'tuple':row['tuple'],
                              'W_image_bytes':row['W_image_bytes'],'update_seconds':row['update_durable_seconds']}),flush=True)
        save(root/'STAGE.json',{'kind':'STAGE','round':args.round,
             'cases':[{'id':r['id'],'observer_events':r['measurement']['events'],
                       'internal':r['native_stats']} for r in results]})
    except BaseException as error:
        save(root/'FAILURE.json',{'status':'FAIL','case':label,'error':str(error),'completed':results})
        raise


if __name__ == '__main__':
    main()

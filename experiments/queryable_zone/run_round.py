#!/usr/bin/env python3
"""One-shot, sequential source-to-durable-image measurements for this campaign."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone

CAMPAIGN = Path('/home/administrator/zimdb_queryable_20261113')
REPO = CAMPAIGN / 'source'
HERE = REPO / 'experiments/queryable_zone'
WORKSPACE = Path('/mnt/c/Users/Administrator/Desktop/BOGI_loop')
SOURCE = Path('/home/administrator/zimdb_block_codec_20261112/artifacts/agency/source.zone')
SOURCE_SHA = '2de164ab7d147dc35192eec70fa9ddb3a46c9e7420d10cd16e33f8ddbc316cd0'
OLD_SOURCE = Path('/home/administrator/zimdb_repo_keycodec_20261112/source')
RDB_BUILDER = Path('/home/administrator/zimdb_repo_keycodec_20261112/bin/agency_codec_builder')


def save(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(document, indent=2) + '\n')
    temporary.replace(path)


def measurement_module(root):
    path = WORKSPACE / 'notes/agency_load_compare_20261112/measure_builds.py'
    spec = importlib.util.spec_from_file_location('qualified_measurement', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = root
    module.SOURCE = SOURCE
    return module


def payload_size(path, backend):
    files = [path] if path.is_file() else sorted(p for p in path.rglob('*') if p.is_file())
    all_bytes = sum(p.stat().st_size for p in files)
    diagnostic_names = {'LOG', 'LOCK'} if backend == 'dnsrocks' else set()
    native_files = [p for p in files if p.name not in diagnostic_names and not p.name.startswith('LOG.old.')]
    return {'image_bytes': sum(p.stat().st_size for p in native_files),
            'complete_directory_bytes': all_bytes,
            'included_files': [{'path': str(p), 'bytes': p.stat().st_size} for p in native_files]}


def case_spec(root, label, native_binary, control_binary, legacy_source=OLD_SOURCE):
    artifact = root / 'artifacts' / label
    artifact.mkdir(parents=True, exist_ok=False)
    if label in ('repo_materialized','legacy_materialized_multiset'):
        output = artifact / 'image.bogi'
        command = ['env', 'BOGI_WORKERS=2', 'BOGI_PARALLEL_SCAN=1', 'BOGI_ZONE_SCAN_REQUIRED=1',
                   f'BOGI_ZONE_SCAN={legacy_source}/builder/zone_scan',
                   f'BOGI_JOIN_SCATTER={legacy_source}/builder/join_scatter',
                   'BOGI_SORT_CHUNK=800000', 'BOGI_OWNER_SORT_CHUNK=500000', 'BOGI_MERGE_FAN_IN=32',
                   'python3', '-u', str(legacy_source/'builder/encode_com_dnssec_zimdb.py'),
                   str(SOURCE), str(output), str(artifact/'work'), 'agency.']
        return {'id': label, 'backend': 'repo_materialized', 'payload': str(output), 'argv': command,
                'legacy_source':str(legacy_source),
                'legacy_role':'separate multiplicity-fixed control' if label == 'legacy_materialized_multiset'
                              else 'unmodified historical diagnostic'}
    if label.startswith('dnsrocks_'):
        is_control = label.startswith('dnsrocks_control_')
        codec = label.removeprefix('dnsrocks_control_') if is_control else label.removeprefix('dnsrocks_')
        block_bytes = 65536 if codec == 'zstd64k' else None
        if block_bytes:
            codec = 'zstd'
        output = artifact / 'payload'
        command = [str(control_binary), 'build'] if is_control else [str(RDB_BUILDER)]
        command += ['--zone', str(SOURCE), '--origin', 'agency.', '--out', str(output),
                   '--stats', str(artifact/'build_stats.json'), '--codec', codec]
        if block_bytes:
            command += ['--block-bytes', str(block_bytes)]
        return {'id': label, 'backend': 'dnsrocks', 'codec': codec, 'payload': str(output), 'argv': command,
                'frontend': 'queryable_control' if is_control else 'qualified_previous_frontend',
                'block_bytes': block_bytes}
    variants = {
        'native_plain': ('none', 'none', '1'),
        'native_pool_plain': ('none', 'local', '1'),
        'native_pool_lz4': ('lz4', 'local', '1'),
        'native_pool_zstd': ('zstd', 'local', '1'),
        'native_no_pool_zstd': ('zstd', 'none', '1'),
        'native_no_front_zstd': ('zstd', 'local', '0'),
        'native_packed_zstd': ('zstd', 'none', '1'),
        'native_fixed_zstd': ('zstd', 'none', '1'),
        'native_cow_zstd': ('zstd', 'none', '1'),
        'native_nibble_zstd': ('zstd', 'none', '1'),
        'native_compact_zstd': ('zstd', 'none', '1'),
        'native_compact_nextkey_zstd': ('zstd', 'none', '1'),
    }
    if label not in variants:
        raise ValueError(f'Unknown configuration {label}')
    codec, pool, front = variants[label]
    output = artifact / 'image.zim'
    command = [str(native_binary), 'build', '--zone', str(SOURCE), '--origin', 'agency.',
               '--out', str(output), '--work', str(artifact/'work'), '--memory-mib', '16',
               '--codec', codec, '--pool', pool, '--front-code', front,
               '--stats', str(artifact/'build_stats.json')]
    index = None
    if label in ('native_packed_zstd', 'native_fixed_zstd', 'native_cow_zstd'):
        index = {'native_packed_zstd':'packed','native_fixed_zstd':'fixed','native_cow_zstd':'cow'}[label]
        command += ['--index', index]
    key_codec = None
    next_key = None
    if label in ('native_nibble_zstd','native_compact_zstd','native_compact_nextkey_zstd'):
        index = 'cow'
        key_codec = 'nibble' if label == 'native_nibble_zstd' else 'compact'
        next_key = label == 'native_compact_nextkey_zstd'
        command += ['--index',index,'--key-codec',key_codec,
                    '--nsec3-next-key',str(int(next_key))]
    return {'id': label, 'backend': 'zimdb_native', 'codec': codec, 'pool': pool,
            'front_code': bool(int(front)), 'index': index, 'memory_mib': 16,
            'key_codec':key_codec,'nsec3_next_key':next_key,
            'payload': str(output), 'argv': command}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--round', required=True)
    parser.add_argument('--cases', nargs='+', required=True)
    parser.add_argument('--frozen-version', type=Path)
    parser.add_argument('--native-version', type=Path,
                        help='Frozen flat directory containing binary, C++ source, Makefile and ledger')
    parser.add_argument('--legacy-source', type=Path)
    parser.add_argument('--legacy-manifest', type=Path)
    args = parser.parse_args()
    if args.native_version and args.frozen_version:
        parser.error('Select one native version directory')
    if 'legacy_materialized_multiset' in args.cases and not (args.legacy_source and args.legacy_manifest):
        parser.error('The separate legacy control requires its source and frozen manifest')
    root = CAMPAIGN / 'rounds' / args.round
    root.mkdir(parents=True, exist_ok=False)
    os.sched_setaffinity(0, {4})
    measure = measurement_module(root)
    assert measure.sha(SOURCE) == SOURCE_SHA
    filesystem = subprocess.check_output(['findmnt','-T',str(CAMPAIGN),'-n','-o','TARGET,SOURCE,FSTYPE'],text=True).strip()
    if not filesystem.endswith('ext4'):
        raise RuntimeError(f'Expected ext4, got {filesystem}')
    snapshot = root/'source_snapshot'
    snapshot.mkdir()
    (root/'bin').mkdir()
    native_binary = root/'bin/native_zone'
    control_binary = root/'bin/rocks_control'
    if any(label.startswith('native_') for label in args.cases):
        version_binary = args.frozen_version/'bin/native_zone' if args.frozen_version else HERE/'native_zone'
        version_source = args.frozen_version/'source_snapshot' if args.frozen_version else HERE
        if args.native_version:
            version_binary = args.native_version/'native_zone'
            version_source = args.native_version
        shutil.copy2(version_binary, native_binary)
        native_binary.chmod(0o755)
        for filename in ['native_zone.cpp','Makefile','ASSUMPTIONS.md']:
            shutil.copy2(version_source/filename, snapshot/filename)
    shutil.copy2(Path(__file__),snapshot/'run_round.py')
    shutil.copy2(HERE/'ASSUMPTIONS.md',snapshot/'PROTOCOL_ASSUMPTIONS.md')
    if args.legacy_manifest:
        shutil.copy2(args.legacy_manifest,snapshot/'legacy_control_manifest.json')
    if any(label.startswith('dnsrocks_control_') for label in args.cases):
        shutil.copy2(CAMPAIGN/'rocks_control', control_binary)
        shutil.copy2(HERE/'rocks_control.go', snapshot/'rocks_control.go')
        binding_patch = CAMPAIGN/'qualification/block64k_control/CONTROL_BINDING.patch'
        if binding_patch.exists():
            shutil.copy2(binding_patch, snapshot/'CONTROL_BINDING.patch')
    identities = [{'path':str(path),'sha256':measure.sha(path),'bytes':path.stat().st_size}
                  for path in sorted(snapshot.iterdir())]
    if native_binary.exists():
        identities.append({'path':str(native_binary),'sha256':measure.sha(native_binary),
                           'bytes':native_binary.stat().st_size})
    if control_binary.exists():
        identities.append({'path':str(control_binary),'sha256':measure.sha(control_binary),
                           'bytes':control_binary.stat().st_size})
    plan = {'round': args.round, 'source': str(SOURCE), 'source_sha256': SOURCE_SHA,
            'source_bytes': SOURCE.stat().st_size, 'cases': args.cases,
            'builder_affinity': [6,7], 'observer_affinity': [4], 'filesystem': filesystem,
            'repeats': 1, 'prewarm': 'Full source SHA256 scan before every case',
            'start_utc': datetime.now(timezone.utc).isoformat(),
            'durability': 'Source to command return plus produced files and directories fsync',
            'semantic_status': 'Each build pending independent set/multiset and name-semantics acceptance',
            'size_contract': 'All native files included, DNSRocks LOG/LOCK diagnostics reported separately',
            'rss_contract': 'Simultaneous process-tree RSS samples about5ms, observer excluded. Shared pages may be counted in more than one process.'}
    plan['frozen_source_and_binary'] = identities
    save(root/'PLAN.json', plan)
    results = []
    for label in args.cases:
        case = case_spec(root, label, native_binary, control_binary,args.legacy_source or OLD_SOURCE)
        result = measure.run_case(case)
        result.update(payload_size(Path(case['payload']), case['backend']))
        result['configuration'] = case
        native_stages = []
        error_log = root/'measurements'/label/'stderr.log'
        for line in error_log.read_text(errors='replace').splitlines():
            if line.startswith('STAGE '):
                native_stages.append(json.loads(line.removeprefix('STAGE ')))
        result['native_stages'] = native_stages
        result['tuple'] = {'image_bytes': result['image_bytes'],
                           'build_durable_seconds': result['durable_wall_seconds'],
                           'peak_tree_rss_kib': result['sampled_tree_peak_rss_kib'],
                           'rewrite_bytes': None, 'reencoded_owners': None}
        stats = Path(case['payload']).parent/'build_stats.json'
        if stats.exists():
            result['internal_stats'] = json.loads(stats.read_text())
        results.append(result)
        summary = {'kind': 'SUMMARY', 'round': args.round, 'status': 'BUILT_PENDING_CORRECTNESS',
                   'results': results, 'completed_cases': len(results), 'planned_cases': len(args.cases)}
        save(root/'SUMMARY.json', summary)
        print(json.dumps({'kind':'SUMMARY','round':args.round,'case':label,'tuple':result['tuple']}),flush=True)
    save(root/'STAGE.json', {'kind':'STAGE','round':args.round,
         'cases': [{'id':r['id'],'observer_events':r['events'],'native_stages':r.get('native_stages',[]),
                    'internal_stats':r.get('internal_stats')} for r in results]})


if __name__ == '__main__':
    main()

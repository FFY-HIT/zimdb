#!/usr/bin/env python3
"""Reproduce chained-CURRENT rejection and verify the shared-resolver fix."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(binary, *arguments):
    return subprocess.run([str(binary), *map(str, arguments)], capture_output=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--old-binary', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    base = root/'data.zim'
    shutil.copy2(args.base, base)
    original = base.read_bytes()
    inner = root/'CURRENT.inner'
    outer = root/'CURRENT'
    inner.write_text('data.zim\n')
    outer.write_text('CURRENT.inner\n')
    delta = root/'empty.delta'
    delta.write_bytes(b'')
    before = run(args.binary,'wire','--image',outer)
    assert before.returncode == 0, before.stderr.decode()
    old_read = run(args.old_binary,'inspect','--image',outer)
    assert old_read.returncode == 0, old_read.stderr.decode()
    old = run(args.old_binary,'update','--image',outer,'--delta',delta,
              '--out',root/'old_rejected.zg','--current',outer,
              '--work',root/'old_work','--memory-mib','16')
    assert old.returncode != 0 and b'CURRENT generation conflict' in old.stderr
    assert not (root/'old_rejected.zg').exists()
    assert base.read_bytes() == original
    assert outer.read_text() == 'CURRENT.inner\n'
    updated = run(args.binary,'update','--image',outer,'--delta',delta,
                  '--out',root/'generation1.zg','--current',outer,
                  '--work',root/'new_work','--memory-mib','16')
    assert updated.returncode == 0, updated.stderr.decode()
    current_wire = run(args.binary,'wire','--image',outer)
    old_wire = run(args.binary,'wire','--image',base)
    assert current_wire.returncode == old_wire.returncode == 0
    assert current_wire.stdout == old_wire.stdout == before.stdout
    assert base.read_bytes()[:len(original)] == original
    before_stale = base.stat().st_size
    stale = run(args.binary,'update','--image',base,'--delta',delta,
                '--out',root/'stale_rejected.zg','--current',outer,
                '--work',root/'stale_work','--memory-mib','16')
    assert stale.returncode != 0 and b'CURRENT generation conflict' in stale.stderr
    assert not (root/'stale_rejected.zg').exists()
    assert base.stat().st_size == before_stale
    for label, immutable in [('base',base),('generation',root/'generation1.zg')]:
        immutable_before = immutable.read_bytes()
        data_size_before = base.stat().st_size
        invalid = run(args.binary,'update','--image',immutable,'--delta',delta,
                      '--out',root/(label+'_invalid.zg'),'--current',immutable,
                      '--work',root/(label+'_invalid_work'),'--memory-mib','16')
        assert invalid.returncode != 0 and b'must be a text pointer' in invalid.stderr
        assert immutable.read_bytes() == immutable_before
        assert base.stat().st_size == data_size_before
        assert not (root/(label+'_invalid.zg')).exists()
    receipt = {'status':'PASS','qualification_only':True,
               'old_binary_sha256':sha(args.old_binary.read_bytes()),
               'binary_sha256':sha(args.binary.read_bytes()),
               'base':str(args.base),'old_reader_accepts_chain':True,
               'old_updater_rejects_same_chain':True,'fixed_updater_accepts_chain':True,
               'stale_snapshot_rejected_before_append':True,
               'binary_image_current_rejected_before_append':True,
               'binary_generation_current_rejected_before_append':True,
               'retained_old_prefix_identical':True,'wire_occurrences':before.stdout.count(b'\n'),
               'wire_export_identical':True,'wire_export_sha256':sha(before.stdout),
               'old_failure':old.stderr.decode(),'stale_failure':stale.stderr.decode()}
    (root/'SUMMARY.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()

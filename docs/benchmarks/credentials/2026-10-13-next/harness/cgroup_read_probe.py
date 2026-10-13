#!/usr/bin/env python3
"""Measure kernel cgroup interfaces with one owned sleep process, not a jail score."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert not args.out.exists(), 'retain previous measurements'
    delegated = Path('/sys/fs/cgroup/user.slice/user-%d.slice/user@%d.service' % (os.getuid(), os.getuid()))
    assert delegated.is_dir()
    leaf = delegated / ('ouro-benchmark-cgroup-read-' + str(os.getpid()))
    rows = []
    child = None
    result = {'schema': 'cgroup-interface-diagnostic/1', 'scored_performance': False,
              'only_owned_trusted_sleep_process': True, 'leaf': str(leaf), 'rows': rows}
    try:
        leaf.mkdir()
        child = subprocess.Popen(['/usr/bin/sleep', '30'], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 env={'PATH': '/usr/bin:/bin'})
        began = time.perf_counter_ns()
        (leaf / 'cgroup.procs').write_text(str(child.pid))
        result['place_write_ms'] = (time.perf_counter_ns() - began) / 1e6
        result['child_pid'] = child.pid
        result['expected_cgroup'] = str(leaf).removeprefix('/sys/fs/cgroup')
        result['leaf_device'] = leaf.stat().st_dev
        result['leaf_inode'] = leaf.stat().st_ino
        for index in range(30):
            for kind, path in [('member-list', leaf / 'cgroup.procs'),
                               ('process-cgroup', Path('/proc/%d/cgroup' % child.pid))]:
                began = time.perf_counter_ns()
                data = path.read_text()
                elapsed = (time.perf_counter_ns() - began) / 1e6
                rows.append({'pair': index, 'interface': kind, 'elapsed_ms': elapsed, 'value': data.strip()})
        result['status'] = 'completed'
    finally:
        if child is not None:
            child.terminate()
            child.wait(timeout=5)
        if leaf.exists():
            leaf.rmdir()
        result['owned_leaf_removed'] = not leaf.exists()
        args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('status', 'place_write_ms', 'owned_leaf_removed')}))


if __name__ == '__main__':
    main()

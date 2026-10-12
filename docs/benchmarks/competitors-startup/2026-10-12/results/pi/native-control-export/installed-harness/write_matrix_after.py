#!/usr/bin/env python3
"""Excluded Pi controls: truncate, overwrite and fresh files on the same ext4.

The scored workload is unchanged. No filesystem, CPU or observer option changes.
"""
import argparse
import json
import random
import shutil
import subprocess
from pathlib import Path
from suite import Suite, SEED
from write_diagnostic import snapshot

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--root', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--instrumented-source', type=Path, required=True)
p.add_argument('--rounds', type=int, default=6)
a = p.parse_args()
a.out.mkdir(parents=True, exist_ok=False)
s = Suite(a.root, a.out, 0, 0, ['direct', 'ouro-jail'])
source = a.instrumented_source.read_text()
for name, content in [('truncate', source), ('overwrite', source.replace(' | O_TRUNC', ''))]:
    path = s.work / ('diagnostic-' + name + '.c')
    path.write_text(content)
    subprocess.run(['cc', '-O2', str(path), '-o', str(s.work / ('diagnostic-' + name))], check=True)
rows = []
generator = random.Random(SEED)
try:
    for round_id in range(a.rounds):
        schedule = [(tool, kind) for tool in s.tools for kind in ['truncate', 'overwrite', 'fresh']]
        generator.shuffle(schedule)
        for tool, kind in schedule:
            # Every cell receives its own output directory. Pre-existing
            # contents are identical for truncate and overwrite controls.
            shutil.rmtree(s.work / 'outputs')
            (s.work / 'outputs').mkdir()
            if kind != 'fresh':
                for index in range(1000):
                    (s.work / 'outputs' / ('f%04d' % index)).write_bytes(b'x' * 1024)
            binary = s.work / ('diagnostic-overwrite' if kind == 'overwrite' else 'diagnostic-truncate')
            before = snapshot()
            row = s.run(tool, [str(binary), 'writes'], 'excluded-write-matrix', kind, round_id)
            row['host_before'] = before
            row['host_after'] = snapshot()
            payload = next(record for record in row['records'] if record.get('workload') == 'writes')
            assert row['exit'] == 0 and payload['count'] == 1000 and payload['checksum'] == 1024000
            if tool == 'ouro-jail':
                assert row['receipt']['policy']['observe'] == 'on'
                assert row['receipt']['policy']['evidence'] == 'strict'
                assert row['receipt']['coverage']['fs.write']['observed_count'] == 1000
            rows.append(row)
            print(round_id, tool, kind, round(row['elapsed_ms'], 1), flush=True)
    (a.out / 'matrix.json').write_text(json.dumps(rows, indent=2) + '\n')
finally:
    s.close()

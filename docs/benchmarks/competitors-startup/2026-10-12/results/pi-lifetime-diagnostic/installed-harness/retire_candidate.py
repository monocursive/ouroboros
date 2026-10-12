#!/usr/bin/env python3
"""Stop the initial candidate before its final receipt-version correction."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time

root = Path.home() / 'bench-ouro-startup'
prefix = 'python3 ' + str(root / 'harness/agentbench_v2.py') + ' '
rows = []
for line in subprocess.check_output(['ps', '-u', str(os.getuid()), '-o', 'pid=,ppid=,pgid=,command='], text=True).splitlines():
    parts = line.split(None, 3)
    if len(parts) == 4:
        rows.append((int(parts[0]), int(parts[1]), int(parts[2]), parts[3]))
parents = [r for r in rows if r[3].startswith(prefix)
           and '--out ' + str(root / 'results/native-after') + ' ' in r[3]]
stopped = []
for pid, _, _, _ in parents:
    for child, parent, group, _ in rows:
        if parent == pid and group == child:
            try:
                os.killpg(group, signal.SIGTERM)
                stopped.append({'pid': child, 'kind': 'owned isolated child group'})
            except ProcessLookupError:
                pass
    time.sleep(1)
    try:
        os.kill(pid, signal.SIGTERM)
        stopped.append({'pid': pid, 'kind': 'native pilot runner'})
    except ProcessLookupError:
        pass
(root / 'results/candidate-interruption.json').write_text(json.dumps(
    {'reason': 'Candidate version reuse is being removed to retain fresh backend-version evidence; this dataset is excluded from the final score',
     'stopped': stopped}, indent=2) + '\n')
print(json.dumps(stopped))

#!/usr/bin/env python3
"""Fresh warm-start availability, with the same policy and provider roles."""
import argparse
import json
from pathlib import Path
from openshell_agent_after import credentials, POLICY
from agentbench_v2 import execute, write

p = argparse.ArgumentParser()
p.add_argument('--root', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--key-file', type=Path, required=True)
p.add_argument('--auth-file', type=Path, required=True)
a = p.parse_args()
if a.out.exists():
    raise SystemExit('Evidence exists')
a.out.mkdir(parents=True)
env = credentials(a)
key = a.key_file.read_text().strip()
policy = a.out / 'policy.yaml'
policy.write_text(POLICY)
rows = []
for agent in ['claude', 'opencode', 'codex']:
    name = 'bench-pi-after-' + agent
    provider = 'benchmark-codex-after' if agent == 'codex' else 'benchmark-anthropic-v2'
    argv = ['openshell', 'sandbox', 'create', '--name', name, '--detach', '--from',
            'ouro-comparison-agents-after:20261011', '--policy', str(policy), '--provider', provider]
    if agent == 'codex':
        argv += ['--env', 'BENCH_CODEX_ROUTING_ACCOUNT_ID=' + env['CODEX_AUTH_ACCOUNT_ID']]
    argv += ['--', '/bin/sleep', '300']
    result = execute(argv, a.root, env, 180)
    result['argv'] = [v.replace(env['CODEX_AUTH_ACCOUNT_ID'], '<CODEX_ACCOUNT_ID>') for v in argv]
    write(a.out / (agent + '-create.json'), result, key)
    write(a.out / (agent + '-startup.log'), execute(['openshell', 'logs', name, '-n', '100'], a.root, env, 30), key)
    write(a.out / (agent + '-delete.json'), execute(['openshell', 'sandbox', 'delete', name], a.root, env, 60), key)
    rows.append({'agent': agent, 'ready': result['exit'] == 0,
                 'exit': result['exit'], 'elapsed_ms': result['elapsed_ms']})
write(a.out / 'availability.json', rows, key)
print(json.dumps(rows))

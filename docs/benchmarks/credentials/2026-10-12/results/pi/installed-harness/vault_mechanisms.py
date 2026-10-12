#!/usr/bin/env python3
"""Live credential boundary checks and paired startup cost, using fake keys.

Loopback HTTP is explicit and used only for these synthetic fixture tokens.
Real provider credentials use HTTPS with normal upstream certificate validation.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import threading
import time


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--samples', type=int, default=30)
    args = p.parse_args()
    root = args.root.resolve()
    out = root / 'results/mechanisms'
    if out.exists():
        raise SystemExit('Existing mechanism evidence must be preserved')
    out.mkdir(parents=True)
    private = root / 'mechanism-private'
    private.mkdir(mode=0o700)
    source = private / 'key'
    source.write_text('fixture-vault-token-v1')
    source.chmod(0o600)
    config = private / 'config/launch'
    config.mkdir(parents=True, mode=0o700)
    workspace = root / 'mechanism-workspace'
    workspace.mkdir()
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            got = self.headers.get('x-api-key')
            received.append({'server': self.server.server_port,
                             'v1': got == 'fixture-vault-token-v1',
                             'v2': got == 'fixture-vault-token-v2'})
            self.send_response(200 if got in ('fixture-vault-token-v1', 'fixture-vault-token-v2') else 401)
            self.end_headers()
            self.wfile.write(b'fixture-ok')

        def log_message(self, *_):
            pass

    servers = [http.server.HTTPServer(('127.0.0.1', 0), Handler) for _ in range(2)]
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for thread in threads:
        thread.start()
    origins = ['http://127.0.0.1:' + str(s.server_port) for s in servers]
    env = dict(os.environ, OURO_CONFIG_DIR=str(config.parent), OURO_DATA_DIR=str(root / 'data'))
    env.pop('ANTHROPIC_API_KEY', None)
    binary = root / 'bin/ouro-jail'
    counter = 0

    def run(name, command, mode='vault', hosts=None, plaintext=True, source_path=None):
        nonlocal counter
        counter += 1
        case = out / ('%03d-' % counter + name)
        case.mkdir()
        profile = 'name="probe"\njail="agent"\nhome_is_state=true\n'
        if mode == 'vault':
            profile += ('[credentials.api]\nmode="vault"\nsource=' + json.dumps(str(source_path or source)) +
                        '\nhosts=' + json.dumps(hosts if hosts is not None else [origins[0]]) +
                        '\nallow_plaintext=' + str(plaintext).lower() + '\nheader={name="x-api-key"}\n')
        else:
            profile += '[environment]\nBENCH_API_KEY="fixture-vault-token-v1"\n'
        profile += '[network]\nallow=' + json.dumps(['127.0.0.1:' + str(s.server_port) for s in servers]) + '\n'
        f = config / 'probe.toml'
        f.write_text(profile)
        f.chmod(0o600)
        before_requests = len(received)
        argv = [str(binary), 'run', '--launch', 'probe', '--workspace', str(workspace),
                '--limit', 'wall=20s', '--receipt', str(case / 'jail.json'), '--', *command]
        started = time.perf_counter_ns()
        r = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=50)
        elapsed = (time.perf_counter_ns() - started) / 1e6
        (case / 'stdout.log').write_bytes(r.stdout)
        (case / 'stderr.log').write_bytes(r.stderr)
        receipt = json.loads((case / 'jail.json').read_text()) if (case / 'jail.json').exists() else None
        journal = []
        if receipt:
            attempt = root / 'data/attempts' / receipt['attempt_id']
            trace = attempt / 'trace.ndjson'
            if trace.exists():
                (case / 'trace.ndjson').write_bytes(trace.read_bytes())
                journal = [json.loads(x) for x in trace.read_text().splitlines()]
            vendor_removed = not (attempt / 'vendor-state').exists()
        else:
            vendor_removed = None
        row = {'name': name, 'mode': mode, 'exit': r.returncode, 'elapsed_ms': elapsed,
               'argv': argv, 'upstream_requests': received[before_requests:],
               'vendor_state_removed': vendor_removed, 'receipt_present': receipt is not None,
               'credential_records': receipt.get('credentials', []) if receipt else [],
               'evidence_strict': receipt.get('evidence') if receipt else None,
               'proxy_reasons': [x.get('fields', {}).get('reason') for x in journal
                                 if x.get('source') == 'proxy'],
               'artifact': str(case.relative_to(root / 'results'))}
        save(case / 'result.json', row)
        return row, r.stdout

    def request(origin, header='x-api-key', marker=None):
        value = '"$OURO_VAULT_API"' if marker is None else json.dumps(marker)
        return ['/bin/sh', '-c', 'curl -fsS --max-time 10 --noproxy "" -H "' + header + ': "' + value + ' ' + origin + '/']

    checks = []
    try:
        row, marker = run('allowed-origin', ['/bin/sh', '-c',
                         'printf "%s\\n" "$OURO_VAULT_API"; ' + request(origins[0])[2]])
        checks.append({'case': 'allowed-origin', 'pass': row['exit'] == 0 and row['upstream_requests'] ==
                       [{'server': servers[0].server_port, 'v1': True, 'v2': False}], 'result': row})
        old_marker = marker.decode().splitlines()[0]
        row, _ = run('wrong-origin-port', request(origins[1]))
        checks.append({'case': 'wrong-origin-port', 'pass': row['exit'] != 0 and not row['upstream_requests'], 'result': row})
        row, _ = run('wrong-header', request(origins[0], 'authorization'))
        checks.append({'case': 'wrong-header', 'pass': row['exit'] != 0 and not row['upstream_requests'], 'result': row})
        row, _ = run('old-attempt-placeholder', request(origins[0], marker=old_marker))
        checks.append({'case': 'old-attempt-placeholder', 'pass': row['exit'] != 0 and not row['upstream_requests'], 'result': row})
        row, _ = run('plaintext-not-opted-in', ['/bin/sh', '-c', 'touch should-not-execute'], plaintext=False)
        checks.append({'case': 'plaintext-not-opted-in', 'pass': row['exit'] != 0 and not (workspace / 'should-not-execute').exists(), 'result': row})
        row, _ = run('missing-source', ['/bin/sh', '-c', 'touch should-not-execute'], source_path=private / 'absent')
        checks.append({'case': 'missing-source', 'pass': row['exit'] != 0 and not (workspace / 'should-not-execute').exists(), 'result': row})
        row, text = run('child-source-hidden', ['python3', '-c', 'import os; print(os.access(' + repr(str(source)) + ',os.R_OK)); print(os.environ["OURO_VAULT_API"].startswith("vault:"))'])
        checks.append({'case': 'child-source-hidden', 'pass': row['exit'] == 0 and text.strip() == b'False\nTrue', 'result': row})
        source.write_text('fixture-vault-token-v2')
        row, _ = run('rotate-next-attempt', request(origins[0]))
        checks.append({'case': 'rotate-next-attempt', 'pass': row['exit'] == 0 and row['upstream_requests'] ==
                       [{'server': servers[0].server_port, 'v1': False, 'v2': True}], 'result': row})
        save(out / 'checks.json', checks)
        print('MECHANISMS', sum(c['pass'] for c in checks), '/', len(checks), flush=True)
        timings = []
        rng = random.Random(20261012)
        for index in range(-3, args.samples):
            modes = ['environment', 'vault']
            rng.shuffle(modes)
            for mode in modes:
                row, _ = run('startup-' + str(index) + '-' + mode, ['/bin/true'], mode=mode)
                row.update({'pair': index, 'warmup': index < 0})
                timings.append(row)
                with (out / 'timings.ndjson').open('a') as f:
                    f.write(json.dumps(row) + '\n')
        valid = [r for r in timings if not r['warmup'] and r['exit'] == 0]
        paired = [{r['mode']: r['elapsed_ms'] for r in valid if r['pair'] == i} for i in range(args.samples)]
        paired = [r for r in paired if len(r) == 2]
        summary = {'samples_requested': args.samples, 'all_attempts': len(timings), 'valid_pairs': len(paired),
                   'failed_measured': [r for r in timings if not r['warmup'] and r['exit'] != 0],
                   'environment_median_ms': statistics.median(r['environment'] for r in paired) if paired else None,
                   'vault_median_ms': statistics.median(r['vault'] for r in paired) if paired else None,
                   'paired_median_extra_ms': statistics.median(r['vault'] - r['environment'] for r in paired) if paired else None,
                   'seed': 20261012, 'no_provider_latency_included': True,
                   'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                   'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        save(out / 'summary.json', summary)
        print(json.dumps(summary), flush=True)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


if __name__ == '__main__':
    main()

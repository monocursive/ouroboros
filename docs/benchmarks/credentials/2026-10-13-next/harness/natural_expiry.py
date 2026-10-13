#!/usr/bin/env python3
"""Real-clock OAuth soak using the frozen client/task and the real JWT expiry.

All raw state is private on the test host. No grant or expiry metadata is
edited. Only one supervisor owns the imported rotating grant. An external
rotation or issuer failure is a retained failure, never silently retried.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)


def jwt_exp(token):
    payload = token.split('.')[1]
    return int(json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))['exp'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--frozen-root', type=Path, required=True)
    args = parser.parse_args()
    root, frozen = args.root.resolve(), args.frozen_root.resolve()
    root.mkdir(mode=0o700)
    for name in ['bin', 'harness', 'private', 'results', 'work', 'home', 'state']:
        (root / name).mkdir(mode=0o700)
    for name in ['agentbench.py', 'agentbench_v2.py', 'vault_agents.py']:
        shutil.copyfile(frozen / 'harness' / name, root / 'harness' / name)
    for name in ['codex', 'ouro-jail']:
        shutil.copyfile(frozen / 'bin' / name, root / 'bin' / name)
        (root / 'bin' / name).chmod(0o755)
    original = json.loads((frozen / 'private/codex-token.json').read_text())
    auth = json.loads((frozen / 'auth/codex/auth.json').read_text())
    expiry = jwt_exp(original['access_token'])
    assert original['expires_at'] == expiry and not original.get('refresh_pending', False)
    assert expiry > int(time.time()) + 600
    assert auth['tokens']['access_token'] == original['access_token']
    save(root / 'private/codex-token.json', original)
    save(root / 'private/auth.json', auth)
    (root / 'private/codex-grant-ready').touch(mode=0o600)
    sys.path.insert(0, str(root / 'harness'))
    import vault_agents as vault
    import agentbench_v2 as bench
    task = bench.make_task_dir(root / 'work', 'add-multiply')
    run = root / 'results/soak'
    run.mkdir(mode=0o700)
    deadline = expiry + 90
    options = SimpleNamespace(root=root, auth_file=root / 'private/auth.json',
                              codex_model='gpt-6.1-sol', wall=deadline - int(time.time()) + 900)
    argv, env, _ = vault.vault_command(options, 'codex', 'ouro', task,
                                       root / 'home', root / 'state', run, '')
    split = argv.index('--')
    waiter = task / 'real_clock_wait.py'
    waiter.write_text('import os,sys,time,json\n'
                      'deadline=int(sys.argv[1]); command=sys.argv[2:]\n'
                      'print(json.dumps({"phase":"waiting_on_real_clock","deadline":deadline}),flush=True)\n'
                      'while time.time()<deadline:time.sleep(min(60,max(.1,deadline-time.time())))\n'
                      'print(json.dumps({"phase":"original_jwt_expired","utc_unix":int(time.time())}),flush=True)\n'
                      'os.execvp(command[0],command)\n')
    argv = argv[:split + 1] + ['/usr/bin/python3', str(waiter), str(deadline)] + argv[split + 1:]
    stdout = (run / 'stdout.log').open('wb')
    stderr = (run / 'stderr.log').open('wb')
    os.chmod(run / 'stdout.log', 0o600)
    os.chmod(run / 'stderr.log', 0o600)
    process = subprocess.Popen(argv, cwd=task, env=env, stdin=subprocess.DEVNULL,
                               stdout=stdout, stderr=stderr)
    facts = {'schema': 'natural-provider-expiry/1', 'phase': 'running',
             'supervisor_pid': process.pid,
             'supervisor_birth': Path('/proc', str(process.pid), 'stat').read_text().rsplit(')', 1)[1].split()[19],
             'started_unix': int(time.time()), 'original_jwt_expiry_unix': expiry,
             'post_expiry_client_deadline_unix': deadline,
             'forced_expiry_metadata': False, 'real_clock_modified': False,
             'refresh_before_seconds': 300, 'independent_scored_benchmark_call': False,
             'task': 'add-multiply', 'model': 'gpt-6.1-sol', 'reasoning': 'low',
             'binary_sha256': {name: hashlib.sha256((root / 'bin' / name).read_bytes()).hexdigest()
                               for name in ['ouro-jail', 'codex']},
             'actual_credential_values_retained': False}
    save(run / 'status.json', facts)
    print(json.dumps(facts), flush=True)
    code = process.wait()
    stdout.close()
    stderr.close()
    source = json.loads((root / 'private/codex-token.json').read_text())
    receipt_path = run / 'jail.json'
    receipt = json.loads(receipt_path.read_text()) if receipt_path.exists() else {}
    trace = root / 'data-v2/attempts' / str(receipt.get('attempt_id', 'missing')) / 'trace.ndjson'
    if trace.exists():
        shutil.copyfile(trace, run / 'trace.ndjson')
    checker = bench.independent_check(task, 'add-multiply')
    checks = {
        'original_token_expired_on_real_clock': int(time.time()) > expiry,
        'supervisor_success': code == 0,
        'access_rotated': source.get('access_token') != original['access_token'],
        'refresh_rotated': source.get('refresh_token') != original['refresh_token'],
        'new_expiry_matches_issuer_jwt': source.get('expires_at') == jwt_exp(source['access_token']),
        'new_access_still_valid': jwt_exp(source['access_token']) > int(time.time()),
        'pending_cleared': not source.get('refresh_pending', False),
        'strict': receipt.get('policy', {}).get('evidence') == 'strict',
        'observed': receipt.get('observer', {}).get('attached') is True,
        'enforced': receipt.get('containment') == 'enforced',
        'active_coverage_without_gaps': bool(receipt.get('coverage')) and all(
            c['status'] == 'active' and not c['gaps'] for c in receipt.get('coverage', {}).values()),
        'tree_empty': receipt.get('lifetime', {}).get('tree_empty') is True,
        'cleanup_complete': receipt.get('state_cleanup') == 'complete',
        'task_and_hidden_checks': all(checker[k] for k in ['tests_pass', 'tests_unchanged', 'hidden_pass']),
        'no_https_fallback_diagnostics': 'falling back' not in (run / 'stderr.log').read_text().lower(),
    }
    facts.update(phase='complete', finished_unix=int(time.time()), exit=code,
                 checks=checks, checker=checker, success=all(checks.values()))
    save(run / 'result.json', facts)
    print(json.dumps(facts), flush=True)
    raise SystemExit(0 if facts['success'] else 1)


if __name__ == '__main__':
    main()

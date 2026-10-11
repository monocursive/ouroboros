#!/usr/bin/env python3
"""VM-only debugger-death research; test registered members and late-fork escapes.

Records independent audit-token snapshots before runner cleanup. Never claims
complete-tree proof or enables the macOS execution backend.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from macos_es import development_settings
from macos_native import json_lines, snapshot, signal_token, wait_until

HERE = Path(__file__).resolve().parent
LATE = ('fork', 'setsid', 'double-fork', 'spawn-group', 'spawn-session', 'deny-attach')


def rows(path):
    return json_lines(path.read_text()) if path.exists() else []


def require(value, message):
    if not value:
        raise RuntimeError(message)


def signal_owned(fixture, row, sig):
    if snapshot(fixture, row)['alive']:
        require(signal_token(row, sig)['rc'] == 0, 'Owned audit-token signal failed')


def trial(exe, fixture, out, case):
    out.mkdir()
    workload = out / 'workload.jsonl'
    tracer_log = out / 'tracer.jsonl'
    payload = tracer = None
    known = []
    tracer_row = None
    record = {'case': case, 'lifetime_contract_verified': False}
    with workload.open('w') as log, (out / 'stderr.txt').open('w') as stderr:
        try:
            if case.startswith('registered'):
                argv = [fixture, 'tree', out]
            else:
                argv = [exe, '--late', out, case]
            payload = subprocess.Popen(list(map(str, argv)), stdout=log, stderr=stderr)
            def initial_ready():
                nonlocal known
                known = [r for r in rows(workload) if 'audit_token' in r]
                return any(r.get('ready') or r.get('kind') == 'before_fork' for r in rows(workload))
            wait_until(initial_ready)
            require(len(known) == (5 if case.startswith('registered') else 1), 'Unexpected initial fixture membership')
            require(all(snapshot(fixture, r)['alive'] for r in known), 'Fixture not live before attach')
            with tracer_log.open('w') as trace_output:
                tracer = subprocess.Popen([str(exe), '--trace', *[f"{r['pid']}:{r['pidversion']}" for r in known]],
                                          stdout=trace_output, stderr=stderr)
                def trace_ready():
                    require(tracer.poll() is None, 'Tracer refused or exited before attach readiness')
                    return any(r.get('kind') == 'tracer_ready' for r in rows(tracer_log))
                wait_until(trace_ready)
                tracer_row = next(r for r in rows(tracer_log) if r.get('role') == 'tracer')
                record['registered_members'] = known.copy()
                record['tracer'] = tracer_row
                record['attach_events'] = [r for r in rows(tracer_log) if r.get('kind') == 'attach']
                if not case.startswith('registered'):
                    (out / 'trigger').write_text('fork after the root is traced\n')
                    def child_ready():
                        nonlocal known
                        known = [r for r in rows(workload) if 'audit_token' in r]
                        return len(known) == 2 and (out / 'late-child.heartbeat').exists()
                    wait_until(child_ready)
                    record['post_registration_members'] = known.copy()
                before = {p.name: p.stat().st_size for p in out.glob('*.heartbeat')}
                start = time.monotonic()
                if case == 'registered_stop':
                    signal_owned(fixture, tracer_row, signal.SIGSTOP)
                else:
                    signal_owned(fixture, tracer_row, signal.SIGKILL)
                    tracer.wait(timeout=5)
                time.sleep(.5)
                after = {r['role']: snapshot(fixture, r) for r in known}
                if case == 'registered_death':
                    wait_until(lambda: all(not snapshot(fixture, r)['alive'] for r in known), timeout=3)
                    after = {r['role']: snapshot(fixture, r) for r in known}
                record.update(observation_ms=(time.monotonic() - start) * 1000,
                              after=after, heartbeat_before=before,
                              heartbeat_after={p.name: p.stat().st_size for p in out.glob('*.heartbeat')},
                              tracer_after=snapshot(fixture, tracer_row),
                              fixture_empty_before_runner_cleanup=not any(r['alive'] for r in after.values()))
        except BaseException as error:
            record['error'] = str(error) or repr(error)
            raise
        finally:
            # Discover a child recorded during a failing readiness check too.
            discovered = [r for r in rows(workload) if 'audit_token' in r]
            if discovered:
                known = discovered
            if tracer_row is None:
                tracer_row = next((r for r in rows(tracer_log) if r.get('role') == 'tracer'), None)
            if tracer_row is not None:
                signal_owned(fixture, tracer_row, signal.SIGKILL)
            elif tracer is not None and tracer.poll() is None:
                tracer.kill()  # unreaped direct child; PID cannot have been reused
            for row in known:
                signal_owned(fixture, row, signal.SIGKILL)
            for process in (tracer, payload):
                if process is not None:
                    if process.poll() is None:
                        process.kill()  # unreaped direct child only
                    process.wait(timeout=5)
            wait_until(lambda: all(not snapshot(fixture, r)['alive'] for r in known), timeout=5)
            record['cleanup_verified'] = True
            record['fixture_processes'] = known
            record['after_runner_cleanup'] = {r['role']: snapshot(fixture, r) for r in known}
            record['tracer_events'] = rows(tracer_log)
            record['workload_events'] = rows(workload)
            (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=3)
    args = parser.parse_args()
    require(1 <= args.samples <= 10, 'Use 1 to 10 bounded samples')
    settings = development_settings()  # Must refuse on the protected host before mutation.
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = ['macos_ptrace_lifetime.c', 'macos_ptrace_lifetime.py', 'macos_native.c',
               'macos_native.py', 'macos_es.py']
    (out / 'tested-source').mkdir()
    result = {'schema': 'ouro.jail.macos-ptrace-lifetime/1', 'settings': settings,
              'source_sha256': {}, 'cases': [], 'lifetime_contract_verified': False,
              'native_execution_ready': False, 'status': 'running'}
    for name in sources:
        data = (HERE / name).read_bytes()
        (out / 'tested-source' / name).write_bytes(data)
        result['source_sha256'][name] = hashlib.sha256(data).hexdigest()
    try:
        exe = out / 'ptrace-research'
        fixture = out / 'native-fixture'
        for source, binary, flags in [('macos_ptrace_lifetime.c', exe, ['-lbsm']),
                                      ('macos_native.c', fixture, ['-fblocks', '-lEndpointSecurity', '-lbsm'])]:
            command = ['cc', '-O2', '-Wall', '-Wextra', '-Werror', str(out / 'tested-source' / source), *flags, '-o', str(binary)]
            subprocess.run(command, check=True, capture_output=True, timeout=30)
        result['binary_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (exe, fixture)}
        result['environment'] = {name: subprocess.check_output(command, text=True, timeout=10).strip()
            for name, command in [('os', ['sw_vers']), ('kernel', ['uname', '-a']), ('sdk', ['xcrun', '--show-sdk-version'])]}
        for sample in range(1, args.samples + 1):
            for case in ('registered_death', 'registered_stop', *LATE):
                row = trial(exe, fixture, out / f'{sample:02}-{case}', case)
                row['sample'] = sample
                result['cases'].append(row)
                (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
                print(json.dumps({'sample': sample, 'case': case,
                                  'empty': row['fixture_empty_before_runner_cleanup']}), flush=True)
        result['status'] = 'experiment_complete'
    except BaseException as error:
        result['status'] = 'experiment_failed'
        result['error'] = str(error) or repr(error)
        raise
    finally:
        (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    # Mechanism evidence only; failure of full-tree lifetime remains explicit.
    return 125


if __name__ == '__main__':
    raise SystemExit(main())

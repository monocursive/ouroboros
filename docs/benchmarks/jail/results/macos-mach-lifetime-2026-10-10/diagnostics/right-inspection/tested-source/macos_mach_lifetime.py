#!/usr/bin/env python3
"""VM-only inherited exception-port owner-death investigation; never enables execution."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from macos_es import development_settings
from macos_native import snapshot, wait_until
from macos_ptrace_lifetime import require, rows, signal_owned

HERE = Path(__file__).resolve().parent
CASES = ('root', 'fork', 'setsid', 'double-fork', 'spawn-group', 'spawn-session', 'clear-exception')


def trial(exe, fixture, out, case):
    out.mkdir()
    workload, control = out / 'workload.jsonl', out / 'custodian.jsonl'
    known, owner = [], None
    record = {'case': case, 'lifetime_contract_verified': False}
    with control.open('w') as log, (out / 'stderr.txt').open('w') as errors:
        custodian = subprocess.Popen([str(exe), '--custodian', str(out), case], stdout=log, stderr=errors)
        try:
            def ready():
                nonlocal known, owner
                known = [r for r in rows(workload) if 'audit_token' in r]
                owner = next((r for r in rows(control) if r.get('role') == 'custodian'), None)
                require(custodian.poll() is None, 'Custodian exited before readiness')
                installed = next((r for r in rows(workload) if r.get('kind') == 'exception_installed'), None)
                if installed:
                    require(installed['rc'] == 0, 'Exception installation refused: ' + str(installed['rc']))
                return any(r.get('kind') == 'before_fork' for r in rows(workload)) and owner
            wait_until(ready)
            installed = next(r for r in rows(workload) if r.get('kind') == 'exception_installed')
            require(installed['rc'] == 0 and len(known) == 1, 'Exception installation failed')
            record['installed_mask'] = installed['mask']
            (out / 'trigger').write_text('Create workload after installing the handler\n')
            def members_ready():
                nonlocal known
                known = [r for r in rows(workload) if 'audit_token' in r]
                return len(known) == (1 if case == 'root' else 2) and all(
                    (out / (r['role'] + '.heartbeat')).exists() for r in known)
            wait_until(members_ready)
            require(all(snapshot(fixture, r)['alive'] for r in known), 'Fixture not live before owner loss')
            before = {p.name: p.stat().st_size for p in out.glob('*.heartbeat')}
            start = time.monotonic()
            signal_owned(fixture, owner, signal.SIGKILL)
            custodian.wait(timeout=5)
            (out / 'after-owner-loss').write_text('Inspect kernel handler after owner death\n')
            wait_until(lambda: len([r for r in rows(workload) if r.get('phase') == 'after_owner_loss']) == len(known))
            time.sleep(.5)
            after = {r['role']: snapshot(fixture, r) for r in known}
            record.update(custodian=owner, custodian_after=snapshot(fixture, owner), after=after,
                          observation_ms=(time.monotonic() - start) * 1000,
                          heartbeat_before=before,
                          heartbeat_after={p.name: p.stat().st_size for p in out.glob('*.heartbeat')},
                          fixture_empty_before_runner_cleanup=not any(r['alive'] for r in after.values()))
        except BaseException as error:
            record['error'] = str(error) or repr(error)
            raise
        finally:
            known = [r for r in rows(workload) if 'audit_token' in r]
            owner = next((r for r in rows(control) if r.get('role') == 'custodian'), owner)
            if owner:
                signal_owned(fixture, owner, signal.SIGKILL)
            elif custodian.poll() is None:
                custodian.kill()  # unreaped direct child only
            for member in known:
                signal_owned(fixture, member, signal.SIGKILL)
            custodian.wait(timeout=5)
            wait_until(lambda: all(not snapshot(fixture, r)['alive'] for r in known))
            record.update(cleanup_verified=True, fixture_processes=known,
                          after_runner_cleanup={r['role']: snapshot(fixture, r) for r in known},
                          custodian_events=rows(control), workload_events=rows(workload))
            (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=3)
    args = parser.parse_args()
    require(1 <= args.samples <= 3, 'Use 1 to 3 bounded repetitions')
    settings = development_settings()  # protected host refuses before mutation
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / 'tested-source').mkdir()
    sources = ('macos_mach_lifetime.c', 'macos_mach_lifetime.py', 'macos_ptrace_lifetime.c',
               'macos_ptrace_lifetime.py', 'macos_native.c', 'macos_native.py', 'macos_es.py')
    result = {'schema': 'ouro.jail.macos-mach-lifetime/1', 'status': 'running',
              'actor_uid': os.getuid(), 'actor_euid': os.geteuid(), 'settings': settings,
              'source_sha256': {}, 'cases': [], 'native_execution_ready': False,
              'lifetime_contract_verified': False}
    for name in sources:
        data = (HERE / name).read_bytes()
        (out / 'tested-source' / name).write_bytes(data)
        result['source_sha256'][name] = hashlib.sha256(data).hexdigest()
    try:
        lib = ctypes.CDLL(None, use_errno=True)
        size = ctypes.c_size_t()
        rc = lib.sysctlbyname(b'machdep.task_get_fatal_port', None, ctypes.byref(size), None, 0)
        result['fatal_port_size_query'] = {'rc': rc, 'errno': ctypes.get_errno(), 'size': size.value,
                                           'port_requested': False}
        exe, fixture = out / 'mach-research', out / 'native-fixture'
        for source, binary, flags in [('macos_mach_lifetime.c', exe, ['-lbsm']),
                                      ('macos_native.c', fixture, ['-fblocks', '-lEndpointSecurity', '-lbsm'])]:
            command = ['cc', '-O2', '-Wall', '-Wextra', '-Werror', str(out / 'tested-source' / source), *flags, '-o', str(binary)]
            built = subprocess.run(command, capture_output=True, timeout=30)
            (out / (source + '.build.stdout')).write_bytes(built.stdout)
            (out / (source + '.build.stderr')).write_bytes(built.stderr)
            built.check_returncode()
        result['binary_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (exe, fixture)}
        result['environment'] = {name: subprocess.check_output(command, text=True, timeout=10).strip()
            for name, command in [('os', ['sw_vers']), ('kernel', ['uname', '-a']), ('sdk', ['xcrun', '--show-sdk-version'])]}
        for sample in range(1, args.samples + 1):
            for case in CASES:
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
    return 125


if __name__ == '__main__':
    raise SystemExit(main())

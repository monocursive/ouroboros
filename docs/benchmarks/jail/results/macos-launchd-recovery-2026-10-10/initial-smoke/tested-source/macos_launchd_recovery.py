#!/usr/bin/env python3
"""VM-only launchd crash-recovery probe; known identities are not a tree boundary.

Loads temporary system jobs outside LaunchDaemons. A restarted root custodian
reaps the seven recorded fixture identities. A stopped custodian cannot restart.
No production services, users, ES clients, or unfenced process signals.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import time
import uuid

from macos_es import development_settings
from macos_native import AuditToken, json_lines, snapshot, wait_until
from macos_ptrace_lifetime import require, rows, signal_owned

HERE = Path(__file__).resolve().parent
SOURCES = ('macos_launchd_recovery.py', 'macos_native.c', 'macos_native.py',
           'macos_ptrace_lifetime.py', 'macos_es.py')


def own_identity(fixture):
    row = json_lines(subprocess.check_output([str(fixture), 'info', str(os.getpid())], text=True))[0]
    system = ctypes.CDLL('/usr/lib/libSystem.B.dylib')
    system.task_info.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
    system.task_info.restype = ctypes.c_int
    token, count = AuditToken(), ctypes.c_uint(8)
    # TASK_AUDIT_TOKEN = 15; TASK_AUDIT_TOKEN_COUNT = 8 in the tested SDK.
    own_task = ctypes.c_uint.in_dll(system, 'mach_task_self_').value
    require(system.task_info(own_task, 15, ctypes.byref(token), ctypes.byref(count)) == 0 and count.value == 8,
            'Own kernel audit token unavailable')
    row.update(role='custodian', audit_token=list(token.val), uid=os.getuid(), euid=os.geteuid())
    require(row['audit_token'][5] == row['pid'] and row['audit_token'][7] == row['pidversion'],
            'Own identity/token mismatch')
    return row


def worker(out, fixture):
    require(os.getuid() == os.geteuid() == 0, 'Research custodian must be root in guest')
    require(out.stat().st_uid == fixture.stat().st_uid == 0 and out.stat().st_mode & 0o022 == 0,
            'Research state must be protected from workload writes')
    signal.signal(signal.SIGALRM, lambda *_: os._exit(0))
    signal.alarm(20)  # Emergency timeout; never the measured cleanup mechanism.
    print(json.dumps(own_identity(fixture)), flush=True)
    marker = out / 'initialized'
    try:
        fd = os.open(str(marker), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Protected state is intentionally only a closed-set fixture journal.
        known = json.loads((out / 'known.json').read_text())
        for row in known:
            signal_owned(fixture, row, signal.SIGKILL)
        wait_until(lambda: all(not snapshot(fixture, r)['alive'] for r in known))
        (out / 'recovery.json').write_text(json.dumps({'known_processes': len(known),
            'after': {r['role']: snapshot(fixture, r) for r in known},
            'lifetime_contract_verified': False}, indent=2) + '\n')
        print(json.dumps({'kind': 'known_recovery_complete', 'known_processes': len(known)}), flush=True)
        return 0  # SuccessfulExit=false prevents a persistent restart loop.
    os.close(fd)
    work = out / 'workload'
    env = os.environ.copy()
    env.update(OURO_RESEARCH_GUARDIAN_PID=str(os.getpid()), OURO_RESEARCH_WARD_PID=str(os.getpid()))

    def drop_credentials():
        os.setgroups([])
        os.setgid(20)
        os.setuid(501)

    with (out / 'workload.jsonl').open('w') as log:
        child = subprocess.Popen(['/usr/bin/sandbox-exec', '-p',
            '(version 1)(allow default)(deny signal)(allow signal (target same-sandbox))',
            str(fixture), 'tree-spawn', str(work)], stdout=log, env=env, preexec_fn=drop_credentials)
        wait_until(lambda: any(r.get('ready') for r in rows(out / 'workload.jsonl')))
        known = [r for r in rows(out / 'workload.jsonl') if 'audit_token' in r]
        require(len(known) == 7 and all(r['audit_token'][1] == 501 for r in known),
                'Ordinary-user fixture membership changed')
        (out / 'known.json').write_text(json.dumps(known, indent=2) + '\n')
        print(json.dumps({'kind': 'custodian_ready', 'child_pid': child.pid}), flush=True)
        while True:
            time.sleep(.1)


def trial(fixture, out, case):
    out.mkdir(mode=0o755)
    work = out / 'workload'; work.mkdir(mode=0o700); os.chown(work, 501, 20)
    label = 'com.monocursive.ouro.recoveryresearch.' + uuid.uuid4().hex
    target = 'system/' + label
    plist = out / 'job.plist'
    plist.write_bytes(plistlib.dumps({'Label': label,
        'ProgramArguments': ['/usr/bin/python3', '-u', str(out.parent / 'tested-source' / Path(__file__).name),
                             '--worker', str(out), '--fixture', str(fixture)],
        'RunAtLoad': True, 'KeepAlive': {'SuccessfulExit': False}, 'ThrottleInterval': 1,
        'AbandonProcessGroup': False, 'ExitTimeOut': 1, 'SessionCreate': True,
        'StandardOutPath': str(out / 'custodian.jsonl'), 'StandardErrorPath': str(out / 'stderr.txt')}))
    known, custodians, loaded = [], [], False
    record = {'case': case, 'lifetime_contract_verified': False}
    try:
        subprocess.run(['launchctl', 'bootstrap', 'system', str(plist)], check=True, capture_output=True, timeout=8)
        loaded = True
        wait_until(lambda: any(r.get('kind') == 'custodian_ready' for r in rows(out / 'custodian.jsonl')), timeout=8)
        known = json.loads((out / 'known.json').read_text())
        custodians = [r for r in rows(out / 'custodian.jsonl') if 'audit_token' in r]
        require(len(custodians) == 1 and all(snapshot(fixture, r)['alive'] for r in known), 'Not ready for fault')
        detail = subprocess.run(['launchctl', 'print', target], capture_output=True, text=True, timeout=5)
        require(detail.returncode == 0, 'Temporary system service not confirmed')
        (out / 'launchd-job.txt').write_text(detail.stdout + detail.stderr)
        before = {p.name: p.stat().st_size for p in work.glob('*.heartbeat')}
        start = time.monotonic()
        sig = signal.SIGKILL if case == 'custodian-death' else signal.SIGSTOP
        signal_owned(fixture, custodians[0], sig)
        time.sleep(3)
        after = {r['role']: snapshot(fixture, r) for r in known}
        recovery = out / 'recovery.json'
        if any(r['alive'] for r in after.values()):
            (work / 'after-loss.trigger').write_text('Post-fault execution control\n')
            time.sleep(.2)
        record.update(signal=int(sig), observation_ms=(time.monotonic() - start) * 1000,
                      after=after, custodian_after=snapshot(fixture, custodians[0]),
                      heartbeat_before=before, heartbeat_after={p.name: p.stat().st_size for p in work.glob('*.heartbeat')},
                      known_empty_before_runner_cleanup=not any(r['alive'] for r in after.values()),
                      recovery=json.loads(recovery.read_text()) if recovery.exists() else None,
                      exec_marker_created=(work / 'after-loss.exec').exists(),
                      exec_probe=json.loads((work / 'after-loss-exec.json').read_text()) if (work / 'after-loss-exec.json').exists() else None)
    except BaseException as error:
        record['error'] = str(error) or repr(error)
        raise
    finally:
        if loaded:
            subprocess.run(['launchctl', 'bootout', target], check=True, capture_output=True, timeout=8)
        known = [r for r in rows(out / 'workload.jsonl') if 'audit_token' in r]
        custodians = [r for r in rows(out / 'custodian.jsonl') if 'audit_token' in r]
        for r in [*known, *custodians]:
            signal_owned(fixture, r, signal.SIGKILL)
        wait_until(lambda: all(not snapshot(fixture, r)['alive'] for r in [*known, *custodians]))
        require(subprocess.run(['launchctl', 'print', target], capture_output=True).returncode != 0,
                'Temporary system job not removed')
        record.update(cleanup_verified=True, fixture_processes=known, custodians=custodians,
                      custodian_events=rows(out / 'custodian.jsonl'), workload_events=rows(out / 'workload.jsonl'),
                      after_runner_cleanup={r['role'] + ':' + str(r['uniqueid']): snapshot(fixture, r) for r in [*known, *custodians]})
        (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--worker', type=Path)
    parser.add_argument('--fixture', type=Path)
    args = parser.parse_args()
    settings = development_settings()  # Refuse the protected host before mutation.
    require(os.getuid() == os.geteuid() == 0, 'Run as root only in the isolated guest')
    if args.worker:
        require(args.fixture is not None, 'Missing worker fixture')
        return worker(args.worker.resolve(), args.fixture.resolve())
    require(args.out is not None and 1 <= args.samples <= 3, 'Fresh output and 1 to 3 samples required')
    out = args.out.resolve(); out.mkdir(mode=0o755, parents=True, exist_ok=False)
    source_dir = out / 'tested-source'; source_dir.mkdir(mode=0o700)
    result = {'schema': 'ouro.jail.macos-launchd-recovery/1', 'status': 'running', 'settings': settings,
              'actor_uid': os.getuid(), 'actor_euid': os.geteuid(), 'cases': [], 'source_sha256': {},
              'native_execution_ready': False, 'lifetime_contract_verified': False}
    try:
        for name in SOURCES:
            data = (HERE / name).read_bytes(); (source_dir / name).write_bytes(data)
            result['source_sha256'][name] = hashlib.sha256(data).hexdigest()
        fixture = out / 'native-fixture'
        built = subprocess.run(['cc', '-O2', '-fblocks', '-Wall', '-Wextra', '-Werror',
            str(source_dir / 'macos_native.c'), '-lEndpointSecurity', '-lbsm', '-o', str(fixture)], capture_output=True, timeout=30)
        (out / 'build.stdout').write_bytes(built.stdout); (out / 'build.stderr').write_bytes(built.stderr)
        built.check_returncode()
        result['binary_sha256'] = {'native-fixture': hashlib.sha256(fixture.read_bytes()).hexdigest()}
        result['environment'] = {name: subprocess.check_output(cmd, text=True, timeout=10).strip() for name, cmd in
                                 [('os', ['sw_vers']), ('kernel', ['uname', '-a']), ('sdk', ['xcrun', '--show-sdk-version'])]}
        for sample in range(1, args.samples + 1):
            for case in ('custodian-death', 'custodian-stop'):
                row = trial(fixture, out / f'{sample:02}-{case}', case); row['sample'] = sample
                result['cases'].append(row)
                print(json.dumps({'sample': sample, 'case': case, 'known_empty': row['known_empty_before_runner_cleanup'],
                                  'generations': len(row['custodians'])}), flush=True)
                (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
        result['status'] = 'experiment_complete'
    except BaseException as error:
        result.update(status='experiment_failed', error=str(error) or repr(error))
        raise
    finally:
        (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    return 125


if __name__ == '__main__':
    raise SystemExit(main())

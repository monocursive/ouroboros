#!/usr/bin/env python3
"""VM-only app-embedded XPC lifecycle probe; no successful native receipts."""
import argparse
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
from macos_native import snapshot, wait_until
from macos_ptrace_lifetime import require, rows, signal_owned

HERE = Path(__file__).resolve().parent
CASES = ('host-death', 'service-death', 'both-death', 'host-stop', 'service-stop')


def trial(exe, fixture, service_name, out, case, launch_services=False, observation_seconds=2):
    out.mkdir()
    workload, service, host_log = out / 'workload.jsonl', out / 'service.jsonl', out / 'host.jsonl'
    known, anchors = [], {}
    record = {'case': case, 'lifetime_contract_verified': False}
    with (out / 'launcher.stdout').open('w') as log, (out / 'stderr.txt').open('w') as errors:
        argv = [str(exe), '--host', service_name, str(out), str(fixture)]
        if launch_services:
            argv = ['open', '-n', '-W', '-a', str(exe.parents[2]), '--args', *argv[1:]]
        host = subprocess.Popen(argv, stdout=log, stderr=errors)
        try:
            def ready():
                nonlocal known, anchors
                known = [r for r in rows(workload) if 'audit_token' in r]
                anchors = {r['role']: r for p in (host_log, service) for r in rows(p) if 'audit_token' in r}
                require(host.poll() is None, 'Host exited before service readiness')
                require(not any(r.get('kind') == 'host_reply' and not r['started'] for r in rows(host_log)),
                        'XPC request failed before workload readiness')
                return len(known) == 7 and set(anchors) == {'host', 'service'} and any(r.get('ready') for r in rows(workload))
            wait_until(ready, timeout=8)
            require(all(snapshot(fixture, r)['alive'] for r in [*known, *anchors.values()]), 'Fixture not live before fault')
            # Private per-app launchd domain, inspected without modifying it.
            domain = subprocess.run(['launchctl', 'print', 'pid/' + str(anchors['host']['pid'])],
                                    capture_output=True, text=True, timeout=5)
            (out / 'launchd-domain.txt').write_text(domain.stdout + domain.stderr)
            require(domain.returncode == 0 and service_name in domain.stdout, 'Embedded XPC service domain not confirmed')
            before = {p.name: p.stat().st_size for p in out.glob('*.heartbeat')}
            start = time.monotonic()
            sig = signal.SIGSTOP if case.endswith('stop') else signal.SIGKILL
            faulted = ('host', 'service') if case == 'both-death' else (case.split('-')[0],)
            for role in faulted:
                signal_owned(fixture, anchors[role], sig)
            checkpoints = []
            offsets = (.2, .5, 1.0, 2.0, 4.0, 8.0)
            for offset in [v for v in offsets if v <= observation_seconds]:
                remaining = start + offset - time.monotonic()
                if remaining > 0:
                    time.sleep(remaining)
                checkpoints.append({'elapsed_ms': (time.monotonic() - start) * 1000,
                                    'heartbeats': {p.name: p.stat().st_size for p in out.glob('*.heartbeat')}})
            after = {r['role']: snapshot(fixture, r) for r in known}
            if any(r['alive'] for r in after.values()):
                (out / 'after-loss.trigger').write_text('Execute a new command after lifecycle fault\n')
                time.sleep(.2)
            exec_path = out / 'after-loss-exec.json'
            record.update(anchors=anchors, faulted=list(faulted), signal=int(sig),
                          anchors_after={role: snapshot(fixture, r) for role, r in anchors.items()},
                          after=after, checkpoints=checkpoints,
                          observation_ms=(time.monotonic() - start) * 1000,
                          heartbeat_before=before,
                          heartbeat_after={p.name: p.stat().st_size for p in out.glob('*.heartbeat')},
                          exec_probe=json.loads(exec_path.read_text()) if exec_path.exists() else None,
                          exec_marker_created=(out / 'after-loss.exec').exists(),
                          fixture_empty_before_runner_cleanup=not any(r['alive'] for r in after.values()))
        except BaseException as error:
            record['error'] = str(error) or repr(error)
            raise
        finally:
            known = [r for r in rows(workload) if 'audit_token' in r]
            anchors = {r['role']: r for p in (host_log, service) for r in rows(p) if 'audit_token' in r}
            for r in [*anchors.values(), *known]:
                signal_owned(fixture, r, signal.SIGKILL)
            if host.poll() is None:
                host.kill()  # unreaped direct child only
            host.wait(timeout=5)
            wait_until(lambda: all(not snapshot(fixture, r)['alive'] for r in [*known, *anchors.values()]), timeout=5)
            record.update(cleanup_verified=True, fixture_processes=known, anchors=anchors,
                          after_runner_cleanup={r['role']: snapshot(fixture, r) for r in [*known, *anchors.values()]},
                          host_events=rows(host_log), service_events=rows(service), workload_events=rows(workload))
            (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=1)
    parser.add_argument('--join-existing-session', action='store_true')
    parser.add_argument('--launch-services', action='store_true')
    parser.add_argument('--observation-seconds', type=int, choices=(2, 8), default=2)
    parser.add_argument('--case', choices=CASES, action='append')
    args = parser.parse_args()
    require(1 <= args.samples <= 3, 'Use 1 to 3 bounded samples')
    settings = development_settings()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / 'tested-source').mkdir()
    names = ('macos_xpc_lifetime.c', 'macos_xpc_lifetime.py', 'macos_native.c', 'macos_native.py',
             'macos_ptrace_lifetime.py', 'macos_es.py')
    result = {'schema': 'ouro.jail.macos-xpc-lifetime/1', 'status': 'running', 'settings': settings,
              'actor_uid': os.getuid(), 'actor_euid': os.geteuid(), 'cases': [], 'source_sha256': {},
              'native_execution_ready': False, 'lifetime_contract_verified': False,
              'join_existing_session': args.join_existing_session,
              'launch_services': args.launch_services, 'observation_seconds': args.observation_seconds,
              'requested_cases': args.case or list(CASES)}
    for name in names:
        data = (HERE / name).read_bytes(); (out / 'tested-source' / name).write_bytes(data)
        result['source_sha256'][name] = hashlib.sha256(data).hexdigest()
    try:
        app = out / 'OuroXPCResearch.app'
        bundle = 'com.monocursive.ouro.xpcresearch.' + uuid.uuid4().hex
        service_name = bundle + '.worker'
        service_app = app / 'Contents/XPCServices/Worker.xpc'
        exe, worker = app / 'Contents/MacOS/host', service_app / 'Contents/MacOS/worker'
        for path in (exe, worker): path.parent.mkdir(parents=True)
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': bundle, 'CFBundleExecutable': 'host', 'CFBundlePackageType': 'APPL',
            'CFBundleName': 'Ouro XPC Research', 'CFBundleVersion': '1', 'LSBackgroundOnly': True}))
        (service_app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': service_name, 'CFBundleExecutable': 'worker', 'CFBundlePackageType': 'XPC!',
            'CFBundleVersion': '1', 'XPCService': {'ServiceType': 'Application', 'RunLoopType': 'dispatch_main',
                                                'JoinExistingSession': args.join_existing_session}}))
        fixture = out / 'native-fixture'
        for source, binary in [('macos_xpc_lifetime.c', exe), ('macos_native.c', fixture)]:
            command = ['cc', '-O2', '-fblocks', '-Wall', '-Wextra', '-Werror',
                       str(out / 'tested-source' / source), '-lEndpointSecurity', '-lbsm', '-o', str(binary)]
            built = subprocess.run(command, capture_output=True, timeout=30)
            (out / (source + '.build.stdout')).write_bytes(built.stdout)
            (out / (source + '.build.stderr')).write_bytes(built.stderr)
            built.check_returncode()
        worker.write_bytes(exe.read_bytes()); worker.chmod(0o755)
        for target in (service_app, app):
            subprocess.run(['codesign', '--force', '--sign', '-', '--timestamp=none', str(target)],
                           check=True, capture_output=True, timeout=15)
            verified = subprocess.run(['codesign', '--verify', '--strict', str(target)], capture_output=True, timeout=15)
            verified.check_returncode()
        result['binary_sha256'] = {name: hashlib.sha256(p.read_bytes()).hexdigest()
                                   for name, p in [('host', exe), ('worker', worker), ('native-fixture', fixture)]}
        result['service_name'] = service_name
        result['signing'] = {'identity': '-', 'approved_profile': False, 'signature_verified': True}
        result['environment'] = {name: subprocess.check_output(command, text=True, timeout=10).strip()
            for name, command in [('os', ['sw_vers']), ('kernel', ['uname', '-a']), ('sdk', ['xcrun', '--show-sdk-version'])]}
        for sample in range(1, args.samples + 1):
            for case in args.case or CASES:
                row = trial(exe, fixture, service_name, out / f'{sample:02}-{case}', case,
                            args.launch_services, args.observation_seconds)
                row['sample'] = sample; result['cases'].append(row)
                (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
                print(json.dumps({'sample': sample, 'case': case,
                                  'empty': row['fixture_empty_before_runner_cleanup'],
                                  'alive': [name for name, r in row['after'].items() if r['alive']]}), flush=True)
        result['status'] = 'experiment_complete'
    except BaseException as error:
        result['status'] = 'experiment_failed'; result['error'] = str(error) or repr(error)
        raise
    finally:
        (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    return 125


if __name__ == '__main__':
    raise SystemExit(main())

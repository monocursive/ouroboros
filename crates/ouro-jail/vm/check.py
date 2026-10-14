#!/usr/bin/env python3
"""Real VM fault matrix; only signals a service proven to hold this attempt's disk."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parent
SERVICE = '/System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine'


def identity(pid):
    result = subprocess.run(['ps', '-p', str(pid), '-o', 'lstart=', '-o', 'comm='], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def owned_service(disk):
    result = subprocess.run(['ps', '-axo', 'pid=,comm='], capture_output=True, text=True, check=True)
    matches = []
    for line in result.stdout.splitlines():
        pid, command = line.strip().split(None, 1)
        if command == SERVICE:
            opened = subprocess.run(['lsof', '-a', '-p', pid, '-F', 'n'], capture_output=True, text=True)
            if 'n' + str(disk) in opened.stdout.splitlines():
                matches.append(int(pid))
    if len(matches) != 1:
        raise RuntimeError(f'expected one VM service holding {disk}, got {matches}')
    return matches[0]


def safe_signal(pid, expected, sig):
    if expected and identity(pid) == expected:
        os.kill(pid, sig)
    else:
        raise RuntimeError('process identity changed before fault injection')


def trial(root, image, case, executable=None):
    workspace = root / 'input'
    workspace.mkdir(parents=True)
    (workspace / 'fixture.py').write_text('''import os, time
for i in range(6):
    if os.fork() == 0:
        os.setsid()
        print("DETACHED", os.getpid(), flush=True)
        while True:
            time.sleep(.1)
print("READY", flush=True)
while True:
    print("TICK", time.monotonic_ns(), flush=True)
    time.sleep(.1)
''')
    out = root / 'attempt'
    result = {'case': case, 'status': 'failed'}
    process = None
    identities = {}
    service = None
    helper = None
    custodian = None
    try:
        with (root / 'stdout').open('wb') as stdout, (root / 'stderr').open('wb') as stderr:
            launcher = [str(executable), 'run'] if executable else [sys.executable, str(SOURCE / 'run.py'), '--image', str(image)]
            process = subprocess.Popen([*launcher,
                                        '--workspace', str(workspace), '--out', str(out), '--wall',
                                        '3' if case == 'wall' else '30', '--keep-disk', '--',
                                        '/usr/bin/python3', 'fixture.py'], stdout=stdout, stderr=stderr)
            identities[process.pid] = identity(process.pid)
            deadline = time.monotonic() + 130
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError('launcher exited before live fixture: ' + (root / 'stderr').read_text())
                text = (root / 'stdout').read_text()
                if 'READY' in text and text.count('DETACHED') == 6:
                    break
                time.sleep(.05)
            else:
                raise TimeoutError('fixture readiness timeout')
            report = json.loads((out / 'attempt.json').read_text())
            # Homebrew's Python launcher execs Python.app after Popen. Capture
            # the settled command identity once our live fixture is running.
            identities[process.pid] = identity(process.pid)
            helper = report['helper_pid']
            identities[helper] = identity(helper)
            custodian = report.get('custodian_pid')
            if custodian:
                identities[custodian] = identity(custodian)
            service = owned_service(out / 'guest.raw')
            identities[service] = identity(service)
            result.update(launcher_pid=process.pid, helper_pid=helper, custodian_pid=custodian, service_pid=service,
                          identities={str(k): v for k, v in identities.items()}, detached_children=6)
            started = time.monotonic()
            if case == 'cancel':
                safe_signal(process.pid, identities[process.pid], signal.SIGINT)
            elif case in ('launcher_kill', 'launcher_stop'):
                safe_signal(process.pid, identities[process.pid], signal.SIGKILL if case.endswith('kill') else signal.SIGSTOP)
            elif case in ('helper_kill', 'helper_stop'):
                safe_signal(helper, identities[helper], signal.SIGKILL if case.endswith('kill') else signal.SIGSTOP)
            elif case in ('custodian_kill', 'custodian_stop'):
                safe_signal(custodian, identities[custodian], signal.SIGKILL if case.endswith('kill') else signal.SIGSTOP)
            elif case.startswith('custodian_') and case.endswith('_pair'):
                safe_signal(custodian, identities[custodian], signal.SIGSTOP)
                pid = helper if case == 'custodian_helper_pair' else process.pid
                safe_signal(pid, identities[pid], signal.SIGSTOP)
            elif case in ('both_kill', 'both_stop'):
                # Stage both as stopped first: otherwise killing the launcher
                # can tear down its helper before the second fault is injected.
                safe_signal(process.pid, identities[process.pid], signal.SIGSTOP)
                safe_signal(helper, identities[helper], signal.SIGSTOP)
                if case == 'both_kill':
                    safe_signal(helper, identities[helper], signal.SIGKILL)
                    safe_signal(process.pid, identities[process.pid], signal.SIGKILL)
            elif case == 'service_kill':
                safe_signal(service, identities[service], signal.SIGKILL)
            elif case == 'service_stop':
                safe_signal(service, identities[service], signal.SIGSTOP)
                time.sleep(4)
                result['service_present_while_stopped'] = identity(service) == identities[service]
                # Resumption is fault recovery, not cleanup. The expired guest
                # lease must shut down, or the host must have already stopped it.
                if identity(service) == identities[service]:
                    safe_signal(service, identities[service], signal.SIGCONT)
                result['service_resumed_after_seconds'] = time.monotonic() - started
            elif case != 'wall':
                raise ValueError(case)
            deadline = started + (12 if case == 'wall' else 8)
            while time.monotonic() < deadline and identity(service) == identities[service]:
                time.sleep(.05)
            result['service_gone_before_cleanup'] = identity(service) != identities[service]
            result['service_gone_seconds'] = time.monotonic() - started if result['service_gone_before_cleanup'] else None
            result['console_before_cleanup'] = (out / 'console.log').read_text(errors='replace')
            result['guest_tree_empty_before_cleanup'] = any(
                line.startswith('OURO_VM ') and json.loads(line[len('OURO_VM '):]).get('event') == 'workload_tree_empty'
                for line in result['console_before_cleanup'].splitlines())
            result['stdout_before_cleanup'] = (root / 'stdout').read_text(errors='replace')
            if case == 'both_stop' and not result['service_gone_before_cleanup']:
                # Record recovery separately; never count it as autonomous
                # teardown while both host controllers were suspended.
                resumed = time.monotonic()
                for pid in (helper, process.pid):
                    safe_signal(pid, identities[pid], signal.SIGCONT)
                while time.monotonic() - resumed < 3 and identity(service) == identities[service]:
                    time.sleep(.05)
                result['service_gone_after_host_resume'] = identity(service) != identities[service]
                result['host_resume_cleanup_seconds'] = time.monotonic() - resumed
            if not result['service_gone_before_cleanup']:
                raise RuntimeError('VM service survived the fault deadline')
            if case == 'wall':
                process.wait(timeout=5)
                receipt = json.loads((out / 'evidence' / 'jail.json').read_text())
                result['guest_lifetime'] = receipt['lifetime']
                if receipt['lifetime']['integrity'] != 'verified' or receipt['lifetime']['tree_empty'] is not True:
                    raise RuntimeError('wall cleanup was not verified')
            result['status'] = 'passed'
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        result['error'] = str(error)
    finally:
        # This is explicitly after the measured verdict, never counted as proof.
        killed = []
        for pid in [helper, custodian, process.pid if process else None, service]:
            if pid and identities.get(pid) and identity(pid) == identities[pid]:
                try:
                    os.kill(pid, signal.SIGKILL)
                    killed.append(pid)
                except ProcessLookupError:
                    pass
        if process:
            process.wait(timeout=10)
        result['emergency_killed_pids'] = killed
        result['emergency_cleanup_used'] = service in killed
        result['service_absent_after_cleanup'] = service is None or identity(service) != identities.get(service)
        if result['service_absent_after_cleanup']:
            (out / 'guest.raw').unlink(missing_ok=True)
        (root / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--executable', type=Path, help='test an installed ouro-vm instead of the source launcher')
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--repeat', type=int, default=1)
    parser.add_argument('--cases', nargs='+', default=['wall', 'cancel', 'launcher_kill', 'launcher_stop',
                                                     'helper_kill', 'helper_stop', 'both_kill', 'service_kill', 'service_stop', 'both_stop',
                                                     'custodian_kill', 'custodian_stop', 'custodian_helper_pair', 'custodian_launcher_pair'])
    args = parser.parse_args()
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    provenance = {'image': json.loads((args.image / 'image.json').read_text()),
                  'runner_sha256': {name: hashlib.sha256((SOURCE / name).read_bytes()).hexdigest()
                                    for name in ('run.py', 'guest.py', 'check.py')},
                  'requested_cases': args.cases, 'repeat': args.repeat}
    if args.executable:
        provenance['packaged_executable'] = str(args.executable.resolve())
        provenance['packaged_executable_sha256'] = hashlib.sha256(args.executable.read_bytes()).hexdigest()
    (root / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    results = []
    for number in range(args.repeat):
        for case in args.cases:
            result = trial(root / f'{number:02d}-{case}', args.image.resolve(), case, args.executable.resolve() if args.executable else None)
            results.append(result)
            print(json.dumps({k: result.get(k) for k in ('case', 'status', 'service_gone_seconds', 'error')}), flush=True)
            (root / 'summary.json').write_text(json.dumps({'schema': 'ouro.vm.fault-check/1', 'results': results,
                                                          'passed': all(r['status'] == 'passed' for r in results)}, indent=2) + '\n')
            if result['status'] != 'passed':
                return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

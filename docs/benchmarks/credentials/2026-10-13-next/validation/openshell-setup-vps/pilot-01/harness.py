#!/usr/bin/env python3
"""Prepare an owned native OpenShell 0.1.3 Docker gateway with verified mTLS.

Use vendor certificate generation and a separate HOME/XDG store. Raw setup logs,
PKI, signing keys, database and client state remain private; export only the
nonsecret setup report. Leave the verified gateway live for subsequent fixtures.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    root.mkdir(mode=0o700)
    private, output = root / 'private', root / 'results'
    private.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    name = 'bench-credentials-20261013'
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(private / 'home'),
           'XDG_CONFIG_HOME': str(private / 'config'), 'XDG_STATE_HOME': str(private / 'state'),
           'OPENSHELL_LOCAL_TLS_DIR': str(private / 'tls'), 'OPENSHELL_COLOR': 'never',
           'LANG': 'C.UTF-8'}
    for path in (private / 'home', private / 'config', private / 'state'):
        path.mkdir(mode=0o700)
    commands = []

    def run(label, argv):
        result = subprocess.run(argv, env=env, capture_output=True, timeout=45)
        for suffix, content in [('stdout', result.stdout), ('stderr', result.stderr)]:
            path = private / (label + '.' + suffix)
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as file:
                file.write(content)
        commands.append({'label': label, 'argv': argv, 'exit': result.returncode,
                         'raw_logs_retained_privately': True})
        assert result.returncode == 0, label + ' failed; inspect private logs without publishing keys'
        return result

    gateway = None
    ready = False
    report = {'schema': 'owned-openshell-mtls-setup/1', 'provider_fixture_executed': False,
              'private_material_exported': False, 'name': name, 'port': port,
              'endpoint': f'https://127.0.0.1:{port}', 'gateway_tls_verification_disabled': False,
              'compute_driver': 'docker', 'separate_home_and_xdg_state': True}
    try:
        version = run('version', ['/usr/bin/openshell', '--version']).stdout.decode().strip()
        assert version == 'openshell 0.1.3'
        report['version'] = version
        run('generate-certs', ['/usr/bin/openshell-gateway', 'generate-certs',
                               '--output-dir', str(private / 'tls'), '--server-san', '127.0.0.1'])
        argv = ['/usr/bin/openshell-gateway', '--name', name, '--bind-address', '127.0.0.1',
                '--port', str(port), '--compute-driver', 'docker', '--enable-mtls-auth', 'true']
        run('config-preflight', argv + ['config', 'preflight'])
        path = private / 'gateway.log'
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as log:
            gateway = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        report['gateway_pid'] = gateway.pid
        report['gateway_birth'] = Path(f'/proc/{gateway.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            assert gateway.poll() is None, 'gateway terminated; inspect private startup log'
            listing = subprocess.check_output(['ss', '-H', '-ltnp', f'sport = :{port}'], text=True)
            if f'pid={gateway.pid},' in listing:
                break
            time.sleep(.1)
        else:
            raise RuntimeError('owned gateway listener readiness expired')
        run('register', ['/usr/bin/openshell', 'gateway', 'add', report['endpoint'],
                         '--name', name, '--local'])
        run('status', ['/usr/bin/openshell', '--gateway', name, 'status', '--output', 'json'])
        ready = True
        report['live_listener_and_authenticated_status_verified'] = True
        report['gateway_environment'] = env
        report['gateway_argv'] = argv
        report['binary_sha256'] = {name: hashlib.file_digest(Path('/usr/bin', name).open('rb'),
                                                           'sha256').hexdigest()
                                   for name in ['openshell', 'openshell-gateway']}
    except (OSError, ValueError, AssertionError, RuntimeError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
    finally:
        if gateway is not None and not ready and gateway.poll() is None:
            gateway.terminate()
            try:
                gateway.wait(timeout=10)
            except subprocess.TimeoutExpired:
                gateway.kill()
                gateway.wait(timeout=10)
        report['commands'] = commands
        report['status'] = 'ready' if ready else 'failed'
        (output / 'setup.json').write_text(json.dumps(report, indent=2) + '\n')
        (output / 'harness.py').write_bytes(Path(__file__).read_bytes())
        print(json.dumps({'status': report['status'], 'error': report.get('error'),
                          'gateway_pid': report.get('gateway_pid'),
                          'provider_fixture_executed': False}), flush=True)
    return int(not ready)


if __name__ == '__main__':
    raise SystemExit(main())

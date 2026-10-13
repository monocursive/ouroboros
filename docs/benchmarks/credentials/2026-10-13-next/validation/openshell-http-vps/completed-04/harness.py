#!/usr/bin/env python3
"""Same HTTP actor/oracle through ordinary OpenShell provider controls.

Gateway PKI/state and raw operator responses stay private. Only fixture v1/v2
credentials are used. This is a feature diagnostic, not performance or TLS/WSS
provider proof. Use a new root for every retained attempt.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import threading
import time


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def sha(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--setup-root', type=Path, required=True)
    parser.add_argument('--resource-host', required=True)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt('fixture interrupted; run owned sandbox cleanup')
    signal.signal(signal.SIGTERM, interrupted)
    root = args.root.resolve()
    root.mkdir(mode=0o700)
    output, private = root / 'results', root / 'private'
    output.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    setup = json.loads((args.setup_root / 'results/setup.json').read_text())
    assert setup['status'] == 'ready' and not setup['gateway_tls_verification_disabled']
    gateway_pid = setup['gateway_pid']
    assert Path(f'/proc/{gateway_pid}/stat').read_text().rsplit(')', 1)[1].split()[19] == setup['gateway_birth']
    env = setup['gateway_environment']
    name = 'matched-http-' + root.name.rsplit('-', 1)[-1]
    prefix = ['/usr/bin/openshell', '--gateway', setup['name']]
    actor = Path(__file__).with_name('credential_actor.py')
    shutil.copyfile(actor, output / 'actor.py')
    shutil.copyfile(Path(__file__), output / 'harness.py')
    controls, received, checks = [], [], []
    context = {'mode': 'openshell', 'stream_stop': threading.Event(),
               'stream_started': threading.Event()}
    server = None
    profile_created = provider_created = sandbox_created = False
    sequence = 0
    status = 'incomplete'
    observation_completed = False
    marker = None
    actor_cli = None

    # This handler is byte-identical to the common Pi harness's resource oracle.
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            run = context.copy()
            value = self.headers.get('x-api-key')
            row = {'mode': run['mode'], 'path': self.path,
                   'v1': value == 'fixture-v1', 'v2': value == 'fixture-v2',
                   'opaque_handle': bool(value and value.startswith(('vault:', 'greyproxy:'))),
                   'client_pid_claim': self.headers.get('x-fixture-client'), 'unix': time.time()}
            received.append(row)
            self.send_response(200)
            self.send_header('Connection', 'close')
            self.send_header('Content-Type', 'text/event-stream' if self.path == '/v1/stream'
                             else 'text/plain')
            self.end_headers()
            try:
                if self.path != '/v1/stream':
                    self.wfile.write(b'fixture-ok\n')
                    return
                run['stream_started'].set()
                while not run['stream_stop'].wait(.05):
                    self.wfile.write(b'data: fixture\n\n')
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                row['client_disconnected_unix'] = time.time()
            finally:
                if self.path == '/v1/stream':
                    row['oracle_stream_cleanup_unix'] = time.time()

        def log_message(self, *_):
            pass

    def cli(label, argv, extra_env=None, timeout=60, require=True):
        nonlocal sequence
        sequence += 1
        actual = prefix + argv
        started = time.time()
        result = subprocess.run(actual, env=dict(env, **(extra_env or {})),
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        for suffix, content in [('stdout', result.stdout), ('stderr', result.stderr)]:
            path = private / f'{sequence:03}-{label}.{suffix}'
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, 'wb') as file:
                file.write(content)
        controls.append({'label': label, 'argv': actual, 'exit': result.returncode,
                         'started_unix': started, 'finished_unix': time.time(),
                         'stdout_bytes': len(result.stdout), 'stderr_bytes': len(result.stderr),
                         'raw_response_retained_privately': True})
        assert not require or result.returncode == 0, label + ' failed; raw response retained privately'
        return result

    def remote(label, code, timeout=45, require=True):
        return cli(label, ['sandbox', 'exec', name, '--workdir', '/work', '--no-tty',
                           '--no-login-shell', '--timeout', str(timeout), '--',
                           '/usr/bin/python3', '-c', code], timeout=timeout + 15, require=require)

    def wait_file(filename, seconds=30):
        code = ('from pathlib import Path;import time\n'
                f'p=Path({filename!r});deadline=time.monotonic()+{seconds}\n'
                'while not p.exists():\n'
                ' if time.monotonic()>deadline:raise RuntimeError("barrier expired")\n'
                ' time.sleep(.02)\n')
        remote('wait-' + filename, code, timeout=seconds + 5)

    def touch(filename):
        remote('touch-' + filename, f'from pathlib import Path;Path({filename!r}).touch()')

    def read_file(filename):
        return remote('read-' + filename,
                      f'from pathlib import Path;print(Path({filename!r}).read_text(),end="")').stdout

    def alive_actor():
        code = ('from pathlib import Path;import json,os\n'
                'p=json.loads(Path("client-identity.json").read_text())["pid"]\n'
                'os.kill(p,0)\n'
                'assert not Path("client-final.json").exists()\n'
                'print(p)\n')
        return remote('verify-persistent-actor', code)

    def scrub_log(data):
        # Gateway-issued tokens can occur in diagnostic responses. Preserve raw
        # logs privately; never export JWTs, PEM material or opaque handles.
        text = data.decode(errors='replace')
        text = re.sub(r'eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}',
                      '[REDACTED-JWT]', text)
        text = re.sub(r'-----BEGIN .*?PRIVATE KEY-----.*?-----END .*?PRIVATE KEY-----',
                      '[REDACTED-PRIVATE-KEY]', text, flags=re.S)
        if marker:
            text = text.replace(marker, '[OPAQUE-FIXTURE-HANDLE]')
        return text

    try:
        server = http.server.ThreadingHTTPServer((args.resource_host, 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_port
        origin = 'http://' + args.resource_host + ':' + str(port)
        image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', args.image]))[0]
        assert image['Config'].get('User') == 'ubuntu:ubuntu'
        assert image['Config'].get('WorkingDir') == '/work'
        save(output / 'metadata.json', {
            'schema': 'matched-openshell-http-lifecycle/1', 'only_synthetic_tokens': True,
            'scored_performance': False, 'tls_wss_provider_proof': False,
            'host': platform.uname()._asdict(), 'origin': origin,
            'actor_sha256': sha(actor), 'harness_sha256': sha(Path(__file__)),
            'version': setup['version'], 'gateway_tls_verification_disabled': False,
            'authorized_executable': '/usr/bin/python3.12', 'authorized_path_pattern': '/v1/**',
            'revocation_window_seconds': 3, 'late_check_after_revoke_seconds': 70,
            'image': args.image, 'image_id': image['Id'], 'workdir': '/work',
            'process_identity': 'ubuntu:ubuntu', 'actor_exec_timeout_seconds': 240,
            'policy_uid_gid': '1000:1000',
            'canonical_keepalive_seconds': 300,
            'landlock_compatibility': 'best_effort', 'native_gateway': True,
            'same_host_as_pi_cohort': False,
            'binary_sha256': setup['binary_sha256'],
        })
        profile = (f'id: {name}\ndisplay_name: Matched HTTP credential fixture\ncategory: other\n'
                   'credentials:\n  - name: api_key\n    env_vars: [BENCH_API_KEY]\n'
                   '    required: true\n    auth_style: header\n    header_name: x-api-key\n'
                   f'endpoints:\n  - host: {args.resource_host}\n    port: {port}\n'
                   '    path: /v1/**\n    protocol: rest\n    access: read-write\n'
                   f'    enforcement: enforce\n    allowed_ips: [{args.resource_host}/32]\n'
                   'binaries: [/usr/bin/python3.12]\n')
        policy = ('version: 1\nfilesystem_policy:\n  include_workdir: true\n'
                  '  read_only: [/usr, /lib, /proc, /etc, /dev/urandom]\n'
                  '  read_write: [/work, /tmp, /dev/null]\nlandlock:\n'
                  '  compatibility: best_effort\nprocess:\n  run_as_user: "1000"\n'
                  '  run_as_group: "1000"\nnetwork_policies: {}\n')
        (output / 'provider-profile.yaml').write_text(profile)
        (output / 'sandbox-policy.yaml').write_text(policy)
        cli('profile-import', ['profile', 'import', '--file', str(output / 'provider-profile.yaml')])
        profile_created = True
        imported = cli('profile-export', ['profile', 'export', name, '--output', 'json'])
        save(output / 'imported-profile.json', json.loads(imported.stdout))
        cli('provider-create', ['provider', 'create', '--name', name, '--type', name,
                                '--credential', 'BENCH_API_KEY'], {'BENCH_API_KEY': 'fixture-v1'})
        provider_created = True
        cli('sandbox-create', ['sandbox', 'create', '--name', name, '--from', args.image,
                              '--provider', name, '--policy', str(output / 'sandbox-policy.yaml'),
                              '--detach', '--no-tty', '--output', 'json', '--',
                              '/usr/bin/sleep', '300'], timeout=150)
        sandbox_created = True
        cli('actor-upload', ['sandbox', 'upload', name, str(actor), '/work/actor.py',
                             '--no-git-ignore'])
        actor_argv = prefix + ['sandbox', 'exec', name, '--workdir', '/work', '--no-tty',
                              '--no-login-shell', '--timeout', '240', '--',
                              '/usr/bin/python3', '/work/actor.py', '--origin', origin]
        with (private / 'actor.stdout').open('wb') as out, (private / 'actor.stderr').open('wb') as err:
            os.chmod(private / 'actor.stdout', 0o600)
            os.chmod(private / 'actor.stderr', 0o600)
            actor_cli = subprocess.Popen(actor_argv, env=env, stdin=subprocess.DEVNULL,
                                         stdout=out, stderr=err)
        controls.append({'label': 'persistent-actor-exec', 'argv': actor_argv,
                         'started_unix': time.time(), 'raw_response_retained_privately': True})
        wait_file('rotation-ready')
        assert any(row['path'] == '/v1/allowed' and row['v1'] for row in received), \
            'positive baseline authentication is mandatory'
        marker = read_file('marker.txt').decode()
        effective = cli('effective-policy', ['sandbox', 'get', name, '--policy-only'])
        (output / 'effective-policy.redacted.yaml').write_text(scrub_log(effective.stdout))
        container_ids = subprocess.check_output(['docker', 'ps', '-q', '--filter',
                                               'label=openshell.ai/sandbox-name=' + name], text=True).split()
        assert len(container_ids) == 2, 'expected owned workload and supervisor containers'
        containers = json.loads(subprocess.check_output(['docker', 'inspect', *container_ids]))
        save(output / 'container-fences.json', [{
            'id': c['Id'], 'name': c['Name'], 'running': c['State']['Running'],
            'user': c['Config'].get('User'), 'image': c['Image'],
            'sandbox_name_label': c['Config']['Labels'].get('openshell.ai/sandbox-name'),
            'host_config': {k: c['HostConfig'].get(k) for k in
                            ['NetworkMode', 'CapDrop', 'CapAdd', 'SecurityOpt', 'PidsLimit',
                             'ReadonlyRootfs', 'Memory', 'NanoCpus']},
            'mount_destinations': [m['Destination'] for m in c['Mounts']],
            'environment_or_private_material_exported': False,
        } for c in containers])
        cli('provider-update', ['provider', 'update', name, '--credential', 'BENCH_API_KEY',
                                '--wait', '--timeout', '30', '--output', 'json'],
            {'BENCH_API_KEY': 'fixture-v2'})
        touch('rotated')
        wait_file('rotated-ready')
        wait_file('stream-ready', seconds=70)
        assert context['stream_started'].is_set()
        stream_before = json.loads(read_file('client-stream.json'))
        assert stream_before['ready'] and 'finished_unix' not in stream_before
        alive_actor()
        revocation_started = time.time()
        cli('provider-detach', ['sandbox', 'provider', 'detach', name, name,
                                '--wait', '--timeout', '30', '--output', 'json'])
        revoked = time.time()
        touch('revoked')
        observe_until = revoked + 3
        while time.time() < observe_until:
            time.sleep(min(.02, max(0, observe_until - time.time())))
        alive_actor()
        observation_completed = True
        stream = json.loads(read_file('client-stream.json'))
        checks.append({'case': 'active-sse-closes-after-revoke', 'supported': True,
                       'pass': revocation_started <= stream.get('finished_unix', float('inf')) <= observe_until,
                       'revocation_started_unix': revocation_started,
                       'revoked_unix': revoked, 'observation_deadline_unix': observe_until,
                       'client_stream': stream})
        while time.time() < revoked + 70:
            time.sleep(min(.1, max(0, revoked + 70 - time.time())))
        alive_actor()
        touch('late-revocation-check')
        wait_file('late-revocation-ready')
        context['stream_stop'].set()
        touch('finish')
        wait_file('client-final.json', seconds=20)
        actor_exit = actor_cli.wait(timeout=20)
        identity = json.loads(read_file('client-identity.json'))
        client_rows = json.loads(read_file('client-requests.json'))
        final = json.loads(read_file('client-final.json'))
        by_path = {row['path']: row for row in received}
        for case, path, version in [('valid', '/v1/allowed', 'v1'),
                                    ('same-live-client-rotation', '/v1/rotated', 'v2'),
                                    ('wrong-path-no-secret', '/outside', None),
                                    ('escaped-path-no-secret', '/v1/%2e%2e/outside', None),
                                    ('wrong-executable-no-secret', '/v1/wrong-process', None),
                                    ('new-request-after-revoke', '/v1/after-revoke', None),
                                    ('revoke-survives-heartbeat', '/v1/late-after-revoke', None)]:
            observed = by_path.get(path)
            sent = next(row for row in client_rows if row['path'] == path)
            passed = bool(observed and observed[version]) if version else \
                not observed or not (observed['v1'] or observed['v2'])
            checks.append({'case': case, 'pass': passed, 'supported': True,
                           'client_request': sent, 'resource_observation': observed})
        checks.append({'case': 'same-application-process-remains-live', 'supported': True,
                       'pass': actor_exit == 0 and final['pid'] == identity['pid'] and all(
                           row['client_pid'] == identity['pid'] for row in client_rows),
                       'identity': identity, 'wrapper_exit': actor_exit})
        checks.append({'case': 'raw-secret-absent-child-handle', 'supported': True,
                       'pass': marker not in ('fixture-v1', 'fixture-v2')})
        status = 'completed'
    except (OSError, ValueError, AssertionError, RuntimeError, subprocess.SubprocessError) as error:
        save(output / 'failure.json', {'error': str(error), 'retained_attempt': True})
    finally:
        context['stream_stop'].set()
        def cleanup_cli(label, argv):
            try:
                return cli(label, argv, require=False)
            except (OSError, subprocess.SubprocessError) as error:
                controls.append({'label': label, 'cleanup_error_class': type(error).__name__})
                return None
        if sandbox_created:
            for filename in ['client-identity.json', 'client-requests.json', 'client-stream.json',
                             'client-final.json']:
                try:
                    result = remote('collect-' + filename,
                                    f'from pathlib import Path;p=Path({filename!r});'
                                    'print(p.read_text() if p.exists() else "null",end="")', require=False)
                except (OSError, subprocess.SubprocessError) as error:
                    controls.append({'label': 'collect-' + filename,
                                     'cleanup_error_class': type(error).__name__})
                    result = None
                if result is not None and result.returncode == 0:
                    try:
                        value = json.loads(result.stdout)
                        if value is not None:
                            save(output / filename, value)
                    except ValueError:
                        pass
            log = cleanup_cli('product-logs', ['logs', name, '-n', '1000'])
            if log is not None:
                (output / 'product-logs.redacted.txt').write_text(scrub_log(log.stdout + log.stderr))
            cleanup_cli('sandbox-delete', ['sandbox', 'delete', name])
        else:
            # A failed create can still have registered resources. Delete only
            # this unique owned name, never every sandbox in the gateway.
            cleanup_cli('sandbox-delete-partial', ['sandbox', 'delete', name])
        if actor_cli is not None and actor_cli.poll() is None:
            actor_cli.terminate()
            try:
                actor_cli.wait(timeout=10)
            except subprocess.TimeoutExpired:
                actor_cli.kill()
                actor_cli.wait(timeout=10)
        if provider_created:
            cleanup_cli('provider-delete-cleanup', ['provider', 'delete', name])
        if profile_created:
            cleanup_cli('profile-delete', ['profile', 'delete', name])
        if server is not None:
            server.shutdown()
            server.server_close()
        save(output / 'operator-controls.json', controls)
        save(output / 'resource-oracle.json', received)
        result = {'mode': 'openshell', 'status': status, 'checks': checks,
                  'resource_observations': received,
                  'live_stream_oracle_ended_only_after_fixed_observation': observation_completed,
                  'child_handle_raw_secret': marker in ('fixture-v1', 'fixture-v2'),
                  'raw_private_material_exported': False}
        save(output / 'result.json', result)
        print(json.dumps({'status': status, 'passed_supported': sum(c['pass'] for c in checks),
                          'supported': len(checks)}), flush=True)
    return int(status != 'completed')


if __name__ == '__main__':
    raise SystemExit(main())

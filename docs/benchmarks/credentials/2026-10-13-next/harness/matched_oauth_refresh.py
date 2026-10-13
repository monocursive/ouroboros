#!/usr/bin/env python3
"""Native managed OAuth refresh through an identical persistent client/issuer.

This is a real-clock synthetic feature fixture, never real-provider expiry or a
performance score. No rotation command, forged expiry, shared custom broker or
client-owned refresh is used. Every attempt requires a fresh private root.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import time
import uuid

from oauth_fixture import Issuer, servers


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def sha(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--mode', choices=['ouro', 'openshell'], required=True)
    p.add_argument('--resource-host', required=True)
    p.add_argument('--ouro', type=Path)
    p.add_argument('--setup-root', type=Path)
    p.add_argument('--image', default='bench-openshell-http:20261013')
    p.add_argument('--seconds', type=int, default=540)
    p.add_argument('--lifetime', type=int, default=180)
    p.add_argument('--margin', type=int, default=75)
    p.add_argument('--lose-generation', type=int)
    a = p.parse_args()
    assert a.lifetime >= 180 and 60 < a.margin < a.lifetime
    assert a.seconds >= 540, 'observe multiple actual expiry/rotation cycles'
    os.umask(0o077)
    root = a.root.resolve()
    root.mkdir(mode=0o700)
    output, private, work = (root / n for n in ['results', 'private', 'work'])
    for path in (output, private, work):
        path.mkdir(mode=0o700)
    actor = Path(__file__).with_name('oauth_actor.py')
    for source in [Path(__file__), actor, Path(__file__).with_name('oauth_fixture.py')]:
        shutil.copyfile(source, output / source.name)
    nonce = uuid.uuid4().hex
    state = Issuer(nonce, a.lifetime, a.lose_generation)
    resource, issuer = servers(state, a.resource_host)
    origin = f'http://{a.resource_host}:{resource.server_port}'
    token_url = f'http://127.0.0.1:{issuer.server_port}/token'
    initial = state.initial()
    source = private / 'token.json'
    save(source, initial)
    controls = []
    process = None
    profile_created = provider_created = sandbox_created = False
    name = 'matched-oauth-' + nonce[:12]
    setup = env = prefix = None
    status = 'incomplete'
    blocker = None
    sequence = 0
    image_info = None

    def cli(label, argv, extra_env=None, timeout=90, require=True):
        nonlocal sequence
        sequence += 1
        actual = prefix + argv
        began = time.time()
        run = subprocess.run(actual, env=dict(env, **(extra_env or {})),
                             stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        for suffix, content in [('stdout', run.stdout), ('stderr', run.stderr)]:
            (private / f'{sequence:03}-{label}.{suffix}').write_bytes(content)
        controls.append({'label': label, 'argv': actual, 'exit': run.returncode,
                         'started_unix': began, 'finished_unix': time.time(),
                         'raw_response_retained_privately': True})
        assert not require or run.returncode == 0, label + ' failed; private response retained'
        return run

    def remote_read(filename):
        code = f'from pathlib import Path;print(Path({filename!r}).read_text(),end="")'
        run = cli('read-' + filename, ['sandbox', 'exec', name, '--workdir', '/work',
                                  '--no-tty', '--no-login-shell', '--timeout', '30', '--',
                                  '/usr/bin/python3', '-c', code], timeout=45)
        return json.loads(run.stdout)

    def interrupted(_signal, _frame):
        raise KeyboardInterrupt('owned fixture interrupted')

    signal.signal(signal.SIGTERM, interrupted)
    try:
        if a.mode == 'ouro':
            assert a.ouro is not None
            home, config = private / 'home', private / 'config/launch'
            home.mkdir()
            config.mkdir(parents=True)
            python = str(Path('/usr/bin/python3').resolve())
            profile = ('name="fixture"\njail="agent"\nhome_is_state=true\n'
                       '[credentials.api]\nmode="vault"\nsource=' + json.dumps(str(source))
                       + '\nhosts=' + json.dumps([origin]) + '\npaths=["/v1/"]\nbinaries='
                       + json.dumps([python]) + '\nallow_plaintext=true\n'
                       'header={name="authorization",prefix="Bearer "}\n'
                       'refresh={token_url=' + json.dumps(token_url)
                       + ',client_id="fixture-client",refresh_before_seconds='
                       + str(a.margin) + ',encoding="form"}\n[network]\nallow='
                       + json.dumps([a.resource_host + ':' + str(resource.server_port)]) + '\n')
            (config / 'fixture.toml').write_text(profile)
            (output / 'launch.toml').write_text(profile)
            shutil.copyfile(actor, work / 'actor.py')
            env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(home),
                   'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                   'OURO_CONFIG_DIR': str(config.parent), 'OURO_DATA_DIR': str(private / 'data'),
                   'XDG_RUNTIME_DIR': '/run/user/' + str(os.getuid()),
                   'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/' + str(os.getuid()) + '/bus'}
            actor_argv = [str(a.ouro.resolve()), 'run', '--launch', 'fixture',
                          '--workspace', str(work), '--observe', 'on', '--evidence', 'strict',
                          '--limit', 'wall=' + str(a.seconds + 120) + 's',
                          '--receipt', str(output / 'jail.json'), '--', python,
                          str(work / 'actor.py'), '--origin', origin, '--nonce', nonce,
                          '--seconds', str(a.seconds)]
            product_version = json.loads(subprocess.check_output([str(a.ouro), 'version', '--json']))
        else:
            assert a.setup_root is not None
            setup = json.loads((a.setup_root / 'results/setup.json').read_text())
            assert setup['status'] == 'ready' and not setup['gateway_tls_verification_disabled']
            stat = Path(f'/proc/{setup["gateway_pid"]}/stat').read_text()
            assert stat.rsplit(')', 1)[1].split()[19] == setup['gateway_birth']
            env = setup['gateway_environment']
            prefix = ['/usr/bin/openshell', '--gateway', setup['name']]
            image_info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', a.image]))[0]
            assert image_info['Config']['User'] == 'ubuntu:ubuntu'
            profile = (f'id: {name}\ndisplay_name: Matched OAuth refresh\ncategory: other\n'
                       'credentials:\n  - name: access_token\n    env_vars: [BENCH_API_KEY]\n'
                       '    required: true\n    auth_style: bearer\n    header_name: authorization\n'
                       '    refresh:\n      strategy: oauth2_refresh_token\n'
                       f'      token_url: {token_url}\n      refresh_before_seconds: {a.margin}\n'
                       f'      max_lifetime_seconds: {a.lifetime}\n      material:\n'
                       '        - name: client_id\n          required: true\n'
                       '        - name: refresh_token\n          required: true\n          secret: true\n'
                       f'endpoints:\n  - host: {a.resource_host}\n    port: {resource.server_port}\n'
                       '    path: /v1/**\n    protocol: rest\n    access: read-write\n'
                       f'    enforcement: enforce\n    allowed_ips: [{a.resource_host}/32]\n'
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
            cli('provider-create', ['provider', 'create', '--name', name, '--type', name,
                                    '--credential', 'BENCH_API_KEY'],
                {'BENCH_API_KEY': initial['access_token']})
            provider_created = True
            cli('refresh-configure', ['provider', 'refresh', 'configure', name,
                '--credential-key', 'BENCH_API_KEY', '--strategy', 'oauth2-refresh-token',
                '--material', 'client_id=fixture-client', '--secret-material-env',
                'refresh_token=BENCH_REFRESH_TOKEN', '--credential-expires-at',
                str(initial['expires_at'] * 1000)], {'BENCH_REFRESH_TOKEN': initial['refresh_token']})
            cli('sandbox-create', ['sandbox', 'create', '--name', name, '--from', a.image,
                '--provider', name, '--policy', str(output / 'sandbox-policy.yaml'),
                '--detach', '--no-tty', '--output', 'json', '--',
                '/usr/bin/sleep', str(a.seconds + 180)], timeout=150)
            sandbox_created = True
            cli('actor-upload', ['sandbox', 'upload', name, str(actor), '/work/actor.py',
                                  '--no-git-ignore'])
            actor_argv = prefix + ['sandbox', 'exec', name, '--workdir', '/work', '--no-tty',
                '--no-login-shell', '--timeout', str(a.seconds + 120), '--',
                '/usr/bin/python3', '/work/actor.py', '--origin', origin, '--nonce', nonce,
                '--seconds', str(a.seconds)]
            product_version = setup['version']
        save(output / 'metadata.json', {
            'schema': 'matched-native-oauth-refresh/1', 'mode': a.mode,
            'synthetic_issuer': True, 'real_provider_expiry_proof': False,
            'scored_performance': False, 'host': platform.uname()._asdict(),
            'actor_sha256': sha(actor), 'issuer_sha256': sha(Path(__file__).with_name('oauth_fixture.py')),
            'harness_sha256': sha(Path(__file__)), 'origin': origin, 'token_url': token_url,
            'lifetime_seconds': a.lifetime, 'refresh_before_seconds': a.margin,
            'actor_seconds': a.seconds, 'initial_expiry_unix': initial['expires_at'],
            'lost_response_generation': a.lose_generation, 'manual_rotation_calls': 0,
            'real_clock_modified': False, 'forced_expiry_metadata': False,
            'product_version': product_version,
            'image_id': image_info['Id'] if image_info else None,
            'gateway_tls_verification_disabled': False,
            'token_transport': 'loopback HTTP, supported synthetic issuer fixture',
            'resource_transport': 'HTTP synthetic fixture; TLS/WebSocket proof remains separate'})
        with (private / 'actor.stdout').open('wb') as out, (private / 'actor.stderr').open('wb') as err:
            process = subprocess.Popen(actor_argv, cwd=work if a.mode == 'ouro' else None,
                                       env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        controls.append({'label': 'persistent-actor', 'argv': actor_argv,
                         'started_unix': time.time(), 'launcher_pid': process.pid})
        deadline = time.monotonic() + a.seconds + 140
        while process.poll() is None and time.monotonic() < deadline:
            save(output / 'oracle.json', state.snapshot())
            save(output / 'running.json', {'status': 'running', 'launcher_pid': process.pid,
                                           'issuer_generation': state.snapshot()['generation'],
                                           'captured_unix': time.time()})
            time.sleep(1)
        assert process.poll() is not None, 'actor exceeded common fixture deadline'
        assert process.returncode == 0, 'actor exited nonzero; private response retained'
        for filename in ['oauth-client-identity.json', 'oauth-client-requests.json', 'oauth-client-final.json']:
            value = json.loads((work / filename).read_text()) if a.mode == 'ouro' else remote_read(filename)
            save(output / filename, value)
        if a.mode == 'ouro':
            receipt = json.loads((output / 'jail.json').read_text())
            attempt = private / 'data/attempts' / receipt['attempt_id']
            for filename in ['policy.json', 'trace.ndjson']:
                shutil.copyfile(attempt / filename, output / filename)
        status = 'completed'
    except (OSError, ValueError, AssertionError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        blocker = str(error)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        if a.mode == 'openshell' and prefix is not None:
            for enabled, label, command in [
                (sandbox_created, 'sandbox-delete', ['sandbox', 'delete', name]),
                (provider_created, 'provider-delete', ['provider', 'delete', name]),
                (profile_created, 'profile-delete', ['profile', 'delete', name])]:
                if enabled:
                    try:
                        cli(label, command, require=False)
                    except (OSError, subprocess.SubprocessError):
                        controls.append({'label': label, 'exit': None, 'cleanup_error': True})
        save(output / 'oracle.json', state.snapshot())
        save(output / 'controls.json', controls)
        save(output / 'result.json', {'schema': 'matched-native-oauth-refresh/1',
             'status': status, 'blocker': blocker, 'actor_exit': process.returncode if process else None,
             'only_synthetic_tokens': True, 'actual_credential_values_retained': False,
             'manual_rotation_calls': 0, 'real_clock_modified': False,
             'completed_feature_verification': False})
        for server in [resource, issuer]:
            server.shutdown()
            server.server_close()
    print(json.dumps({'status': status, 'blocker': blocker}), flush=True)
    return 0 if status == 'completed' else 1


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Same persistent client and oracle; ordinary Ouro/Greywall/MXC credentials.

Only synthetic credentials on a private test-host HTTP interface. This does not
score performance or prove TLS/WSS/provider authentication. MXC's environment
workflow is retained explicitly as client-owned credentials, without inventing
a product broker. Greywall is tested with both global and session network rules.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import socket
import subprocess
import threading
import time
import urllib.request


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def sha(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--bin-root', type=Path, required=True)
    parser.add_argument('--ouro', type=Path, required=True)
    parser.add_argument('--proxy-template', type=Path, required=True)
    parser.add_argument('--resource-host', required=True)
    parser.add_argument('--modes', default='ouro,greywall-global,greywall-session,mxc')
    parser.add_argument('--late-seconds', type=float, default=70)
    args = parser.parse_args()
    assert args.late_seconds >= 70, 'observe across Greywall 0.3.7\'s real 60-second heartbeat'
    root = args.root.resolve()
    root.mkdir(mode=0o700)
    output, private, bindir = (root / name for name in ('results', 'private', 'bin'))
    for path in (output, private, bindir):
        path.mkdir(mode=0o700)
    for name in ('greywall', 'greyproxy', 'lxc-exec'):
        (bindir / name).symlink_to(args.bin_root.resolve() / name)
    (bindir / 'bwrap').symlink_to('/usr/bin/bwrap')
    env = {'PATH': str(bindir) + ':/usr/bin:/bin:/usr/sbin:/sbin',
           'LANG': 'C.UTF-8', 'USER': os.environ.get('USER', 'benchmark'),
           'XDG_RUNTIME_DIR': '/run/user/' + str(os.getuid()),
           'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/' + str(os.getuid()) + '/bus'}
    controls, received, results = [], [], []
    context = {}
    proxy = None
    server = None
    api_base = 'http://127.0.0.1:43080'
    python = str(Path('/usr/bin/python3').resolve())
    actor = Path(__file__).with_name('credential_actor.py')
    shutil.copyfile(Path(__file__), output / 'harness.py')
    shutil.copyfile(actor, output / 'actor.py')

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

    def api(method, path, body=None):
        req = urllib.request.Request(api_base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=5) as response:
            value = json.loads(response.read() or b'null')
            controls.append({'mode': context.get('mode'), 'method': method, 'path': path,
                             'body': body, 'status': response.status, 'response': value,
                             'unix': time.time()})
            return value

    def wait_file(work, name, child, seconds=30):
        deadline = time.monotonic() + seconds
        while not (work / name).exists():
            if child.poll() is not None:
                raise RuntimeError('application ended before ' + name)
            if time.monotonic() > deadline:
                raise RuntimeError('synchronization expired: ' + name)
            time.sleep(.02)

    def free_port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]

    try:
        server = http.server.ThreadingHTTPServer((args.resource_host, 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        origin = 'http://' + args.resource_host + ':' + str(server.server_port)
        modes = args.modes.split(',')
        ports = {name: free_port() for name in ('http', 'socks', 'dns')}
        assert len(set(ports.values())) == 3 and 43080 not in ports.values()
        if any(mode != 'ouro' for mode in modes):
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 43080))
            config = args.proxy_template.read_text()
            for old, name in [('43051', 'http'), ('43052', 'socks'), ('43053', 'dns')]:
                config = config.replace(old, str(ports[name]))
            proxy_config = output / 'greyproxy.yml'
            proxy_config.write_text(config)
            proxy_env = dict(env, HOME=str(private), GREYPROXY_DATA_HOME=str(private / 'proxy-data'))
            proxy_log = (output / 'proxy.log').open('wb')
            proxy = subprocess.Popen([str(bindir / 'greyproxy'), 'serve', '-C', str(proxy_config)],
                                     env=proxy_env, stdin=subprocess.DEVNULL,
                                     stdout=proxy_log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 15
            while True:
                try:
                    api('GET', '/api/health')
                    break
                except (OSError, ValueError):
                    assert proxy.poll() is None and time.monotonic() < deadline
                    time.sleep(.1)
        save(output / 'metadata.json', {
            'schema': 'matched-persistent-http-lifecycle/1', 'only_synthetic_tokens': True,
            'scored_performance': False, 'tls_wss_provider_proof': False,
            'host': platform.uname()._asdict(), 'origin': origin, 'modes': modes,
            'authorized_executable': python, 'authorized_path_prefix': '/v1/',
            'revocation_window_seconds': 3, 'late_check_after_revoke_seconds': args.late_seconds,
            'actor_sha256': sha(actor), 'harness_sha256': sha(Path(__file__)),
            'binary_sha256': {name: sha(path) for name, path in
                              [('ouro', args.ouro.resolve()), ('bwrap', Path('/usr/bin/bwrap')),
                               *[(name, bindir / name) for name in ('greywall', 'greyproxy', 'lxc-exec')]]},
            'ouro_version': json.loads(subprocess.check_output([str(args.ouro), 'version', '--json'])),
            'frozen_versions': {'greywall': '0.3.7', 'greyproxy': '0.4.5', 'mxc_executor': '1.0.0'},
        })
        for mode in modes:
            assert mode in ('ouro', 'greywall-global', 'greywall-session', 'mxc')
            run = output / mode
            run.mkdir()
            work, home, mode_private = (root / (mode + '-' + name)
                                        for name in ('work', 'home', 'private'))
            for path in (work, home, mode_private):
                path.mkdir(mode=0o700)
            shutil.copyfile(actor, work / 'actor.py')
            source = mode_private / 'token'
            source.write_text('fixture-v1')
            source.chmod(0o600)
            context.clear()
            context.update({'mode': mode, 'stream_stop': threading.Event(),
                            'stream_started': threading.Event()})
            mode_env = dict(env, HOME=str(home), XDG_CONFIG_HOME=str(home / '.config'))
            command = [python, str(work / 'actor.py'), '--origin', origin]
            rule = {'container_pattern': '*', 'destination_pattern': args.resource_host,
                    'port_pattern': str(server.server_port), 'action': 'allow',
                    'notes': 'owned matched synthetic lifecycle fixture'}
            global_rule = None
            network_rules = [{'destination_pattern': args.resource_host,
                              'port_pattern': str(server.server_port), 'action': 'allow'}]
            child = None
            status = 'incomplete'
            checks = []
            stdout, stderr = (run / name for name in ('stdout.log', 'stderr.log'))
            with stdout.open('wb') as out, stderr.open('wb') as err:
                try:
                    if mode == 'ouro':
                        config = mode_private / 'config' / 'launch'
                        config.mkdir(mode=0o700, parents=True)
                        profile = ('name="fixture"\njail="agent"\nhome_is_state=true\n'
                                   '[credentials.api]\nmode="vault"\nsource=' + json.dumps(str(source))
                                   + '\nhosts=' + json.dumps([origin])
                                   + '\npaths=["/v1/"]\nbinaries=' + json.dumps([python])
                                   + '\nallow_plaintext=true\nheader={name="x-api-key"}\n'
                                   '[network]\nallow=' + json.dumps([args.resource_host + ':' + str(server.server_port)])
                                   + '\n')
                        (config / 'fixture.toml').write_text(profile)
                        (config / 'fixture.toml').chmod(0o600)
                        shutil.copyfile(config / 'fixture.toml', run / 'launch.toml')
                        mode_env.update({'OURO_CONFIG_DIR': str(config.parent),
                                         'OURO_DATA_DIR': str(mode_private / 'data')})
                        argv = [str(args.ouro), 'run', '--launch', 'fixture', '--workspace', str(work),
                                '--observe', 'on', '--evidence', 'strict', '--limit', 'wall=150s',
                                '--receipt', str(run / 'jail.json'), '--', *command]
                    elif mode.startswith('greywall'):
                        settings = {'filesystem': {'defaultDenyRead': True,
                                                    'allowRead': ['/usr', '/lib', '/lib64', '/etc/ssl',
                                                                  '/etc/hosts', '/etc/resolv.conf', '/dev/null',
                                                                  '/dev/urandom', '/dev/zero'],
                                                    'allowWrite': [str(work), str(home)]},
                                    'network': {'allowLocalOutbound': False, 'allowAllUnixSockets': False}}
                        if mode == 'greywall-session':
                            settings['network']['rules'] = [{'destination': args.resource_host,
                                                             'port': str(server.server_port), 'action': 'allow'}]
                        else:
                            global_rule = api('POST', '/api/rules', rule)
                        cfg = run / 'greywall.json'
                        save(cfg, settings)
                        mode_env['BENCH_API_KEY'] = 'fixture-v1'
                        argv = [str(bindir / 'greywall'), '--auto-profile', '--settings', str(cfg),
                                '--secret', 'BENCH_API_KEY', '--proxy', 'socks5://127.0.0.1:' + str(ports['socks']),
                                '--http-proxy', 'http://127.0.0.1:' + str(ports['http']),
                                '--dns', '127.0.0.1:' + str(ports['dns']), '--', *command]
                    else:
                        global_rule = api('POST', '/api/rules', rule)
                        mode_env['BENCH_API_KEY'] = 'fixture-v1'
                        cfg = {'version': '1.0.0', 'containment': 'bubblewrap',
                               'process': {'commandLine': shlex.join(command), 'cwd': str(work),
                                           'timeout': 150000, 'inheritDefaultEnv': True,
                                           'env': [key + '=' + value for key, value in mode_env.items()]},
                               'filesystem': {'readonlyPaths': ['/usr', '/lib', '/lib64', '/etc/ssl'],
                                              'readwritePaths': [str(work), str(home)]},
                               'network': {'egress': {'default': 'deny'}},
                               'runtimeConfig': {'networkProxy': 'http://127.0.0.1:' + str(ports['http'])}}
                        path = run / 'mxc.json'
                        save(path, cfg)
                        argv = [str(bindir / 'lxc-exec'), str(path)]
                    save(run / 'command.json', {'argv': argv, 'environment': mode_env,
                                               'credential_scope': 'client-owned environment' if mode == 'mxc'
                                               else 'product-managed substitution',
                                               'network_scope': 'session' if mode == 'greywall-session' else 'destination'})
                    child = subprocess.Popen(argv, cwd=work, env=mode_env, stdin=subprocess.DEVNULL,
                                             stdout=out, stderr=err)
                    wait_file(work, 'rotation-ready', child)
                    before = [row for row in received if row['mode'] == mode]
                    assert any(row['path'] == '/v1/allowed' and row['v1'] for row in before), \
                        'positive baseline authentication is mandatory'
                    marker = (work / 'marker.txt').read_text()
                    if mode == 'ouro':
                        replacement = source.with_name('token-next')
                        replacement.write_text('fixture-v2')
                        replacement.chmod(0o600)
                        os.replace(replacement, source)
                        controls.append({'mode': mode, 'action': 'source-rotation', 'unix': time.time()})
                    elif mode.startswith('greywall'):
                        sessions = api('GET', '/api/sessions')
                        assert len(sessions) == 1 and marker.startswith('greyproxy:credential:v1:')
                        session = sessions[0]
                        body = {'session_id': session['session_id'], 'container_name': session['container_name'],
                                'mappings': {marker: 'fixture-v2'}, 'labels': {marker: 'BENCH_API_KEY'},
                                'ttl_seconds': 900}
                        if mode == 'greywall-session':
                            body['network_rules'] = network_rules
                        api('POST', '/api/sessions', body)
                    else:
                        controls.append({'mode': mode, 'action': 'credential-rotation', 'supported': False,
                                         'operation_performed': False, 'unix': time.time()})
                    (work / 'rotated').touch()
                    wait_file(work, 'rotated-ready', child)
                    wait_file(work, 'stream-ready', child)
                    assert context['stream_started'].is_set()
                    if mode == 'ouro':
                        source.unlink()
                        controls.append({'mode': mode, 'action': 'source-delete', 'unix': time.time()})
                    elif mode.startswith('greywall'):
                        api('DELETE', '/api/sessions/' + session['session_id'])
                    else:
                        controls.append({'mode': mode, 'action': 'credential-revoke', 'supported': False,
                                         'operation_performed': False, 'unix': time.time()})
                    revoked = time.time()
                    (work / 'revoked').touch()
                    observe_until = revoked + 3
                    while time.time() < observe_until:
                        assert child.poll() is None, 'persistent actor must remain live after credential revocation'
                        time.sleep(.02)
                    stream_state = json.loads((work / 'client-stream.json').read_text())
                    closed = (work / 'stream-finished').exists()
                    checks.append({'case': 'active-sse-closes-after-revoke',
                                   'pass': closed and stream_state.get('finished_unix', 0) >= revoked,
                                   'supported': mode != 'mxc', 'revoked_unix': revoked,
                                   'observation_deadline_unix': observe_until, 'client_stream': stream_state})
                    while time.time() < revoked + args.late_seconds:
                        assert child.poll() is None
                        time.sleep(.1)
                    (work / 'late-revocation-check').touch()
                    wait_file(work, 'late-revocation-ready', child)
                    context['stream_stop'].set()
                    (work / 'finish').touch()
                    child.wait(timeout=20)
                    identity = json.loads((work / 'client-identity.json').read_text())
                    client_rows = json.loads((work / 'client-requests.json').read_text())
                    observations = [row for row in received if row['mode'] == mode]
                    by_path = {row['path']: row for row in observations}
                    for case, path, version in [('valid', '/v1/allowed', 'v1'),
                                                ('same-live-client-rotation', '/v1/rotated', 'v2'),
                                                ('wrong-path-no-secret', '/outside', None),
                                                ('escaped-path-no-secret', '/v1/%2e%2e/outside', None),
                                                ('wrong-executable-no-secret', '/v1/wrong-process', None),
                                                ('new-request-after-revoke', '/v1/after-revoke', None),
                                                ('revoke-survives-heartbeat', '/v1/late-after-revoke', None)]:
                        observed = by_path.get(path)
                        sent = next(row for row in client_rows if row['path'] == path)
                        passed = (bool(observed and observed[version]) if version is not None
                                  else not observed or not (observed['v1'] or observed['v2']))
                        checks.append({'case': case, 'pass': passed, 'supported': mode != 'mxc' or case == 'valid',
                                       'client_request': sent, 'resource_observation': observed})
                    checks.append({'case': 'same-application-process-remains-live',
                                   'pass': child.returncode == 0 and all(row['client_pid'] == identity['pid']
                                                                      for row in client_rows), 'supported': True,
                                   'identity': identity, 'wrapper_exit': child.returncode})
                    checks.append({'case': 'raw-secret-absent-child-handle',
                                   'pass': marker not in ('fixture-v1', 'fixture-v2'), 'supported': mode != 'mxc'})
                    status = 'completed'
                except (OSError, ValueError, AssertionError, RuntimeError, subprocess.SubprocessError) as error:
                    save(run / 'failure.json', {'error': str(error), 'retained_attempt': True})
                finally:
                    context['stream_stop'].set()
                    (work / 'finish').touch()
                    if child is not None and child.poll() is None:
                        child.terminate()
                        try:
                            child.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait(timeout=10)
                    for path in work.glob('client-*.json'):
                        shutil.copyfile(path, run / path.name)
                    if mode == 'ouro' and (run / 'jail.json').exists():
                        receipt = json.loads((run / 'jail.json').read_text())
                        attempt = mode_private / 'data' / 'attempts' / receipt['attempt_id']
                        for name in ('policy.json', 'trace.ndjson'):
                            if (attempt / name).exists():
                                shutil.copyfile(attempt / name, run / name)
                    if global_rule is not None:
                        api('DELETE', '/api/rules/' + str(global_rule['id']))
                    result = {'mode': mode, 'status': status, 'checks': checks,
                              'resource_observations': [row for row in received if row['mode'] == mode],
                              'live_stream_oracle_ended_only_after_fixed_observation': True,
                              'child_handle_raw_secret': (work / 'marker.txt').exists()
                              and (work / 'marker.txt').read_text() in ('fixture-v1', 'fixture-v2')}
                    save(run / 'result.json', result)
                    results.append(result)
                    print(json.dumps({'mode': mode, 'status': status,
                                      'passed_supported': sum(row['pass'] for row in checks if row['supported']),
                                      'supported': sum(row['supported'] for row in checks)}), flush=True)
        return int(any(result['status'] != 'completed' for result in results))
    finally:
        if proxy is not None and proxy.poll() is None:
            proxy.terminate()
            try:
                proxy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait(timeout=10)
        if server is not None:
            server.shutdown()
            server.server_close()
        save(output / 'operator-api.json', controls)
        save(output / 'resource-oracle.json', received)
        save(output / 'results.json', results)


if __name__ == '__main__':
    raise SystemExit(main())

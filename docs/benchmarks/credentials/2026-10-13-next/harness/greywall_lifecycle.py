#!/usr/bin/env python3
"""Exercise frozen Greywall/Greyproxy through ordinary operator APIs.

Synthetic private-host HTTP fixtures only. This is a credential feature diagnostic,
not a model, HTTPS, TLS-security or scored latency benchmark. The proxy, store,
ports and child home belong exclusively to this run. No provider key is used.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import threading
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--bin-root', type=Path, required=True)
    parser.add_argument('--proxy-template', type=Path, required=True)
    parser.add_argument('--resource-host', required=True,
                        help='An owned host interface reachable through a sandbox network namespace')
    args = parser.parse_args()
    root = args.root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    out = root / 'results'
    out.mkdir()
    private = root / 'private'
    private.mkdir(mode=0o700)
    work = root / 'work'
    work.mkdir()
    child_home = root / 'home'
    child_home.mkdir()
    binaries = {name: args.bin_root.resolve() / name for name in ('greywall', 'greyproxy')}
    env = {'PATH': str(args.bin_root.resolve()) + ':/usr/local/bin:/usr/bin:/bin',
           'HOME': str(child_home), 'LANG': 'C.UTF-8',
           'USER': os.environ.get('USER', 'benchmark'),
           'XDG_CONFIG_HOME': str(private / 'child-config'),
           'GREYPROXY_DATA_HOME': str(private / 'proxy-data')}
    rows = []
    received = []
    stream_started = threading.Event()
    stop_stream = threading.Event()
    stdout = (out / 'child.stdout').open('wb')
    stderr = (out / 'child.stderr').open('wb')
    child = proxy = server = None
    status = 'incomplete'

    def save(name, value):
        (out / name).write_text(json.dumps(value, indent=2) + '\n')

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            value = self.headers.get('x-api-key')
            row = {'path': self.path, 'v1': value == 'fixture-v1',
                   'v2': value == 'fixture-v2', 'placeholder': bool(value and 'greyproxy:' in value),
                   'unix': time.time()}
            received.append(row)
            self.send_response(200)
            self.send_header('Connection', 'close')
            if self.path == '/v1/stream':
                self.send_header('Content-Type', 'text/event-stream')
            self.end_headers()
            if self.path != '/v1/stream':
                self.wfile.write(b'fixture-ok\n')
                return
            stream_started.set()
            try:
                while not stop_stream.wait(.05):
                    self.wfile.write(b'data: fixture\n\n')
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                row['client_disconnected_unix'] = time.time()
            finally:
                row['fixture_stream_cleanup_unix'] = time.time()

        def log_message(self, *_):
            pass

    def free_port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]

    # v0.3.7 registers and heartbeats credentials at this fixed API address.
    # Custom traffic ports do not relocate the management API.
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 43080))
    ports = {'management': 43080,
             **{key: free_port() for key in ('http', 'socks', 'dns')}}
    assert len(set(ports.values())) == len(ports)
    endpoint = 'http://127.0.0.1:' + str(ports['management'])
    controls = []

    def api(method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(endpoint + path, data=data, method=method,
                                         headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=4) as response:
            raw = response.read()
            value = json.loads(raw) if raw else None
            controls.append({'method': method, 'path': path, 'body': body,
                             'status': response.status, 'response': value, 'unix': time.time()})
            return value

    def wait_file(name, timeout=20):
        deadline = time.monotonic() + timeout
        while not (work / name).exists():
            if child.poll() is not None:
                raise RuntimeError('child ended before ' + name)
            if time.monotonic() >= deadline:
                raise RuntimeError('synchronization deadline: ' + name)
            time.sleep(.02)

    try:
        server = http.server.ThreadingHTTPServer((args.resource_host, 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        origin = 'http://' + args.resource_host + ':' + str(server.server_port)
        config = args.proxy_template.read_text()
        for old, new in [('43080', 'management'), ('43051', 'http'),
                         ('43052', 'socks'), ('43053', 'dns')]:
            config = config.replace(old, str(ports[new]))
        proxy_config = out / 'greyproxy.yml'
        proxy_config.write_text(config)
        proxy = subprocess.Popen([str(binaries['greyproxy']), 'serve', '-C', str(proxy_config)],
                                 env=env, stdin=subprocess.DEVNULL,
                                 stdout=(out / 'proxy.log').open('wb'), stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 10
        while True:
            try:
                api('GET', '/api/health')
                break
            except (OSError, ValueError):
                if proxy.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('owned proxy failed readiness')
                time.sleep(.1)
        api('POST', '/api/rules', {'container_pattern': '*', 'destination_pattern': args.resource_host,
                                 'port_pattern': str(server.server_port), 'action': 'allow',
                                 'notes': 'owned synthetic lifecycle resource only'})
        settings = {'filesystem': {'defaultDenyRead': True,
                                  'allowRead': ['/usr', '/lib', '/lib64', '/etc/ssl',
                                                '/etc/hosts', '/etc/resolv.conf',
                                                '/dev/null', '/dev/urandom', '/dev/zero'],
                                  'allowWrite': [str(work), str(child_home)],
                                  'denyRead': [], 'denyWrite': []},
                    'network': {'proxyUrl': 'socks5://127.0.0.1:' + str(ports['socks']),
                                'allowLocalOutbound': False, 'allowAllUnixSockets': False}}
        settings_path = out / 'greywall.json'
        settings_path.write_text(json.dumps(settings, indent=2) + '\n')
        curl = '/usr/bin/curl'

        def request(path):
            return (curl + ' -fsS --path-as-is --max-time 15 --noproxy "" '
                    '-H "x-api-key: $BENCH_API_KEY" ' + shlex.quote(origin + path))

        python_wrong_process = ('import os,urllib.request; '
                                'r=urllib.request.Request(' + repr(origin + '/v1/wrong-process')
                                + ',headers={"x-api-key":os.environ["BENCH_API_KEY"]}); '
                                'print(urllib.request.urlopen(r,timeout=10).read().decode())')
        command = ('printf "%s" "$BENCH_API_KEY" > marker.txt; '
                   'if test "$BENCH_API_KEY" = fixture-v1; then echo raw; else echo hidden; fi > child-key-status.txt; '
                   + request('/v1/allowed') + ' && '
                   + request('/outside') + ' && '
                   + request('/v1/%2e%2e/outside') + ' && '
                   '/usr/bin/python3 -c ' + shlex.quote(python_wrong_process) + ' && '
                   'touch rotation-ready; while test ! -f rotated; do sleep .02; done; '
                   + request('/v1/rotated') + ' && touch rotated-ready; '
                   + request('/v1/stream') + ' > stream.log & stream_pid=$!; '
                   'while test ! -f revoked; do sleep .02; done; '
                   + request('/v1/after-revoke') + '; touch after-revoke-ready; '
                   'wait "$stream_pid"; touch stream-finished')
        argv = [str(binaries['greywall']), '--auto-profile', '--settings', str(settings_path),
                '--proxy', 'socks5://127.0.0.1:' + str(ports['socks']),
                '--http-proxy', 'http://127.0.0.1:' + str(ports['http']),
                '--dns', '127.0.0.1:' + str(ports['dns']), '--secret', 'BENCH_API_KEY',
                '--', '/bin/sh', '-c', command]
        save('configuration.json', {'argv': argv, 'ports': ports, 'resource_origin': origin,
                                   'product_versions': {'greywall': '0.3.7', 'greyproxy': '0.4.5'},
                                   'binary_sha256': {k: hashlib.file_digest(v.open('rb'), 'sha256').hexdigest()
                                                     for k, v in binaries.items()},
                                   'only_synthetic_tokens': True, 'scored_performance': False,
                                   'desired_authority': {'path_prefix': '/v1/', 'executable': curl},
                                   'configured_authority': 'destination IP and port; no supported path/executable credential binding'})
        child = subprocess.Popen(argv, cwd=work, env=dict(env, BENCH_API_KEY='fixture-v1'),
                                 stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        wait_file('rotation-ready')
        assert any(r['path'] == '/v1/allowed' and r['v1'] for r in received), \
            'baseline must authenticate before lifecycle results can be compared'
        sessions = api('GET', '/api/sessions')
        assert len(sessions) == 1, 'owned proxy must have exactly this run session'
        session = sessions[0]
        marker = (work / 'marker.txt').read_text()
        assert marker.startswith('greyproxy:credential:v1:'), 'no substitution handle supplied'
        api('POST', '/api/sessions', {'session_id': session['session_id'],
                                    'container_name': session['container_name'],
                                    'mappings': {marker: 'fixture-v2'},
                                    'labels': {marker: 'BENCH_API_KEY'}, 'ttl_seconds': 900})
        (work / 'rotated').touch()
        wait_file('rotated-ready')
        assert stream_started.wait(15), 'stream was not established'
        api('DELETE', '/api/sessions/' + session['session_id'])
        revoked_at = time.time()
        (work / 'revoked').touch()
        wait_file('after-revoke-ready')
        deadline = time.monotonic() + 2
        while not (work / 'stream-finished').exists() and time.monotonic() < deadline:
            time.sleep(.02)
        stream_closed = (work / 'stream-finished').exists()
        stop_stream.set()  # Oracle cleanup after the fixed revocation observation window.
        child.wait(timeout=20)
        by_path = {r['path']: r for r in received}
        for name, path, predicate in [
            ('valid', '/v1/allowed', lambda r: r['v1']),
            ('wrong-path-no-secret', '/outside', lambda r: not r['v1'] and not r['v2']),
            ('escaped-path-no-secret', '/v1/%2e%2e/outside', lambda r: not r['v1'] and not r['v2']),
            ('wrong-process-no-secret', '/v1/wrong-process', lambda r: not r['v1'] and not r['v2']),
            ('same-live-process-rotation', '/v1/rotated', lambda r: r['v2']),
            ('new-request-after-revoke', '/v1/after-revoke', lambda r: not r['v1'] and not r['v2']),
        ]:
            observed = by_path.get(path)
            rows.append({'case': name, 'pass': bool(observed and predicate(observed)),
                         'resource_observation': observed})
        rows.append({'case': 'active-sse-closes-after-revoke', 'pass': stream_closed,
                     'observation_window_seconds': 2, 'revoked_unix': revoked_at,
                     'server_stream_ended_for_cleanup': True})
        rows.append({'case': 'child-environment-hides-secret',
                     'pass': (work / 'child-key-status.txt').read_text().strip() == 'hidden'})
        status = 'completed'
    except (OSError, ValueError, AssertionError, RuntimeError, subprocess.SubprocessError) as error:
        save('failure.json', {'error': str(error), 'retained_attempt': True})
    finally:
        stop_stream.set()
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)
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
        stdout.close()
        stderr.close()
        save('operator-api.json', controls)
        save('resource-oracle.json', received)
        save('result.json', {'schema': 'matched-credential-lifecycle-greywall/1',
                             'status': status, 'checks': rows,
                             'only_synthetic_tokens': True,
                             'observation': 'Greyproxy API/log and resource-server oracle; no Ouro-equivalent child journal',
                             'pending': ['WebSocket duplex and live revocation', 'automatic OAuth refresh',
                                         'concurrent rotating-grant ownership', 'issuer failure/pending safety',
                                         'revocation across heartbeat re-registration']})
        print(json.dumps({'status': status, 'checks': rows}))
    return 0 if status == 'completed' else 1


if __name__ == '__main__':
    raise SystemExit(main())

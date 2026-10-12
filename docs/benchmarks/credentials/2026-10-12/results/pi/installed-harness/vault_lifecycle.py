#!/usr/bin/env python3
"""Demonstrate static snapshot/rotation/revocation semantics with fake tokens."""
import argparse
import http.server
import json
import os
from pathlib import Path
import subprocess
import threading
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    args = p.parse_args()
    root = args.root.resolve()
    out = root / 'results/lifecycle'
    if out.exists():
        raise SystemExit('Preserve existing lifecycle evidence')
    out.mkdir(parents=True)
    private = root / 'lifecycle-private'
    private.mkdir(mode=0o700)
    source = private / 'key'
    source.write_text('lifecycle-fixture-v1')
    source.chmod(0o600)
    work = root / 'lifecycle-work'
    work.mkdir()
    config = private / 'config/launch'
    config.mkdir(parents=True)
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            value = self.headers.get('x-api-key')
            received.append({'path': self.path, 'v1': value == 'lifecycle-fixture-v1',
                             'v2': value == 'lifecycle-fixture-v2'})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'fixture-ok')

        def log_message(self, *_):
            pass

    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = 'http://127.0.0.1:' + str(server.server_port)
    profile = ('name="lifecycle"\njail="agent"\nhome_is_state=true\n[credentials.api]\nmode="vault"\nsource=' +
               json.dumps(str(source)) + '\nhosts=' + json.dumps([origin]) +
               '\nallow_plaintext=true\nheader={name="x-api-key"}\n[network]\nallow=' +
               json.dumps(['127.0.0.1:' + str(server.server_port)]) + '\n')
    f = config / 'lifecycle.toml'
    f.write_text(profile)
    f.chmod(0o600)
    env = dict(os.environ, OURO_CONFIG_DIR=str(config.parent), OURO_DATA_DIR=str(root / 'data'))

    def argv(name, command):
        d = out / name
        d.mkdir()
        return [str(root / 'bin/ouro-jail'), 'run', '--launch', 'lifecycle', '--workspace', str(work),
                '--limit', 'wall=20s', '--receipt', str(d / 'jail.json'), '--', '/bin/sh', '-c', command]

    def request(path):
        return 'curl -fsS --max-time 5 --noproxy "" -H "x-api-key: $OURO_VAULT_API" ' + origin + path

    def wait_file(path, process):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if path.exists():
                return
            if process.poll() is not None:
                raise RuntimeError('Attempt ended before lifecycle synchronization')
            time.sleep(.01)
        raise RuntimeError('Lifecycle synchronization timed out')

    def retain(name, code, stdout, stderr):
        d = out / name
        (d / 'stdout.log').write_bytes(stdout)
        (d / 'stderr.log').write_bytes(stderr)
        receipt = json.loads((d / 'jail.json').read_text())
        a = root / 'data/attempts' / receipt['attempt_id']
        trace = a / 'trace.ndjson'
        if trace.exists():
            (d / 'trace.ndjson').write_bytes(trace.read_bytes())
        return {'exit': code, 'phase': receipt['phase'], 'tree_empty': (receipt.get('lifetime') or {}).get('tree_empty'),
                'cleanup': receipt['state_cleanup'], 'source_unreadable_after_deletion': b'SOURCE_HIDDEN' in stdout,
                'credentials': receipt.get('credentials'), 'artifact': str(d.relative_to(root / 'results'))}

    process = None
    try:
        command = (request('/v1/messages') + ' && touch rotate-ready; while test ! -f rotated; do sleep .01; done; ' +
                   request('/outside-path-binding') + ' && touch revoke-ready; while test ! -f revoked; do sleep .01; done; ' +
                   request('/after-source-deletion') + '; test ! -r ' + str(source) + ' && echo SOURCE_HIDDEN')
        process = subprocess.Popen(argv('in-flight', command), cwd=work, env=env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wait_file(work / 'rotate-ready', process)
        source.write_text('lifecycle-fixture-v2')
        (work / 'rotated').touch()
        wait_file(work / 'revoke-ready', process)
        source.unlink()
        (work / 'revoked').touch()
        stdout, stderr = process.communicate(timeout=30)
        current = retain('in-flight', process.returncode, stdout, stderr)
        r = subprocess.run(argv('next-source-missing', 'touch should-not-execute'), cwd=work, env=env,
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=40)
        missing = retain('next-source-missing', r.returncode, r.stdout, r.stderr)
        source.write_text('lifecycle-fixture-v2')
        source.chmod(0o600)
        r = subprocess.run(argv('next-source-replaced', request('/v1/messages')), cwd=work, env=env,
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=40)
        replaced = retain('next-source-replaced', r.returncode, r.stdout, r.stderr)
        result = {'schema': 'vault-static-lifecycle/1', 'received_token_equality_only': received,
                  'in_flight': current, 'next_source_missing': missing, 'next_source_replaced': replaced,
                  'running_attempt_keeps_snapshot_after_rotation_and_deletion': received[:3] == [
                      {'path': '/v1/messages', 'v1': True, 'v2': False},
                      {'path': '/outside-path-binding', 'v1': True, 'v2': False},
                      {'path': '/after-source-deletion', 'v1': True, 'v2': False}],
                  'next_missing_source_refuses_before_target': missing['exit'] != 0 and not (work / 'should-not-execute').exists(),
                  'next_attempt_uses_rotated_source': replaced['exit'] == 0 and received[-1]['v2'],
                  'origin_binding_has_no_path_restriction': received[1]['path'] == '/outside-path-binding' and received[1]['v1'],
                  'synthetic_local_http_only': True, 'automatic_oauth_refresh_exercised': False}
        (out / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == '__main__':
    main()

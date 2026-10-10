#!/usr/bin/env python3
"""Linux preview gates through the real CLI; private fixture state only."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import threading
import time
import tomllib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--case', choices=['none', 'adopt', 'tail', 'vault'], required=True)
    args = parser.parse_args()
    os.umask(0o077)
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix='.ouro-preview-', dir=Path.home()) as tmp:
        root = Path(tmp)
        work, config, data = (root / name for name in ['work', 'config', 'data'])
        work.mkdir(); config.mkdir(); (config / 'launch').mkdir()
        env = {'PATH': os.environ['PATH'], 'HOME': str(Path.home()),
               'OURO_CONFIG_DIR': str(config), 'OURO_DATA_DIR': str(data)}

        def run(verb, flags, argv=(), expected=0):
            command = [str(binary), verb, '--workspace', str(work), *map(str, flags)]
            if argv:
                command += ['--', *map(str, argv)]
            result = subprocess.run(command, env=env, cwd=work, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=30)
            assert result.returncode == expected, (command, result.returncode, result.stderr)
            return result

        def latest():
            return max((data / 'attempts').iterdir(), key=lambda p: p.stat().st_mtime_ns)

        def settled(attempt):
            receipt = json.loads((attempt / 'jail.json').read_bytes())
            assert receipt['phase'] == 'settled' and receipt['lifetime']['tree_empty'] is True, receipt
            return receipt

        if args.case == 'none':
            marker = work / 'executed'
            for path, contents in [(config / 'config.toml', '[jail]\n'),
                                   (config / 'launch' / 'fixture.toml', 'name="fixture"\njail="tool"\n')]:
                path.write_text(contents)
                result = run('run', ['--profile', 'none', '--observe', 'on'],
                             ['/bin/sh', '-c', 'touch executed'], 125)
                assert b'unsafe_config_path' in result.stderr and path.name.encode() in result.stderr
                assert not marker.exists()
                path.unlink()
            run('run', ['--profile', 'none', '--observe', 'on'], ['/bin/sh', '-c', 'touch executed'])
            assert marker.exists()
            receipt = settled(latest())
            assert receipt['child_protection'] == 'unprotected'

        elif args.case == 'adopt':
            source = Path(__file__).parent / 'fixtures' / 'learn_access.c'
            fixture = work / 'learn-access'
            subprocess.run(['cc', '-O2', str(source), '-o', str(fixture)], check=True, timeout=30)
            outside = root / 'needed.txt'
            outside.write_text('fixture, never an operator credential')
            policy = config / 'config.toml'
            original = '# preserve this operator comment\n[jail]\n'
            policy.write_text(original)
            no_tty = run('learn', ['--adopt', '--profile', 'tool'], ['/bin/true'], 2)
            assert b'interactive terminal' in no_tty.stderr and policy.read_text() == original

            def interact(answer, proposal, change=False):
                master, slave = pty.openpty()
                command = [str(binary), 'learn', '--profile', 'tool', '--adopt', '--out', str(proposal),
                           '--workspace', str(work), '--', str(fixture), 'read', str(outside)]
                proc = subprocess.Popen(command, env=env, cwd=work, stdin=slave, stdout=slave, stderr=slave)
                os.close(slave)
                transcript = b''
                answered = False
                try:
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        if select.select([master], [], [], .05)[0]:
                            try:
                                block = os.read(master, 65536)
                            except OSError:
                                break
                            if not block:
                                break
                            transcript += block
                            if b'Type yes:' in transcript and not answered:
                                assert policy.read_text() == original, 'configuration changed before consent'
                                if change:
                                    policy.write_text(original + '# concurrent edit\n')
                                os.write(master, answer + b'\n')
                                answered = True
                        if proc.poll() is not None:
                            break
                    assert answered, transcript
                    return proc.wait(timeout=2), transcript
                finally:
                    os.close(master)
                    if proc.poll() is None:
                        proc.kill(); proc.wait()

            code, transcript = interact(b'no', root / 'cancelled.toml')
            assert code == 2 and b'adoption cancelled' in transcript and policy.read_text() == original
            code, transcript = interact(b'yes', root / 'changed.toml', change=True)
            assert code == 2 and b'configuration changed during review' in transcript
            assert policy.read_text() == original + '# concurrent edit\n'
            policy.write_text(original)
            with policy.open('rb') as old_handle:
                old_inode = policy.stat().st_ino
                code, transcript = interact(b'yes', root / 'adopted.toml')
                assert code == 1, transcript  # the learning workload's denied read exited 1
                assert old_handle.read() == original.encode(), 'replacement modified the original inode'
                assert policy.stat().st_ino != old_inode and policy.stat().st_mode & 0o777 == 0o600
            adopted = tomllib.loads(policy.read_text())
            assert adopted['jail']['filesystem']['read_only'] == [str(outside)]
            proposal = tomllib.loads((root / 'adopted.toml').read_text())
            assert proposal['read_only'] == [str(outside)] and not proposal['denied_writes']
            assert proposal['provenance']['receipt_digest'] == 'sha256:' + hashlib.sha256((latest() / 'jail.json').read_bytes()).hexdigest()
            run('run', ['--profile', 'tool', '--observe', 'on'], [fixture, 'read', outside])
            settled(latest())

        elif args.case == 'tail':
            proc = subprocess.Popen([str(binary), 'run', '--profile', 'tool', '--observe', 'on',
                                     '--workspace', str(work), '--', '/bin/sh', '-c',
                                     'printf first > first; sleep 2; printf last > last'],
                                    env=env, cwd=work, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            follow = None
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    attempts = list((data / 'attempts').glob('*'))
                    if attempts and (attempts[0] / 'trace.ndjson').exists():
                        break
                    assert proc.poll() is None, proc.communicate()
                    time.sleep(.02)
                else:
                    raise AssertionError('live journal did not appear')
                attempt = attempts[0]
                follow = subprocess.Popen([str(binary), 'tail', '--attempt', attempt.name, '--follow', '--json'],
                                          env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                start = time.monotonic()
                assert select.select([follow.stdout], [], [], 1.5)[0], 'follow lag exceeded 1.5 seconds'
                first = os.read(follow.stdout.fileno(), 65536)
                assert b'\n' in first and proc.poll() is None, 'follow buffered until settlement'
                assert time.monotonic() - start < 1.5
                _, errors = proc.communicate(timeout=10)
                assert proc.returncode == 0, errors
                rest, errors = follow.communicate(timeout=3)
                assert follow.returncode == 0, errors
                journal = (attempt / 'trace.ndjson').read_bytes()
                assert first + rest == journal, 'live tail rewrote, dropped or duplicated evidence'
                settled(attempt)
                replay = subprocess.run([str(binary), 'tail', '--attempt', attempt.name, '--json'],
                                        env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
                assert replay.returncode == 0 and replay.stdout == journal
                assert (attempt / 'trace.ndjson').read_bytes() == journal
            finally:
                for child in [follow, proc]:
                    if child is not None and child.poll() is None:
                        child.kill(); child.wait()

        elif args.case == 'vault':
            received = []
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    received.append(self.headers.get('Authorization'))
                    self.send_response(200); self.end_headers(); self.wfile.write(b'vault-ok')
                def log_message(self, *_):
                    pass
            server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                token = root / 'fixture-token'
                token.write_text('Bearer preview-fixture-secret')
                origin = f'http://127.0.0.1:{server.server_port}'
                profile = config / 'launch' / 'vault.toml'
                prefix = f'name="vault"\njail="agent"\nhome_is_state=true\n[credentials.api]\nmode="vault"\nsource="{token}"\nallow_plaintext=true\n'
                profile.write_text(prefix + 'hosts=[]\n')
                rejected = subprocess.run([str(binary), 'run', '--launch', 'vault', '--workspace', str(work),
                                           '--', '/bin/sh', '-c', 'touch executed'], env=env,
                                          stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
                assert rejected.returncode != 0 and b'vault needs 1..64' in rejected.stderr
                assert not (work / 'executed').exists() and not received
                profile.write_text(prefix + f'hosts=["{origin}"]\n[network]\nallow=["127.0.0.1:{server.server_port}"]\n')
                result = run('run', ['--launch', 'vault'], ['/bin/sh', '-c',
                             f'printf "%s\\n" "$OURO_VAULT_API"; curl -fsS --noproxy "" -H "Authorization: $OURO_VAULT_API" {origin}/'])
                assert received == ['Bearer preview-fixture-secret'] and b'vault-ok' in result.stdout
                attempt = latest()
                receipt = settled(attempt)
                row = receipt['credentials'][0]
                assert row['never_staged'] is True and row.get('digest') is None
                assert row['digest_unavailable_reason'] == 'never_staged'
                evidence = result.stdout + result.stderr + (attempt / 'jail.json').read_bytes() + (attempt / 'trace.ndjson').read_bytes()
                assert b'preview-fixture-secret' not in evidence and not (attempt / 'vendor-state').exists()
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=2)
        print('PASS Linux preview gate:', args.case)


if __name__ == '__main__':
    main()

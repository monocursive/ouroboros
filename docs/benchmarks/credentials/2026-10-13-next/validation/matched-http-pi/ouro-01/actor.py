#!/usr/bin/env python3
"""One persistent application for the matched synthetic HTTP lifecycle fixture.

The application knows its credential handle, not the resource oracle's secrets.
Expected negative requests never abort the remaining fixture steps. No refresh
or credential broker is implemented here; those belong to the tested product.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', required=True)
    args = parser.parse_args()
    work = Path.cwd()
    key = os.environ.get('BENCH_API_KEY') or os.environ['OURO_VAULT_API']
    pid = os.getpid()
    requests = []
    stream = {}
    lock = threading.Lock()
    clean_stream = threading.Event()

    def save(name, value):
        (work / name).write_text(json.dumps(value, indent=2) + '\n')

    def record(value):
        with lock:
            requests.append(value)
            save('client-requests.json', requests)

    def request(path):
        row = {'path': path, 'client_pid': pid, 'started_unix': time.time()}
        headers = {'x-api-key': key, 'x-fixture-client': str(pid)}
        try:
            req = urllib.request.Request(args.origin + path, headers=headers)
            with urllib.request.urlopen(req, timeout=8) as response:
                row.update({'status': response.status, 'body_bytes': len(response.read())})
        except urllib.error.HTTPError as error:
            row.update({'status': error.code, 'error': 'HTTPError'})
        except (OSError, ValueError) as error:
            row.update({'status': None, 'error': type(error).__name__, 'detail': str(error)})
        row['finished_unix'] = time.time()
        record(row)

    def barrier(name):
        deadline = time.monotonic() + 180
        while not (work / name).exists():
            if time.monotonic() > deadline:
                raise RuntimeError('operator barrier expired: ' + name)
            time.sleep(.02)

    def streaming():
        stream.update({'client_pid': pid, 'started_unix': time.time(), 'ready': False})
        save('client-stream.json', stream)
        req = urllib.request.Request(args.origin + '/v1/stream',
                                     headers={'x-api-key': key, 'x-fixture-client': str(pid)})
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                stream['status'] = response.status
                for line in response:
                    if line.strip() and not stream['ready']:
                        stream['ready'] = True
                        stream['ready_unix'] = time.time()
                        save('client-stream.json', stream)
                        (work / 'stream-ready').touch()
                    if clean_stream.is_set():
                        break
                stream['end'] = 'eof-or-oracle-cleanup'
        except (OSError, ValueError) as error:
            stream['end'] = type(error).__name__
            stream['error'] = str(error)
        stream['finished_unix'] = time.time()
        save('client-stream.json', stream)
        (work / 'stream-finished').touch()

    (work / 'marker.txt').write_text(key)
    save('client-identity.json', {'pid': pid, 'executable': os.readlink('/proc/self/exe'),
                                'origin': args.origin})
    request('/v1/allowed')
    request('/outside')
    request('/v1/%2e%2e/outside')
    # This connection belongs to curl, even though a client-controlled header
    # claims the authorized Python process. It must not grant Ouro authority.
    wrong = subprocess.run(['/usr/bin/curl', '-fsS', '--max-time', '8', '--noproxy', '',
                            '-H', 'x-api-key: ' + key, '-H', 'X-Ouro-Process: Python',
                            args.origin + '/v1/wrong-process'], capture_output=True)
    record({'path': '/v1/wrong-process', 'client_pid': pid, 'executable': '/usr/bin/curl',
            'exit': wrong.returncode, 'stdout_bytes': len(wrong.stdout),
            'stderr': wrong.stderr.decode(errors='replace'), 'finished_unix': time.time()})
    (work / 'rotation-ready').touch()
    barrier('rotated')
    request('/v1/rotated')
    (work / 'rotated-ready').touch()
    reader = threading.Thread(target=streaming, daemon=True)
    reader.start()
    barrier('revoked')
    request('/v1/after-revoke')
    (work / 'after-revoke-ready').touch()
    barrier('late-revocation-check')
    request('/v1/late-after-revoke')
    (work / 'late-revocation-ready').touch()
    barrier('finish')
    clean_stream.set()
    reader.join(timeout=12)
    save('client-final.json', {'pid': pid, 'stream_thread_joined': not reader.is_alive()})


if __name__ == '__main__':
    main()

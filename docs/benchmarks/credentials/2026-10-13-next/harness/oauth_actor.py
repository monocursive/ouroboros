#!/usr/bin/env python3
"""One persistent, identical client; only native products refresh credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import threading
import time
import urllib.error
import urllib.request


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--origin', required=True)
    p.add_argument('--nonce', required=True)
    p.add_argument('--seconds', type=float, default=540)
    p.add_argument('--interval', type=float, default=3)
    a = p.parse_args()
    key = os.environ.get('BENCH_API_KEY') or os.environ['OURO_VAULT_API']
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    pid = os.getpid()
    lock = threading.Lock()
    rows = []
    sequence = 0
    start = time.monotonic()

    def save(name, value):
        target = Path(name)
        temporary = target.with_suffix(target.suffix + '.tmp')
        temporary.write_text(json.dumps(value, indent=2) + '\n')
        temporary.replace(target)

    def request(label):
        nonlocal sequence
        with lock:
            sequence += 1
            request_id = f'{a.nonce}:{sequence}'
        row = {'label': label, 'request_id': request_id,
               'pid': pid, 'started_unix': time.time()}
        req = urllib.request.Request(a.origin + '/v1/probe', headers={
            'Authorization': 'Bearer ' + key, 'X-Fixture-Run': a.nonce,
            'X-Fixture-Request': request_id, 'X-Fixture-Client': str(pid)})
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                row['status'] = response.status
                data = json.loads(response.read(4096))
                row['generation'] = data.get('generation')
                row['accepted'] = data.get('accepted')
        except urllib.error.HTTPError as error:
            row.update({'status': error.code, 'error': 'HTTPError'})
        except (OSError, ValueError) as error:
            row.update({'status': None, 'error': type(error).__name__})
        row['finished_unix'] = time.time()
        with lock:
            rows.append(row)
            save('oauth-client-requests.json', rows)

    save('oauth-client-identity.json', {
        'pid': pid, 'executable': os.readlink('/proc/self/exe'),
        'birth': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19],
        'key_sha256': key_hash, 'credential_variable_contains_fixture_access':
            key.startswith('fixture-access-'), 'started_unix': time.time(),
        'refresh_is_owned_by_client': False})
    burst_index = 0
    burst_times = [100, 220, 340, 460]
    while time.monotonic() - start < a.seconds:
        request('regular')
        elapsed = time.monotonic() - start
        if burst_index < len(burst_times) and elapsed >= burst_times[burst_index]:
            workers = [threading.Thread(target=request, args=('concurrent',)) for _ in range(12)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()
            burst_index += 1
        time.sleep(min(a.interval, max(0, a.seconds - (time.monotonic() - start))))
    save('oauth-client-final.json', {
        'pid': pid, 'key_sha256_unchanged': hashlib.sha256(key.encode()).hexdigest() == key_hash,
        'requests': len(rows), 'concurrency_bursts': burst_index,
        'completed_unix': time.time(), 'runtime_seconds': time.monotonic() - start,
        'refresh_is_owned_by_client': False})


if __name__ == '__main__':
    main()

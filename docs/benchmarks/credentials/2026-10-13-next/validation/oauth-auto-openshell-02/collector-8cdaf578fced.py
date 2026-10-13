#!/usr/bin/env python3
"""Collect native log enums/times without exporting handles or raw diagnostics."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--setup-root', type=Path, required=True)
    a = p.parse_args()
    setup = json.loads((a.setup_root / 'results/setup.json').read_text())
    profile = (a.root / 'results/provider-profile.yaml').read_text()
    name = profile.splitlines()[0].removeprefix('id: ')
    assert re.fullmatch(r'oauth-[a-f0-9]{12}', name)
    env = setup['gateway_environment']
    argv = ['/usr/bin/openshell', '--gateway', setup['name'], 'logs', name, '-n', '10000']
    result = subprocess.run(argv, env=env, capture_output=True, timeout=45)
    stamp = str(time.time_ns())
    raw = result.stdout + result.stderr
    private_log = a.root / ('private/native-logs-' + stamp + '.txt')
    private_log.write_bytes(raw)
    private_log.chmod(0o600)
    ansi = re.compile(r'\x1b\[[0-9;]*m')
    lines = ansi.sub('', raw.decode(errors='replace')).splitlines()
    ocsf = []
    for index, line in enumerate(lines):
        match = re.search(r'\[ocsf\]\s+([A-Z_]+:[A-Z_]+)', line)
        if match:
            ts = re.match(r'\[([0-9.]+)\]', line)
            ocsf.append({'line': index + 1, 'class': match[1],
                         'unix': float(ts[1]) if ts else None})
    gateway = (a.setup_root / 'private/gateway.log').read_bytes()
    refresh = []
    messages = {'provider credential refresh watch': 'watch',
                'refreshing provider credential': 'refresh_started',
                'provider credential refresh completed': 'refreshed',
                'provider credential refresh errored': 'refresh_errored',
                'provider credential refresh failed': 'refresh_failed'}
    for index, line in enumerate(ansi.sub('', gateway.decode(errors='replace')).splitlines()):
        if name not in line:
            continue
        for text, event in messages.items():
            if text in line:
                numeric = {key: int(value) for key, value in re.findall(
                    r'\b(expires_at_ms|next_refresh_at_ms|last_refresh_at_ms|seconds_until_expiry|seconds_until_refresh)=(-?\d+)\b', line)}
                refresh.append({'line': index + 1, 'event': event, 'numeric_fields': numeric})
                break
    projection = {'schema': 'openshell-native-oauth-observation-projection/1',
                  'captured_unix': time.time(), 'cli_exit': result.returncode,
                  'native_logs_sha256': hashlib.sha256(raw).hexdigest(),
                  'gateway_snapshot_sha256': hashlib.sha256(gateway).hexdigest(),
                  'collector_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  'raw_diagnostics_retained_privately': True,
                  'actual_credential_values_retained': False,
                  'ocsf_counts': dict(Counter(v['class'] for v in ocsf)),
                  'ocsf_rows': ocsf, 'refresh_rows': refresh,
                  'scope': 'Safe enum/numeric projection from native logs. Captured before fixture cleanup; not six-class observation equivalence.'}
    output = a.root / ('results/native-observation-' + stamp + '.json')
    output.write_text(json.dumps(projection, indent=2) + '\n')
    print(json.dumps({'cli_exit': result.returncode, 'ocsf_counts': projection['ocsf_counts'],
                      'native_refresh_rows': len(refresh), 'snapshot': output.name}))


if __name__ == '__main__':
    main()

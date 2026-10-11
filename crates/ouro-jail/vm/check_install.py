#!/usr/bin/env python3
"""Exercise the actual offline installer without host developer-tool PATH entries."""
import argparse
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--volume', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    source = args.volume.resolve()
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    environment = {'HOME': os.environ['HOME'], 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
    results = []

    def invoke(name, volume, prefix, expected, message):
        result = subprocess.run(['/bin/bash', str(volume / 'install.sh'), '--prefix', str(prefix)],
                                env=environment, capture_output=True, text=True)
        (root / (name + '.stdout')).write_text(result.stdout)
        (root / (name + '.stderr')).write_text(result.stderr)
        passed = result.returncode == expected and message in result.stdout + result.stderr
        results.append({'case': name, 'exit_code': result.returncode, 'passed': passed})
        if not passed:
            raise RuntimeError(f'{name} failed: {result.stderr}')

    try:
        installed = root / 'prefix with spaces'
        invoke('install', source, installed, 0, 'Installed ')
        link = installed / 'bin' / 'ouro-vm'
        version = subprocess.run([str(link), 'version', '--json'], env=environment, capture_output=True, text=True, check=True)
        (root / 'version.json').write_text(version.stdout)
        invoke('repeat-refused', source, installed, 2, 'Already installed:')
        unrelated = root / 'unrelated'
        (unrelated / 'bin').mkdir(parents=True)
        marker = unrelated / 'bin' / 'ouro-vm'
        marker.write_text('preserve me')
        invoke('unrelated-refused', source, unrelated, 2, 'unrelated command:')
        assert marker.read_text() == 'preserve me'
        for case, filename, expected in [('manifest-tamper', 'SHA256SUMS', 'manifest checksum mismatch'),
                                         ('payload-tamper', 'payload/image/vz', 'Package checksum mismatch')]:
            clone = root / case
            subprocess.run(['/bin/cp', '-cR', str(source), str(clone)], check=True)
            target = clone / filename
            with target.open('ab') as output:
                output.write(b'tampered')
            destination = root / (case + '-prefix')
            invoke(case, clone, destination, 1, expected)
            assert not destination.exists()
    finally:
        (root / 'summary.json').write_text(json.dumps({'schema': 'ouro.vm.installer-check/1', 'results': results,
                                                      'passed': len(results) == 5 and all(r['passed'] for r in results)}, indent=2) + '\n')


if __name__ == '__main__':
    main()

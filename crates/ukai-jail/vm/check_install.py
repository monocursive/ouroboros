#!/usr/bin/env python3
"""Exercise the actual offline installer without host developer-tool PATH entries."""
import argparse
import json
import os
from pathlib import Path
import subprocess

if not __debug__:
    raise SystemExit('check_install.py must not run with python -O: its checks are gates')

SCHEMA = 'ukai.vm.installer-check/1'
CASES = ('install', 'repeat-refused', 'unrelated-refused', 'manifest-tamper', 'payload-tamper')


class CaseFailed(RuntimeError):
    pass


def run_case(results, root, name, argv, environment, expected, message, postconditions=()):
    """Run one installer case and record it as passed only if every check held.

    Postconditions are evaluated before the case is recorded, so the summary
    can never report a case as passed while its after-state was wrong.
    """
    result = subprocess.run(argv, env=environment, capture_output=True, text=True)
    (root / (name + '.stdout')).write_text(result.stdout)
    (root / (name + '.stderr')).write_text(result.stderr)
    checks = {'exit_code': result.returncode == expected, 'message': message in result.stdout + result.stderr}
    errors = []
    for label, check in postconditions:
        try:
            checks[label] = check()
        except (OSError, subprocess.SubprocessError) as error:
            checks[label] = False
            errors.append(f'{label}: {error}')
    failed = [label for label, held in checks.items() if held is not True]
    results.append({'case': name, 'exit_code': result.returncode, 'passed': not failed, 'failed_checks': failed})
    if failed:
        raise CaseFailed(f'{name} failed {failed} {errors}: {result.stderr}')


def summary(results):
    passed = tuple(r['case'] for r in results) == CASES and all(r['passed'] is True for r in results)
    return {'schema': SCHEMA, 'results': results, 'passed': passed}


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

    def invoke(name, volume, prefix, expected, message, postconditions=()):
        run_case(results, root, name, ['/bin/bash', str(volume / 'install.sh'), '--prefix', str(prefix)],
                 environment, expected, message, postconditions)

    try:
        installed = root / 'prefix with spaces'
        link = installed / 'bin' / 'ukai-vm'

        def version_runs():
            version = subprocess.run([str(link), 'version', '--json'], env=environment, capture_output=True, text=True)
            (root / 'version.json').write_text(version.stdout)
            return version.returncode == 0

        invoke('install', source, installed, 0, 'Installed ', [('installed-command-runs', version_runs)])
        invoke('repeat-refused', source, installed, 2, 'Already installed:')
        unrelated = root / 'unrelated'
        (unrelated / 'bin').mkdir(parents=True)
        marker = unrelated / 'bin' / 'ukai-vm'
        marker.write_text('preserve me')
        invoke('unrelated-refused', source, unrelated, 2, 'unrelated command:',
               [('unrelated-command-preserved', lambda: marker.read_text() == 'preserve me')])
        for case, filename, expected in [('manifest-tamper', 'SHA256SUMS', 'manifest checksum mismatch'),
                                         ('payload-tamper', 'payload/image/vz', 'Package checksum mismatch')]:
            clone = root / case
            subprocess.run(['/bin/cp', '-cR', str(source), str(clone)], check=True)
            target = clone / filename
            with target.open('ab') as output:
                output.write(b'tampered')
            destination = root / (case + '-prefix')
            invoke(case, clone, destination, 1, expected,
                   [('nothing-installed', lambda destination=destination: not os.path.lexists(destination))])
    finally:
        (root / 'summary.json').write_text(json.dumps(summary(results), indent=2) + '\n')


if __name__ == '__main__':
    main()

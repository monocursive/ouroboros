import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import check_install

HERE = Path(__file__).resolve().parent
ENVIRONMENT = {key: value for key, value in os.environ.items() if key != 'PYTHONOPTIMIZE'}


def exits(code, text):
    return [sys.executable, '-c', f'import sys; print({text!r}, file=sys.stderr); sys.exit({code})']


def passed_case(name):
    return {'case': name, 'exit_code': 0, 'passed': True, 'failed_checks': []}


class CaseRecordingTests(unittest.TestCase):
    def test_failed_postcondition_is_recorded_before_the_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            leftover = root / 'payload-tamper-prefix'
            leftover.mkdir()
            results = [passed_case(name) for name in check_install.CASES[:-1]]
            with self.assertRaises(check_install.CaseFailed):
                check_install.run_case(results, root, 'payload-tamper', exits(1, 'Package checksum mismatch.'),
                                       ENVIRONMENT, 1, 'Package checksum mismatch',
                                       [('nothing-installed', lambda: not os.path.lexists(leftover))])
            self.assertEqual(results[-1], {'case': 'payload-tamper', 'exit_code': 1, 'passed': False,
                                           'failed_checks': ['nothing-installed']})
            self.assertFalse(check_install.summary(results)['passed'])

    def test_postcondition_error_is_a_failed_check(self):
        def unreadable():
            raise FileNotFoundError('marker removed')

        with tempfile.TemporaryDirectory() as temporary:
            results = []
            with self.assertRaises(check_install.CaseFailed):
                check_install.run_case(results, Path(temporary), 'unrelated-refused', exits(2, 'unrelated command:'),
                                       ENVIRONMENT, 2, 'unrelated command:', [('preserved', unreadable)])
            self.assertEqual(results[0]['failed_checks'], ['preserved'])

    def test_exit_code_and_message_are_both_required(self):
        for argv in (exits(0, 'Package checksum mismatch.'), exits(1, 'something else')):
            with self.subTest(argv=argv), tempfile.TemporaryDirectory() as temporary:
                results = []
                with self.assertRaises(check_install.CaseFailed):
                    check_install.run_case(results, Path(temporary), 'payload-tamper', argv, ENVIRONMENT, 1,
                                           'Package checksum mismatch')
                self.assertFalse(results[0]['passed'])

    def test_case_passes_only_when_every_check_holds(self):
        with tempfile.TemporaryDirectory() as temporary:
            results = []
            check_install.run_case(results, Path(temporary), 'install', exits(0, 'Installed x'), ENVIRONMENT, 0,
                                   'Installed ', [('runs', lambda: True)])
            self.assertEqual(results, [passed_case('install')])

    def test_summary_requires_every_case_in_order(self):
        complete = [passed_case(name) for name in check_install.CASES]
        self.assertTrue(check_install.summary(complete)['passed'])
        for results in (complete[:-1], complete + [passed_case('install')], list(reversed(complete)),
                        complete[:-1] + [dict(complete[-1], passed=False)]):
            with self.subTest(results=[r['case'] for r in results]):
                self.assertFalse(check_install.summary(results)['passed'])

    def test_refuses_optimized_python(self):
        script = str(HERE / 'check_install.py')
        normal = subprocess.run([sys.executable, script, '--help'], env=ENVIRONMENT, capture_output=True, text=True)
        self.assertEqual(normal.returncode, 0, normal.stderr)
        optimized = subprocess.run([sys.executable, '-O', script, '--help'], env=ENVIRONMENT,
                                   capture_output=True, text=True)
        self.assertNotEqual(optimized.returncode, 0)
        self.assertIn('must not run with python -O', optimized.stderr)


FAKE_INSTALLER = r'''#!/bin/bash
set -eu
prefix="$2"
here="$(cd -- "$(dirname -- "$0")" && pwd -P)"
destination="$prefix/share/ukai-vm/test"
link="$prefix/bin/ukai-vm"
[[ ! -e "$destination" ]] || { echo "Already installed: $destination" >&2; exit 2; }
[[ ! -e "$link" ]] || { @UNRELATED@ echo "Refusing to replace an existing unrelated command: $link" >&2; exit 2; }
if grep -q tampered "$here/SHA256SUMS"; then echo 'Package manifest checksum mismatch.' >&2; exit 1; fi
if grep -q tampered "$here/payload/image/vz"; then @PAYLOAD@ echo 'Package checksum mismatch.' >&2; exit 1; fi
mkdir -p "$destination/bin" "$prefix/bin"
cp "$here/payload/bin/ukai-vm" "$destination/bin/ukai-vm"
ln -s "$destination/bin/ukai-vm" "$link"
printf '\nInstalled %s\n' "$link"
'''


@unittest.skipUnless(sys.platform == 'darwin', 'the installer check clones volumes with macOS cp -c')
class InstallerCheckTests(unittest.TestCase):
    def check(self, unrelated=':;', payload=':;'):
        with tempfile.TemporaryDirectory() as temporary:
            volume = Path(temporary) / 'volume'
            (volume / 'payload' / 'image').mkdir(parents=True)
            (volume / 'payload' / 'bin').mkdir()
            (volume / 'payload' / 'image' / 'vz').write_text('helper\n')
            (volume / 'payload' / 'bin' / 'ukai-vm').write_text('#!/bin/sh\necho \'{"component":"ukai-vm"}\'\n')
            (volume / 'payload' / 'bin' / 'ukai-vm').chmod(0o755)
            (volume / 'SHA256SUMS').write_text('manifest\n')
            (volume / 'install.sh').write_text(FAKE_INSTALLER.replace('@UNRELATED@', unrelated)
                                               .replace('@PAYLOAD@', payload))
            out = Path(temporary) / 'out'
            result = subprocess.run([sys.executable, str(HERE / 'check_install.py'), '--volume', str(volume),
                                     '--out', str(out)], env=ENVIRONMENT, capture_output=True, text=True)
            return result.returncode, json.loads((out / 'summary.json').read_text())

    def test_honest_installer_passes(self):
        code, summary = self.check()
        self.assertEqual(code, 0)
        self.assertTrue(summary['passed'])
        self.assertEqual([r['case'] for r in summary['results']], list(check_install.CASES))

    def test_install_after_refused_tamper_fails_the_summary(self):
        code, summary = self.check(payload='mkdir -p "$prefix";')
        self.assertNotEqual(code, 0)
        self.assertFalse(summary['passed'])
        self.assertEqual(summary['results'][-1]['failed_checks'], ['nothing-installed'])

    def test_overwritten_unrelated_command_fails_the_summary(self):
        code, summary = self.check(unrelated='echo replaced > "$link";')
        self.assertNotEqual(code, 0)
        self.assertFalse(summary['passed'])
        self.assertEqual(summary['results'][-1]['failed_checks'], ['unrelated-command-preserved'])


if __name__ == '__main__':
    unittest.main()

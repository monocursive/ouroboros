"""Exercise the installer's actual shell functions against SemVer examples."""
from pathlib import Path
import subprocess
import unittest

from package import VERSION

script = Path(__file__).with_name('install.sh').read_text()
validation = script[script.index('valid_version() {'):script.index('\nvalid_version "$staged_version"')]
comparison = script[script.index('version_relation() {'):script.index('\nmkdir -p "$prefix"')]


class VersionTests(unittest.TestCase):
    def shell(self, expression, *args):
        return subprocess.run(['sh', '-c', validation + '\n' + comparison + '\n' + expression,
                               'test-versions', *args], capture_output=True, text=True, timeout=5)

    def test_semver_precedence(self):
        ordered = ['1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta',
                   '1.0.0-beta', '1.0.0-beta.2', '1.0.0-beta.11',
                   '1.0.0-rc.1', '1.0.0-rc.2', '1.0.0-rc.10', '1.0.0']
        pairs = list(zip(ordered, ordered[1:])) + [
            ('1.0.0-1', '1.0.0-a'),
            ('1.0.0-99999999999999999999', '1.0.0-100000000000000000000'),
            ('99999999999999999999.0.0', '100000000000000000000.0.0')]
        for older, newer in pairs:
            for a, b, expected in [(older, newer, '-1'), (newer, older, '1')]:
                with self.subTest(a=a, b=b):
                    result = self.shell('version_relation "$1" "$2"', a, b)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), expected)
        result = self.shell('version_relation "$1" "$2"', '1.0.0+one', '1.0.0+two')
        self.assertEqual(result.stdout.strip(), '0')

    def test_packager_and_installer_agree_on_version_syntax(self):
        for valid in ['0.0.0', '1.0.0-rc.10', '1.0.0-0', '1.0.0-01a', '1.0.0+001.test']:
            self.assertIsNotNone(VERSION.fullmatch(valid), valid)
            self.assertEqual(self.shell('valid_version "$1"', valid).returncode, 0, valid)
        for invalid in ['', '01.0.0', '1.0.0-01', '1.0.0-rc..1', '1.0.0-rc.',
                        '1.0.0+build..a', '1.0.0+', '../1.0.0', '1.0.0\n2.0.0']:
            self.assertIsNone(VERSION.fullmatch(invalid), invalid)
            self.assertNotEqual(self.shell('valid_version "$1"', invalid).returncode, 0, invalid)


if __name__ == '__main__':
    unittest.main()

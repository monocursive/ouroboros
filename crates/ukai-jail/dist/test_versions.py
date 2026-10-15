"""Exercise both installers' actual shell functions against SemVer examples.

The public Bash bootstrap (root install.sh) and the signed POSIX installer
(dist/install.sh) implement version validation and ordering separately; the
same corpus runs against each, so they cannot drift apart.
"""
from pathlib import Path
import subprocess
import textwrap
import unittest

from package import VERSION

ROOT = Path(__file__).resolve().parents[3]


def between(script, start, end):
    first = script.index(start)
    return script[first:script.index(end, first)]


def signed_installer():
    script = Path(__file__).with_name('install.sh').read_text()
    functions = (between(script, 'valid_version() {', '\nvalid_version "$staged_version"') + '\n'
                 + between(script, 'version_relation() {', '\nmkdir -p "$prefix"'))
    return ['sh', '-c'], functions


def bootstrap():
    script = (ROOT / 'install.sh').read_text()
    functions = (between(script, "    number='", '    valid_version "$version"') + '\n'
                 + between(script, '    version_relation() {', '\n    mkdir -p "$prefix"'))
    return ['bash', '-c'], textwrap.dedent(functions)


INSTALLERS = {'dist/install.sh': signed_installer, 'install.sh': bootstrap}


class VersionTests(unittest.TestCase):
    def shell(self, installer, expression, *args):
        command, functions = INSTALLERS[installer]()
        return subprocess.run(command + [functions + '\n' + expression, 'test-versions', *args],
                              capture_output=True, text=True, timeout=5)

    def test_semver_precedence(self):
        ordered = ['1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta',
                   '1.0.0-beta', '1.0.0-beta.2', '1.0.0-beta.11',
                   '1.0.0-rc.1', '1.0.0-rc.2', '1.0.0-rc.10', '1.0.0']
        pairs = list(zip(ordered, ordered[1:])) + [
            ('1.0.0-1', '1.0.0-a'),
            ('1.0.0-99999999999999999999', '1.0.0-100000000000000000000'),
            ('99999999999999999999.0.0', '100000000000000000000.0.0')]
        for installer in INSTALLERS:
            for older, newer in pairs:
                for a, b, expected in [(older, newer, '-1'), (newer, older, '1')]:
                    with self.subTest(installer=installer, a=a, b=b):
                        result = self.shell(installer, 'version_relation "$1" "$2"', a, b)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout.strip(), expected)
            with self.subTest(installer=installer, build_metadata=True):
                result = self.shell(installer, 'version_relation "$1" "$2"', '1.0.0+one', '1.0.0+two')
                self.assertEqual(result.stdout.strip(), '0')

    def test_packager_and_installers_agree_on_version_syntax(self):
        valid = ['0.0.0', '1.0.0-rc.10', '1.0.0-0', '1.0.0-01a', '1.0.0+001.test']
        invalid = ['', '01.0.0', '1.0.0-01', '1.0.0-rc..1', '1.0.0-rc.',
                   '1.0.0+build..a', '1.0.0+', '../1.0.0', '1.0.0\n2.0.0']
        for version in valid:
            self.assertIsNotNone(VERSION.fullmatch(version), version)
        for version in invalid:
            self.assertIsNone(VERSION.fullmatch(version), version)
        for installer in INSTALLERS:
            for version in valid:
                with self.subTest(installer=installer, valid=version):
                    self.assertEqual(self.shell(installer, 'valid_version "$1"', version).returncode, 0)
            for version in invalid:
                with self.subTest(installer=installer, invalid=version):
                    self.assertNotEqual(self.shell(installer, 'valid_version "$1"', version).returncode, 0)


if __name__ == '__main__':
    unittest.main()

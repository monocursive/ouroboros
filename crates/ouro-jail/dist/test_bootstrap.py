"""Real signed downloads with a local curl adapter; no public release is required."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from package import create_archive

ROOT = Path(__file__).resolve().parents[3]


@unittest.skipUnless(shutil.which('minisign'), 'minisign is required')
class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ouro-bootstrap-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / 'artifacts'
        self.shims = self.root / 'shims'
        self.shims.mkdir()
        self.prefix = self.root / 'installed bin'
        self.log = self.root / 'curl.log'
        subprocess.run(['minisign', '-G', '-W', '-s', str(self.root / 'key'),
                        '-p', str(self.root / 'public')], check=True, capture_output=True)
        self.key = (self.root / 'public').read_text().splitlines()[1]
        self.binary = self.root / 'binary'
        self.binary.write_text("#!/bin/sh\nprintf 'ouro-jail 0.1.0\\nplatform test\\n'\n")
        self.binary.chmod(0o755)
        self.package('0.1.0-rc.1')
        self.shim('uname', '#!/bin/sh\ncase "$1" in\n-s) echo "${BOOTSTRAP_OS:-Linux}";;\n-m) echo "${BOOTSTRAP_ARCH:-x86_64}";;\nesac\n')
        self.shim('getconf', '#!/bin/sh\nprintf "%s\\n" "${BOOTSTRAP_LIBC:-glibc 2.39}"\n')
        self.shim('curl', '''#!/bin/sh
printf '%s\\n' "$@" >> "$BOOTSTRAP_LOG"
url= output=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) output=$2; shift 2 ;;
        https://*) url=$1; shift ;;
        *) shift ;;
    esac
done
[ -n "$output" ] && [ -n "$url" ] || exit 2
cp "$BOOTSTRAP_ARTIFACTS/${url##*/}" "$output"
''')
        self.env = {**os.environ, 'PATH': str(self.shims) + ':' + os.environ['PATH'],
                    'BOOTSTRAP_ARTIFACTS': str(self.artifacts), 'BOOTSTRAP_LOG': str(self.log)}

    def shim(self, name, contents):
        path = self.shims / name
        path.write_text(contents)
        path.chmod(0o755)

    def package(self, release, target='x86_64-unknown-linux-gnu'):
        self.archive = create_archive(self.binary, target, self.artifacts, release)
        shutil.copyfile(ROOT / 'crates/ouro-jail/dist/install.sh', self.artifacts / 'install.sh')
        self.sign()

    def sign(self):
        files = [self.archive, self.artifacts / 'install.sh']
        (self.artifacts / 'SHA256SUMS').write_text(''.join(
            f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files))
        subprocess.run(['minisign', '-Sm', str(self.artifacts / 'SHA256SUMS'),
                        '-s', str(self.root / 'key')], check=True, capture_output=True)

    def run_installer(self, *args, pipe=False):
        command = ['bash', '-s', '--'] if pipe else ['bash', str(ROOT / 'install.sh')]
        return subprocess.run(command + ['--public-key', self.key, '--bin-dir', str(self.prefix), *args],
                              input=(ROOT / 'install.sh').read_bytes() if pipe else b'',
                              env=self.env, capture_output=True, timeout=20)

    def test_piped_install_and_repeat_upgrade_from_exact_preview(self):
        for pipe in [True, False]:
            result = self.run_installer(pipe=pipe)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual((self.prefix / 'ouro-jail').read_bytes(), self.binary.read_bytes())
        urls = [line for line in self.log.read_text().splitlines() if line.startswith('https://')]
        self.assertEqual(len(urls), 8)
        self.assertTrue(all('/releases/download/ouro-jail-v0.1.0-rc.1/' in url for url in urls))
        self.assertNotIn('/latest/', '\n'.join(urls))
        flags = self.log.read_text()
        self.assertIn('--disable\n', flags)
        self.assertIn('--proto\n=https\n', flags)
        self.assertIn('--proto-redir\n=https\n', flags)

    def test_version_selection_and_authenticated_downgrade_refusal(self):
        self.package('0.1.0-rc.10')
        result = self.run_installer('--version', 'ouro-jail-v0.1.0-rc.10')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.package('0.1.0-rc.2')
        result = self.run_installer('--version', 'v0.1.0-rc.2')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'downgrade', result.stderr)
        self.assertEqual((self.prefix / 'ouro-jail.release').read_text().splitlines()[0], '0.1.0-rc.10')
        self.assertEqual(self.run_installer('--version', '0.1.0-rc.2', '--allow-downgrade').returncode, 0)

    def test_wrong_key_archive_and_installer_tampering_preserve_install(self):
        self.assertEqual(self.run_installer().returncode, 0)
        before = (self.prefix / 'ouro-jail').read_bytes()
        for name in ['install.sh', self.archive.name, 'SHA256SUMS']:
            file = self.artifacts / name
            original = file.read_bytes()
            file.write_bytes(original + b'\ntampered\n')
            result = self.run_installer()
            self.assertNotEqual(result.returncode, 0, name)
            self.assertEqual((self.prefix / 'ouro-jail').read_bytes(), before)
            file.write_bytes(original)
        subprocess.run(['minisign', '-G', '-W', '-s', str(self.root / 'wrong-key'),
                        '-p', str(self.root / 'wrong-public')], check=True, capture_output=True)
        wrong = (self.root / 'wrong-public').read_text().splitlines()[1]
        self.assertNotEqual(self.run_installer('--public-key', wrong).returncode, 0)
        self.assertEqual((self.prefix / 'ouro-jail').read_bytes(), before)

    def test_arm64_selection_and_offline_install(self):
        self.env['BOOTSTRAP_ARCH'] = 'aarch64'
        self.package('0.1.0-rc.1', 'aarch64-unknown-linux-gnu')
        result = self.run_installer('--from-dir', str(self.artifacts))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse(self.log.exists())

    def test_missing_invalid_arguments_and_unsupported_hosts_fail_before_download(self):
        for args in [('--version',), ('--version', '../v1.0.0'), ('--version', '01.0.0'),
                     ('--version', '1.0.0-01'), ('--bin-dir', 'relative'),
                     ('--base-url', 'http://example.com'), ('--unknown',)]:
            with self.subTest(args=args):
                self.assertNotEqual(self.run_installer(*args).returncode, 0)
                self.assertFalse(self.log.exists())
        for system, arch in [('Darwin', 'arm64'), ('Linux', 'riscv64')]:
            self.env['BOOTSTRAP_OS'] = system
            self.env['BOOTSTRAP_ARCH'] = arch
            self.assertNotEqual(self.run_installer().returncode, 0)
            self.assertFalse(self.log.exists())
        self.env['BOOTSTRAP_OS'] = 'Linux'
        self.env['BOOTSTRAP_ARCH'] = 'x86_64'
        for libc in ['glibc 2.38', 'musl 1.2.5', 'glibc invalid']:
            self.env['BOOTSTRAP_LIBC'] = libc
            self.assertNotEqual(self.run_installer().returncode, 0)
            self.assertFalse(self.log.exists())

    def test_wrong_release_and_truncated_pipe_do_not_install(self):
        self.package('0.1.0-rc.2')
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertFalse(self.prefix.exists())
        incomplete = (ROOT / 'install.sh').read_bytes().split(b'    fetch SHA256SUMS')[0]
        result = subprocess.run(['bash', '-s', '--', '--public-key', self.key], input=incomplete,
                                env=self.env, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.prefix.exists())

    def test_existing_destination_directories_and_symlinks_are_preserved(self):
        self.prefix.mkdir()
        for name in ['ouro-jail', 'ouro-jail.release', 'ouro-jail.LICENSES.txt']:
            destination = self.prefix / name
            destination.mkdir()
            self.assertNotEqual(self.run_installer().returncode, 0)
            self.assertEqual(list(destination.iterdir()), [])
            destination.rmdir()
            untouched = self.root / ('existing-' + name)
            untouched.write_bytes(b'preserve me')
            destination.symlink_to(untouched)
            self.assertNotEqual(self.run_installer().returncode, 0)
            self.assertEqual(untouched.read_bytes(), b'preserve me')
            self.assertTrue(destination.is_symlink())
            destination.unlink()


if __name__ == '__main__':
    unittest.main()

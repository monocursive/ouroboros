"""Exercise pinned downloads and installation without a Minisign dependency."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from bootstrap import archive_pins, render_bootstrap
from package import create_archive

ROOT = Path(__file__).resolve().parents[3]
TARGETS = ['x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu']


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
        self.installer = self.root / 'install.sh'
        self.installer.write_text((ROOT / 'install.sh').read_text())
        self.binary = self.root / 'binary'
        self.binary.write_text("#!/bin/sh\nprintf 'ouro-jail 0.1.0\\nplatform test\\n'\n")
        self.binary.chmod(0o755)
        self.package('0.1.0-rc.1')
        self.shim('uname', '#!/bin/sh\ncase "$1" in\n-s) echo "${BOOTSTRAP_OS:-Linux}";;\n-m) echo "${BOOTSTRAP_ARCH:-x86_64}";;\nesac\n')
        self.shim('getconf', '#!/bin/sh\nprintf "%s\\n" "${BOOTSTRAP_LIBC:-glibc 2.39}"\n')
        # A call to Minisign is always an error, even if it is on the host PATH.
        self.shim('minisign', '#!/bin/sh\nprintf "unexpected minisign invocation\\n" >&2\nexit 77\n')
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

    def package(self, release):
        hashes = {}
        for target in TARGETS:
            archive = create_archive(self.binary, target, self.artifacts, release)
            hashes[target] = hashlib.sha256(archive.read_bytes()).hexdigest()
        # Only the trusted test script is repinned; there is no runtime hash override.
        self.installer.write_text(render_bootstrap(self.installer.read_text(), release, hashes))
        self.archive = self.artifacts / f'ouro-jail-{release}-{TARGETS[0]}.tar.gz'

    def run_installer(self, *args, pipe=False):
        command = ['bash', '-s', '--'] if pipe else ['bash', str(self.installer)]
        return subprocess.run(command + ['--bin-dir', str(self.prefix), *args],
                              input=self.installer.read_bytes() if pipe else b'',
                              env=self.env, capture_output=True, timeout=20)

    def test_piped_install_and_repeat_upgrade_without_signature_tools(self):
        for pipe in [True, False]:
            result = self.run_installer(pipe=pipe)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual((self.prefix / 'ouro-jail').read_bytes(), self.binary.read_bytes())
        urls = [line for line in self.log.read_text().splitlines() if line.startswith('https://')]
        self.assertEqual(len(urls), 2)
        self.assertTrue(all('/releases/download/ouro-jail-v0.1.0-rc.1/' in url for url in urls))
        self.assertTrue(all(url.endswith(self.archive.name) for url in urls))
        flags = self.log.read_text()
        self.assertIn('--disable\n', flags)
        self.assertIn('--proto\n=https\n', flags)
        self.assertIn('--proto-redir\n=https\n', flags)
        self.assertEqual((self.prefix / 'ouro-jail.release').read_text().splitlines(),
                         ['0.1.0-rc.1', hashlib.sha256(self.binary.read_bytes()).hexdigest()])

    def test_version_selection_and_downgrade_refusal(self):
        self.package('0.1.0-rc.10')
        self.assertEqual(self.run_installer('--version', 'ouro-jail-v0.1.0-rc.10').returncode, 0)
        self.package('0.1.0-rc.2')
        result = self.run_installer('--version', 'v0.1.0-rc.2')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'downgrade', result.stderr)
        self.assertEqual((self.prefix / 'ouro-jail.release').read_text().splitlines()[0], '0.1.0-rc.10')
        self.assertEqual(self.run_installer('--version', '0.1.0-rc.2', '--allow-downgrade').returncode, 0)

    def test_changed_archive_and_remote_checksum_cannot_replace_install(self):
        self.assertEqual(self.run_installer().returncode, 0)
        before = {name: (self.prefix / name).read_bytes()
                  for name in ['ouro-jail', 'ouro-jail.release', 'ouro-jail.LICENSES.txt']}
        # Replace both package and server-side manifest: the embedded pin still wins.
        self.archive.write_bytes(self.archive.read_bytes() + b'\ntampered\n')
        (self.artifacts / 'SHA256SUMS').write_text(
            hashlib.sha256(self.archive.read_bytes()).hexdigest() + '  ' + self.archive.name + '\n')
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'checksum verification failed', result.stderr)
        for name, content in before.items():
            self.assertEqual((self.prefix / name).read_bytes(), content)
        self.assertFalse(any(self.prefix.glob('.ouro-jail*')))

    def test_arm64_offline_install_and_https_mirror_use_the_same_pins(self):
        self.env['BOOTSTRAP_ARCH'] = 'aarch64'
        result = self.run_installer('--from-dir', str(self.artifacts))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse(self.log.exists())
        self.assertEqual(self.run_installer('--base-url', 'https://mirror.example/release').returncode, 0)
        self.assertIn('https://mirror.example/release/ouro-jail-0.1.0-rc.1-aarch64-', self.log.read_text())
        archive = self.artifacts / 'ouro-jail-0.1.0-rc.1-aarch64-unknown-linux-gnu.tar.gz'
        archive.write_bytes(b'corrupted ARM archive')
        result = self.run_installer('--from-dir', str(self.artifacts))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'checksum verification failed', result.stderr)

    def test_missing_invalid_arguments_and_unsupported_hosts_fail_before_download(self):
        for args in [('--version',), ('--version', '../v1.0.0'), ('--version', '01.0.0'),
                     ('--version', '1.0.0-01'), ('--version', '0.1.0-rc.99'),
                     ('--bin-dir', 'relative'), ('--base-url', 'http://example.com'),
                     ('--public-key', 'anything'), ('--unknown',),
                     ('--from-dir', str(self.artifacts), '--base-url', 'https://example.com')]:
            with self.subTest(args=args):
                self.assertNotEqual(self.run_installer(*args).returncode, 0)
                self.assertFalse(self.log.exists())
        result = self.run_installer('--version', '0.1.0-rc.99')
        self.assertIn(b'no pinned SHA-256', result.stderr)
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

    def test_wrong_archive_and_truncated_pipe_do_not_install(self):
        self.archive.unlink()
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertFalse(self.prefix.exists())
        incomplete = self.installer.read_bytes().split(b'    fetch "$artifact"')[0]
        result = subprocess.run(['bash', '-s', '--'], input=incomplete,
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

    def test_published_pins_and_website_copy_are_consistent(self):
        script = (ROOT / 'install.sh').read_text()
        self.assertEqual(script, (ROOT / 'website/public/install.sh').read_text())
        pins = archive_pins(script)
        self.assertEqual({target for release, target in pins if release == '0.1.0-rc.1'}, set(TARGETS))
        self.assertNotIn('minisign', script)
        self.assertNotIn('SHA256SUMS', script)


if __name__ == '__main__':
    unittest.main()

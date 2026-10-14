"""Exercise pinned downloads and installation without a Minisign dependency."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from bootstrap import archive_pins, render_bootstrap, render_vm_pin
from coordinates import JAIL_VERSION, LINUX_TARGETS, VM_TARGET, VM_VERSION, vm_tag
from package import create_archive

ROOT = Path(__file__).resolve().parents[3]
TARGETS = list(LINUX_TARGETS)


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

    def test_published_installer_pins_the_release_coordinates(self):
        script = (ROOT / 'install.sh').read_text()
        pins = archive_pins(script)
        self.assertEqual({target for release, target in pins if release == JAIL_VERSION}, set(TARGETS))
        self.assertIn((VM_VERSION, VM_TARGET), pins)
        self.assertIn(f'\n    version={JAIL_VERSION}\n', script)
        self.assertIn(f'\n    macos_version={VM_VERSION}\n', script)
        self.assertNotIn('minisign', script)
        self.assertNotIn('SHA256SUMS', script)
        # The website serves this file itself (website/src/pages/install.sh.ts);
        # a second copy could drift from it.
        self.assertFalse((ROOT / 'website/public/install.sh').exists())

    def test_vm_pin_rendering_keeps_linux_pins_and_sets_the_mac_default(self):
        script = (ROOT / 'install.sh').read_text()
        rendered = render_vm_pin(script, '0.1.0-preview.9', 'c' * 64)
        pins = archive_pins(rendered)
        self.assertEqual(pins['0.1.0-preview.9', VM_TARGET], 'c' * 64)
        self.assertEqual({k: v for k, v in pins.items() if k[1] != VM_TARGET},
                         {k: v for k, v in archive_pins(script).items() if k[1] != VM_TARGET})
        self.assertIn('\n    macos_version=0.1.0-preview.9\n', rendered)
        self.assertIn(f'\n    version={JAIL_VERSION}\n', rendered)
        # A Linux release keeps the macOS pins it does not name.
        relinked = render_bootstrap(rendered, '0.1.0-rc.9', {t: 'd' * 64 for t in TARGETS})
        self.assertEqual(archive_pins(relinked)['0.1.0-preview.9', VM_TARGET], 'c' * 64)
        for version, digest in [('01.0.0', 'c' * 64), ('0.1.0-preview.9', 'C' * 64)]:
            with self.assertRaises(ValueError):
                render_vm_pin(script, version, digest)
        with self.assertRaises(ValueError):
            render_bootstrap(script, '0.1.0-rc.9', {VM_TARGET: 'd' * 64})

    def test_signed_installer_sends_macos_to_the_vm_preview(self):
        # Only Linux archives are released; a Mac must not look for a Darwin one.
        self.env.update(BOOTSTRAP_OS='Darwin', BOOTSTRAP_ARCH='arm64')
        result = subprocess.run(['sh', str(Path(__file__).with_name('install.sh')), '--from-dir',
                                 str(self.artifacts), '--public-key', 'unused', '--prefix', str(self.prefix)],
                                env=self.env, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'Ouro VM preview', result.stderr)
        self.assertFalse(self.prefix.exists())

    def mac_fixture(self):
        self.env.update(BOOTSTRAP_OS='Darwin', BOOTSTRAP_ARCH='arm64')
        self.shim('sw_vers', '#!/bin/sh\necho "${BOOTSTRAP_MACOS:-27.0.1}"\n')
        self.mac_log = self.root / 'mount.log'
        self.env['BOOTSTRAP_MOUNT_LOG'] = str(self.mac_log)
        self.shim('hdiutil', '''#!/bin/sh
printf '%s\\n' "$@" >> "$BOOTSTRAP_MOUNT_LOG"
if [ "$1" = attach ]; then
    while [ "$1" != -mountpoint ]; do shift; done
    cat > "$2/install.sh" <<'INSTALL'
#!/bin/sh
printf '%s\\n' "$@" >> "$BOOTSTRAP_MOUNT_LOG"
exit "${BOOTSTRAP_INSTALL_STATUS:-0}"
INSTALL
fi
''')
        dmg = self.artifacts / f'ouro-vm-{VM_VERSION}-{VM_TARGET}.dmg'
        dmg.write_bytes(b'checksum-verified test disk image')
        self.installer.write_text(render_vm_pin(self.installer.read_text(), VM_VERSION,
                                                hashlib.sha256(dmg.read_bytes()).hexdigest()))
        return dmg

    def run_mac(self, *args):
        return subprocess.run(['bash', '-s', '--', '--vm-prefix', str(self.root / 'Mac prefix'), *args],
                              input=self.installer.read_bytes(), env=self.env,
                              capture_output=True, timeout=20)

    def test_mac_pinned_download_mount_install_and_eject(self):
        dmg = self.mac_fixture()
        result = self.run_mac()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertIn(f'/releases/download/{vm_tag(VM_VERSION)}/' + dmg.name, self.log.read_text())
        mount = self.mac_log.read_text()
        self.assertIn('-readonly\n', mount)
        self.assertIn('--prefix\n' + str(self.root / 'Mac prefix'), mount)
        self.assertIn('detach\n', mount)
        self.log.unlink()
        result = self.run_mac('--version', vm_tag(VM_VERSION), '--from-dir', str(self.artifacts))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse(self.log.exists())

    def test_mac_tampering_fails_before_mount_or_install(self):
        dmg = self.mac_fixture()
        dmg.write_bytes(b'tampered')
        result = self.run_mac()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'checksum verification failed', result.stderr)
        self.assertFalse(self.mac_log.exists())

    def test_mac_install_failure_still_ejects(self):
        self.mac_fixture()
        self.env['BOOTSTRAP_INSTALL_STATUS'] = '2'
        self.assertEqual(self.run_mac().returncode, 2)
        self.assertIn('detach\n', self.mac_log.read_text())

    def test_mac_unsupported_hosts_and_options_refuse_before_download(self):
        self.mac_fixture()
        for args in [('--version', '0.1.0-preview.99'), ('--vm-prefix', 'relative'),
                     ('--bin-dir', str(self.prefix)), ('--allow-downgrade',)]:
            self.assertNotEqual(self.run_mac(*args).returncode, 0)
            self.assertFalse(self.log.exists())
        self.env['BOOTSTRAP_MACOS'] = '26.1'
        self.assertNotEqual(self.run_mac().returncode, 0)
        self.env['BOOTSTRAP_MACOS'] = '27.0'
        self.env['BOOTSTRAP_ARCH'] = 'x86_64'
        self.assertNotEqual(self.run_mac().returncode, 0)
        self.assertFalse(self.log.exists())
        self.assertFalse(self.mac_log.exists())


if __name__ == '__main__':
    unittest.main()

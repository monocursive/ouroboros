#!/usr/bin/env python3
"""Local signature/install regression using an ephemeral test key, never a release identity."""
import argparse
import pathlib
import platform
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('binary', type=pathlib.Path)
args = parser.parse_args()
source = pathlib.Path(__file__).resolve().parent
host = platform.machine()
triple = ('aarch64' if host in ('arm64', 'aarch64') else 'x86_64') + ('-apple-darwin' if platform.system() == 'Darwin' else '-unknown-linux-gnu')
release = '0.1.0-rc.1'
with tempfile.TemporaryDirectory(prefix='ouro-install-test-') as tmp:
    root = pathlib.Path(tmp)
    subprocess.run(['minisign', '-G', '-W', '-s', str(root/'test.key'), '-p', str(root/'test.pub')], check=True, capture_output=True)
    key = (root/'test.pub').read_text().splitlines()[1]
    artifacts = root/'artifacts'
    artifacts.mkdir()
    # An archive left in --out by an earlier invocation is not signed by this one.
    (artifacts/f'ouro-jail-0.0.1-{triple}.tar.gz').write_bytes(b'left over')
    subprocess.run(['python3', str(source/'package.py'), '--binary', str(args.binary.resolve()), '--target', triple,
                    '--version', release, '--out', str(artifacts), '--signing-key', str(root/'test.key')], check=True, capture_output=True)
    manifest = (artifacts/'SHA256SUMS').read_text().splitlines()
    assert sorted(line.split('  ')[1] for line in manifest) == sorted(
        [f'ouro-jail-{release}-{triple}.tar.gz', 'install.sh']), manifest
    assert (artifacts/'install.sh').read_bytes() == (source/'install.sh').read_bytes()
    (artifacts/f'ouro-jail-0.0.1-{triple}.tar.gz').unlink()
    command = ['sh', str(source/'install.sh'), '--from-dir', str(artifacts), '--public-key', key, '--prefix', str(root/'installed')]
    def run(extra=()):
        return subprocess.run(command + list(extra), stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
    assert run().returncode == 0
    installed = (root/'installed/ouro-jail').read_bytes()
    record = root/'installed/ouro-jail.release'
    assert record.read_text().splitlines()[0] == release
    assert run().returncode != 0
    assert run(['--upgrade']).returncode == 0
    # The installer ships beside the artifacts under the same signature; a
    # doctored copy refuses before anything is installed.
    keep = (artifacts/'install.sh').read_bytes()
    (artifacts/'install.sh').write_bytes(keep + b'# tampered\n')
    result = run(['--upgrade'])
    assert result.returncode != 0 and b'install.sh' in result.stderr, result.stderr
    assert (root/'installed/ouro-jail').read_bytes() == installed
    (artifacts/'install.sh').write_bytes(keep)
    # Identical binaries can be signed under distinct RC coordinates. The
    # package's `version` output cannot establish their ordering.
    original_command = command.copy()
    for candidate, expected in [('0.1.0-rc.10', 0), ('0.1.0-rc.2', 1), ('0.1.0-rc.1', 1)]:
        directory = root/candidate
        subprocess.run(['python3', str(source/'package.py'), '--binary', str(args.binary.resolve()),
                        '--target', triple, '--version', candidate, '--out', str(directory),
                        '--signing-key', str(root/'test.key')], check=True, capture_output=True)
        command = original_command.copy()
        command[command.index('--from-dir') + 1] = str(directory)
        result = run(['--upgrade'])
        assert result.returncode == expected, (candidate, result.stderr)
        if expected:
            assert b'downgrade' in result.stderr, result.stderr
            assert record.read_text().splitlines()[0] == '0.1.0-rc.10'
    assert run(['--upgrade', '--allow-downgrade']).returncode == 0
    assert record.read_text().splitlines()[0] == release
    command = original_command
    # A staged release older than the installed one refuses without an
    # explicit --allow-downgrade; the installed binary survives the refusal.
    installed_file = root/'installed/ouro-jail'
    installed_file.write_text('#!/bin/sh\nprintf \'ouro-jail 9.0.0\\nplatform test\\n\'\n')
    installed_file.chmod(0o755)
    # A mismatched receipt refuses rather than accepting stale release data.
    result = run(['--upgrade'])
    assert result.returncode != 0 and b'does not match' in result.stderr, result.stderr
    assert run(['--upgrade', '--allow-downgrade']).returncode == 0
    assert installed_file.read_bytes() == installed
    installed_file.write_text('#!/bin/sh\nprintf \'ouro-jail 9.0.0\\nplatform test\\n\'\n')
    installed_file.chmod(0o755)
    record.unlink()  # Exercise the documented legacy-install fallback.
    result = run(['--upgrade'])
    assert result.returncode != 0 and b'downgrade' in result.stderr, result.stderr
    assert installed_file.read_text().startswith('#!/bin/sh')
    assert run(['--upgrade', '--allow-downgrade']).returncode == 0
    assert (root/'installed/ouro-jail').read_bytes() == installed
    archive = artifacts/f'ouro-jail-{release}-{triple}.tar.gz'
    archive.write_bytes(archive.read_bytes() + b'corruption')
    result = run(['--upgrade'])
    assert result.returncode != 0 and b'Checksum verification failed' in result.stderr
    assert (root/'installed/ouro-jail').read_bytes() == installed
    (artifacts/'SHA256SUMS').write_text('tampered manifest\n')
    result = run(['--upgrade'])
    assert result.returncode != 0 and b'signature verification failed' in result.stderr
    assert (root/'installed/ouro-jail').read_bytes() == installed
print('PASS: signed RC version ordering, non-TTY install, explicit upgrade and downgrade override, stale record refusal, legacy fallback, installer/archive/signature tampering, installed binary preserved')

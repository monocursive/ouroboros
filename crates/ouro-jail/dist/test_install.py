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
with tempfile.TemporaryDirectory(prefix='ouro-install-test-') as tmp:
    root = pathlib.Path(tmp)
    subprocess.run(['minisign', '-G', '-W', '-s', str(root/'test.key'), '-p', str(root/'test.pub')], check=True, capture_output=True)
    key = (root/'test.pub').read_text().splitlines()[1]
    subprocess.run(['python3', str(source/'package.py'), '--binary', str(args.binary.resolve()), '--target', triple, '--out', str(root/'artifacts'), '--signing-key', str(root/'test.key')], check=True, capture_output=True)
    command = ['sh', str(source/'install.sh'), '--from-dir', str(root/'artifacts'), '--public-key', key, '--prefix', str(root/'installed')]
    def run(extra=()):
        return subprocess.run(command + list(extra), stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
    assert run().returncode == 0
    installed = (root/'installed/ouro-jail').read_bytes()
    assert run().returncode != 0
    assert run(['--upgrade']).returncode == 0
    archive = root/'artifacts'/f'ouro-jail-{triple}.tar.gz'
    archive.write_bytes(archive.read_bytes() + b'corruption')
    result = run(['--upgrade'])
    assert result.returncode != 0 and b'Checksum verification failed' in result.stderr
    assert (root/'installed/ouro-jail').read_bytes() == installed
    (root/'artifacts/SHA256SUMS').write_text('tampered manifest\n')
    result = run(['--upgrade'])
    assert result.returncode != 0 and b'signature verification failed' in result.stderr
    assert (root/'installed/ouro-jail').read_bytes() == installed
print('PASS: non-TTY install, explicit upgrade, corrupt archive rejection, signature rejection, installed binary preserved')

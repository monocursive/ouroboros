#!/usr/bin/env python3
"""Package supplied binaries; signing identity and publication remain operator choices."""
import argparse
import hashlib
import io
import pathlib
import subprocess
import tarfile

parser = argparse.ArgumentParser()
parser.add_argument('--binary', type=pathlib.Path, required=True)
parser.add_argument('--target', required=True, choices=['x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'x86_64-apple-darwin', 'aarch64-apple-darwin'])
parser.add_argument('--out', type=pathlib.Path, required=True)
parser.add_argument('--signing-key', type=pathlib.Path, required=True)
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=True)
name = f'ouro-jail-{args.target}.tar.gz'
with tarfile.open(args.out / name, 'w:gz') as archive:
    archive.add(args.binary, arcname='ouro-jail', recursive=False)
    license_bytes = (pathlib.Path(__file__).resolve().parents[3]/'LICENSE').read_bytes() + b'\n\nwebpki-roots 1.0.9, Mozilla CA certificate data\n\n' + (pathlib.Path(__file__).parent/'WEBPKI_ROOTS_LICENSE').read_bytes()
    notice = tarfile.TarInfo('ouro-jail.LICENSES.txt'); notice.size=len(license_bytes); notice.mode=0o644
    archive.addfile(notice, io.BytesIO(license_bytes))
manifest = args.out / 'SHA256SUMS'
# A manifest covers every archive already supplied to this staging directory.
manifest.write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(args.out.glob('ouro-jail-*.tar.gz'))))
subprocess.run(['minisign', '-Sm', str(manifest), '-s', str(args.signing_key)], check=True)

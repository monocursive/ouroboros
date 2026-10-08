#!/usr/bin/env python3
"""Package supplied binaries; signing identity and publication remain operator choices."""
import argparse
import gzip
import hashlib
import io
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

TARGETS = ['x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu',
           'x86_64-apple-darwin', 'aarch64-apple-darwin']

# A semantic release version: the archive name and the installer's downgrade
# check both key on it.
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?')


def create_archive(binary, target, out, version):
    """Stable archive bytes: file times, uid, gzip name and gzip time are normalized.

    The release version is part of the archive name, so a directory of
    artifacts states which release each archive belongs to.
    """
    if target not in TARGETS:
        raise ValueError('unsupported artifact target')
    if not VERSION.fullmatch(version):
        raise ValueError('expected a semantic release version')
    out.mkdir(parents=True, exist_ok=True)
    archive_path = out / f'ouro-jail-{version}-{target}.tar.gz'
    notices = ((Path(__file__).resolve().parents[3] / 'LICENSE').read_bytes()
               + b'\n\nwebpki-roots 1.0.9, Mozilla CA certificate data\n\n'
               + (Path(__file__).parent / 'WEBPKI_ROOTS_LICENSE').read_bytes())
    with archive_path.open('wb') as raw:
        with gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for name, contents, mode in [('ouro-jail', binary.read_bytes(), 0o755),
                                             ('ouro-jail.LICENSES.txt', notices, 0o644)]:
                    member = tarfile.TarInfo(name)
                    member.size, member.mode = len(contents), mode
                    archive.addfile(member, io.BytesIO(contents))
    return archive_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--target', required=True, choices=TARGETS)
    parser.add_argument('--version', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--signing-key', type=Path, required=True)
    args = parser.parse_args()
    archive = create_archive(args.binary, args.target, args.out, args.version)
    # The signed manifest covers exactly this invocation's own outputs, plus
    # the installer itself. Archives an earlier run left in --out are not
    # signed; the installer copies install.sh beside the artifacts so the
    # release directory is self-contained under one signature.
    install_sh = args.out / 'install.sh'
    shutil.copyfile(Path(__file__).with_name('install.sh'), install_sh)
    manifest = args.out / 'SHA256SUMS'
    manifest.write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n'
                               for p in [archive, install_sh]))
    subprocess.run(['minisign', '-Sm', str(manifest), '-s', str(args.signing_key)], check=True)


if __name__ == '__main__':
    main()

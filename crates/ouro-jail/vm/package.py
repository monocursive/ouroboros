#!/usr/bin/env python3
"""Build a signed, offline macOS preview DMG from a verified prepared image.

Run in a venv installed with --require-hashes from requirements-build.txt.
Notarization is a separate explicit command so its result is retained.
"""
import argparse
import gzip
import hashlib
import importlib.metadata
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

from cli import VERSION
from run import digest

SOURCE = Path(__file__).resolve().parent
REPO = SOURCE.parents[2]


def command(*args):
    subprocess.run([str(arg) for arg in args], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--identity', required=True, help='Developer ID Application identity')
    parser.add_argument('--jail-archive', required=True, type=Path)
    args = parser.parse_args()
    prepared = args.image.resolve()
    metadata = json.loads((prepared / 'image.json').read_text())
    if (metadata['status'] != 'prepared' or digest(prepared / 'base.raw') != metadata['disk_sha256']
            or digest(SOURCE / 'guest.py') != metadata['source_sha256']['guest.py']
            or digest(prepared / 'seed.iso') != metadata['seed_sha256']
            or digest(args.jail_archive) != metadata['jail_archive_sha256']):
        parser.error('prepared guest, seed, or Linux archive does not match provenance')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    volume = out / 'volume'
    payload = volume / 'payload'
    image = payload / 'image'
    image.mkdir(parents=True)
    command('xcrun', 'swiftc', '-warnings-as-errors', '-O', SOURCE / 'vz.swift', '-o', image / 'vz')
    command('xcrun', 'clang', '-Wall', '-Wextra', '-Werror', '-O2', SOURCE / 'custodian.c', '-o', image / 'custodian')
    for name in ('vz', 'custodian'):
        flags = ['--entitlements', SOURCE / 'entitlements.plist'] if name == 'vz' else []
        command('codesign', '--force', '--options', 'runtime', '--timestamp', '--sign', args.identity, *flags, image / name)
        command('codesign', '--verify', '--strict', image / name)
    command(sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--console',
            '--name', 'ouro-vm', '--codesign-identity', args.identity,
            '--distpath', out / 'dist', '--workpath', out / 'work', '--specpath', out,
            SOURCE / 'cli.py')
    shutil.move(out / 'dist' / 'ouro-vm', payload / 'bin')
    shutil.copy2(prepared / 'seed.iso', image / 'seed.iso')
    print('Compressing verified guest image', flush=True)
    with (prepared / 'base.raw').open('rb') as source, (image / 'base.raw.gz').open('wb') as output:
        with gzip.GzipFile(filename='', mode='wb', compresslevel=6, fileobj=output, mtime=0) as compressed:
            shutil.copyfileobj(source, compressed, 1024 * 1024)
    metadata.update(preview_version=VERSION, host_minimum='macOS 27; Apple Silicon',
                    helper_sha256=digest(image / 'vz'), custodian_sha256=digest(image / 'custodian'),
                    compressed_disk_sha256=digest(image / 'base.raw.gz'),
                    source_sha256={p.name: digest(p) for p in SOURCE.iterdir() if p.is_file()},
                    guest_source_sha256=metadata['source_sha256']['guest.py'])
    (image / 'image.json').write_text(json.dumps(metadata, indent=2) + '\n')
    notices = payload / 'licenses'
    notices.mkdir()
    shutil.copy2(REPO / 'LICENSE', notices / 'Ouroboros-LICENSE.txt')
    with tarfile.open(args.jail_archive) as archive:
        for member in archive.getmembers():
            if member.isfile() and member.name.endswith('LICENSES.txt'):
                (notices / 'Linux-Jail-LICENSES.txt').write_bytes(archive.extractfile(member).read())
    # Runtime licenses, including the PyInstaller bootloader exception.
    for package in ('pyinstaller',):
        distribution = importlib.metadata.distribution(package)
        for relative in distribution.files:
            if 'license' in str(relative).lower() and distribution.locate_file(relative).is_file():
                shutil.copy2(distribution.locate_file(relative), notices / (package + '-' + Path(relative).name))
    python_license = Path(sys.base_prefix) / 'lib' / f'python{sys.version_info.major}.{sys.version_info.minor}' / 'LICENSE.txt'
    if not python_license.is_file():
        raise RuntimeError('bundled Python license was not found')
    shutil.copy2(python_license, notices / 'Python-LICENSE.txt')
    shutil.copy2(SOURCE / 'PREVIEW.txt', volume / 'READ-ME.txt')
    with tarfile.open(volume / 'preview-source.tar.gz', 'w:gz') as archive:
        for path in sorted(SOURCE.iterdir()):
            if path.is_file():
                archive.add(path, arcname='vm/' + path.name, recursive=False)
    files = sorted(path for path in volume.rglob('*') if path.is_file())
    manifest = volume / 'SHA256SUMS'
    manifest.write_text(''.join(f'{digest(path)}  {path.relative_to(volume)}\n' for path in files))
    installer = (SOURCE / 'install.sh.in').read_text().replace('@VERSION@', VERSION).replace('@MANIFEST_SHA256@', digest(manifest))
    (volume / 'install.sh').write_text(installer)
    (volume / 'install.sh').chmod(0o755)
    command('bash', '-n', volume / 'install.sh')
    dmg = out / f'ouro-vm-{VERSION}-macos-arm64.dmg'
    command('hdiutil', 'create', '-quiet', '-fs', 'APFS', '-volname', 'Ouro VM Preview',
            '-srcfolder', volume, '-format', 'UDRO', dmg)
    command('codesign', '--force', '--timestamp', '--sign', args.identity, dmg)
    report = {'schema': 'ouro.vm.package/1', 'version': VERSION, 'dmg': dmg.name,
              'dmg_sha256_before_notarization': digest(dmg), 'manifest_sha256': digest(manifest),
              'installer_sha256': digest(volume / 'install.sh'), 'image': metadata,
              'python_version': sys.version, 'pyinstaller_version': importlib.metadata.version('pyinstaller'),
              'notarization': 'pending', 'published': False}
    (out / 'package.json').write_text(json.dumps(report, indent=2) + '\n')
    print(dmg)


if __name__ == '__main__':
    main()

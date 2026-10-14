#!/usr/bin/env python3
"""Build a signed, offline macOS preview DMG from a verified prepared image.

Run in a venv installed with --require-hashes from requirements-build.txt.
Notarization is a separate explicit command so its result is retained.
"""
import argparse
import gzip
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

from cli import VERSION
from run import digest

SOURCE = Path(__file__).resolve().parent
REPO = SOURCE.parents[2]


class SourceError(ValueError):
    pass


def command(*args):
    subprocess.run([str(arg) for arg in args], check=True)


def committed_sources(directory):
    """List the committed files under `directory`, refusing uncommitted changes to them.

    preview-source.tar.gz claims to be this preview's source, so untracked
    strays (bytecode caches, local outputs) are never included, and an
    edited, staged or deleted tracked file stops the build.
    """
    def git(*args):
        try:
            return subprocess.run(['git', '--no-optional-locks', '-C', str(directory), *args],
                                  capture_output=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError) as error:
            raise SourceError(f'cannot list committed preview sources with git: {error}') from error

    if git('status', '--porcelain=v1', '-z', '--untracked-files=no', '--', '.'):
        raise SourceError('preview sources have uncommitted changes')
    names = sorted(os.fsdecode(name) for name in git('ls-files', '-z', '--', '.').split(b'\0') if name)
    if not names:
        raise SourceError('no committed preview sources found')
    return names


def verify_prepared_sources(recorded, current):
    """Refuse unless the committed sources reproduce every hash prepare.py recorded.

    prepare.py records the sources that built the prepared disk, seed and
    helpers, and the prepared-image fault checks measured those helpers.
    Requiring every one keeps the package, its archived source and that
    evidence on one set of sources.
    """
    if not isinstance(recorded, dict) or 'guest.py' not in recorded:
        raise SourceError('prepared image does not record its guest source')
    changed = sorted(name for name, value in recorded.items() if current.get(name) != value)
    if changed:
        raise SourceError('prepared image was built from other sources: ' + ', '.join(changed))


def write_source_archive(path, directory, sources):
    """Archive under vm/ exactly the bytes whose SHA-256 `sources` recorded."""
    with tarfile.open(path, 'w:gz') as archive:
        for name, expected in sorted(sources.items()):
            source = directory / name
            info = archive.gettarinfo(source, arcname='vm/' + name)
            if not info.isreg():
                raise SourceError('preview source is not a regular file: ' + name)
            data = source.read_bytes()
            if len(data) != info.size or hashlib.sha256(data).hexdigest() != expected:
                raise SourceError('preview source changed while packaging: ' + name)
            archive.addfile(info, io.BytesIO(data))


def package_metadata(metadata, sources, **artifacts):
    """Extend prepared-image provenance without changing what its fields mean.

    `source_sha256` stays the prepare-time hashes of the sources that built
    the image; `package_source_sha256` is every committed file archived here.
    """
    return {**metadata, 'preview_version': VERSION, 'host_minimum': 'macOS 27; Apple Silicon', **artifacts,
            'package_source_sha256': sources, 'guest_source_sha256': metadata['source_sha256']['guest.py']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--identity', required=True, help='Developer ID Application identity')
    parser.add_argument('--jail-archive', required=True, type=Path)
    args = parser.parse_args()
    prepared = args.image.resolve()
    metadata = json.loads((prepared / 'image.json').read_text())
    try:
        sources = {name: digest(SOURCE / name) for name in committed_sources(SOURCE)}
        verify_prepared_sources(metadata.get('source_sha256'), sources)
    except SourceError as error:
        parser.error(str(error))
    if (metadata['status'] != 'prepared' or digest(prepared / 'base.raw') != metadata['disk_sha256']
            or digest(prepared / 'seed.iso') != metadata['seed_sha256']
            or digest(args.jail_archive) != metadata['jail_archive_sha256']):
        parser.error('prepared disk, seed, or Linux archive does not match provenance')
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
    metadata = package_metadata(metadata, sources, helper_sha256=digest(image / 'vz'),
                                custodian_sha256=digest(image / 'custodian'),
                                compressed_disk_sha256=digest(image / 'base.raw.gz'))
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
    write_source_archive(volume / 'preview-source.tar.gz', SOURCE, sources)
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

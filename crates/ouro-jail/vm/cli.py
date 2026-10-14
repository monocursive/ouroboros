"""Packaged entry point; all runtime dependencies are bundled."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

import run

# The packaged binary cannot read dist/release.json; test_coordinates.py keeps
# this equal to its vm.version.
VERSION = '0.1.0-preview.1'


def installed_image():
    return Path(sys.executable).resolve().parent.parent / 'image'


def expand_image(directory):
    metadata = json.loads((directory / 'image.json').read_text())
    destination = directory / 'base.raw'
    digest = hashlib.sha256()
    total = 0
    created = False
    try:
        output = destination.open('xb')
        created = True
        with output, gzip.open(directory / 'base.raw.gz', 'rb') as source:
            while block := source.read(1024 * 1024):
                total += len(block)
                if total > 6 * 1024**3:
                    raise ValueError('image exceeds its declared size')
                digest.update(block)
                if block.count(0) == len(block):
                    output.seek(len(block), 1)
                else:
                    output.write(block)
            output.truncate(total)
        if total != 6 * 1024**3 or digest.hexdigest() != metadata['disk_sha256']:
            raise ValueError('expanded image checksum mismatch')
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(prog='ouro-vm', description='Offline Linux Jail preview for Apple Silicon Macs.')
    parser.add_argument('command', choices=['run', 'version', 'doctor', 'expand-image'])
    args, rest = parser.parse_known_args()
    image = installed_image()
    if args.command == 'version':
        value = {'component': 'ouro-vm', 'version': VERSION, 'execution': 'linux-vm', 'native_macos_execution': False}
        print(json.dumps(value) if '--json' in rest else f'Ouro VM {VERSION} (offline Linux on Apple Silicon)')
        return 0
    supported = sys.platform == 'darwin' and platform.machine() == 'arm64' and int(platform.mac_ver()[0].split('.')[0]) >= 27
    if not supported:
        parser.error('this preview is qualified for Apple Silicon and macOS 27 or later')
    if args.command == 'expand-image':
        if rest:
            parser.error('expand-image takes no arguments')
        expand_image(image)
        return 0
    if args.command == 'doctor':
        metadata = json.loads((image / 'image.json').read_text())
        checks = {'virtualization_supported': subprocess.run(['/usr/sbin/sysctl', '-n', 'kern.hv_support'], capture_output=True, text=True).stdout.strip() == '1'}
        for name, key in [('base.raw', 'disk_sha256'), ('seed.iso', 'seed_sha256'), ('vz', 'helper_sha256'), ('custodian', 'custodian_sha256')]:
            checks[name] = (image / name).is_file() and run.digest(image / name) == metadata[key]
        result = {'schema': 'ouro.vm.install-check/1', 'ready': all(checks.values()), 'checks': checks,
                  'scope': 'package and host prerequisites; a real run still verifies the guest jail'}
        print(json.dumps(result, indent=2))
        return 0 if result['ready'] else 125
    sys.argv = [sys.argv[0], '--image', str(image), *rest]
    return run.main()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f'ouro-vm: {error}', file=sys.stderr)
        sys.exit(125)

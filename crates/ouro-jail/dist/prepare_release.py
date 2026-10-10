#!/usr/bin/env python3
"""Stage native Linux builds and assemble a reviewable, unpublished release candidate."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tarfile

from package import VERSION as RELEASE_VERSION
from package import create_archive
from bootstrap import render_bootstrap

TARGETS = {'x86_64-unknown-linux-gnu': 62, 'aarch64-unknown-linux-gnu': 183}
REPOSITORY = 'monocursive/ouroboros'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_build(version, revision, inputs, target):
    build = version['build']
    if (target not in TARGETS or build['target'] != target or build['revision'] != revision
            or build['inputs'] != inputs or build['dirty'] is not False
            or build['opt_level'] != '3' or build['debug_assertions'] is not False
            or not build.get('rustc', '').startswith('rustc 1.98.1 ')):
        raise ValueError('release requires the exact clean optimized Linux build')


def verify_elf(binary_bytes, target):
    if (len(binary_bytes) < 20 or binary_bytes[:6] != b'\x7fELF\x02\x01'
            or int.from_bytes(binary_bytes[18:20], 'little') != TARGETS[target]):
        raise ValueError('binary ELF architecture does not match its target')


def stage(binary, target, revision, inputs, out, release_version):
    binary = binary.resolve(strict=True)
    verify_elf(binary.read_bytes()[:20], target)
    before = digest(binary)
    version = json.loads(subprocess.check_output([binary, 'version', '--json'], timeout=15))
    verify_build(version, revision, inputs, target)
    if not RELEASE_VERSION.fullmatch(release_version):
        raise ValueError('expected a semantic release version')
    out.mkdir(parents=True, exist_ok=False)
    archive = create_archive(binary, target, out, release_version)
    if digest(binary) != before:
        raise ValueError('binary changed while packaging')
    record = {'schema': 'ouro.jail.release-artifact/1', 'target': target, 'version': version,
              'release': release_version,
              'binary_sha256': before, 'archive': archive.name, 'archive_sha256': digest(archive),
              'provenance': 'version queried by executing this binary on its native host'}
    (out / 'artifact.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def verify_stage(directory, revision, inputs, record=None):
    if record is None:
        record = json.loads((directory / 'artifact.json').read_text())
    if record.get('schema') != 'ouro.jail.release-artifact/1':
        raise ValueError('unsupported native artifact record')
    target = record['target']
    verify_build(record['version'], revision, inputs, target)
    # The release version names the archive, so a record cannot pass off one
    # release's archive as another's.
    if not RELEASE_VERSION.fullmatch(record.get('release', '')):
        raise ValueError('artifact record does not name a semantic release version')
    if record['archive'] != f"ouro-jail-{record['release']}-{target}.tar.gz":
        raise ValueError('unexpected archive filename')
    archive = directory / record['archive']
    if digest(archive) != record['archive_sha256']:
        raise ValueError('archive digest mismatch')
    with tarfile.open(archive, 'r:gz') as stream:
        members = stream.getmembers()
        if ([m.name for m in members] != ['ouro-jail', 'ouro-jail.LICENSES.txt']
                or not all(m.isfile() for m in members)
                or members[0].mode != 0o755 or members[1].mode != 0o644
                or any(m.size > 256 * 1024 * 1024 for m in members)):
            raise ValueError('unexpected archive members, modes or sizes')
        binary = stream.extractfile(members[0]).read()
        verify_elf(binary, target)
        if hashlib.sha256(binary).hexdigest() != record['binary_sha256']:
            raise ValueError('packaged binary does not match its native build record')
        if not stream.extractfile(members[1]).read():
            raise ValueError('missing license notices')
    return record


def assemble(stages, revision, inputs, version, out, signing_key=None, public_key=None):
    if not RELEASE_VERSION.fullmatch(version):
        raise ValueError('expected a semantic release version')
    records = [verify_stage(directory, revision, inputs) for directory in stages]
    if sorted(r['target'] for r in records) != sorted(TARGETS):
        raise ValueError('exactly one native artifact for each Linux architecture is required')
    if any(r['release'] != version for r in records):
        raise ValueError('staged artifacts do not all carry this release version')
    if bool(signing_key) != bool(public_key):
        raise ValueError('provide both the signing key and its independently trusted public key')
    if public_key and not re.fullmatch(r'[A-Za-z0-9+/]{56}', public_key):
        raise ValueError('expected a Minisign public key, not a path or shell expression')
    out.mkdir(parents=True, exist_ok=False)
    for directory, record in zip(stages, records):
        shutil.copyfile(directory / record['archive'], out / record['archive'])
        if digest(out / record['archive']) != record['archive_sha256']:
            raise ValueError('archive changed during assembly')
    # The installer ships beside the archives and is covered by the same
    # signature, so what installs a release is part of that release.
    install_sh = out / 'install.sh'
    shutil.copyfile(Path(__file__).with_name('install.sh'), install_sh)
    # Users verify embedded archive hashes without a signature-tool dependency.
    # Maintainer signatures still bind the candidate and publication evidence.
    bootstrap = (Path(__file__).resolve().parents[3] / 'install.sh').read_text()
    bootstrap = render_bootstrap(bootstrap, version,
                                {r['target']: r['archive_sha256'] for r in records})
    (out / 'bootstrap.sh').write_text(bootstrap)
    entries = [(record['archive'], record['archive_sha256']) for record in records]
    entries.append(('install.sh', digest(install_sh)))
    entries.append(('bootstrap.sh', digest(out / 'bootstrap.sh')))
    plan = {'schema': 'ouro.jail.release-candidate/1', 'repository': REPOSITORY,
            'tag': 'ouro-jail-v' + version, 'target_commit': revision, 'inputs': inputs,
            'publication_scope': 'linux-preview',
            'unsupported_clauses': ['K22.2', 'K23.1', 'K24.1', 'K26.1', 'K29.1'],
            'draft': True, 'published': False, 'signature_verified': bool(signing_key),
            'publication_blockers': ([] if signing_key else ['production_signing_identity_not_configured'])
                + ['operator_review_of_host_support_and_validation_required'],
            'artifacts': records,
            'support': {'x86_64': 'Ubuntu 26.04 reference host; other hosts require their own doctor result',
                        'aarch64': 'Debian 13 Raspberry Pi with matching Unix diagnostics support; memory cgroups and Landlock unavailable; the default build profile refuses'},
            'native_records_are_attestations': 'Review the native builder and validation evidence before signing.'}
    (out / 'release-plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    (out / 'RELEASE_NOTES.md').write_text(
        '# Ouroboros Jail ' + version + ' — developer preview\n\n'
        'Linux x86_64 and ARM64. This preview installs `ouro-jail`; '
        'the fleet and ledger are not part of this package.\n\n'
        'After this release is published, install with:\n\n```sh\n'
        'curl --proto "=https" --tlsv1.2 -fsSL '
        'https://github.com/monocursive/ouroboros/releases/download/ouro-jail-v' + version +
        '/bootstrap.sh | bash\n```\n\n'
        'Requires Bash, curl, tar, and sha256sum or shasum. '
        'The installer checks embedded SHA-256 hashes before extracting or executing the archive. '
        'The GNU/Linux binaries require glibc 2.39 or newer; Alpine/musl is unsupported. '
        'Installs to `~/.local/bin`; no sudo or Rust compiler. '
        'Install bubblewrap separately before running contained commands.\n\n'
        'Linux x86_64 and ARM64 packages; host enforcement depends on `ouro-jail doctor`.\n'
        'Ubuntu 24 stock execution remains refused. Pi memory ceilings and Landlock remain unavailable; the default build profile refuses.\n'
        'Real-agent reliability remains experimental: attach the completed compatibility record before changing that claim.\n'
        'Maintainers can also verify the signed SHA256SUMS with an independently trusted public key.\n')
    # Bind provenance and support notes to the signature as well as executable
    # bytes: the publisher must not trust a subsequently edited release plan.
    entries.extend((name, digest(out / name)) for name in ['release-plan.json', 'RELEASE_NOTES.md'])
    manifest = out / 'SHA256SUMS'
    manifest.write_text(''.join(f'{sha256}  {name}\n' for name, sha256 in sorted(entries)))
    if signing_key:
        try:
            subprocess.run(['minisign', '-Sm', manifest, '-s', signing_key], check=True)
            subprocess.run(['minisign', '-Vm', manifest, '-P', public_key], check=True)
        except subprocess.CalledProcessError:
            (out / 'release-plan.json').unlink()
            raise
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    native = commands.add_parser('stage')
    native.add_argument('--binary', type=Path, required=True)
    native.add_argument('--target', choices=TARGETS, required=True)
    native.add_argument('--version', required=True)
    release = commands.add_parser('assemble')
    release.add_argument('--stage', type=Path, action='append', required=True)
    release.add_argument('--version', required=True)
    release.add_argument('--signing-key', type=Path)
    release.add_argument('--public-key')
    for command in [native, release]:
        command.add_argument('--revision', required=True)
        command.add_argument('--inputs', required=True)
        command.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.revision) or not re.fullmatch('sha256:[0-9a-f]{64}', args.inputs):
        parser.error('provide a full 40-character git revision and sha256 build-input digest')
    os.umask(0o077)
    if args.command == 'stage':
        record = stage(args.binary, args.target, args.revision, args.inputs, args.out,
                       args.version)
    else:
        record = assemble(args.stage, args.revision, args.inputs, args.version, args.out,
                          args.signing_key, args.public_key)
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()

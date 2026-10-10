#!/usr/bin/env python3
"""Verify a signed developer preview, create a draft, then publish verified assets."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from package import VERSION
from prepare_release import REPOSITORY, TARGETS, digest, verify_stage

ROOT = Path(__file__).resolve().parents[3]


def run(*args):
    return subprocess.check_output(args, text=True, timeout=120).strip()


def gh_json(*args):
    return json.loads(run('gh', *args))


def check(directory, public_key):
    directory = directory.resolve(strict=True)
    subprocess.run(['minisign', '-Vm', str(directory / 'SHA256SUMS'),
                    '-x', str(directory / 'SHA256SUMS.minisig'), '-P', public_key],
                   check=True, capture_output=True, timeout=15)
    hashes = {}
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.+-]+)', line)
        if not match or match[2] in hashes:
            raise ValueError('invalid or duplicate signed manifest entry')
        hashes[match[2]] = match[1]
    # Verify signed metadata before using its revision, filenames or tag.
    for name in ['release-plan.json', 'RELEASE_NOTES.md', 'install.sh', 'bootstrap.sh']:
        if name not in hashes or digest(directory / name) != hashes[name]:
            raise ValueError('signed release asset changed: ' + name)
    plan = json.loads((directory / 'release-plan.json').read_text())
    revision = plan['target_commit']
    inputs = plan['inputs']
    version = plan['tag'].removeprefix('ouro-jail-v')
    if (plan.get('schema') != 'ouro.jail.release-candidate/1'
            or plan.get('repository') != REPOSITORY
            or plan.get('publication_scope') != 'linux-preview'
            or plan.get('unsupported_clauses') != ['K22.2', 'K23.1', 'K24.1', 'K26.1', 'K29.1']
            or not re.fullmatch('[0-9a-f]{40}', revision)
            or not re.fullmatch('sha256:[0-9a-f]{64}', inputs)
            or not VERSION.fullmatch(version) or plan['tag'] != 'ouro-jail-v' + version
            or plan.get('signature_verified') is not True):
        raise ValueError('invalid signed release plan')
    records = plan['artifacts']
    if sorted(r['target'] for r in records) != sorted(TARGETS):
        raise ValueError('release requires both distinct native Linux targets')
    expected = {'release-plan.json', 'RELEASE_NOTES.md', 'install.sh', 'bootstrap.sh'}
    for record in records:
        if record['release'] != version:
            raise ValueError('release versions disagree')
        verify_stage(directory, revision, inputs, record)
        expected.add(record['archive'])
        if hashes.get(record['archive']) != record['archive_sha256']:
            raise ValueError('native archive is not covered by the signed manifest')
    if set(hashes) != expected:
        raise ValueError('unexpected assets in the signed manifest')
    bootstrap = (directory / 'bootstrap.sh').read_text()
    if (f'    version={version}\n' not in bootstrap
            or f"    public_key='{public_key}'\n" not in bootstrap):
        raise ValueError('bootstrap must pin the release version and trusted public key')
    return plan, sorted(expected | {'SHA256SUMS', 'SHA256SUMS.minisig'})


def publication_gates(plan, public_key):
    revision = plan['target_commit']
    if run('git', '-C', str(ROOT), 'rev-parse', 'HEAD') != revision:
        raise ValueError('publish from the exact candidate commit')
    if run('git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError('commit and review the working tree before publication')
    trusted = (ROOT / 'crates/ouro-jail/dist/release.pub').read_text().splitlines()[1]
    if public_key != trusted or f"    public_key='{trusted}'\n" not in (ROOT / 'install.sh').read_text():
        raise ValueError('publication must use the production key pinned in the reviewed repository')
    subprocess.run(['cargo', '+1.98.1', 'run', '-q', '-p', 'xtask', '--', 'freeze', '--check'],
                   cwd=ROOT, check=True, timeout=120)
    runs = gh_json('run', 'list', '--repo', REPOSITORY, '--commit', revision,
                   '--limit', '100', '--json', 'databaseId,workflowName,status,conclusion')
    # The latest run of each required workflow must pass for this exact commit.
    for workflow in ['rust', 'contracts', 'conformance']:
        latest = next((r for r in runs if r['workflowName'] == workflow), None)
        if not latest or latest['status'] != 'completed' or latest['conclusion'] != 'success':
            raise ValueError(f'{workflow} must pass on the exact release commit')
        if workflow == 'conformance':
            jobs = gh_json('run', 'view', str(latest['databaseId']), '--repo', REPOSITORY,
                           '--json', 'jobs')['jobs']
            if not any(j['name'] == 'reference-host' and j['conclusion'] == 'success' for j in jobs):
                raise ValueError('reference-host conformance must actually run and pass')
    tag_revision = run('gh', 'api', f'repos/{REPOSITORY}/commits/{plan["tag"]}', '--jq', '.sha')
    if tag_revision != revision:
        raise ValueError('push an immutable release tag pointing at the candidate commit')


def verify_remote_assets(plan, directory, names, release):
    if (release['tag_name'] != plan['tag'] or release['prerelease'] is not True
            or sorted(asset['name'] for asset in release['assets']) != names):
        raise ValueError('remote release does not have the exact preview assets')
    # Download by release asset ID: gh authenticates draft downloads, whereas
    # browser URLs are only usable after publication.
    for asset in release['assets']:
        data = subprocess.check_output(
            ['gh', 'api', f'repos/{REPOSITORY}/releases/assets/{asset["id"]}',
             '-H', 'Accept: application/octet-stream'], timeout=120)
        if hashlib.sha256(data).hexdigest() != digest(directory / asset['name']):
            raise ValueError('remote asset digest mismatch: ' + asset['name'])


def release_info(plan):
    # The REST tag endpoint excludes drafts. gh resolves the authenticated
    # draft or public release first; fetch its stable numeric REST identity.
    identity = gh_json('release', 'view', plan['tag'], '--repo', REPOSITORY,
                       '--json', 'apiUrl,tagName')
    prefix = f'https://api.github.com/repos/{REPOSITORY}/releases/'
    if (identity['tagName'] != plan['tag']
            or not identity['apiUrl'].startswith(prefix)
            or not identity['apiUrl'].removeprefix(prefix).isdigit()):
        raise ValueError('release lookup returned a different tag or repository')
    return gh_json('api', identity['apiUrl'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['check', 'draft', 'publish', 'verify'])
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--public-key', required=True)
    args = parser.parse_args()
    try:
        directory = args.candidate.resolve(strict=True)
        plan, names = check(directory, args.public_key)
        if args.command in ['draft', 'publish']:
            publication_gates(plan, args.public_key)
        if args.command == 'draft':
            # No --clobber: previous releases and existing drafts are preserved.
            subprocess.run(['gh', 'release', 'create', plan['tag'], '--repo', REPOSITORY,
                            '--verify-tag', '--draft', '--prerelease', '--latest=false',
                            '--title', 'Ouroboros Jail ' + plan['tag'].removeprefix('ouro-jail-v')
                            + ' — developer preview', '--notes-file', str(directory / 'RELEASE_NOTES.md'),
                            *(str(directory / name) for name in names)], check=True, timeout=180)
            release = release_info(plan)
            if release['draft'] is not True:
                raise ValueError('new release must remain a draft')
            verify_remote_assets(plan, directory, names, release)
        elif args.command in ['publish', 'verify']:
            release = release_info(plan)
            verify_remote_assets(plan, directory, names, release)
            if args.command == 'publish':
                if release['draft'] is not True:
                    raise ValueError('refusing to mutate an already published release')
                subprocess.run(['gh', 'release', 'edit', plan['tag'], '--repo', REPOSITORY,
                                '--draft=false', '--prerelease', '--latest=false'],
                               check=True, timeout=120)
                release = release_info(plan)
            if release['draft'] is not False:
                raise ValueError('release is still a draft')
            # Public availability proof is independent of the operator's gh token.
            with tempfile.TemporaryDirectory(prefix='ouro-release-public-') as tmp:
                for name in names:
                    destination = Path(tmp) / name
                    subprocess.run(['curl', '--disable', '--fail', '--silent', '--show-error',
                                    '--location', '--proto', '=https', '--proto-redir', '=https',
                                    '--tlsv1.2', '--connect-timeout', '15', '--max-time', '600',
                                    f'https://github.com/{REPOSITORY}/releases/download/{plan["tag"]}/{name}',
                                    '--output', str(destination)], check=True, timeout=610)
                    if digest(destination) != digest(directory / name):
                        raise ValueError('public asset digest mismatch: ' + name)
        print(json.dumps({'tag': plan['tag'], 'revision': plan['target_commit'],
                          'assets_verified': names, 'action': args.command}, indent=2))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f'release: {error}\n')


if __name__ == '__main__':
    main()

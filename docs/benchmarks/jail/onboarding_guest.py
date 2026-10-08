#!/usr/bin/env python3
"""Run K27 inside a fresh VM; retain refusal evidence instead of claiming success.

The VM runner provisions distribution prerequisites before this timed workflow.
No operator source, credentials, Rust toolchain, or production signing key is used.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tarfile
import time


PROFILES = ['codex', 'claude', 'opencode', 'cursor', 'aider', 'goose', 'gemini',
            'amp', 'cline', 'copilot', 'kilo', 'auggie', 'droid', 'pi']
AGENT_URL = ('https://github.com/anomalyco/opencode/releases/download/v1.18.32/'
             'opencode-linux-x64-baseline.tar.gz')
AGENT_SHA256 = '763af386ef88a8cab18df00fcf055690e5a55e31a7088beabe02307142a6adce'


def verify_build(version, revision, inputs=None):
    build = version['build']
    if (build['revision'] != revision or build['dirty'] is not False
            or build['target'] != 'x86_64-unknown-linux-gnu'
            or build['opt_level'] != '3' or build['debug_assertions'] is not False):
        raise ValueError('Expected the named clean optimized x86_64 Linux build.')
    if inputs is not None and build['inputs'] != inputs:
        raise ValueError('The artifact does not match the expected Jail source inputs.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=pathlib.Path, required=True)
    parser.add_argument('--installer', type=pathlib.Path, required=True)
    parser.add_argument('--public-key', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--inputs', help='Expected Jail build-input SHA256, independently verified.')
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    home = pathlib.Path.home()
    binary = home / '.local/bin/ouro-jail'
    env = {'HOME': str(home), 'PATH': os.environ['PATH'],
           'OURO_CONFIG_DIR': str(home / 'ouro-config'),
           'OURO_DATA_DIR': str(home / 'ouro-data'),
           'XDG_RUNTIME_DIR': os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')}
    result = {'schema': 'ouro.jail.onboarding/1', 'status': 'blocked',
              'expected_revision': args.revision, 'rows': [],
              'expected_inputs': args.inputs,
              'timer_scope': 'signed install through first sandboxed OpenCode result; '
                             'includes agent download, excludes VM/dependency bootstrap',
              'publication': 'deferred', 'signing_identity': 'ephemeral test key'}
    workflow_start = None

    def save():
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')

    def run(name, argv, *, check=True, timeout=300):
        started = time.monotonic()
        done = subprocess.run([str(a) for a in argv], env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=timeout)
        (out / f'{name}.stdout').write_bytes(done.stdout)
        (out / f'{name}.stderr').write_bytes(done.stderr)
        result['rows'].append({'name': name, 'argv': [str(a) for a in argv],
                               'seconds': time.monotonic() - started, 'exit': done.returncode})
        save()
        if check and done.returncode:
            if len(argv) > 1 and str(argv[0]) == str(binary) and argv[1] == 'run':
                try:
                    receipt(name)
                except (AssertionError, OSError, ValueError) as error:
                    result['receipt_validation_error'] = str(error) or repr(error)
            raise RuntimeError(f'{name} refused with exit {done.returncode}; see {name}.stderr')
        return done

    def receipt(name):
        attempt = max((home / 'ouro-data/attempts').iterdir(), key=lambda p: p.stat().st_mtime_ns)
        for filename in ['jail.json', 'trace.ndjson', 'policy.json']:
            source = attempt / filename
            if source.is_file():
                shutil.copyfile(source, out / f'{name}-{filename}')
        data = json.loads((attempt / 'jail.json').read_text())
        assert data['phase'] == 'settled', data['phase']
        assert data['containment'] == 'enforced', data['containment']
        assert data['exec_observed'] is True
        assert data['lifetime']['tree_empty'] is True
        assert data['lifetime']['integrity'] == 'verified'
        assert data['outcome']['kind'] == 'exited' and data['outcome']['code'] == 0
        assert data['state_cleanup'] == 'complete'
        return data

    def distribution_checks():
        result['distribution_checks'] = 'started'
        original = result['binary_sha256']
        bad = home / 'corrupt-artifacts'
        shutil.copytree(args.artifacts, bad)
        with (bad / 'ouro-jail-x86_64-unknown-linux-gnu.tar.gz').open('ab') as file:
            file.write(b'CORRUPT-TEST-FIXTURE')
        corrupt = run('corrupt-archive', ['sh', args.installer, '--from-dir', bad,
                       '--public-key', args.public_key, '--upgrade'], check=False)
        assert corrupt.returncode != 0 and b'Checksum verification failed' in corrupt.stderr
        assert hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest() == original
        shutil.copyfile(args.artifacts / 'ouro-jail-x86_64-unknown-linux-gnu.tar.gz',
                        bad / 'ouro-jail-x86_64-unknown-linux-gnu.tar.gz')
        (bad / 'SHA256SUMS.minisig').write_text('invalid signature fixture\n')
        signature = run('corrupt-signature', ['sh', args.installer, '--from-dir', bad,
                         '--public-key', args.public_key, '--upgrade'], check=False)
        assert signature.returncode != 0 and b'signature verification failed' in signature.stderr
        assert hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest() == original
        run('upgrade', ['sh', args.installer, '--from-dir', args.artifacts,
                       '--public-key', args.public_key, '--upgrade'])
        result['distribution_checks'] = 'passed'

    save()
    try:
        assert os.getuid() != 0, 'The user workflow must run unprivileged.'
        assert not any(os.isatty(fd) for fd in [0, 1, 2]), 'Run through SSH -T with no TTY.'
        rust = {name: shutil.which(name) for name in ['cargo', 'rustc', 'rustup']}
        result['rust_before'] = rust
        assert not any(rust.values()) and not (home / '.rustup').exists()
        assert not binary.exists(), 'A fresh VM must not have ouro-jail installed.'
        assert not (home / '.opencode').exists(), 'A fresh VM must not have OpenCode installed.'
        assert os.uname().machine == 'x86_64' and os.uname().sysname == 'Linux'
        run('host', ['sh', '-c', 'uname -a; cat /etc/os-release; '
                    'systemd-detect-virt; id; getconf GNU_LIBC_VERSION; '
                    'bwrap --version; minisign -v; '
                    'cat /proc/sys/kernel/yama/ptrace_scope; '
                    'cat /proc/sys/user/max_user_namespaces; '
                    'cat /proc/sys/kernel/unprivileged_userns_clone; '
                    'cat /proc/self/cgroup; cat /etc/machine-id; '
                    'cat /proc/sys/kernel/random/boot_id'], check=False)
        vm = run('virtualization', ['systemd-detect-virt']).stdout.decode().strip()
        assert vm in ['qemu', 'kvm'], f'Expected a genuine QEMU VM, received {vm!r}.'
        for program in ['bwrap', 'minisign', 'shasum', 'curl', 'git', 'rg']:
            assert shutil.which(program), f'Missing pre-provisioned prerequisite: {program}'
        workflow_start = time.monotonic()
        run('install', ['sh', args.installer, '--from-dir', args.artifacts,
                        '--public-key', args.public_key, '--yes'])
        version = json.loads(run('version', [binary, 'version', '--json']).stdout)
        result['build'] = version
        verify_build(version, args.revision, args.inputs)
        result['binary_sha256'] = hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest()
        workspace = home / 'onboarding-project'
        workspace.mkdir()
        run('git-init', ['git', 'init', '-q', workspace])
        run('true', [binary, 'run', '--workspace', workspace, '--', '/usr/bin/true'])
        receipt('true')
        agent_dir = home / '.opencode/bin'
        agent_dir.mkdir(parents=True)
        archive = home / 'opencode.tar.gz'
        run('opencode-download', ['curl', '--fail', '--silent', '--show-error', '--location',
                                 '--proto', '=https', '--proto-redir', '=https', AGENT_URL,
                                 '-o', archive])
        digest = hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest()
        result['agent_artifact'] = {'url': AGENT_URL, 'sha256': digest}
        assert digest == AGENT_SHA256, 'OpenCode artifact checksum mismatch.'
        with tarfile.open(archive) as tar:
            member = next(item for item in tar.getmembers() if pathlib.PurePosixPath(item.name).name == 'opencode')
            assert member.isfile(), 'Agent archive member is not a regular file.'
            with (agent_dir / 'opencode').open('wb') as target:
                shutil.copyfileobj(tar.extractfile(member), target)
        agent = agent_dir / 'opencode'
        agent.chmod(0o755)
        result['vendor_version'] = run('opencode-version', [agent, '--version']).stdout.decode().strip()
        assert result['vendor_version'] == '1.18.32'
        run('ripgrep-version', ['rg', '--version'])
        # Force the agent's file-search path as well as its write tool. Without
        # rg, OpenCode downloads it from GitHub, outside the starter allowlist.
        (workspace / 'task.txt').write_text('hello\n')
        run('opencode', [binary, 'run', '--launch', 'opencode', '--workspace', workspace,
                         '--ro', agent_dir, '--limit', 'wall=300s', '--', agent, 'run',
                         '--model', 'opencode/big-pickle',
                         'Use your glob tool to find task.txt, read it, then create greeting.txt '
                         'with exactly the same contents. Do not use the network yourself.'], timeout=330)
        data = receipt('opencode')
        assert (workspace / 'greeting.txt').read_bytes() == b'hello\n'
        shutil.copyfile(workspace / 'greeting.txt', out / 'greeting.txt')
        assert all(row['status'] == 'active' and not row['gaps'] for row in data['coverage'].values())
        assert all(data['coverage'][name]['observed_count'] > 0
                   for name in ['exec', 'fs.write', 'net', 'proxy.net'])
        result['workflow_seconds'] = time.monotonic() - workflow_start
        assert result['workflow_seconds'] < 600, 'The user workflow exceeded ten minutes.'
        result['main_workflow'] = 'passed'
        for profile in PROFILES:
            run(f'doctor-{profile}', [binary, 'doctor', '--launch', profile, '--json'])
        distribution_checks()
        result['rust_after'] = {name: shutil.which(name) for name in rust}
        assert not any(result['rust_after'].values())
        result['status'] = 'passed'
    except (AssertionError, KeyError, StopIteration, ValueError, OSError,
            RuntimeError, subprocess.SubprocessError) as error:
        result['blocker'] = str(error) or repr(error)
        if workflow_start is not None and 'workflow_seconds' not in result:
            result['workflow_seconds_to_failure'] = time.monotonic() - workflow_start
        if binary.is_file():
            try:
                run('failure-doctor', [binary, 'doctor', '--launch', 'opencode', '--json'], check=False)
                run('failure-bwrap', ['bwrap', '--unshare-all', '--ro-bind', '/', '/',
                                     '--proc', '/proc', '--dev', '/dev', '/usr/bin/true'], check=False)
                run('failure-security-policy', ['sh', '-c',
                    'cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns; '
                    'sudo -n aa-status; ls /etc/apparmor.d | sort'], check=False)
            except (OSError, subprocess.SubprocessError) as diagnostic:
                result['diagnostic_error'] = str(diagnostic)
        if 'binary_sha256' in result and 'distribution_checks' not in result:
            try:
                distribution_checks()
            except (AssertionError, KeyError, ValueError, OSError,
                    RuntimeError, subprocess.SubprocessError) as distribution:
                result['distribution_error'] = str(distribution) or repr(distribution)
    finally:
        save()
    print(json.dumps({key: result[key] for key in ['status', 'workflow_seconds', 'blocker'] if key in result}))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())

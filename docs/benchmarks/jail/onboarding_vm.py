#!/usr/bin/env python3
"""Reproduce K27 in a new disposable x86_64 QEMU VM, without host policy changes.

Supply an official Ubuntu amd64 QCOW2 image and its independently checked SHA256,
and an optimized GNU/Linux binary built from a clean revision. Distribution
packages are provisioned before the user-workflow timer starts. The guest must
have no Rust. A CPU emulator is suitable for compatibility/onboarding evidence,
not jail performance benchmarks. Linux can use --accelerator kvm; macOS ARM uses
the default tcg. No production key, release publication, or paid resource exists.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=pathlib.Path, required=True)
    parser.add_argument('--image-sha256', required=True)
    parser.add_argument('--image-url', required=True)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--inputs', help='Expected Jail build-input SHA256 passed to the guest.')
    parser.add_argument('--out', type=pathlib.Path, required=True)
    parser.add_argument('--accelerator', choices=['tcg', 'kvm'], default='tcg')
    parser.add_argument('--cpus', type=int, default=2)
    parser.add_argument('--memory-mib', type=int, default=3072)
    parser.add_argument('--boot-timeout', type=int, default=900)
    args = parser.parse_args()
    os.umask(0o077)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    metadata = {'schema': 'ouro.jail.onboarding-vm/1', 'status': 'blocked',
                'image_url': args.image_url, 'expected_image_sha256': args.image_sha256,
                'revision': args.revision, 'accelerator': args.accelerator,
                'expected_inputs': args.inputs,
                'cpus': args.cpus, 'memory_mib': args.memory_mib,
                'guest_disk_gib': 12, 'fresh_overlay': True,
                'host_policy_changes': [], 'host_uname': list(os.uname()),
                'prerequisites': ['bubblewrap', 'minisign', 'curl', 'ca-certificates',
                                  'perl', 'git', 'python3', 'ripgrep'],
                'private_key_persisted': False, 'production_signing': False}
    vm = None
    temporary = None

    def save():
        (out / 'vm.json').write_text(json.dumps(metadata, indent=2) + '\n')

    def execute(argv, **kwargs):
        return subprocess.run([str(part) for part in argv], check=True,
                              stdin=subprocess.DEVNULL, **kwargs)

    save()
    try:
        for tool in ['qemu-system-x86_64', 'qemu-img', 'ssh', 'scp', 'ssh-keygen', 'minisign']:
            if not shutil.which(tool):
                raise RuntimeError(f'Missing VM prerequisite: {tool}; no container fallback is valid.')
        iso_tool = 'hdiutil' if os.uname().sysname == 'Darwin' else 'genisoimage'
        if not shutil.which(iso_tool):
            raise RuntimeError(f'Missing NoCloud ISO tool: {iso_tool}.')
        if not re.fullmatch(r'[0-9a-f]{40}', args.revision):
            raise RuntimeError('A full git revision is required for clean-build evidence.')
        digest = hashlib.file_digest(args.image.open('rb'), 'sha256').hexdigest()
        metadata['image_sha256'] = digest
        if digest != args.image_sha256:
            raise RuntimeError('Supplied VM image checksum does not match.')
        metadata['binary_sha256'] = hashlib.file_digest(args.binary.open('rb'), 'sha256').hexdigest()
        metadata['qemu_version'] = execute(['qemu-system-x86_64', '--version'], capture_output=True,
                                          text=True).stdout.strip()
        temporary = tempfile.TemporaryDirectory(prefix='ouro-k27-vm-')
        root = pathlib.Path(temporary.name)
        seed = root / 'seed'
        seed.mkdir()
        key = root / 'guest-key'
        execute(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key])
        public_key = key.with_suffix('.pub').read_text().strip()
        seed.joinpath('meta-data').write_text('instance-id: ouro-k27-disposable\nlocal-hostname: ouro-k27-fresh\n')
        seed.joinpath('network-config').write_text('version: 2\nethernets:\n  ens3:\n    dhcp4: true\n')
        seed.joinpath('user-data').write_text(
            '#cloud-config\nusers:\n  - name: ubuntu\n    groups: [sudo]\n'
            '    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n'
            '    ssh_authorized_keys:\n      - ' + public_key + '\n'
            'ssh_pwauth: false\npackage_update: true\n'
            'packages: [bubblewrap, minisign, curl, ca-certificates, perl, git, python3, ripgrep]\n'
            'runcmd:\n  - [touch, /home/ubuntu/cloud-ready]\n')
        shutil.copytree(seed, out / 'seed')
        iso = root / 'seed.iso'
        with (out / 'setup.log').open('wb') as setup:
            if iso_tool == 'hdiutil':
                execute(['hdiutil', 'makehybrid', '-o', iso, seed, '-iso', '-joliet',
                         '-default-volume-name', 'cidata'], stdout=setup, stderr=subprocess.STDOUT)
            else:
                execute(['genisoimage', '-output', iso, '-volid', 'cidata', '-joliet', '-rock', seed],
                        stdout=setup, stderr=subprocess.STDOUT)
            disk = root / 'guest.qcow2'
            execute(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b',
                     args.image.resolve(), disk, '12G'], stdout=setup, stderr=subprocess.STDOUT)
            signing_key = root / 'test-signing.key'
            signing_public = root / 'test-signing.pub'
            execute(['minisign', '-G', '-W', '-s', signing_key, '-p', signing_public],
                    stdout=setup, stderr=subprocess.STDOUT)
            trusted_key = signing_public.read_text().splitlines()[1]
            metadata['test_signing_public_key'] = trusted_key
            artifacts = root / 'artifacts'
            script_dir = pathlib.Path(__file__).resolve().parent
            repo = script_dir.parents[2]
            execute(['python3', repo / 'crates/ouro-jail/dist/package.py', '--binary',
                     args.binary.resolve(), '--target', 'x86_64-unknown-linux-gnu', '--out',
                     artifacts, '--signing-key', signing_key], stdout=setup, stderr=subprocess.STDOUT)
        (out / 'artifacts').mkdir()
        for filename in ['SHA256SUMS', 'SHA256SUMS.minisig']:
            shutil.copyfile(artifacts / filename, out / 'artifacts' / filename)
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
        qemu = ['qemu-system-x86_64', '-accel', args.accelerator, '-cpu', 'max',
                '-smp', str(args.cpus), '-m', str(args.memory_mib),
                '-drive', f'file={disk},if=virtio,format=qcow2',
                '-drive', f'file={iso},format=raw,media=cdrom,readonly=on',
                '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22',
                '-device', 'virtio-net-pci,netdev=net0', '-display', 'none',
                '-serial', f'file:{out / "console.log"}', '-monitor', 'none']
        metadata['qemu_argv'] = qemu
        save()
        with (out / 'qemu.stderr').open('wb') as errors:
            vm = subprocess.Popen(qemu, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=errors)
        known_hosts = root / 'known_hosts'
        options = ['-i', str(key), '-o', f'UserKnownHostsFile={known_hosts}',
                   '-o', 'StrictHostKeyChecking=accept-new', '-o', 'BatchMode=yes',
                   '-o', 'ConnectTimeout=5']
        ssh = ['ssh', '-T', '-p', str(port)] + options + ['ubuntu@127.0.0.1']
        boot_started = time.monotonic()
        while time.monotonic() - boot_started < args.boot_timeout:
            if vm.poll() is not None:
                raise RuntimeError('QEMU stopped before VM readiness; see qemu.stderr.')
            try:
                ready = subprocess.run(ssh + ['test -f /home/ubuntu/cloud-ready'],
                                       stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
            except subprocess.TimeoutExpired:
                continue
            if ready.returncode == 0:
                break
            time.sleep(2)
        else:
            raise RuntimeError('Fresh VM did not finish prerequisite setup before boot timeout.')
        metadata['bootstrap_seconds'] = time.monotonic() - boot_started
        # Trust learned only from this loopback VM remains pinned for every later call.
        options[options.index('StrictHostKeyChecking=accept-new')] = 'StrictHostKeyChecking=yes'
        ssh = ['ssh', '-T', '-p', str(port)] + options + ['ubuntu@127.0.0.1']
        execute(['scp', '-r', '-P', str(port)] + options +
                [artifacts, repo / 'crates/ouro-jail/dist/install.sh',
                 script_dir / 'onboarding_guest.py', 'ubuntu@127.0.0.1:'])
        with (out / 'workflow.log').open('wb') as workflow:
            guest_args = ['python3', 'onboarding_guest.py', '--artifacts', 'artifacts',
                                  '--installer', 'install.sh', '--public-key', trusted_key,
                                  '--revision', args.revision, '--out', 'onboarding-results']
            if args.inputs is not None:
                guest_args += ['--inputs', args.inputs]
            command = shlex.join(guest_args)
            attempt = subprocess.run(ssh + [command], stdin=subprocess.DEVNULL,
                     stdout=workflow, stderr=subprocess.STDOUT, timeout=1800)
        metadata['guest_exit'] = attempt.returncode
        execute(['scp', '-r', '-P', str(port)] + options +
                ['ubuntu@127.0.0.1:onboarding-results', out / 'guest'])
        execute(ssh + ['sudo -n cat /var/log/cloud-init-output.log'],
                stdout=(out / 'bootstrap.log').open('wb'))
        result = json.loads((out / 'guest/result.json').read_text())
        metadata['status'] = result['status']
        if result.get('blocker'):
            metadata['blocker'] = result['blocker']
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        metadata['blocker'] = str(error)
    finally:
        if vm is not None and vm.poll() is None:
            vm.terminate()
            try:
                vm.wait(timeout=15)
            except subprocess.TimeoutExpired:
                vm.kill()
                vm.wait(timeout=15)
        if temporary is not None:
            temporary.cleanup()
        metadata['vm_destroyed'] = True
        save()
    print(json.dumps({key: metadata[key] for key in ['status', 'blocker'] if key in metadata}))
    return 0 if metadata['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())

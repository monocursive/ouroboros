#!/usr/bin/env python3
"""Opt-in hosted Intel VM smoke. No credentials, model work, or artifact upload.

Run only from intel-macos.yml. Unit tests import helpers without invoking main.
Local checks: python3 scripts/test-intel-macos-smoke.py
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

GIB = 1024 ** 3
MIN_FREE = 2 * GIB
LOG_LIMIT = 16 * 1024 ** 2
ROOT = Path(__file__).resolve().parents[1]


class Refused(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Refused(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as file:
        for chunk in iter(lambda: file.read(1024 ** 2), b''):
            h.update(chunk)
    return h.hexdigest()


def end_group(proc):
    # This is the group we created, not a group found through runtime metadata.
    # TERM/KILL both target remaining members even after the leader has exited.
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        proc.wait(timeout=5)
        return
    try:
        time.sleep(0.2)
    finally:
        # Cancellation during TERM grace must not skip descendant teardown.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)


def run(argv, *, cwd, env, timeout=60, limit=LOG_LIMIT, min_free=MIN_FREE, log_path=None):
    """Bound stdout+stderr on disk and time; never print raw/token-bearing output.

    The process group is created by this call. No PID discovered in runtime state
    is signalled. Detached daemon cleanup uses authenticated ouro stop separately.
    """
    with (Path(log_path).open('x+b') if log_path else tempfile.TemporaryFile(dir=cwd)) as log:
        require(shutil.disk_usage(cwd).free >= min_free, 'disk reserve reached before command')
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + timeout
        ended = False
        try:
            while proc.poll() is None:
                require(time.monotonic() < deadline, 'command deadline exceeded')
                require(os.fstat(log.fileno()).st_size <= limit, 'command output limit exceeded')
                require(shutil.disk_usage(cwd).free >= min_free, 'disk reserve reached')
                time.sleep(0.1)
            require(proc.returncode == 0, f'command exited {proc.returncode}')
            ended = True
            end_group(proc)
            require(os.fstat(log.fileno()).st_size <= limit, 'command output limit exceeded')
            log.seek(0)
            output = log.read(limit + 1)
            require(len(output) <= limit, 'command output limit exceeded')
            return output.decode('utf-8', errors='replace')
        finally:
            if not ended:
                end_group(proc)


def isolated_env(state):
    # Runtime/eval never inherit CI token, model keys, BEAM flags, or build PATH.
    return {'HOME': str(state / 'home'), 'XDG_CONFIG_HOME': str(state / 'config'),
            'XDG_DATA_HOME': str(state / 'data'), 'XDG_CACHE_HOME': str(state / 'cache'),
            'OUROBOROS_DATA_DIR': str(state / 'data'), 'OUROBOROS_DIST': 'none',
            'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'SHELL': '/bin/sh', 'LANG': 'en_US.UTF-8',
            'TMPDIR': str(state / 'tmp')}


def state_path():
    require(os.environ.get('GITHUB_ACTIONS') == 'true', 'hosted workflow only')
    require(os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'not a hosted runner')
    require(platform.system() == 'Darwin' and platform.machine() == 'x86_64', 'Intel macOS only')
    return Path(os.environ['RUNNER_TEMP']).resolve() / 'ouro-intel-smoke'


def cleanup(state):
    if not state.exists():
        return
    require(not state.is_symlink() and (state / 'owned').read_text() == 'intel-smoke-v1\n',
            'unowned cleanup directory')
    binary = state / 'bin/ouro'
    publication = state / 'data/gateway.json'
    stopped = state / 'stopped'
    if stopped.exists():
        return stopped.read_text() == 'authenticated\n'
    if publication.exists():
        # The real client authenticates owner/token/hello and observes incarnation exit.
        output = run([str(binary), 'stop'], cwd=state, env=isolated_env(state), timeout=60, min_free=0)
        authenticated = ('the runtime accepted runtime.shutdown' in output and
                         re.search(r'the runtime stopped \(pid [0-9]+\)', output) is not None)
        stopped.write_text('authenticated\n' if authenticated else 'stale-or-unconfirmed\n')
        print('intel-smoke: stop outcome ' + ('authenticated' if authenticated else 'stale-or-unconfirmed'))
        return authenticated
    elif (state / 'start-attempted').exists():
        raise Refused('startup attempted but no publication: cleanup unconfirmed; VM disposal backstop')
    print('intel-smoke: owned runtime cleanup completed (or no publication)')


def main():
    state = state_path()
    require(len(sys.argv) == 2 and sys.argv[1] in ('run', 'cleanup'), 'expected run or cleanup')
    if sys.argv[1] == 'cleanup':
        cleanup(state)
        return
    source = os.environ.get('SOURCE_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', source) and source == os.environ.get('GITHUB_SHA'),
            'source must equal dispatched workflow commit')
    state.mkdir(mode=0o700)  # Never adopt an earlier directory or runtime.
    (state / 'owned').write_text('intel-smoke-v1\n')
    for name in ('home', 'config', 'data', 'cache', 'tmp', 'bin', 'workspace', 'logs'):
        (state / name).mkdir(mode=0o700)
    build_env = {k: os.environ[k] for k in ('PATH', 'HOME', 'TMPDIR') if k in os.environ}
    build_env.update({'LANG': 'en_US.UTF-8', 'CARGO_INCREMENTAL': '0', 'CARGO_BUILD_JOBS': '2',
                      'GIT_OPTIONAL_LOCKS': '0'})
    phase = 'identity'
    report = {'source': source, 'checks': [], 'passed': False}
    sequence = 0

    def command(argv, timeout=60, cwd=ROOT, env=build_env):
        nonlocal sequence
        sequence += 1
        return run(argv, cwd=cwd, env=env, timeout=timeout,
                   log_path=state / 'logs' / f'{sequence:02}-{phase}.log')

    try:
        require(command(['git', 'rev-parse', 'HEAD']).strip() == source, 'checkout SHA mismatch')
        require(not command(['git', 'status', '--porcelain', '--untracked-files=no']).strip(),
                'dirty tracked checkout')
        require(command(['/usr/sbin/sysctl', '-n', 'machdep.cpu.vendor']).strip() == 'GenuineIntel',
                'ARM/Rosetta is not Intel evidence')
        report['os'] = command(['sw_vers']).strip()
        report['machine'] = platform.machine()
        report['free_bytes_before'] = shutil.disk_usage(ROOT).free
        report['elixir'] = command(['elixir', '--version']).strip()
        require('Elixir 1.20.' in report['elixir'] and 'Erlang/OTP 29' in report['elixir'],
                'wrong Elixir/OTP version')
        report['rust'] = command(['rustc', '-vV']).strip()
        require('release: 1.95.' in report['rust'] and 'host: x86_64-apple-darwin' in report['rust'],
                'wrong Rust toolchain/architecture')
        report['clang'] = command(['clang', '--version']).splitlines()[0]
        phase = 'seatbelt-preflight'
        command(['/usr/bin/sandbox-exec', '-p', '(version 1) (allow default)', '/usr/bin/true'])
        phase = 'dependencies'
        command(['mix', 'local.hex', '--force'], timeout=180)
        command(['mix', 'local.rebar', '--force'], timeout=180)
        command(['mix', 'deps.get'], timeout=600)
        phase = 'build'
        # No alternate build recipe, cache restore or cleanup of runner-global tools.
        command(['make', 'ouro'], timeout=3600)
        require(not command(['git', 'diff', '--exit-code', 'HEAD']).strip(), 'tracked source/locks changed')
        tarballs = list((ROOT / '_build/prod').glob('ouroboros-*.tar.gz'))
        require(len(tarballs) == 1 and not tarballs[0].is_symlink(), 'ambiguous release tarball')
        report['release_tar_sha256'] = digest(tarballs[0])
        binary = state / 'bin/ouro'
        shutil.copy2(ROOT / 'tui/target/release/ouro', binary)
        report['binary_sha256'] = digest(binary)
        runtime_env = isolated_env(state)
        phase = 'packaged-start'
        report['client_version'] = command([str(binary), 'version'], cwd=state, env=runtime_env).strip()
        (state / 'start-attempted').write_text('owned startup attempt\n')
        command([str(binary), 'daemon'], timeout=90, cwd=state, env=runtime_env)
        require((state / 'data/gateway.json').is_file(), 'no gateway publication after startup')
        report['checks'].append('packaged startup with runtime-only PATH')
        phase = 'helper'
        status = json.loads(command([str(binary), 'wasm', 'doctor', '--json'], cwd=state, env=runtime_env))
        require(status['helper']['present'] is True, 'bundled helper missing')
        report['checks'].append('gateway wasm.status helper presence (not component execution)')
        phase = 'web-refusal'
        command([str(binary), 'web', '--print'], cwd=state, env=runtime_env)
        web = json.loads((state / 'data/web.json').read_text())
        require(type(web['port']) is int and 0 < web['port'] < 65536, 'invalid owned web port')
        connection = http.client.HTTPConnection('127.0.0.1', web['port'], timeout=5)
        try:
            connection.request('GET', '/')
            require(connection.getresponse().status == 401, 'unauthenticated web did not refuse')
        finally:
            connection.close()
        report['checks'].append('unauthenticated web HTTP401 (not authenticated browser acceptance)')
        releases = list((state / 'cache/ouroboros/releases').glob('*/bin/ouroboros'))
        require(len(releases) == 1, 'ambiguous extracted release')
        release = releases[0].parent.parent
        helpers = list((release / 'lib').glob('ouroboros-*/priv/wasm/ouro-wasm'))
        require(len(helpers) == 1, 'ambiguous packaged helper')
        helper = helpers[0]
        doctor = json.loads(command([str(helper), 'doctor'], cwd=state, env=runtime_env))
        require(doctor['usable'] is True and doctor['target'] == 'x86_64-apple-darwin',
                'helper engine unavailable or wrong target')
        report['helper'] = {k: doctor[k] for k in ('usable', 'target', 'wasmtime')}
        report['helper']['sha256'] = digest(helper)
        phase = 'abi'
        beams = list(release.glob('erts-*/bin/beam.smp'))
        require(len(beams) == 1, 'missing ERTS executable')
        report['abi'] = []
        for path in (binary, helper, beams[0]):
            require(command(['/usr/bin/lipo', '-archs', str(path)]).strip() == 'x86_64',
                    'non-Intel Mach-O')
            report['abi'].append({'file': path.name, 'otool': command(['/usr/bin/otool', '-L', str(path)]).strip()})
        phase = 'packaged-stop'
        require(cleanup(state) is True, 'no authenticated lifecycle stop (stale cleanup is not acceptance)')
        report['checks'].append('authenticated owned stop and observed process exit')
        phase = 'packaged-seatbelt-shell'
        eval_env = dict(runtime_env, OUROBOROS_DATA_DIR=str(state / 'eval-data'),
                        OUROBOROS_PROCESS_ID_HELPER=str(binary), INTEL_SMOKE_ROOT=str(state))
        (state / 'eval-data').mkdir(mode=0o700)
        expression = 'Code.eval_file(' + json.dumps(str(ROOT / 'scripts/intel-macos-shell.exs')) + ')'
        output = command([str(releases[0]), 'eval', expression], timeout=90, cwd=state, env=eval_env)
        records = [line.removeprefix('INTEL_SHELL_SMOKE=') for line in output.splitlines()
                   if line.startswith('INTEL_SHELL_SMOKE=')]
        require(len(records) == 1, 'missing actual product-shell result')
        report['shell'] = json.loads(records[0])
        report['checks'].append('actual packaged read-only/workspace/protected-file Seatbelt controls')
        report['passed'] = True
    except Exception as error:
        # Never serialize arbitrary subprocess output, tokens or URLs into Actions logs.
        report['failure_phase'] = phase
        report['failure_kind'] = type(error).__name__
        if isinstance(error, Refused):
            report['failure_reason'] = str(error)
        raise
    finally:
        try:
            cleanup(state)
        except Exception:
            report['passed'] = False
            report['cleanup_failed'] = True
            raise
        finally:
            report['free_bytes_after'] = shutil.disk_usage(ROOT).free
            print(json.dumps(report, indent=2))


if __name__ == '__main__':
    try:
        os.umask(0o077)
        def interrupted(_signum, _frame):
            raise Refused('workflow interrupted')
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        main()
    except Exception as error:
        print('intel-smoke failed: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)

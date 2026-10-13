#!/usr/bin/env python3
"""Exercise vault credentials using the frozen native coding benchmark.

Only credential transport changes. Tasks, models, flags, deadlines, schedule,
binary grants, and independent checkers come from the sealed startup harness.
Supervisor refresh and kernel/path bindings are enabled. The child receives an
access placeholder, account routing metadata, and non-secret adapter identity.
"""
import json
import os
from pathlib import Path
import shlex
import sys
import signal
import subprocess
import threading
import time

import agentbench_v2 as bench

original_command = bench.command
original_execute = bench.execute
protected_values = []


def observed_execute(argv, cwd, env, wall):
    if 'run' not in argv or '--receipt' not in argv:
        return original_execute(argv, cwd, env, wall)
    run_dir = Path(argv[argv.index('--receipt') + 1]).parent
    root = Path(env['OURO_DATA_DIR'])
    proof = {'schema': 'sampled-credential-exposure/1', 'period_ms': 100,
             'snapshots': 0, 'readable_process_environments': 0,
             'unreadable_process_environments': 0, 'files_checked': 0,
             'hits': [], 'actual_values_retained': False,
             'limit': 'Periodic readable environment/argv and regular-file checks, not arbitrary process memory or exhaustive history.'}
    started = time.perf_counter_ns()
    process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    stop = threading.Event()

    def check(where, data):
        if any(v and v in data for v in protected_values):
            if where not in proof['hits']:
                proof['hits'].append(where)

    def observe():
        while not stop.is_set():
            proof['snapshots'] += 1
            parents = {}
            for path in Path('/proc').glob('[0-9]*/stat'):
                try:
                    parents[int(path.parent.name)] = int(path.read_text().rsplit(')', 1)[1].split()[1])
                except (OSError, ValueError, IndexError):
                    continue
            descendants = {process.pid}
            while True:
                new = {pid for pid, parent in parents.items() if parent in descendants}
                if new <= descendants:
                    break
                descendants.update(new)
            for pid in descendants - {process.pid}:
                try:
                    check('process-environment', (Path('/proc') / str(pid) / 'environ').read_bytes())
                    check('process-argv', (Path('/proc') / str(pid) / 'cmdline').read_bytes())
                    proof['readable_process_environments'] += 1
                except OSError:
                    proof['unreadable_process_environments'] += 1
            # Only child state/workspace; source files remain private supervisor
            # inputs outside all grants. Skip symlinks and oversized caches.
            locations = [Path(cwd)] + list((root / 'attempts').glob('*/vendor-state'))
            for location in locations:
                for path in location.rglob('*'):
                    try:
                        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
                            continue
                        check('child-file', path.read_bytes())
                        proof['files_checked'] += 1
                    except OSError:
                        continue
            stop.wait(.1)

    watcher = threading.Thread(target=observe, daemon=True)
    watcher.start()
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=wall)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=10)
    finally:
        stop.set()
        watcher.join(timeout=5)
    check('raw-stdout', stdout)
    check('raw-stderr', stderr)
    bench.write(run_dir / 'credential-exposure.json', proof)
    return {'exit': process.returncode, 'timeout': timed_out,
            'elapsed_ms': (time.perf_counter_ns() - started) / 1e6,
            'stdout': stdout.decode(errors='replace'), 'stderr': stderr.decode(errors='replace')}


def vault_command(args, agent, mode, task_dir, home, state, run_dir, key):
    argv, env, config = original_command(args, agent, mode, task_dir, home, state, run_dir, key)
    if mode != 'ouro':
        return argv, env, config
    if agent == 'codex':
        marker = args.root / 'private/codex-grant-ready'
        announced = False
        while not marker.exists():
            if not announced:
                print('Codex grant verification pending; no scored Codex CLI launched.', flush=True)
                announced = True
            time.sleep(1)
    private = run_dir / 'ouro-config/launch' / (agent + '.toml')
    profile = private.read_text()
    root = args.root / 'private'
    root.mkdir(mode=0o700, exist_ok=True)
    source = root / ('codex-token.json' if agent == 'codex' else 'anthropic-api')
    account = None
    if agent == 'codex':
        auth = json.loads(args.auth_file.read_text())
        if not source.exists():
            import base64
            token = auth['tokens']['access_token']
            payload = token.split('.')[1]
            expiry = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))['exp']
            source.write_text(json.dumps({'access_token': token, 'refresh_token': auth['tokens']['refresh_token'], 'id_token': auth['tokens']['id_token'], 'expires_at': expiry}))
        document = json.loads(source.read_text())
        protected_values.extend(document[k].encode() for k in ('access_token', 'refresh_token', 'id_token') if isinstance(document.get(k), str))
        account = auth['tokens']['account_id']
        # Replace the original copy_rw declaration; its source is outside the
        # child grants, and no real OAuth token is staged into this run.
        start = profile.index('[credentials.auth]')
        end = profile.index('[network]', start)
        profile = profile[:start] + profile[end:]
        (state / 'auth.json').unlink(missing_ok=True)
    else:
        source.write_text(key)
        profile = '\n'.join(line for line in profile.splitlines()
                            if not line.startswith('ANTHROPIC_API_KEY=')) + '\n'
    source.chmod(0o600)
    origins = ['https://chatgpt.com'] if agent == 'codex' else ['https://api.anthropic.com']
    header = '{name="authorization",prefix="Bearer "}' if agent == 'codex' else '{name="x-api-key"}'
    profile += ('\n[credentials.api]\nmode="vault"\nsource=' + json.dumps(str(source)) +
                '\nhosts=' + json.dumps(origins) + '\nheader=' + header + '\n')
    profile += 'paths=' + json.dumps(['/backend-api/'] if agent == 'codex' else ['/v1/']) + '\nbinaries=' + json.dumps([str((args.root / 'bin' / agent).resolve())]) + '\n'
    if agent == 'codex':
        profile += 'refresh={token_url="https://auth.openai.com/oauth/token",client_id="app_EMoamEEZ73f0CkXaXp7hrann",refresh_before_seconds=300,encoding="json"}\n'
    private.write_text(profile)
    private.chmod(0o600)
    bench.write(run_dir / 'config/launch.toml', profile)
    env.pop('ANTHROPIC_API_KEY', None)
    split = argv.index('--')
    client = argv[split + 1:]
    inspect = 'import json,os; print("VAULT_INSPECTION "+json.dumps({"placeholder":os.environ["OURO_VAULT_API"].startswith("vault:"),"source_readable":os.access(' + repr(str(source)) + ',os.R_OK),"raw_anthropic_inherited":"ANTHROPIC_API_KEY" in os.environ}),file=__import__("sys").stderr)'
    setup = ['python3 -c ' + shlex.quote(inspect)]
    if agent == 'codex':
        # Use exactly the non-secret identity/external-token adaptation already
        # exercised for OpenShell 0.1.3, whose handles are also opaque. This
        # declares externally supplied access tokens without exposing the real
        # ID/refresh tokens or changing client/model/task flags.
        prepare = ('import base64,json,os,pathlib,time; '
                   'b64=lambda v:base64.urlsafe_b64encode(json.dumps(v).encode()).decode().rstrip("="); '
                   'now=int(time.time()); identity=".".join((b64({"alg":"none","typ":"JWT"}),'
                   'b64({"iss":"https://auth.openai.com","aud":"codex","sub":"openshell-app-server",'
                   '"email":"app-server@openshell.local","iat":now,"exp":now+3600}),"placeholder")); '
                   'p=pathlib.Path(os.environ["CODEX_HOME"])/"auth.json"; '
                   'p.write_text(json.dumps({"auth_mode":"chatgptAuthTokens","OPENAI_API_KEY":None,"tokens":'
                   '{"id_token":identity,"access_token":os.environ["OURO_VAULT_API"],"refresh_token":"",'
                   '"account_id":' + repr(account) + '},"last_refresh":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())})); p.chmod(0o600)')
        setup.append('python3 -c ' + shlex.quote(prepare))
    else:
        setup.append('export ANTHROPIC_API_KEY="$OURO_VAULT_API"')
    setup.append('exec "$@"')
    argv = argv[:split + 1] + ['/bin/sh', '-c', '; '.join(setup), 'vault-client', *client]
    # The actual account routing value is private metadata. The exporter
    # removes it from saved argv and client outputs using the auth file.
    return argv, env, config


bench.command = vault_command
bench.execute = observed_execute

if __name__ == '__main__':
    key_path = Path(sys.argv[sys.argv.index('--key-file') + 1]).expanduser()
    auth_path = Path(sys.argv[sys.argv.index('--auth-file') + 1]).expanduser()
    protected_values.append(key_path.read_bytes().strip())
    auth_values = json.loads(auth_path.read_text())['tokens']
    protected_values.extend(v.encode() for k, v in auth_values.items()
                            if k != 'account_id' and isinstance(v, str))
    out = Path(sys.argv[sys.argv.index('--out') + 1]).expanduser().resolve()
    bench.write(out / 'vault-protocol.json', {
        'entry_sha256': bench.sha(__file__),
        'frozen_native_harness_sha256': bench.sha(bench.__file__),
        'frozen_task_harness_sha256': bench.sha(Path(__file__).with_name('agentbench.py')),
        'workflow_fixture_sha256': bench.sha(Path(__file__).with_name('workflow_fixture.py')),
        'codex_adapter': 'Same external-token/unsigned non-secret ID template already used for OpenShell 0.1.3; access token vault-only; no ID/refresh token staged.',
        'credentials_transport_only': True,
        'sampled_exposure_checks_affect_descriptive_client_time': True,
        'fresh_per_run': True,
        'automatic_oauth_refresh': True})
    if '--workflow' in sys.argv:
        sys.argv.remove('--workflow')
        import agentbench_workflow  # installs the unchanged workflow fixture
    bench.main()

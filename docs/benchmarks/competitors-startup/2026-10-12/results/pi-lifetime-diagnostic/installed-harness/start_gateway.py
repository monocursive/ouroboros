#!/usr/bin/env python3
"""Restart the same local Docker gateway with private state copied for this run."""
import json
import os
from pathlib import Path
import subprocess
import time

root = Path.home() / 'bench-ouro-startup'
tls = root / 'openshell/tls'
env = dict(os.environ, OPENSHELL_LOCAL_TLS_DIR=str(tls),
           XDG_STATE_HOME=str(root / 'openshell/state'))
if os.uname().sysname == 'Darwin':
    env.update(DOCKER_HOST='unix://' + str(Path.home() / '.orbstack/run/docker.sock'),
               DOCKER_CONFIG=str(root / 'openshell/docker-config'))
argv = [str(root / 'bin/openshell-gateway'), '--compute-driver', 'docker',
        '--tls-cert', str(tls / 'server/tls.crt'), '--tls-key', str(tls / 'server/tls.key'),
        '--tls-client-ca', str(tls / 'ca.crt'), '--enable-mtls-auth', 'true']
log = (root / 'results/gateway-after.log').open('w')
process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                           stdout=log, stderr=log, start_new_session=True)
status = None
for _ in range(60):
    status = subprocess.run([str(root / 'bin/openshell'), 'status'], env=env,
                            capture_output=True, text=True, timeout=10)
    if status.returncode == 0 or process.poll() is not None:
        break
    time.sleep(.5)
(root / 'results/gateway-start.json').write_text(json.dumps(
    {'argv': argv, 'pid': process.pid, 'exit_at_ready_check': process.poll(),
     'status_exit': status.returncode, 'status_stdout': status.stdout,
     'status_stderr': status.stderr}, indent=2) + '\n')
raise SystemExit(status.returncode)

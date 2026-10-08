#!/usr/bin/env python3
"""Reproduce OpenCode's missing-rg refusal and verify provisioned file search.

This exercises the real agent's code, without a model request or credentials.
It does not count as a completed model-driven agent task.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['binary', 'agent', 'tool-dir', 'out']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inputs', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    binary, agent, tools, out = (p.resolve() for p in [args.binary, args.agent, args.tool_dir, args.out])
    out.mkdir(parents=True, exist_ok=False)
    build = json.loads(subprocess.check_output([binary, 'version', '--json'], timeout=15))
    assert build['build']['inputs'] == args.inputs
    result = {'schema': 'ouro.jail.opencode-tools/1', 'build': build,
              'vendor_version': subprocess.check_output([agent, '--version'], timeout=15).decode().strip(),
              'ripgrep_version': subprocess.check_output([tools / 'rg', '--version'], timeout=15).decode().strip(),
              'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'provider_requests': 0, 'credential': 'none', 'rows': [], 'status': 'running'}
    cases = [('missing', ['files', '--glob', '*.py'], False)] + [
        (f'{iteration}-{name}', argv, True) for iteration in range(3)
        for name, argv in [('files', ['files', '--glob', '*.py']), ('search', ['search', 'ouro_probe_marker'])]]
    for name, argv, supplied in cases:
        destination = out / name
        destination.mkdir()
        root = Path(tempfile.mkdtemp(prefix='.ouro-opencode-tools-', dir=Path.home()))
        work, config = root / 'work', root / 'config'
        work.mkdir(); config.mkdir()
        (work / 'numbers_task.py').write_text('# ouro_probe_marker\n')
        env = {'HOME': str(root), 'PATH': '/usr/bin:/bin',
               'OURO_CONFIG_DIR': str(config), 'OURO_DATA_DIR': str(root / 'data'),
               'XDG_RUNTIME_DIR': os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')}
        if supplied:
            env['PATH'] = str(tools) + os.pathsep + env['PATH']
        else:
            assert shutil.which('rg', path=env['PATH']) is None, 'Missing-rg fixture needs a host without system rg.'
        subprocess.run(['git', 'init', '-q', work], env=env, check=True)
        command = [str(binary), 'run', '--launch', 'opencode', '--workspace', str(work),
                   '--ro', str(agent.parent), '--limit', 'wall=30s']
        if supplied:
            command += ['--ro', str(tools)]
        command += ['--']
        if supplied:
            command += ['/usr/bin/env', 'PATH=' + env['PATH']]
        command += [str(agent), 'debug', 'rg', *argv]
        done = subprocess.run(command, env=env, cwd=work, capture_output=True, timeout=45)
        (destination / 'stdout.txt').write_bytes(done.stdout)
        (destination / 'stderr.txt').write_bytes(done.stderr)
        [attempt] = list((root / 'data/attempts').iterdir())
        receipt = json.loads((attempt / 'jail.json').read_text())
        shutil.copyfile(attempt / 'jail.json', destination / 'jail.json')
        events = [json.loads(line) for line in (attempt / 'trace.ndjson').read_text().splitlines()]
        with gzip.open(destination / 'trace.ndjson.gz', 'wb') as file:
            file.write((attempt / 'trace.ndjson').read_bytes())
        denied = [e['fields'].get('destination') for e in events
                  if e['source'] == 'proxy' and e.get('decision') == 'deny']
        cleaned = receipt['lifetime']['tree_empty'] is True and receipt['state_cleanup'] == 'complete'
        healthy = all(r['status'] == 'active' and not r['gaps'] for r in receipt['coverage'].values())
        passed = cleaned and healthy and receipt['containment'] == 'enforced'
        if supplied:
            passed = passed and done.returncode == 0 and b'numbers_task.py' in done.stdout and not denied
        else:
            passed = passed and done.returncode != 0 and 'github.com:443' in denied
        row = {'case': name, 'rg_supplied': supplied, 'exit': done.returncode,
               'passed': passed, 'denied_destinations': denied, 'tree_empty': cleaned,
               'coverage_healthy': healthy}
        result['rows'].append(row)
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(name, 'PASS' if passed else 'FAIL', flush=True)
        if cleaned:
            shutil.rmtree(root)
        else:
            result['retained_root'] = str(root)
            break
    result['status'] = 'passed' if len(result['rows']) == len(cases) and all(r['passed'] for r in result['rows']) else 'failed'
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())

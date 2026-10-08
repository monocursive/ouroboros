#!/usr/bin/env python3
"""Repeat real OpenCode tasks with isolated state and receipt-bound results.

Direct/off/on timings include model latency; they are descriptive, not a causal
estimate of sandbox overhead. Use xtask perf for fixed-workload phase budgets.
Only disposable fixture source and a credential-free model are used. Never
delete an attempt whose receipt has not proved tree death and state cleanup.
"""
import argparse
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import random
import shutil
import signal
import statistics
import subprocess
import tempfile
import time


MODEL = 'opencode/big-pickle'
PROMPTS = {
    'greeting': 'Create greeting.txt containing exactly hello followed by a newline. '
                'Do not read any other file or use the network yourself.',
    'repair': 'Fix sum_even in numbers_task.py so it sums only even integers, including '
              'negative integers. Run python3 -m unittest -v. Do not change test_numbers.py. '
              'Do not install dependencies or use the network yourself.',
}
TEST_SOURCE = '''import unittest
from numbers_task import sum_even
class NumbersTest(unittest.TestCase):
    def test_mixed(self): self.assertEqual(sum_even([1,2,3,4]), 6)
    def test_negative(self): self.assertEqual(sum_even([-4,-3,-2,-1,0,2]), -4)
    def test_empty(self): self.assertEqual(sum_even([]), 0)
'''


def sha256(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def stop_group(child):
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        return child.wait(timeout=15)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return child.wait(timeout=15)


def wait_trial(child, stderr_path, outer_seconds):
    """Stop the experiment on a provider refusal instead of amplifying its retries."""
    deadline = time.monotonic() + outer_seconds
    while child.poll() is None:
        with stderr_path.open('rb') as stream:
            stream.seek(max(0, stderr_path.stat().st_size - 65536))
            limited = b'Rate limit exceeded' in stream.read(65536)
        if limited:
            return stop_group(child), ['stopped after explicit provider rate limit']
        if time.monotonic() >= deadline:
            return stop_group(child), ['outer deadline exceeded']
        time.sleep(.1)
    return child.returncode, []


def receipt_problems(receipt, observe):
    problems = []
    for key, expected in [('phase', 'settled'), ('containment', 'enforced'),
                          ('exec_observed', True), ('state_cleanup', 'complete')]:
        if receipt.get(key) != expected:
            problems.append(f'{key} != {expected!r}')
    lifetime = receipt.get('lifetime', {})
    if lifetime.get('tree_empty') is not True or lifetime.get('integrity') != 'verified':
        problems.append('tree death is not verified')
    outcome = receipt.get('outcome', {})
    if outcome.get('kind') != 'exited' or outcome.get('code') != 0:
        problems.append('target did not exit zero')
    coverage = receipt.get('coverage', {})
    if observe == 'on':
        for name in ['exec', 'fs.write', 'fs.deny', 'net', 'proxy.net', 'limits']:
            row = coverage.get(name, {})
            if row.get('status') != 'active' or row.get('gaps') != []:
                problems.append(f'{name} coverage incomplete')
        for name in ['exec', 'fs.write', 'net', 'proxy.net']:
            if coverage.get(name, {}).get('observed_count', 0) <= 0:
                problems.append(f'{name} has no observed events')
    else:
        for name in ['exec', 'fs.write', 'fs.deny', 'net']:
            if coverage.get(name, {}).get('status') != 'unsupported':
                problems.append(f'{name} must be unobserved')
    return problems


def summarize(rows):
    cells = {}
    for task in PROMPTS:
        for arm in ['direct', 'off', 'on']:
            selected = [r for r in rows if r['task'] == task and r['arm'] == arm]
            if not selected:
                continue
            passed = [r['seconds'] for r in selected if r['passed']]
            cells[f'{task}/{arm}'] = {
                'attempts': len(selected), 'passed': len(passed),
                'failed': len(selected) - len(passed),
                'median_seconds': statistics.median(passed) if passed else None,
                'p95_seconds': sorted(passed)[math.ceil(len(passed) * .95) - 1] if passed else None,
                'timing_population': 'successful attempts only; failures retained separately',
            }
    return cells


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--model', default=MODEL, help='Explicit provider/model; defaults to the credential-free fixture.')
    parser.add_argument('--tool-dir', type=Path, help='Read-only directory containing a provisioned rg binary.')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--inputs', required=True, help='Expected Jail build-input SHA256.')
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--arms', nargs='+', choices=['direct', 'off', 'on'], default=['direct', 'off', 'on'])
    parser.add_argument('--tasks', nargs='+', choices=list(PROMPTS), default=list(PROMPTS))
    parser.add_argument('--seed', type=int, default=20261008)
    parser.add_argument('--wall-seconds', type=int, default=120)
    parser.add_argument('--diagnostic-logs', action='store_true')
    parser.add_argument('--pure', action='store_true', help='Explicit separate OpenCode no-plugin experiment.')
    parser.add_argument('--cooldown-seconds', type=int, default=10)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 30 or not 15 <= args.wall_seconds <= 300:
        parser.error('rounds must be 1..30; wall-seconds must be 15..300')
    if not 0 <= args.cooldown_seconds <= 60:
        parser.error('cooldown-seconds must be 0..60')
    os.umask(0o077)
    binary, agent, out = args.binary.resolve(), args.agent.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    minimal = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(Path.home()),
               'XDG_RUNTIME_DIR': os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')}
    if args.tool_dir:
        args.tool_dir = args.tool_dir.resolve(strict=True)
        minimal['PATH'] = str(args.tool_dir) + os.pathsep + minimal['PATH']
    rg = shutil.which('rg', path=minimal['PATH'])
    if 'repair' in args.tasks and rg is None:
        parser.error('OpenCode file search requires ripgrep; provision rg or pass --tool-dir. '
                     'The profile intentionally does not allow its GitHub fallback download.')
    build = json.loads(subprocess.check_output([binary, 'version', '--json'], env=minimal, timeout=15))
    if build['build']['inputs'] != args.inputs or build['build']['opt_level'] != '3':
        raise RuntimeError('The optimized binary must match the expected source inputs.')
    vendor = subprocess.check_output([agent, '--version'], env=minimal, timeout=15).decode().strip()
    if vendor != '1.18.32':
        raise RuntimeError('This fixture pins OpenCode 1.18.32.')
    result = {'schema': 'ouro.jail.agent-matrix/1', 'build': build,
              'harness_sha256': sha256(Path(__file__)),
              'binary_sha256': sha256(binary), 'agent_sha256': sha256(agent),
              'vendor_version': vendor, 'model': args.model, 'credential': 'none',
              'ripgrep': {'path': rg, 'sha256': sha256(Path(rg))} if rg else None,
              'host': list(os.uname()), 'seed': args.seed, 'rounds': args.rounds,
              'arms': args.arms, 'tasks': args.tasks, 'pure': args.pure,
              'diagnostic_logs': args.diagnostic_logs,
              'cooldown_seconds': args.cooldown_seconds,
              'wall_seconds': args.wall_seconds, 'rows': [], 'status': 'running',
              'timing_limit': 'Includes remote model latency and fresh vendor state per attempt.'}

    def save():
        result['summary'] = summarize(result['rows'])
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')

    save()
    rng = random.Random(args.seed)
    for iteration in range(args.rounds):
        cells = [(task, arm) for task in args.tasks for arm in args.arms]
        rng.shuffle(cells)
        for task, arm in cells:
            name = f'{iteration:02d}-{task}-{arm}'
            destination = out / name
            destination.mkdir()
            root = Path(tempfile.mkdtemp(prefix='.ouro-agent-matrix-', dir=Path.home()))
            work, config, home = root / 'work', root / 'config', root / 'home'
            for path in [work, config, home]:
                path.mkdir(mode=0o700)
            env = {**minimal, 'HOME': str(home), 'OURO_CONFIG_DIR': str(config),
                   'OURO_DATA_DIR': str(root / 'data')}
            for key, leaf in [('XDG_CONFIG_HOME', 'config'), ('XDG_DATA_HOME', 'data'),
                              ('XDG_CACHE_HOME', 'cache'), ('XDG_STATE_HOME', 'state')]:
                env[key] = str(home / leaf)
            subprocess.run(['git', 'init', '-q', work], env=env, check=True)
            if task == 'repair':
                (work / 'numbers_task.py').write_text('def sum_even(numbers):\n    return sum(numbers)\n')
                (work / 'test_numbers.py').write_text(TEST_SOURCE)
            command = [str(agent), 'run', '--model', args.model, PROMPTS[task]]
            if args.diagnostic_logs:
                command[2:2] = ['--print-logs', '--log-level', 'DEBUG', '--format', 'json']
            if args.pure:
                command[2:2] = ['--pure']
            if arm != 'direct':
                # Contained profiles deliberately replace the host PATH. A
                # supplied tool directory must be explicit in the child's argv.
                if args.tool_dir:
                    command = ['/usr/bin/env', 'PATH=' + minimal['PATH']] + command
                command = [str(binary), 'run', '--launch', 'opencode', '--workspace', str(work),
                           '--ro', str(agent.parent), '--observe', arm, '--limit',
                           f'wall={args.wall_seconds}s'] + (
                               ['--ro', str(args.tool_dir)] if args.tool_dir else []
                           ) + ['--'] + command
            row = {'name': name, 'iteration': iteration, 'task': task, 'arm': arm,
                   'load_before': os.getloadavg(), 'passed': False, 'problems': []}
            started = time.monotonic()
            with (destination / 'stdout.txt').open('wb') as stdout, (destination / 'stderr.txt').open('wb') as stderr:
                child = subprocess.Popen(command, env=env, cwd=work, stdin=subprocess.DEVNULL,
                                         stdout=stdout, stderr=stderr, start_new_session=True)
                result['active_trial'] = {'name': name, 'root': str(root), 'pid': child.pid}
                save()
                row['exit'], wait_problems = wait_trial(child, destination / 'stderr.txt', args.wall_seconds + 20)
                row['problems'] += wait_problems
            row['seconds'] = time.monotonic() - started
            row['provider_rate_limited'] = 'Rate limit exceeded' in (destination / 'stderr.txt').read_text(errors='replace')
            if row['exit'] != 0:
                row['problems'].append('CLI did not exit zero')
            judge_safe = True
            if task == 'greeting':
                output = work / 'greeting.txt'
                if not output.is_file() or output.is_symlink() or output.read_bytes() != b'hello\n':
                    row['problems'].append('incorrect greeting')
                else:
                    shutil.copyfile(output, destination / 'greeting.txt')
            else:
                if (work / 'test_numbers.py').read_text() != TEST_SOURCE:
                    row['problems'].append('agent modified the judge')
                judge = subprocess.run([str(binary), 'run', '--profile', 'tool', '--workspace', str(work),
                                        '--limit', 'wall=15s', '--', '/usr/bin/python3', '-I', '-m',
                                        'unittest', 'discover', '-s', str(work), '-v'],
                                       env={**env, 'OURO_DATA_DIR': str(root / 'judge-data')},
                                       cwd=work, capture_output=True, timeout=30)
                (destination / 'judge.txt').write_bytes(judge.stdout + judge.stderr)
                if judge.returncode != 0:
                    row['problems'].append('independent tests failed')
                shutil.copyfile(work / 'numbers_task.py', destination / 'numbers_task.py')
                judge_attempts = list((root / 'judge-data/attempts').glob('*/jail.json'))
                judge_safe = False
                if len(judge_attempts) == 1:
                    shutil.copyfile(judge_attempts[0], destination / 'judge-jail.json')
                    judged = json.loads(judge_attempts[0].read_text())
                    judge_safe = (judged.get('lifetime', {}).get('tree_empty') is True
                                  and judged.get('state_cleanup') == 'complete')
                if not judge_safe:
                    row['problems'].append('judge cleanup is unverified')
            cleanup_safe = False
            if arm == 'direct':
                # This baseline has no Jail lifetime guarantee. Only claim that
                # the group we created has ended; retain state if it has not.
                try:
                    os.killpg(child.pid, 0)
                except ProcessLookupError:
                    cleanup_safe = True
                row['cleanup_scope'] = 'process_group_only_not_attempt_tree'
            if arm != 'direct':
                attempts = list((root / 'data/attempts').glob('*'))
                if len(attempts) != 1:
                    row['problems'].append('expected exactly one attempt')
                else:
                    attempt = attempts[0]
                    for filename in ['jail.json', 'policy.json']:
                        if (attempt / filename).is_file():
                            shutil.copyfile(attempt / filename, destination / filename)
                    if (attempt / 'trace.ndjson').is_file():
                        row['trace_sha256'] = sha256(attempt / 'trace.ndjson')
                        with (attempt / 'trace.ndjson').open('rb') as source, gzip.open(destination / 'trace.ndjson.gz', 'wb') as target:
                            shutil.copyfileobj(source, target)
                    try:
                        receipt = json.loads((attempt / 'jail.json').read_text())
                        row['problems'] += receipt_problems(receipt, arm)
                        row['attempt_id'] = receipt.get('attempt_id')
                        row['outcome'] = receipt.get('outcome')
                        cleanup_safe = (receipt.get('lifetime', {}).get('tree_empty') is True
                                        and receipt.get('state_cleanup') == 'complete')
                    except (OSError, ValueError) as error:
                        row['problems'].append(f'receipt unavailable: {type(error).__name__}')
            row['passed'] = not row['problems']
            cleanup_safe = cleanup_safe and judge_safe
            if cleanup_safe:
                shutil.rmtree(root)
            else:
                row['retained_root'] = str(root)
            result['rows'].append(row)
            result.pop('active_trial', None)
            save()
            print(name, 'PASS' if row['passed'] else 'FAIL', round(row['seconds'], 2), row['problems'], flush=True)
            if row['provider_rate_limited']:
                result['status'] = 'blocked'
                result['blocked_reason'] = 'provider_rate_limit; remaining trials were not attempted'
                save()
                return 125
            if not cleanup_safe:
                result['status'] = 'failed'
                save()
                return 1
            time.sleep(args.cooldown_seconds)
    result['status'] = 'passed' if all(row['passed'] for row in result['rows']) else 'failed'
    save()
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())

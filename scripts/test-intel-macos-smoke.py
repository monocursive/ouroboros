#!/usr/bin/env python3
"""Small harness tests only, not simulated Intel platform acceptance.

    python3 scripts/test-intel-macos-smoke.py
"""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('intel_smoke', Path(__file__).with_name('intel-macos-smoke.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class HarnessTests(unittest.TestCase):
    def test_runtime_environment_drops_secrets_and_toolchains(self):
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'not-a-secret-test-value', 'GITHUB_TOKEN': 'test'}):
            env = smoke.isolated_env(Path('/synthetic'))
        self.assertNotIn('OPENAI_API_KEY', env)
        self.assertNotIn('GITHUB_TOKEN', env)
        self.assertEqual(env['PATH'], '/usr/bin:/bin:/usr/sbin:/sbin')
        self.assertEqual(env['OUROBOROS_DIST'], 'none')

    def test_non_workflow_execution_refuses_before_runtime(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(smoke.Refused):
                smoke.state_path()

    def test_owned_runner_success_failure_output_and_disk(self):
        with tempfile.TemporaryDirectory() as root:
            def run(code, **kwargs):
                return smoke.run([sys.executable, '-I', '-c', code], cwd=root,
                                 env={}, min_free=0, **kwargs)
            self.assertEqual(run('print("ok")').strip(), 'ok')
            for code, opts in [('raise SystemExit(7)', {}),
                               ('print("x" * 4096)', {'limit': 128})]:
                with self.subTest(code=code), self.assertRaises(smoke.Refused):
                    run(code, **opts)
            with self.assertRaises(smoke.Refused):
                smoke.run([sys.executable, '-I', '-c', 'raise SystemExit("must not run")'],
                          cwd=root, env={}, min_free=10**30)

    def test_cleanup_absent_unowned_and_unpublished_attempt(self):
        with tempfile.TemporaryDirectory() as root, patch.object(smoke, 'run') as run:
            state = Path(root) / 'state'
            smoke.cleanup(state)
            state.mkdir()
            with self.assertRaises(FileNotFoundError):
                smoke.cleanup(state)
            (state / 'owned').write_text('intel-smoke-v1\n')
            (state / 'start-attempted').write_text('attempted')
            with self.assertRaises(smoke.Refused):
                smoke.cleanup(state)
            run.assert_not_called()

    def test_cleanup_uses_only_owned_client_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as root, patch.object(smoke, 'run') as run:
            run.return_value = 'the runtime accepted runtime.shutdown\nthe runtime stopped (pid 42)\n'
            state = Path(root)
            (state / 'owned').write_text('intel-smoke-v1\n')
            (state / 'data').mkdir()
            (state / 'data/gateway.json').write_text('{}')
            smoke.cleanup(state)
            smoke.cleanup(state)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0], [str(state / 'bin/ouro'), 'stop'])

    def test_stale_cleanup_is_not_authenticated_lifecycle_evidence(self):
        with tempfile.TemporaryDirectory() as root, patch.object(smoke, 'run') as run:
            run.return_value = 'no runtime is running: pid 42 is gone; stale publication removed\n'
            state = Path(root)
            (state / 'owned').write_text('intel-smoke-v1\n')
            (state / 'data').mkdir()
            (state / 'data/gateway.json').write_text('{}')
            self.assertIs(smoke.cleanup(state), False)
            self.assertIs(smoke.cleanup(state), False)
            self.assertEqual(run.call_count, 1)

    def test_group_teardown_targets_descendants_even_after_leader_exit(self):
        leader = Mock(pid=999999, returncode=0)
        with patch.object(smoke.os, 'killpg') as kill, patch.object(smoke.time, 'sleep'):
            smoke.end_group(leader)
        self.assertEqual([c.args for c in kill.call_args_list],
                         [(999999, smoke.signal.SIGTERM), (999999, smoke.signal.SIGKILL)])
        leader.wait.assert_called_once_with(timeout=5)

    def test_interrupted_grace_still_kills_owned_group(self):
        leader = Mock(pid=999999, returncode=0)
        with patch.object(smoke.os, 'killpg') as kill, \
             patch.object(smoke.time, 'sleep', side_effect=smoke.Refused('interrupted')):
            with self.assertRaises(smoke.Refused):
                smoke.end_group(leader)
        self.assertEqual(kill.call_args.args, (999999, smoke.signal.SIGKILL))
        leader.wait.assert_called_once_with(timeout=5)

    def test_timeout_teardown_with_deterministic_child_double(self):
        # No live timeout child: host group-signalling refusal is retained in the
        # preparation receipt, not retried or represented as a passing kernel test.
        with tempfile.TemporaryDirectory() as root, \
             patch.object(smoke.subprocess, 'Popen') as popen, \
             patch.object(smoke, 'end_group') as end:
            child = popen.return_value
            child.poll.return_value = None
            with self.assertRaises(smoke.Refused):
                smoke.run(['/not/executed'], cwd=root, env={}, timeout=-1, min_free=0)
            end.assert_called_once_with(child)

    def test_cleanup_failure_cannot_mark_success(self):
        with tempfile.TemporaryDirectory() as root, patch.object(smoke, 'run', side_effect=smoke.Refused('failed')):
            state = Path(root)
            (state / 'owned').write_text('intel-smoke-v1\n')
            (state / 'data').mkdir()
            (state / 'data/gateway.json').write_text('{}')
            with self.assertRaises(smoke.Refused):
                smoke.cleanup(state)
            self.assertFalse((state / 'stopped').exists())


if __name__ == '__main__':
    unittest.main()

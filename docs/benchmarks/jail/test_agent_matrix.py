import copy
from pathlib import Path
import tempfile
import unittest

from agent_matrix import receipt_problems, summarize
from verify_agent_matrix import verify_inventory, verify_trial_files
from onboarding_guest import verify_build


class AgentEvidenceTests(unittest.TestCase):
    def test_missing_trace_judge_or_fixture_cannot_pass_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = ['stdout.txt', 'stderr.txt', 'jail.json', 'trace.ndjson.gz',
                     'judge-jail.json', 'judge.txt', 'numbers_task.py']
            row = {'task': 'repair', 'arm': 'on', 'passed': True}
            for name in names:
                (root / name).write_bytes(b'')
            verify_trial_files(root, row)
            for name in names:
                with self.subTest(name=name):
                    (root / name).unlink()
                    with self.assertRaises(ValueError):
                        verify_trial_files(root, row)
                    (root / name).write_bytes(b'')
            row['task'] = 'greeting'
            with self.assertRaises(ValueError):
                verify_trial_files(root, row)
            self.assertFalse(verify_trial_files(root, row, allow_missing_greetings=True))
            (root / 'greeting.txt').write_bytes(b'wrong\n')
            with self.assertRaises(ValueError):
                verify_trial_files(root, row)
            with self.assertRaises(ValueError):
                verify_trial_files(root, row, allow_missing_greetings=True)
            (root / 'greeting.txt').write_bytes(b'hello\n')
            verify_trial_files(root, row)

    def test_onboarding_requires_the_expected_clean_optimized_artifact(self):
        build = {'revision': 'revision', 'dirty': False, 'target': 'x86_64-unknown-linux-gnu',
                 'opt_level': '3', 'debug_assertions': False, 'inputs': 'sha256:expected'}
        verify_build({'build': build}, 'revision', 'sha256:expected')
        for key, value in [('revision', 'other'), ('dirty', None), ('dirty', True),
                           ('opt_level', '0'), ('debug_assertions', True),
                           ('target', 'aarch64-apple-darwin'), ('inputs', 'sha256:other')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                verify_build({'build': {**build, key: value}}, 'revision', 'sha256:expected')

    def receipt(self):
        return {
            'phase': 'settled', 'containment': 'enforced', 'exec_observed': True,
            'state_cleanup': 'complete', 'outcome': {'kind': 'exited', 'code': 0},
            'lifetime': {'tree_empty': True, 'integrity': 'verified'},
            'coverage': {name: {'status': 'active', 'gaps': [], 'observed_count': 1}
                         for name in ['exec', 'fs.write', 'fs.deny', 'net', 'proxy.net', 'limits']},
        }

    def test_zero_exit_cannot_hide_missing_containment_cleanup_or_coverage(self):
        valid = self.receipt()
        self.assertEqual(receipt_problems(valid, 'on'), [])
        mutations = [
            lambda r: r.update(containment='unprotected'),
            lambda r: r.update(exec_observed=False),
            lambda r: r.update(state_cleanup='pending'),
            lambda r: r['lifetime'].update(tree_empty=False),
            lambda r: r['lifetime'].update(integrity='unknown'),
            lambda r: r['outcome'].update(code=1),
            lambda r: r['coverage']['exec'].update(gaps=[{'reason': 'lost'}]),
            lambda r: r['coverage']['proxy.net'].update(observed_count=0),
            lambda r: r['coverage'].pop('fs.deny'),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(valid)
                mutate(changed)
                self.assertTrue(receipt_problems(changed, 'on'))

    def test_observation_off_must_be_labelled_unsupported(self):
        row = self.receipt()
        self.assertTrue(receipt_problems(row, 'off'))
        for name in ['exec', 'fs.write', 'fs.deny', 'net']:
            row['coverage'][name]['status'] = 'unsupported'
        self.assertEqual(receipt_problems(row, 'off'), [])

    def test_failed_attempts_are_retained_and_never_improve_timing(self):
        rows = [{'task': 'greeting', 'arm': 'on', 'passed': True, 'seconds': 10},
                {'task': 'greeting', 'arm': 'on', 'passed': False, 'seconds': 1}]
        cell = summarize(rows)['greeting/on']
        self.assertEqual((cell['attempts'], cell['passed'], cell['failed']), (2, 1, 1))
        self.assertEqual(cell['median_seconds'], 10)
        self.assertEqual(cell['p95_seconds'], 10)
        rows[0]['passed'] = False
        self.assertIsNone(summarize(rows)['greeting/on']['median_seconds'])

    def test_partial_duplicate_or_edited_evidence_cannot_pass_inventory(self):
        row = {'name': '00-greeting-on', 'iteration': 0, 'task': 'greeting',
               'arm': 'on', 'passed': True, 'problems': [], 'exit': 0, 'seconds': 1}
        result = {'rounds': 1, 'arms': ['on'], 'tasks': ['greeting'],
                  'rows': [row], 'status': 'passed', 'summary': summarize([row])}
        verify_inventory(result)
        for mutate in [lambda d: d['rows'].clear(), lambda d: d['rows'].append(row),
                       lambda d: d['rows'][0].update(exit=1),
                       lambda d: d['rows'][0].update(problems=['lost']),
                       lambda d: d.update(status='running'),
                       lambda d: d.update(active_trial={'pid': 123}),
                       lambda d: d.update(rounds=1000000),
                       lambda d: d.update(tasks=['../../outside']),
                       lambda d: d['rows'][0].update(task='repair'),
                       lambda d: d['rows'][0].update(seconds=float('nan')),
                       lambda d: d['summary'].clear()]:
            changed = copy.deepcopy(result)
            mutate(changed)
            with self.assertRaises(ValueError):
                verify_inventory(changed)

    def test_retained_provider_refusal_never_closes_missing_trials(self):
        row = {'name': '00-greeting-on', 'iteration': 0, 'task': 'greeting',
               'arm': 'on', 'passed': False, 'problems': ['CLI did not exit zero'],
               'provider_rate_limited': True, 'exit': 1, 'seconds': 1}
        result = {'rounds': 3, 'arms': ['on'], 'tasks': ['greeting'],
                  'rows': [row], 'status': 'blocked', 'blocked_reason': 'provider_rate_limit',
                  'summary': summarize([row])}
        with self.assertRaises(ValueError):
            verify_inventory(result)
        self.assertFalse(verify_inventory(result, require_complete=False)['complete'])
        result['status'] = 'passed'
        with self.assertRaises(ValueError):
            verify_inventory(result, require_complete=False)


if __name__ == '__main__':
    unittest.main()

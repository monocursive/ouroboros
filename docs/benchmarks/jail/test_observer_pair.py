import unittest
from summarize_observer_pair import analyze


class PairedEvidenceTests(unittest.TestCase):
    def data(self):
        result = {'status': 'completed', 'samples': 10, 'warmups': 1, 'rounds': 5, 'rows': []}
        for i in range(-1, 10):
            for arm in ['before', 'after']:
                work = 100 if arm == 'before' else 80
                if i < 0: work = 10000
                result['rows'].append({'iteration': i, 'arm': arm, 'exit': 0,
                    'receipt_healthy': True, 'wall_ns': work + 100, 'load1': 1,
                    'fixture_start': {'op': 'perf-start', 'args': {'monotonic_ns': 1}},
                    'fixture_end': {'op': 'fileops', 'args': {'start_ns': 1, 'end_ns': work + 1,
                        'created': 5, 'renamed': 5, 'unlinked': 5, 'ok': True}}})
        return result

    def test_paired_ratio_excludes_only_declared_warmups(self):
        out = analyze(self.data())
        self.assertTrue(out['work_improvement_demonstrated'])
        self.assertEqual(out['work_ns']['paired_ratio']['median'], .8)
        self.assertEqual(out['measured_launches'], 20)
        self.assertEqual(out['warmup_launches'], 2)
        self.assertEqual(out['exclusions'], 0)

    def test_incomplete_duplicate_failed_and_altered_workload_refuse(self):
        for mutate in [lambda d: d['rows'].pop(), lambda d: d['rows'].append(d['rows'][0]),
                       lambda d: d.update(status='running'),
                       lambda d: d['rows'][0].update(receipt_healthy=False),
                       lambda d: d['rows'][0].update(exit=1),
                       lambda d: d['rows'][0]['fixture_end']['args'].update(created=4),
                       lambda d: d['rows'][0]['fixture_end']['args'].update(start_ns=2)]:
            data = self.data(); mutate(data)
            with self.assertRaises(ValueError): analyze(data)

    def test_no_change_does_not_become_an_improvement(self):
        data = self.data()
        for row in data['rows']:
            row['fixture_end']['args']['end_ns'] = 101
        self.assertFalse(analyze(data)['work_improvement_demonstrated'])


if __name__ == '__main__':
    unittest.main()

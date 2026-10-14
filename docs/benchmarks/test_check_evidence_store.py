import hashlib
import json
import pathlib
import subprocess
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check_evidence_store as store  # noqa: E402

BIG = store.LIMIT + 1
CORPUS = 'docs/benchmarks/demo/2026-11-01'
SUMS = b'00  a.log\n'


def run(files, allowlist):
    """files: {path: bytes}."""
    return store.check({p: len(d) if isinstance(d, bytes) else d for p, d in files.items()},
                       lambda p: files.get(p) if isinstance(files.get(p), bytes) else None, allowlist)


def bundle(**fields):
    base = {'url': 'https://github.com/o/r/releases/download/evidence%2Fdemo/demo.tar.gz',
            'sha256': 'a' * 64, 'bytes': 10, 'files': 1,
            'root_manifest_sha256': hashlib.sha256(SUMS).hexdigest()}
    base.update(fields)
    return json.dumps(base).encode()


class EvidenceStore(unittest.TestCase):
    def test_small_files_and_undated_directories_pass(self):
        self.assertEqual(run({'README.md': b'x', 'docs/benchmarks/jail/results/run-2026-11-01/a.json': b'{}'}, {}), [])

    def test_a_large_file_needs_an_allowlist_entry(self):
        problems = run({'crates/x/blob.bin': BIG}, {})
        self.assertEqual(len(problems), 1)
        self.assertIn('crates/x/blob.bin', problems[0])
        self.assertEqual(run({'crates/x/blob.bin': BIG}, {'large_files': ['crates/x/blob.bin']}), [])

    def test_exactly_the_limit_is_allowed(self):
        self.assertEqual(run({'crates/x/blob.bin': store.LIMIT}, {}), [])

    def test_stale_large_file_entries_fail(self):
        problems = run({'crates/x/blob.bin': 10}, {'large_files': ['crates/x/blob.bin', 'gone.bin']})
        self.assertEqual(len(problems), 2)

    def test_a_new_dated_corpus_needs_a_bundle(self):
        problems = run({f'{CORPUS}/README.md': b'x', f'{CORPUS}/2026-11-02/nested.log': b'y'}, {})
        self.assertEqual(problems, [f'{CORPUS}: a new evidence corpus needs a bundle.json (docs/benchmarks/README.md)'])

    def test_a_listed_corpus_passes_and_stale_entries_fail(self):
        files = {f'{CORPUS}/README.md': b'x'}
        self.assertEqual(run(files, {'corpora_without_bundle': [CORPUS]}), [])
        self.assertEqual(len(run(files, {'corpora_without_bundle': [CORPUS, 'docs/benchmarks/gone/2026-01-01']})), 1)

    def test_a_valid_bundle_binds_the_manifest(self):
        files = {f'{CORPUS}/README.md': b'x', f'{CORPUS}/SHA256SUMS': SUMS, f'{CORPUS}/bundle.json': bundle()}
        self.assertEqual(run(files, {}), [])
        self.assertEqual(len(run(files, {'corpora_without_bundle': [CORPUS]})), 1)

    def test_bundle_problems_are_reported(self):
        cases = {
            'not JSON': b'{',
            'url': bundle(url='http://example.com/x'),
            'sha256': bundle(sha256='A' * 64),
            'bytes': bundle(bytes=True),
            'files': bundle(files=0),
            'root_manifest_sha256 is not': bundle(root_manifest_sha256='b' * 64),
        }
        for expected, data in cases.items():
            with self.subTest(expected):
                files = {f'{CORPUS}/SHA256SUMS': SUMS, f'{CORPUS}/bundle.json': data}
                problems = run(files, {})
                self.assertTrue(problems and any(expected in p for p in problems), problems)
        missing = run({f'{CORPUS}/bundle.json': bundle()}, {})
        self.assertTrue(any('SHA256SUMS' in p for p in missing), missing)

    def test_refuses_optimized_python(self):
        result = subprocess.run([sys.executable, '-O', str(HERE / 'check_evidence_store.py')],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('must not run with python -O', result.stderr)


if __name__ == '__main__':
    unittest.main()

import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'specs'))

import retired_archives  # noqa: E402
import validate_links  # noqa: E402

RUN = 'docs/benchmarks/demo/2026-01-01'


def git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


class RetiredArchives(unittest.TestCase):
    def setUp(self):
        self.repo = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        git(self.repo, 'init', '-q')
        git(self.repo, 'config', 'user.email', 'test@example.invalid')
        git(self.repo, 'config', 'user.name', 'test')
        results = self.repo / RUN / 'results'
        (results / 'host').mkdir(parents=True)
        (results / 'host' / 'a.log').write_bytes(b'line\r\n')
        (results / 'host' / 'b.json').write_text('{}\n')
        (self.repo / RUN / 'archives').mkdir()
        self.archive(f'{RUN}/archives/host.tar.gz', {'a.log': b'line\r\n', 'b.json': b'{}\n'})
        self.archive(f'{RUN}/archives/stale.tar.gz', {'a.log': b'older\n', 'b.json': b'{}\n'})
        self.commit()

    def archive(self, path, members):
        with tarfile.open(self.repo / path, 'w:gz') as output:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                output.addfile(info, io.BytesIO(data))

    def commit(self):
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', 'x')
        return git(self.repo, 'rev-parse', 'HEAD')

    def run_quietly(self, function, *args):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = function(self.repo, *args)
        return code, out.getvalue()

    def test_a_full_duplicate_gets_a_record_and_verifies(self):
        self.run_quietly(retired_archives.prove, 'HEAD', [f'{RUN}/archives/host.tar.gz'])
        record = json.loads((self.repo / RUN / 'archives/host.tar.gz.retired.json').read_text())
        self.assertEqual(record['members'], {'file': 2})
        self.assertEqual(record['members_identical'], 2)
        self.assertEqual(record['duplicate_of'], f'{RUN}/results/host/')
        self.assertEqual(record['parts'][0]['git_blob'], git(self.repo, 'rev-parse', f'HEAD:{RUN}/archives/host.tar.gz'))
        git(self.repo, 'rm', '-q', f'{RUN}/archives/host.tar.gz')
        self.commit()
        code, out = self.run_quietly(retired_archives.verify, 'HEAD')
        self.assertEqual(code, 0, out)

    def test_an_archive_with_a_differing_member_gets_no_record(self):
        _, out = self.run_quietly(retired_archives.prove, 'HEAD', [f'{RUN}/archives/stale.tar.gz'])
        self.assertIn('NOT A DUPLICATE', out)
        self.assertFalse((self.repo / RUN / 'archives/stale.tar.gz.retired.json').exists())

    def test_verify_fails_once_the_tracked_tree_diverges(self):
        self.run_quietly(retired_archives.prove, 'HEAD', [f'{RUN}/archives/host.tar.gz'])
        (self.repo / RUN / 'results/host/a.log').write_bytes(b'line\n')
        self.commit()
        code, out = self.run_quietly(retired_archives.verify, 'HEAD')
        self.assertEqual(code, 1)
        self.assertIn('DIVERGED', out)

    def test_verify_fails_when_a_record_is_edited(self):
        self.run_quietly(retired_archives.prove, 'HEAD', [f'{RUN}/archives/host.tar.gz'])
        path = self.repo / RUN / 'archives/host.tar.gz.retired.json'
        record = json.loads(path.read_text())
        record['members_identical'] = 3
        path.write_text(json.dumps(record))
        self.commit()
        code, out = self.run_quietly(retired_archives.verify, 'HEAD')
        self.assertEqual(code, 1)
        self.assertIn('MISMATCH', out)

    def test_split_parts_are_one_archive(self):
        whole = (self.repo / RUN / 'archives/host.tar.gz').read_bytes()
        bundle = self.repo / 'docs/benchmarks/demo/2026-01-01-evidence.tar.gz'
        bundle.with_name(bundle.name + '.part00').write_bytes(whole[:100])
        bundle.with_name(bundle.name + '.part01').write_bytes(whole[100:])
        self.commit()
        parts = f'{bundle.relative_to(self.repo)}.part00+{bundle.relative_to(self.repo)}.part01'
        self.run_quietly(retired_archives.prove, 'HEAD', [parts])
        record = json.loads(bundle.with_name(bundle.name + '.retired.json').read_text())
        self.assertEqual(record['archive'], str(bundle.relative_to(self.repo)))
        self.assertEqual([p['bytes'] for p in record['parts']], [100, len(whole) - 100])
        self.assertEqual(record['bytes'], len(whole))
        self.assertEqual(record['members_identical'], 2)

    def test_link_checker_accepts_only_a_matching_record(self):
        target = (self.repo / RUN / 'archives/gone.tar.gz').resolve()
        original = validate_links.ROOT
        validate_links.ROOT = self.repo.resolve()
        self.addCleanup(setattr, validate_links, 'ROOT', original)
        self.assertFalse(validate_links.retired(target))
        record = target.with_name(target.name + '.retired.json')
        record.write_text(json.dumps({'schema': retired_archives.SCHEMA, 'archive': f'{RUN}/archives/other.tar.gz'}))
        self.assertFalse(validate_links.retired(target))
        record.write_text(json.dumps({'schema': retired_archives.SCHEMA, 'archive': f'{RUN}/archives/gone.tar.gz'}))
        self.assertTrue(validate_links.retired(target))

    def test_refuses_optimized_python(self):
        result = subprocess.run([sys.executable, '-O', str(HERE / 'retired_archives.py'), 'verify'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('must not run with python -O', result.stderr)


if __name__ == '__main__':
    unittest.main()

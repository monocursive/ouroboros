import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest

import run
import cli


class WorkspaceBoundaryTests(unittest.TestCase):
    def test_copies_exact_bytes_and_executable_bit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'file with spaces').write_bytes(b'\x00\xff\n')
            (root / 'file with spaces').chmod(0o755)
            entries = run.snapshot(root)
            self.assertEqual(entries[0]['path'], 'file with spaces')
            self.assertEqual(base64.b64decode(entries[0]['data']), b'\x00\xff\n')
            self.assertTrue(entries[0]['executable'])

    def test_excludes_build_outputs_and_git_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / '.git').mkdir()
            (root / '.git' / 'config').write_text('private')
            (root / 'target').mkdir()
            (root / 'target' / 'artifact').write_text('not an input')
            self.assertEqual(run.snapshot(root), [])

    def test_rejects_file_and_directory_symlinks(self):
        for directory in (False, True):
            with self.subTest(directory=directory), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / 'workspace'
                root.mkdir()
                outside = Path(temporary) / 'secret'
                outside.mkdir() if directory else outside.write_text('secret')
                (root / 'link').symlink_to(outside, target_is_directory=directory)
                with self.assertRaises((ValueError, OSError)):
                    run.snapshot(root)

    def test_rejects_fifo_without_blocking(self):
        import os
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.mkfifo(root / 'fifo')
            with self.assertRaises(ValueError):
                run.snapshot(root)

    def test_rejects_large_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (root / 'large').open('wb') as output:
                output.truncate(run.MAX_FILE + 1)
            with self.assertRaises(ValueError):
                run.snapshot(root)

    def test_rejects_output_traversal_and_unknown_group(self):
        for name in ('../escape', '/absolute', 'a/../../escape', 'a//b', './a', 'a/./b', 'a\0b', ''):
            with self.subTest(name=name), self.assertRaises(ValueError):
                run.output_path(Path('/staging'), 'workspace', name)
        with self.assertRaises(ValueError):
            run.output_path(Path('/staging'), '../bad', 'file')


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.receipt = {'schema': 'ouro.jail.receipt/1', 'platform': {'os': 'linux'},
                        'policy': {'name': 'tool'}, 'containment': 'enforced',
                        'child_protection': 'enforced', 'exec_observed': True,
                        'lifetime': {'tree_empty': True, 'integrity': 'verified'},
                        'state_cleanup': 'complete', 'errors': [],
                        'applied': {'network': {'mode': 'none'},
                                    'limits': [{'key': key, 'applied': True}
                                               for key in ('wall', 'mem', 'pids', 'swap')]}}

    def test_accepts_verified_linux_receipt(self):
        run.verify_receipt(self.receipt, 'tool')

    def test_rejects_unproven_cleanup(self):
        for field, value in [('tree_empty', False), ('integrity', 'unverified')]:
            receipt = copy.deepcopy(self.receipt)
            receipt['lifetime'][field] = value
            with self.assertRaises(ValueError):
                run.verify_receipt(receipt, 'tool')


    def test_rejects_refusal_platform_mismatch_and_missing_limit(self):
        for mutate in [lambda r: r.update(containment='refused'),
                       lambda r: r['platform'].update(os='macos'),
                       lambda r: r['applied']['limits'].pop(),
                       lambda r: r['applied']['network'].update(mode='host')]:
            receipt = copy.deepcopy(self.receipt)
            mutate(receipt)
            with self.assertRaises(ValueError):
                run.verify_receipt(receipt, 'tool')


class PackageTests(unittest.TestCase):
    def test_expansion_does_not_delete_an_existing_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'image.json').write_text('{}')
            (root / 'base.raw').write_bytes(b'existing image')
            with self.assertRaises(FileExistsError):
                cli.expand_image(root)
            self.assertEqual((root / 'base.raw').read_bytes(), b'existing image')

    def test_invalid_expansion_removes_partial_image(self):
        import gzip
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'image.json').write_text('{"disk_sha256":"invalid"}')
            (root / 'base.raw.gz').write_bytes(gzip.compress(b'bad image'))
            with self.assertRaises(ValueError):
                cli.expand_image(root)
            self.assertFalse((root / 'base.raw').exists())

    def test_invalid_owner_token_is_rejected_before_signalling(self):
        for token in (None, [], [0] * 7, [0] * 7 + [True], [0] * 7 + [-1], [0] * 7 + [2**32]):
            with self.subTest(token=token), self.assertRaises(ValueError):
                run.terminate_owner(token)


if __name__ == '__main__':
    unittest.main()

import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest

import cli
import guest
import run

# Both ends must agree on every name. Accepted names keep every component as
# written (a file system may still refuse one at open, like the 4096-byte
# component); rejected names are empty, absolute or contain NUL, or have
# components that PurePosixPath would drop or that climb out of the root.
ACCEPTED_PATHS = ['file', 'file with spaces', 'dir/file', 'a/b/c', '.hidden', '..hidden', 'a..b', '...', ' ',
                  'a\\b', '\\', '\u00e9/\u00fc', 'a\nb', 'x' * 4096, '/'.join(['d'] * 1000)]
REJECTED_PATHS = ['', '.', '..', '/', '/absolute', '//a', 'a//b', 'a/', 'a/b/', './a', 'a/.', 'a/./b',
                  '../escape', 'a/../b', 'a/..', 'a\0b', '\0']


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

    def test_rejects_ill_typed_receipts_without_type_errors(self):
        for mutate in [lambda r: r.update(platform='linux'),
                       lambda r: r.update(lifetime=['verified']),
                       lambda r: r['applied'].update(network='none'),
                       lambda r: r['applied'].update(limits={'wall': True}),
                       lambda r: r['applied']['limits'].append('swap'),
                       lambda r: r['applied']['limits'].append({'key': ['wall'], 'applied': True}),
                       lambda r: r['applied']['limits'].append({'applied': True})]:
            receipt = copy.deepcopy(self.receipt)
            mutate(receipt)
            with self.subTest(receipt=receipt), self.assertRaises(ValueError):
                run.verify_receipt(receipt, 'tool')
        for receipt in ([], 'receipt', None, 7):
            with self.subTest(receipt=receipt), self.assertRaises(ValueError):
                run.verify_receipt(receipt, 'tool')


class ProtocolMessageTests(unittest.TestCase):
    def test_accepts_every_guest_event_the_controller_sends(self):
        for message in [{'event': 'ready', 'kernel': '7.0.0', 'lease_seconds': 2.0},
                        {'event': 'pong', 'sequence': 0}, {'event': 'put', 'path': 'a/b'},
                        {'event': 'running', 'supervisor_pid': 42}, {'event': 'stdout', 'data': ''},
                        {'event': 'stderr', 'data': 'eA=='},
                        {'event': 'file', 'group': 'evidence', 'path': 'jail.json', 'executable': False, 'data': ''},
                        {'event': 'done', 'exit_code': -9}]:
            with self.subTest(message=message):
                self.assertEqual(run.parse_guest_message(json.dumps(message).encode()), message)

    def test_rejects_guest_lines_that_are_not_objects_with_a_string_event(self):
        for line in (b'[1]', b'"ready"', b'7', b'null', b'{}', b'{"event": 5}', b'{"event": null}',
                     b'{"event": ["ready"]}', b'{"event": {"name": "ready"}}', b'not json', b'\xff'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                run.parse_guest_message(line)

    def test_rejects_wrongly_typed_or_missing_guest_fields(self):
        for message in [{'event': 'ready'}, {'event': 'ready', 'kernel': 7},
                        {'event': 'pong', 'sequence': '0'}, {'event': 'pong', 'sequence': True},
                        {'event': 'pong', 'sequence': 1.0}, {'event': 'put', 'path': ['a']},
                        {'event': 'running', 'supervisor_pid': None}, {'event': 'stdout', 'data': 5},
                        {'event': 'stderr', 'data': ['eA==']},
                        {'event': 'file', 'group': 'workspace', 'path': 'a', 'executable': 'yes', 'data': ''},
                        {'event': 'file', 'group': 'workspace', 'path': 'a', 'executable': 1, 'data': ''},
                        {'event': 'file', 'group': ['workspace'], 'path': 'a', 'executable': False, 'data': ''},
                        {'event': 'done', 'exit_code': False}, {'event': 'done', 'exit_code': '0'},
                        {'event': 'unknown'}]:
            with self.subTest(message=message), self.assertRaises(ValueError):
                run.parse_guest_message(json.dumps(message).encode())

    def test_helper_lifecycle_events_pass_but_read_fields_are_typed(self):
        for message in [{'event': 'booted', 'pid': 1, 'network': False}, {'event': 'connected'},
                        {'event': 'stopping', 'reason': 'eof'}, {'event': 'guest_stopped'},
                        {'event': 'stopped', 'error': ''}, {'event': 'data', 'data': 'eA=='},
                        {'event': 'owner', 'pid': 1, 'audit_token': [0] * 8}, {'event': 'error', 'error': 'x'}]:
            with self.subTest(message=message):
                self.assertEqual(run.parse_helper_message(json.dumps(message).encode()), message)
        for message in [[], {'event': 1}, {'event': 'data', 'data': None}, {'event': 'stopped', 'error': None},
                        {'event': 'owner', 'pid': True, 'audit_token': [0] * 8},
                        {'event': 'owner', 'pid': 1, 'audit_token': {}}, {'event': 'error'}]:
            with self.subTest(message=message), self.assertRaises(ValueError):
                run.parse_helper_message(json.dumps(message).encode())


class TransportAgreementTests(unittest.TestCase):
    """guest.py runs alone in the guest image, so it repeats the host's limits and path rule."""

    def test_host_and_guest_limits_agree(self):
        for name in ('MAX_LINE', 'MAX_BYTES', 'MAX_FILE', 'MAX_FILES'):
            with self.subTest(limit=name):
                self.assertEqual(getattr(run, name), getattr(guest, name))

    def test_host_and_guest_path_verdicts_agree(self):
        root = Path('/staging')

        def verdicts(name):
            try:
                host = run.output_path(root, 'workspace', name).relative_to(root / 'workspace').parts
            except ValueError:
                host = None
            try:
                inside = guest.relative(name)
            except ValueError:
                inside = None
            return host, inside

        for name in ACCEPTED_PATHS:
            with self.subTest(name=name):
                host, inside = verdicts(name)
                self.assertIsNotNone(host)
                self.assertEqual(host, inside)
                self.assertEqual('/'.join(host), name)
        for name in REJECTED_PATHS:
            with self.subTest(name=name):
                self.assertEqual(verdicts(name), (None, None))

    def test_snapshot_paths_are_accepted_by_both_ends(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'dir' / 'nested').mkdir(parents=True)
            for name in ('top', 'dir/a b', 'dir/nested/..x', 'dir/nested/a\\b'):
                (root / name).write_text(name)
            for entry in run.snapshot(root):
                with self.subTest(path=entry['path']):
                    self.assertEqual(guest.relative(entry['path']), tuple(entry['path'].split('/')))
                    run.output_path(root, 'workspace', entry['path'])


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

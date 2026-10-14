"""Drive run.execute against a scripted custodian/helper/guest; no VM is booted."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import run

# Stands in for custodian + VZ helper + guest controller. It acknowledges the
# custody lease like the native custodian and plays one scripted scenario.
FAKE_CUSTODIAN = r'''
import base64, json, os, sys, threading

scenario = json.loads(open(sys.argv[1]).read())
lease, ack = int(sys.argv[2]), int(sys.argv[3])


def acknowledge():
    while os.read(lease, 64):
        os.write(ack, b'.')


threading.Thread(target=acknowledge, daemon=True).start()


def emit(value):
    sys.stdout.write(json.dumps(value) + '\n')
    sys.stdout.flush()


def guest(value):
    line = value.encode() if isinstance(value, str) else json.dumps(value).encode()
    emit({'event': 'data', 'data': base64.b64encode(line + b'\n').decode()})


for line in scenario.get('helper_lines', []):
    sys.stdout.write(line + '\n')
for line in scenario.get('guest_lines', []):
    guest(line)
sys.stdout.flush()
if scenario.get('guest'):
    guest({'event': 'ready', 'kernel': 'fake', 'lease_seconds': 2.0})
for raw in sys.stdin:
    request = json.loads(raw)
    if request['op'] == 'stop':
        emit({'event': 'stopped', 'error': ''})
        sys.exit(0)
    message = json.loads(base64.b64decode(request['data']))
    if message['op'] == 'ping':
        guest({'event': 'pong', 'sequence': message['sequence']})
    elif message['op'] == 'put':
        guest({'event': 'put', 'path': message['path']})
    elif message['op'] == 'run':
        guest({'event': 'running', 'supervisor_pid': 4242})
        guest({'event': 'stdout', 'data': base64.b64encode(b'relayed\n').decode()})
        for group, path, data in scenario['outputs']:
            guest({'event': 'file', 'group': group, 'path': path, 'executable': False,
                   'data': base64.b64encode(data.encode()).decode()})
        guest({'event': 'done', 'exit_code': 3})
'''

RECEIPT = {'schema': 'ouro.jail.receipt/1', 'platform': {'os': 'linux'}, 'policy': {'name': 'tool'},
           'containment': 'enforced', 'child_protection': 'enforced', 'exec_observed': True,
           'lifetime': {'tree_empty': True, 'integrity': 'verified'}, 'state_cleanup': 'complete', 'errors': [],
           'applied': {'network': {'mode': 'none'},
                       'limits': [{'key': key, 'applied': True} for key in ('wall', 'mem', 'pids', 'swap')]}}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AttemptTests(unittest.TestCase):
    def setUp(self):
        # execute() sets a private umask for its evidence; keep it out of other tests.
        self.umask = os.umask(0o022)
        os.umask(self.umask)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace = self.root / 'workspace'
        self.workspace.mkdir()
        (self.workspace / 'input.txt').write_text('hello\n')
        self.image = self.root / 'image'
        self.image.mkdir()
        for name in ('base.raw', 'vz', 'seed.iso'):
            (self.image / name).write_bytes(name.encode())
        (self.root / 'fake_custodian.py').write_text(FAKE_CUSTODIAN)

    def tearDown(self):
        os.umask(self.umask)

    def attempt(self, scenario, clone=shutil.copyfile):
        (self.root / 'scenario.json').write_text(json.dumps(scenario))
        custodian = self.image / 'custodian'
        custodian.write_text('#!/bin/sh\nexec ' + ' '.join(shlex.quote(str(part)) for part in (
            sys.executable, self.root / 'fake_custodian.py', self.root / 'scenario.json')) + ' "$@"\n')
        custodian.chmod(0o755)
        (self.image / 'image.json').write_text(json.dumps({
            'status': 'prepared', 'disk_sha256': sha256(self.image / 'base.raw'),
            'helper_sha256': sha256(self.image / 'vz'), 'custodian_sha256': sha256(custodian),
            'seed_sha256': sha256(self.image / 'seed.iso')}))
        args = argparse.Namespace(image=self.image, workspace=self.workspace, out=self.root / 'out',
                                  profile='tool', wall=30, keep_disk=False, command=['/bin/true'])
        stdout = io.TextIOWrapper(io.BytesIO())
        with mock.patch.object(run, 'clone_disk', clone), mock.patch('sys.stdout', stdout), \
                mock.patch('sys.stderr', io.TextIOWrapper(io.BytesIO())):
            code = run.execute(args)
            stdout.flush()
            relayed = stdout.buffer.getvalue()
        report = json.loads((self.root / 'out' / 'attempt.json').read_text())
        return code, report, relayed

    def test_completed_attempt_returns_the_guest_exit_code(self):
        code, report, relayed = self.attempt({'guest': True, 'outputs': [
            ['workspace', 'input.txt', 'hello\n'], ['workspace', 'output.txt', 'created\n'],
            ['evidence', 'jail.json', json.dumps(RECEIPT)]]})
        self.assertEqual((code, report['status'], report['guest_exit_code']), (3, 'completed', 3), report)
        self.assertEqual(report['input_files'], 1)
        self.assertEqual(relayed, b'relayed\n')
        self.assertEqual((self.root / 'out' / 'workspace' / 'output.txt').read_text(), 'created\n')
        self.assertFalse((self.root / 'out' / 'guest.raw').exists())

    def test_unverified_receipt_fails_the_attempt(self):
        receipt = dict(RECEIPT, lifetime={'tree_empty': False, 'integrity': 'verified'})
        code, report, _ = self.attempt({'guest': True, 'outputs': [['evidence', 'jail.json', json.dumps(receipt)]]})
        self.assertEqual((code, report['status']), (125, 'failed'))
        self.assertIn('cleanup was not verified', report['error'])

    def test_ill_typed_receipt_fails_the_attempt(self):
        for receipt in ([], 'receipt', dict(RECEIPT, platform='linux'),
                        dict(RECEIPT, applied={'network': {'mode': 'none'}, 'limits': ['wall']})):
            with self.subTest(receipt=receipt):
                shutil.rmtree(self.root / 'out', ignore_errors=True)
                code, report, _ = self.attempt({'guest': True,
                                                'outputs': [['evidence', 'jail.json', json.dumps(receipt)]]})
                self.assertEqual((code, report['status']), (125, 'failed'))

    def test_malformed_guest_output_is_a_failed_attempt(self):
        for line, reason in [('[1]', 'malformed guest message'), ('"ready"', 'malformed guest message'),
                             ('{"event": 5}', 'malformed guest message'), ('{"event": null}', 'malformed guest message'),
                             ('{"event": "stdout", "data": 5}', 'data must be str'),
                             ('{"event": "ready", "kernel": ["fake"]}', 'kernel must be str'),
                             ('{"event": "pong", "sequence": true}', 'sequence must be int'),
                             ('{"event": "unknown"}', 'unexpected guest event'), ('not json', 'Expecting value')]:
            with self.subTest(line=line):
                shutil.rmtree(self.root / 'out', ignore_errors=True)
                code, report, _ = self.attempt({'guest_lines': [line]})
                self.assertEqual((code, report['status']), (125, 'failed'))
                self.assertIn(reason, report['error'])

    def test_malformed_helper_output_is_a_failed_attempt(self):
        for line, reason in [('[]', 'malformed helper message'), ('{"event": {}}', 'malformed helper message'),
                             ('{"event": "data", "data": 1}', 'data must be str'),
                             ('{"event": "owner", "pid": "1", "audit_token": []}', 'pid must be int'),
                             ('{"event": "error", "error": 7}', 'error must be str')]:
            with self.subTest(line=line):
                shutil.rmtree(self.root / 'out', ignore_errors=True)
                code, report, _ = self.attempt({'helper_lines': [line]})
                self.assertEqual((code, report['status']), (125, 'failed'))
                self.assertIn(reason, report['error'])

    def test_unforeseen_error_still_leaves_a_terminal_record(self):
        with mock.patch.object(run, 'parse_guest_message', side_effect=ZeroDivisionError('bug')), \
                self.assertRaises(ZeroDivisionError):
            self.attempt({'guest': True})
        report = json.loads((self.root / 'out' / 'attempt.json').read_text())
        self.assertEqual((report['status'], report['error']), ('failed', 'ZeroDivisionError: bug'))

    def test_failed_disk_clone_leaves_a_terminal_record(self):
        def clone(_base, _destination):
            raise subprocess.CalledProcessError(1, ['cp', '-c'])

        code, report, _ = self.attempt({'guest': True}, clone=clone)
        self.assertEqual((code, report['status']), (125, 'failed'))
        self.assertIn('cp', report['error'])
        self.assertNotIn('custodian_pid', report)

    def test_a_failing_cleanup_step_still_saves_a_terminal_record(self):
        # The helper names its owner, then fails; releasing that owner raises too.
        owner = {'event': 'owner', 'pid': 7, 'audit_token': [0, 0, 0, 0, 0, 7, 0, 0]}
        with mock.patch.object(run, 'terminate_owner', side_effect=TypeError('bug')) as terminate:
            code, report, _ = self.attempt({'helper_lines': [json.dumps(owner), '{"event": "error", "error": "boom"}']})
        terminate.assert_called_once_with(owner['audit_token'])
        self.assertEqual((code, report['status'], report['error']), (125, 'failed', 'boom'))
        self.assertEqual(report['owner_cleanup_error'], 'TypeError: bug')
        self.assertIn('elapsed_seconds', report)

    def test_a_signal_after_the_transport_ends_is_a_cancelled_attempt(self):
        transport = run.Transport.run

        def run_then_signal(session):
            transport(session)
            signal.raise_signal(signal.SIGTERM)

        with mock.patch.object(run.Transport, 'run', run_then_signal):
            code, report, _ = self.attempt({'guest': True,
                                            'outputs': [['evidence', 'jail.json', json.dumps(RECEIPT)]]})
        self.assertEqual((code, report['status'], report['signal']), (125, 'cancelled', signal.SIGTERM))
        self.assertEqual(report['guest_exit_code'], 3)

    def test_ill_formed_image_metadata_is_refused_before_any_output(self):
        args = argparse.Namespace(image=self.image, workspace=self.workspace, out=self.root / 'out',
                                  profile='tool', wall=30, keep_disk=False, command=['/bin/true'])
        for metadata in ({}, [], {'status': 'prepared'}, 'prepared'):
            with self.subTest(metadata=metadata):
                (self.image / 'image.json').write_text(json.dumps(metadata))
                with self.assertRaisesRegex(ValueError, 'does not match prepared metadata'):
                    run.execute(args)
                self.assertFalse((self.root / 'out').exists())


if __name__ == '__main__':
    unittest.main()

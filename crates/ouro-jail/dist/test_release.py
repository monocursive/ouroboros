import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from package import create_archive
from prepare_release import assemble, stage, verify_build, verify_stage, TARGETS

REVISION = 'a' * 40
INPUTS = 'sha256:' + 'b' * 64


def version(target):
    return {'build': {'target': target, 'revision': REVISION, 'inputs': INPUTS,
                     'dirty': False, 'opt_level': '3', 'debug_assertions': False,
                     'rustc': 'rustc 1.98.1 (fixture)'}}


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def fixture(self, target):
        binary = self.root / target
        contents = bytearray(64)
        contents[:6] = b'\x7fELF\x02\x01'
        contents[18:20] = TARGETS[target].to_bytes(2, 'little')
        binary.write_bytes(contents)
        out = self.root / ('stage-' + target)
        # Unit fixture only; actual native execution is exercised separately.
        with patch('prepare_release.subprocess.check_output', return_value=json.dumps(version(target)).encode()):
            stage(binary, target, REVISION, INPUTS, out)
        return out

    def test_packaging_is_independent_of_source_mtime_and_location(self):
        binary = self.root / 'binary'
        binary.write_bytes(b'fixed test payload')
        target = next(iter(TARGETS))
        first = create_archive(binary, target, self.root / 'first').read_bytes()
        os.utime(binary, (1234567, 1234567))
        other = self.root / 'other'; shutil.copyfile(binary, other)
        second = create_archive(other, target, self.root / 'second').read_bytes()
        self.assertEqual(first, second)

    def test_dirty_mismatched_and_debug_builds_refuse(self):
        target = next(iter(TARGETS))
        for key, value in [('target', 'aarch64-apple-darwin'), ('revision', 'c' * 40),
                           ('inputs', 'sha256:' + 'd' * 64), ('dirty', True),
                           ('dirty', None), ('opt_level', '0'), ('debug_assertions', True),
                           ('rustc', 'rustc 1.80.0 (fixture)')]:
            with self.subTest(key=key, value=value):
                record = version(target); record['build'][key] = value
                with self.assertRaises(ValueError):
                    verify_build(record, REVISION, INPUTS, target)

    def test_assembly_requires_both_distinct_native_targets(self):
        single = self.fixture(next(iter(TARGETS)))
        for records in [[single], [single, single]]:
            with self.assertRaises(ValueError):
                assemble(records, REVISION, INPUTS, '0.1.0-rc.1', self.root / 'out')
        self.assertFalse((self.root / 'out').exists())

    def test_tampered_archive_and_binary_attestation_refuse(self):
        target = next(iter(TARGETS)); directory = self.fixture(target)
        archive = next(directory.glob('*.tar.gz'))
        original = archive.read_bytes(); archive.write_bytes(original + b'corruption')
        with self.assertRaises(ValueError):
            verify_stage(directory, REVISION, INPUTS)
        archive.write_bytes(original)
        record = json.loads((directory / 'artifact.json').read_text())
        record['binary_sha256'] = '0' * 64
        (directory / 'artifact.json').write_text(json.dumps(record))
        with self.assertRaises(ValueError):
            verify_stage(directory, REVISION, INPUTS)

    def test_architecture_is_checked_independently_of_version_json(self):
        target = next(iter(TARGETS)); directory = self.fixture(target)
        other = next(t for t in TARGETS if t != target)
        binary = self.root / target
        with patch('prepare_release.subprocess.check_output', return_value=json.dumps(version(other)).encode()):
            with self.assertRaises(ValueError):
                stage(binary, other, REVISION, INPUTS, self.root / 'wrong')
        record = json.loads((directory / 'artifact.json').read_text())
        record['archive'] = '../outside.tar.gz'
        (directory / 'artifact.json').write_text(json.dumps(record))
        with self.assertRaises(ValueError):
            verify_stage(directory, REVISION, INPUTS)

    def test_unsigned_preparation_remains_unpublished_and_names_signing_blocker(self):
        stages = [self.fixture(t) for t in TARGETS]
        plan = assemble(stages, REVISION, INPUTS, '0.1.0-rc.1', self.root / 'out')
        self.assertFalse(plan['published']); self.assertFalse(plan['signature_verified'])
        self.assertTrue(plan['draft'])
        self.assertIn('production_signing_identity_not_configured', plan['publication_blockers'])
        self.assertEqual(plan['repository'], 'monocursive/ouroboros')

    @unittest.skipUnless(shutil.which('minisign'), 'minisign is required for actual signature checks')
    def test_real_signature_and_wrong_key_rejection(self):
        stages = [self.fixture(t) for t in TARGETS]
        for name in ['test', 'wrong']:
            subprocess.run(['minisign', '-G', '-W', '-s', str(self.root / (name + '.key')),
                            '-p', str(self.root / (name + '.pub'))], check=True, capture_output=True)
        key = (self.root / 'test.pub').read_text().splitlines()[1]
        plan = assemble(stages, REVISION, INPUTS, '0.1.0-rc.1', self.root / 'signed',
                        self.root / 'test.key', key)
        self.assertTrue(plan['signature_verified']); self.assertFalse(plan['published'])
        wrong = (self.root / 'wrong.pub').read_text().splitlines()[1]
        with self.assertRaises(subprocess.CalledProcessError):
            assemble(stages, REVISION, INPUTS, '0.1.0-rc.1', self.root / 'refused',
                     self.root / 'test.key', wrong)
        self.assertFalse((self.root / 'refused/release-plan.json').exists())


if __name__ == '__main__':
    unittest.main()

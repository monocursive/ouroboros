import json
from pathlib import Path
import tempfile
import unittest

from freeze import MANIFEST, check, contracts


class FreezeTest(unittest.TestCase):
    def test_changed_removed_added_and_unsafe_contracts_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schema = root / "run.schema.json"
            schema.write_text('{}\n')
            (root / MANIFEST).write_text(json.dumps(contracts(root)))
            self.assertEqual(check(root), 1)
            schema.write_text('{"changed":true}\n')
            with self.assertRaisesRegex(ValueError, "run.schema.json"):
                check(root)
            schema.unlink()
            with self.assertRaises(ValueError):
                check(root)
            schema.write_text('{}\n')
            extra = root / "extra.schema.json"
            extra.write_text('{}\n')
            with self.assertRaisesRegex(ValueError, "extra.schema.json"):
                check(root)
            extra.unlink()
            extra.symlink_to(schema)
            with self.assertRaisesRegex(ValueError, "regular file"):
                check(root)

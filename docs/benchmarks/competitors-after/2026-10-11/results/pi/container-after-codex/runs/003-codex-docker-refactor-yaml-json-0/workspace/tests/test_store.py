import unittest, tempfile, os
from src.store import Store

class TestStore(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as t:
            path = t.name
        try:
            s = Store(path)
            s.save({'a': 1, 'b': [1, 2]})
            self.assertEqual(s.load(), {'a': 1, 'b': [1, 2]})
        finally:
            os.unlink(path)

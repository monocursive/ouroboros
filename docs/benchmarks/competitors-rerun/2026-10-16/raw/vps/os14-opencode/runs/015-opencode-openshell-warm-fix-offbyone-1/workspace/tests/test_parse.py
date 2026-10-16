import unittest
from src.parse import first_word

class TestParse(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(first_word('hello world'), 'hello')
    def test_single(self):
        self.assertEqual(first_word('solo'), 'solo')

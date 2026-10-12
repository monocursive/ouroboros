import unittest
import tempfile
from pathlib import Path
from decimal import Decimal
from inventory.loader import load_items

class LoaderTests(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'stock.csv'
            p.write_text(text)
            return load_items(p)
    def test_exact_prices(self):
        x = self.load('sku,category,quantity,unit_price\na,tools,3,0.10\n')[0]
        self.assertEqual(x.unit_price, Decimal('0.10'))
    def test_missing_header(self):
        with self.assertRaises(ValueError): self.load('name\na\n')
    def test_invalid_quantity(self):
        with self.assertRaises(ValueError):
            self.load('sku,category,quantity,unit_price\na,tools,no,1\n')
    def test_negative_quantity(self):
        with self.assertRaises(ValueError):
            self.load('sku,category,quantity,unit_price\na,tools,-1,1\n')
    def test_nonfinite_price(self):
        with self.assertRaises(ValueError):
            self.load('sku,category,quantity,unit_price\na,tools,1,NaN\n')

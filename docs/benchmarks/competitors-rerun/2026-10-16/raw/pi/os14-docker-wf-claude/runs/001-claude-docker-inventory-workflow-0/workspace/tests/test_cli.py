import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

DATA = 'sku,category,quantity,unit_price\npen,office,10,0.10\nnotebook,office,2,2.50\nmug,kitchen,3,4.25\n'

class CliTests(unittest.TestCase):
    def cli(self, data=DATA, *flags):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'stock.csv'
            p.write_text(data)
            return subprocess.run([sys.executable, '-m', 'inventory.cli', str(p), *flags], capture_output=True, text=True)
    def test_ungrouped(self):
        r = self.cli()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(json.loads(r.stdout)), 3)
        self.assertEqual(json.loads(r.stdout)[0]['unit_price'], '0.10')
    def test_filter(self):
        r = self.cli(DATA, '--min-quantity', '3')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([x['sku'] for x in json.loads(r.stdout)], ['pen', 'mug'])
    def test_category_summaries(self):
        r = self.cli(DATA, '--group-by-category')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), [
            {'category': 'kitchen', 'quantity': 3, 'stock_value': '12.75'},
            {'category': 'office', 'quantity': 12, 'stock_value': '6.00'}])
    def test_filter_before_group(self):
        r = self.cli(DATA, '--group-by-category', '--min-quantity', '3')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)[1]['stock_value'], '1.00')
    def test_bad_csv(self):
        r = self.cli('sku,category,quantity,unit_price\na,b,invalid,2\n')
        self.assertEqual(r.returncode, 2)
        self.assertNotIn('Traceback', r.stderr)
        self.assertIn('row', r.stderr.lower())

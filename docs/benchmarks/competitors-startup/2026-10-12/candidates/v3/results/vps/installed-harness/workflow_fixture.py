"""A controlled multi-file CLI change, checked from outside the writable repo."""
import json
import subprocess
from pathlib import Path
import shutil

NAME = "inventory-workflow"
SPEC = {
    "prompt": "Implement category summaries in this inventory CLI. Add --group-by-category to python3 -m inventory.cli. Read the CSV using the existing loader, apply --min-quantity before grouping, and emit a JSON array sorted by category. Each object must have category (string), quantity (sum of quantities), and stock_value (sum of quantity * unit_price as an exact decimal formatted with two fractional digits, a JSON string). Ungrouped output must keep its current behavior. Invalid CSV must produce exit code 2 and a useful stderr message without a traceback. Update README.md with a grouped example and its expected output. Run python3 -m unittest discover -s tests -v and fix failures. Do not change the supplied tests. Keep processing and argument parsing in separate modules.",
    "files": {
        "pyproject.toml": '[project]\nname = "inventory-cli"\nversion = "0.1.0"\nrequires-python = ">=3.10"\n',
        "inventory/__init__.py": '"""Inventory reporting tools."""\n',
        "inventory/models.py": '''from dataclasses import dataclass
from decimal import Decimal

@dataclass(frozen=True)
class Item:
    sku: str
    category: str
    quantity: int
    unit_price: Decimal
''',
        "inventory/loader.py": '''import csv
from decimal import Decimal, InvalidOperation
from .models import Item

def load_items(path):
    items = []
    with open(path, newline='', encoding='utf-8') as source:
        reader = csv.DictReader(source)
        required = {'sku', 'category', 'quantity', 'unit_price'}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError('CSV requires sku, category, quantity and unit_price')
        for line, row in enumerate(reader, 2):
            try:
                quantity = int(row['quantity'])
                price = Decimal(row['unit_price'])
                if quantity < 0 or price < 0 or not price.is_finite():
                    raise ValueError('negative or non-finite value')
                items.append(Item(row['sku'], row['category'], quantity, price))
            except (ValueError, InvalidOperation, TypeError) as exc:
                raise ValueError(f'Invalid CSV row {line}: {exc}') from exc
    return items
''',
        "inventory/report.py": '''def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]
''',
        "inventory/cli.py": '''import argparse
import json
import sys
from .loader import load_items
from .report import item_report

def main(argv=None):
    parser = argparse.ArgumentParser(description='Report inventory from CSV')
    parser.add_argument('csv_file')
    parser.add_argument('--min-quantity', type=int, default=0)
    args = parser.parse_args(argv)
    try:
        items = load_items(args.csv_file)
        result = item_report(items, args.min_quantity)
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0

if __name__ == '__main__':
    sys.exit(main())
''',
        "examples/stock.csv": "sku,category,quantity,unit_price\npen,office,10,0.10\nnotebook,office,2,2.50\nmug,kitchen,3,4.25\n",
        "README.md": "# Inventory CLI\n\nRun `python3 -m inventory.cli examples/stock.csv`.\nUse `--min-quantity 3` to filter before reporting.\nPrices are decimal strings. No third-party dependencies are required.\n",
        "tests/test_loader.py": '''import unittest
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
        x = self.load('sku,category,quantity,unit_price\\na,tools,3,0.10\\n')[0]
        self.assertEqual(x.unit_price, Decimal('0.10'))
    def test_missing_header(self):
        with self.assertRaises(ValueError): self.load('name\\na\\n')
    def test_invalid_quantity(self):
        with self.assertRaises(ValueError):
            self.load('sku,category,quantity,unit_price\\na,tools,no,1\\n')
    def test_negative_quantity(self):
        with self.assertRaises(ValueError):
            self.load('sku,category,quantity,unit_price\\na,tools,-1,1\\n')
    def test_nonfinite_price(self):
        with self.assertRaises(ValueError):
            self.load('sku,category,quantity,unit_price\\na,tools,1,NaN\\n')
''',
        "tests/test_cli.py": '''import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

DATA = 'sku,category,quantity,unit_price\\npen,office,10,0.10\\nnotebook,office,2,2.50\\nmug,kitchen,3,4.25\\n'

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
        r = self.cli('sku,category,quantity,unit_price\\na,b,invalid,2\\n')
        self.assertEqual(r.returncode, 2)
        self.assertNotIn('Traceback', r.stderr)
        self.assertIn('row', r.stderr.lower())
''',
    },
    "check": "python3 -m unittest discover -s tests -v",
    "required": [],
}

HIDDEN = r'''
import json,subprocess,tempfile,pathlib,sys
repo=pathlib.Path(sys.argv[1])
def run(data,flags=()):
    with tempfile.TemporaryDirectory() as d:
        p=pathlib.Path(d)/'in.csv';p.write_text(data,encoding='utf-8')
        return subprocess.run([sys.executable,'-m','inventory.cli',str(p),*flags],cwd=repo,capture_output=True,text=True)
header='sku,category,quantity,unit_price\n'
r=run(header+'x,z,3,0.10\ny,a,2,0.20\nz,z,0,99.99\n',('--group-by-category',))
assert r.returncode==0,r.stderr
assert json.loads(r.stdout)==[{'category':'a','quantity':2,'stock_value':'0.40'},{'category':'z','quantity':3,'stock_value':'0.30'}]
r=run(header,('--group-by-category',));assert r.returncode==0 and json.loads(r.stdout)==[]
r=run(header+'x,café,1,0.25\ny,café,3,0.10\n',('--min-quantity','2','--group-by-category'))
assert r.returncode==0 and json.loads(r.stdout)==[{'category':'café','quantity':3,'stock_value':'0.30'}]
r=run(header+'x,b,1,Infinity\n',('--group-by-category',));assert r.returncode==2 and 'Traceback' not in r.stderr and r.stderr.strip()
r=run(header+'x,z,1,1.20\n');assert r.returncode==0 and json.loads(r.stdout)==[{'sku':'x','category':'z','quantity':1,'unit_price':'1.20'}]
doc=(repo/'README.md').read_text();assert '--group-by-category' in doc and 'stock_value' in doc
'''

def make_task_dir(base, task=NAME):
    target = base / task
    if target.exists():
        shutil.rmtree(target)
    for name, content in SPEC['files'].items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    (target / 'tests/__init__.py').write_text('')
    subprocess.run(['git', 'init', '-q', str(target)], check=True)
    subprocess.run(['git', 'add', '-A'], cwd=target, check=True)
    subprocess.run(['git', '-c', 'user.email=bench@local', '-c', 'user.name=bench',
                    'commit', '-qm', 'fixture'], cwd=target, check=True)
    return target

def independent_check(task_dir, task=NAME):
    untouched = all((task_dir / p).exists() and (task_dir / p).read_text() == content
                    for p, content in SPEC['files'].items() if p.startswith('tests/'))
    hidden = subprocess.run(['python3', '-I', '-c', HIDDEN, str(task_dir)], capture_output=True, timeout=30)
    tests = subprocess.run(['python3', '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
                           cwd=task_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    return {'tests_unchanged': untouched, 'tests_pass': tests.returncode == 0, 'hidden_pass': hidden.returncode == 0,
            'test_output': tests.stdout.decode(errors='replace'),
            'hidden_output': (hidden.stdout + hidden.stderr).decode(errors='replace')}

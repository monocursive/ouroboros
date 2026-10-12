import csv
from decimal import Decimal, InvalidOperation
from .models import Item

def load_items(path):
    items = []
    with open(path, newline='', encoding='utf-8') as source:
        reader = csv.DictReader(source, strict=True)
        required = {'sku', 'category', 'quantity', 'unit_price'}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError('CSV requires sku, category, quantity and unit_price')
        for line, row in enumerate(reader, 2):
            try:
                if None in row or any(row[name] is None for name in required):
                    raise ValueError('incorrect number of fields')
                quantity = int(row['quantity'])
                price = Decimal(row['unit_price'])
                if quantity < 0 or price < 0 or not price.is_finite():
                    raise ValueError('negative or non-finite value')
                items.append(Item(row['sku'], row['category'], quantity, price))
            except (ValueError, InvalidOperation, TypeError) as exc:
                raise ValueError(f'Invalid CSV row {line}: {exc}') from exc
    return items

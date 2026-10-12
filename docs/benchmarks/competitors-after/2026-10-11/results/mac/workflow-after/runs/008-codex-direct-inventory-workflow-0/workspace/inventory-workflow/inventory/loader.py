import csv
from decimal import Decimal, InvalidOperation
from .models import Item

def load_items(path):
    items = []
    with open(path, newline='', encoding='utf-8') as source:
        reader = csv.DictReader(source, strict=True)
        required = {'sku', 'category', 'quantity', 'unit_price'}
        try:
            fieldnames = reader.fieldnames
        except csv.Error as exc:
            raise ValueError(f'Invalid CSV header: {exc}') from exc
        if not required.issubset(fieldnames or []):
            raise ValueError('CSV requires sku, category, quantity and unit_price')
        try:
            rows = list(reader)
        except csv.Error as exc:
            raise ValueError(f'Invalid CSV near row {reader.line_num}: {exc}') from exc
        for line, row in enumerate(rows, 2):
            try:
                if None in row or any(row[field] is None for field in required):
                    raise ValueError('missing or extra fields')
                quantity = int(row['quantity'])
                price = Decimal(row['unit_price'])
                if quantity < 0 or price < 0 or not price.is_finite():
                    raise ValueError('negative or non-finite value')
                items.append(Item(row['sku'], row['category'], quantity, price))
            except (ValueError, InvalidOperation, TypeError) as exc:
                raise ValueError(f'Invalid CSV row {line}: {exc}') from exc
    return items

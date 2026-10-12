# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

## Ungrouped output

```bash
python3 -m inventory.cli examples/stock.csv
```

```json
[
  {"sku": "pen", "category": "office", "quantity": 10, "unit_price": "0.10"},
  {"sku": "notebook", "category": "office", "quantity": 2, "unit_price": "2.50"},
  {"sku": "mug", "category": "kitchen", "quantity": 3, "unit_price": "4.25"}
]
```

## Grouped by category

```bash
python3 -m inventory.cli examples/stock.csv --group-by-category
```

```json
[
  {"category": "kitchen", "quantity": 3, "stock_value": "12.75"},
  {"category": "office", "quantity": 12, "stock_value": "6.00"}
]
```

The `--min-quantity` filter is applied before grouping.

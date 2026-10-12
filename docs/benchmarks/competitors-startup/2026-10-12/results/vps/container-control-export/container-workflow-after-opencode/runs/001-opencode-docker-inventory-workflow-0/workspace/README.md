# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

## Grouped Reports

Use `--group-by-category` to group items by category and sum quantities and stock values:

```bash
python3 -m inventory.cli examples/stock.csv --group-by-category
```

Example output:
```json
[
  {"category": "kitchen", "quantity": 3, "stock_value": "12.75"},
  {"category": "office", "quantity": 12, "stock_value": "6.00"}
]
```

Filters are applied before grouping:
```bash
python3 -m inventory.cli examples/stock.csv --group-by-category --min-quantity 3
```

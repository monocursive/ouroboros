# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

## Grouping by Category

Use `--group-by-category` to group items by category and summarize quantities and stock values:

```bash
python3 -m inventory.cli examples/stock.csv --group-by-category
```

Expected output:
```json
[
  {"category": "kitchen", "quantity": 3, "stock_value": "12.75"},
  {"category": "office", "quantity": 12, "stock_value": "6.00"}
]
```

Combine with `--min-quantity` to filter items before grouping:

```bash
python3 -m inventory.cli examples/stock.csv --group-by-category --min-quantity 3
```

# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

## Grouped by Category

Use `--group-by-category` to get category summaries:

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

The output is sorted by category name. The `stock_value` is the sum of quantity × unit_price for all items in that category, formatted as a decimal string with two fractional digits.

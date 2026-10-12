# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

## Grouped reporting

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

The `stock_value` is the sum of quantity × unit_price for all items in the category, formatted with two decimal places. Filters like `--min-quantity` are applied before grouping.

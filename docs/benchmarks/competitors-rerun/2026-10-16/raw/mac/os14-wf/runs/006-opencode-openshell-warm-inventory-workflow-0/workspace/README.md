# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

## Grouped by Category

Run `python3 -m inventory.cli examples/stock.csv --group-by-category` to get category summaries:

```json
[
  {"category": "kitchen", "quantity": 3, "stock_value": "12.75"},
  {"category": "office", "quantity": 12, "stock_value": "6.00"}
]
```

The output is a JSON array sorted by category name. Each object contains:
- `category`: the category name (string)
- `quantity`: sum of quantities for all items in the category (integer)
- `stock_value`: sum of quantity × unit_price for all items, formatted as a decimal string with two fractional digits

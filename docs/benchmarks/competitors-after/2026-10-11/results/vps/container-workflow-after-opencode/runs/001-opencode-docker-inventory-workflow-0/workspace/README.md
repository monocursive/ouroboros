# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

## Category Summaries

Use `--group-by-category` to aggregate inventory by category:

```bash
python3 -m inventory.cli examples/stock.csv --group-by-category
```

Expected output:
```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

The output is a JSON array sorted by category. Each object includes:
- `category` (string): the category name
- `quantity` (integer): sum of quantities for all items in that category
- `stock_value` (string): sum of quantity × unit_price for all items, formatted with exactly two decimal places

Filtering with `--min-quantity` is applied before grouping.

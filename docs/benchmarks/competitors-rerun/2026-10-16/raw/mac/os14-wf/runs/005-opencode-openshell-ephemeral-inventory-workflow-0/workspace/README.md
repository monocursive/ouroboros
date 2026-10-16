# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

## Category Summaries

Use `--group-by-category` to group items by category:

```bash
python3 -m inventory.cli examples/stock.csv --group-by-category
```

Expected output:
```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

The output is a JSON array sorted by category. Each object contains:
- `category`: the category name (string)
- `quantity`: sum of quantities across all items in the category (integer)
- `stock_value`: sum of (quantity * unit_price) formatted with two decimal places (string)

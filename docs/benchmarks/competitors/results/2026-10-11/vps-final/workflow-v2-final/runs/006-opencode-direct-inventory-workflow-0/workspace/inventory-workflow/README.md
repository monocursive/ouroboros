# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

## Grouped Output

Use `--group-by-category` to aggregate by category:

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

The output is a JSON array sorted by category. Each object contains the category name, total quantity, and total stock value (formatted as a decimal string with two fractional digits).

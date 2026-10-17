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

The output is sorted alphabetically by category. Each summary includes the total quantity and stock value (sum of quantity * unit_price) formatted with two decimal places.

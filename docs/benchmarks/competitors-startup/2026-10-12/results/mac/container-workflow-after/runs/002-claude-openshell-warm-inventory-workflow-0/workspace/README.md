# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

## Grouping by Category

Use `--group-by-category` to summarize inventory by category:

```bash
python3 -m inventory.cli examples/stock.csv --group-by-category
```

Output:
```json
[
  {"category": "kitchen", "quantity": 3, "stock_value": "12.75"},
  {"category": "office", "quantity": 12, "stock_value": "6.00"}
]
```

The filter applies before grouping:
```bash
python3 -m inventory.cli examples/stock.csv --group-by-category --min-quantity 3
```

Output:
```json
[
  {"category": "kitchen", "quantity": 3, "stock_value": "12.75"},
  {"category": "office", "quantity": 10, "stock_value": "1.00"}
]
```

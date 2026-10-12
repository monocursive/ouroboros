# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Use `--group-by-category` for category summaries sorted by name.

Example grouped output:
```
python3 -m inventory.cli examples/stock.csv --group-by-category
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

Prices are decimal strings. No third-party dependencies are required.

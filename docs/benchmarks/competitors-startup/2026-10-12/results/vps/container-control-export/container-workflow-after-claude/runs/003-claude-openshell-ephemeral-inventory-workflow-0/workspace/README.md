# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

## Grouped output

Use `--group-by-category` to summarize by category:

```bash
python3 -m inventory.cli examples/stock.csv --group-by-category
```

Expected output:
```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

The `--min-quantity` filter applies before grouping:
```bash
python3 -m inventory.cli examples/stock.csv --group-by-category --min-quantity 3
```

Expected output:
```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 10, "stock_value": "1.00"}]
```

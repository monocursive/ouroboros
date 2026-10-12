# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

Group by category with quantities and total stock values:

```sh
python3 -m inventory.cli examples/stock.csv --group-by-category --min-quantity 3
```

Expected output:

```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 10, "stock_value": "1.00"}]
```

The quantity filter applies to individual items before grouping. Categories are
sorted alphabetically, and stock values are decimal strings with two fractional digits.

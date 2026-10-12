# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

Group by category, filtering individual items before summing:

```sh
python3 -m inventory.cli examples/stock.csv --group-by-category --min-quantity 3
```

Expected output (sorted by category):

```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 10, "stock_value": "1.00"}]
```

Stock values use exact decimal arithmetic and are formatted as strings with
two fractional digits.

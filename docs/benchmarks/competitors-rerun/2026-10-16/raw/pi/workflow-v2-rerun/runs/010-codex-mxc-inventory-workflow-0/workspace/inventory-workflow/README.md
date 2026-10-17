# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

Summarize inventory by category (sorted by category):

```sh
python3 -m inventory.cli examples/stock.csv --group-by-category
```

Expected output:

```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

Combine with `--min-quantity 3` to filter individual items before grouping.
Stock values are calculated with exact decimals and formatted as strings with
two fractional digits. Invalid CSV reports an error on stderr and exits with code 2.

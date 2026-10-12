# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

Group inventory by category:

```sh
python3 -m inventory.cli examples/stock.csv --group-by-category
```

Expected output:

```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

Categories are sorted alphabetically. Each stock value sums quantity times
unit price using decimal arithmetic and is formatted as a string with two
fractional digits. Add `--min-quantity 3` to filter individual rows before
grouping; the office summary then has quantity `10` and stock value `"1.00"`.

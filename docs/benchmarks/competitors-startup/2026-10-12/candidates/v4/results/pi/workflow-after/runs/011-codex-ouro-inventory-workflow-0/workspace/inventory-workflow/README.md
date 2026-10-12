# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

Group by category with `python3 -m inventory.cli examples/stock.csv --group-by-category`:

```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

Grouped results are sorted by category. Quantities and stock values are summed
after applying `--min-quantity`; stock values are decimal strings with two
fractional digits.

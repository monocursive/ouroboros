# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

Group by category with `python3 -m inventory.cli examples/stock.csv --group-by-category`:

```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

Categories are sorted by name. Quantity and stock value are summed within each
category, with stock values formatted as decimal strings with two fractional
digits. Add `--min-quantity 3` to filter items before grouping; the office summary
then has quantity `10` and stock value `"1.00"`.

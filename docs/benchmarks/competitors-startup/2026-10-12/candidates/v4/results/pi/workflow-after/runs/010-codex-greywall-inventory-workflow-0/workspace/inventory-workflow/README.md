# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

Group by category with `python3 -m inventory.cli examples/stock.csv --group-by-category`:

```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

Categories are sorted alphabetically. Stock values sum quantity times unit price
using exact decimal arithmetic and are formatted as strings with two fractional
digits. `--min-quantity` filters individual items before grouping; adding
`--min-quantity 3` to the command above changes the office quantity to `10` and
its stock value to `"1.00"`.

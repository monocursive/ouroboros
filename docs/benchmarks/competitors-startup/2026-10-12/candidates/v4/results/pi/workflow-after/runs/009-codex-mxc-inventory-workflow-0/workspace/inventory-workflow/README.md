# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

Group by category with `python3 -m inventory.cli examples/stock.csv --group-by-category --min-quantity 3`.
The quantity filter applies to individual items before grouping. Categories are
sorted, quantities are summed, and stock values are decimal strings with two
fractional digits. Expected output:

```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 10, "stock_value": "1.00"}]
```

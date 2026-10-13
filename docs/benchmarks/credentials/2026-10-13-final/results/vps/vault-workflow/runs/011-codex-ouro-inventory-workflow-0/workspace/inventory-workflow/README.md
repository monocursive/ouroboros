# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

Group by category with `python3 -m inventory.cli examples/stock.csv --group-by-category`.
The output is sorted by category, with total quantities and stock values:

```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

Add `--min-quantity 3` to filter individual items before grouping. For this
example, the office summary then has quantity `10` and stock value `"1.00"`.

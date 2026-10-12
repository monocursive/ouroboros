# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

Group items by category with:

```sh
python3 -m inventory.cli examples/stock.csv --group-by-category
```

Expected output (categories are sorted alphabetically):

```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

Add `--min-quantity 3` to filter individual items before grouping. This changes
the office summary to quantity `10` and stock value `"1.00"`.

# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

Group inventory by category with:

```sh
python3 -m inventory.cli examples/stock.csv --group-by-category
```

Expected output (categories are sorted alphabetically):

```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

Stock values sum quantity times unit price using exact decimal arithmetic and
are formatted as strings with two fractional digits. Add `--min-quantity 3`
to filter individual items before grouping; the office summary then has
quantity `10` and stock value `"1.00"`.

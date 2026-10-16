# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

Group by category (categories are sorted alphabetically):

```sh
python3 -m inventory.cli examples/stock.csv --group-by-category
```

Expected output:

```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

Combine with `--min-quantity 3` to filter individual items before grouping;
the office summary then has quantity `10` and stock value `"1.00"`.
Stock values use exact decimal arithmetic and are formatted as strings with
two fractional digits.

# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

Group by category (sorted by category):

```sh
python3 -m inventory.cli examples/stock.csv --group-by-category
```

Expected output:

```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

Combine with `--min-quantity 3` to filter items before grouping; the office
summary then has quantity `10` and stock value `"1.00"`. Stock values are
decimal strings with two fractional digits. Invalid CSV exits with code `2`
and an error message on stderr.

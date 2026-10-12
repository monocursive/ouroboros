# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

Group by category, filtering individual items before summing:

```sh
python3 -m inventory.cli examples/stock.csv --group-by-category --min-quantity 3
```

For a CSV containing:

```csv
sku,category,quantity,unit_price
pen,office,10,0.10
notebook,office,2,2.50
mug,kitchen,3,4.25
```

Expected output (categories are sorted; stock values have two fractional digits):

```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 10, "stock_value": "1.00"}]
```

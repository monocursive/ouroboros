# Inventory CLI

Run `python3 -m inventory.cli examples/stock.csv`.
Use `--min-quantity 3` to filter before reporting.
Prices are decimal strings. No third-party dependencies are required.

## Examples

### Ungrouped output
```bash
python3 -m inventory.cli examples/stock.csv
```
Returns all items as a JSON array with sku, category, quantity, and unit_price.

### Grouped by category
```bash
python3 -m inventory.cli examples/stock.csv --group-by-category
```
Expected output:
```json
[{"category": "kitchen", "quantity": 3, "stock_value": "12.75"}, {"category": "office", "quantity": 12, "stock_value": "6.00"}]
```

The `--group-by-category` flag groups items by category, summing quantities and calculating total stock value. Results are sorted alphabetically by category name. The `--min-quantity` filter is applied before grouping.

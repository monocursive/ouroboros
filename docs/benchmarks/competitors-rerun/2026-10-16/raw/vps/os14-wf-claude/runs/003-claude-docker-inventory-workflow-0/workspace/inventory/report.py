from decimal import Decimal

def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_report(items, min_quantity=0):
    """Group items by category and return aggregated summaries."""
    # Filter by min_quantity first
    filtered = [item for item in items if item.quantity >= min_quantity]

    # Group by category
    by_category = {}
    for item in filtered:
        if item.category not in by_category:
            by_category[item.category] = {'quantity': 0, 'stock_value': Decimal('0')}
        by_category[item.category]['quantity'] += item.quantity
        by_category[item.category]['stock_value'] += item.quantity * item.unit_price

    # Build result sorted by category
    result = []
    for category in sorted(by_category.keys()):
        stats = by_category[category]
        result.append({
            'category': category,
            'quantity': stats['quantity'],
            'stock_value': f"{stats['stock_value']:.2f}"
        })

    return result

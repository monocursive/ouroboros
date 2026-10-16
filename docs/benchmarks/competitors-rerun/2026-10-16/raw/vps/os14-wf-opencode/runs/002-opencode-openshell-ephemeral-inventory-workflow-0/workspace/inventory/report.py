from decimal import Decimal

def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_summary(items, min_quantity=0):
    """Generate category summaries with total quantities and stock values.
    
    Filters items by min_quantity before grouping, then aggregates by category.
    Returns a list of dicts sorted by category name.
    """
    # Filter first, then group
    filtered = [x for x in items if x.quantity >= min_quantity]
    
    # Group by category
    categories = {}
    for item in filtered:
        if item.category not in categories:
            categories[item.category] = {'quantity': 0, 'value': Decimal('0')}
        categories[item.category]['quantity'] += item.quantity
        categories[item.category]['value'] += item.quantity * item.unit_price
    
    # Build result sorted by category
    result = []
    for category in sorted(categories.keys()):
        result.append({
            'category': category,
            'quantity': categories[category]['quantity'],
            'stock_value': f"{categories[category]['value']:.2f}"
        })
    
    return result

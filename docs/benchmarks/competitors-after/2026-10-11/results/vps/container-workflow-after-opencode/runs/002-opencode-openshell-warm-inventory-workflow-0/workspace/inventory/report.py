from decimal import Decimal

def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_report(items, min_quantity=0):
    """Group items by category after filtering by min_quantity.
    
    Returns a JSON array sorted by category, where each object contains:
    - category: string
    - quantity: sum of quantities
    - stock_value: sum of quantity * unit_price formatted to 2 decimal places
    """
    # Filter items first
    filtered = [x for x in items if x.quantity >= min_quantity]
    
    # Group by category
    groups = {}
    for item in filtered:
        if item.category not in groups:
            groups[item.category] = {'quantity': 0, 'stock_value': Decimal('0')}
        groups[item.category]['quantity'] += item.quantity
        groups[item.category]['stock_value'] += item.quantity * item.unit_price
    
    # Build result sorted by category
    result = []
    for category in sorted(groups.keys()):
        result.append({
            'category': category,
            'quantity': groups[category]['quantity'],
            'stock_value': f"{groups[category]['stock_value']:.2f}"
        })
    
    return result

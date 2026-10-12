from decimal import Decimal

def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_summary(items, min_quantity=0):
    """Group items by category and return summary with total quantity and stock value."""
    # Filter items by min_quantity first
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
            'stock_value': '{:.2f}'.format(groups[category]['stock_value'])
        })
    
    return result

def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_report(items, min_quantity=0):
    from decimal import Decimal
    from collections import defaultdict
    
    # Filter items by min_quantity first
    filtered = [x for x in items if x.quantity >= min_quantity]
    
    # Group by category
    groups = defaultdict(lambda: {'quantity': 0, 'stock_value': Decimal('0')})
    for item in filtered:
        groups[item.category]['quantity'] += item.quantity
        groups[item.category]['stock_value'] += item.quantity * item.unit_price
    
    # Build result sorted by category
    result = []
    for category in sorted(groups.keys()):
        data = groups[category]
        result.append({
            'category': category,
            'quantity': data['quantity'],
            'stock_value': f"{data['stock_value']:.2f}"
        })
    
    return result

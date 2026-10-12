def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_summary(items, min_quantity=0):
    from collections import defaultdict
    from decimal import Decimal
    
    # Filter items by min_quantity first
    filtered = [x for x in items if x.quantity >= min_quantity]
    
    # Group by category
    grouped = defaultdict(lambda: {'quantity': 0, 'stock_value': Decimal('0')})
    for item in filtered:
        grouped[item.category]['quantity'] += item.quantity
        grouped[item.category]['stock_value'] += item.quantity * item.unit_price
    
    # Convert to sorted list
    result = []
    for category in sorted(grouped.keys()):
        result.append({
            'category': category,
            'quantity': grouped[category]['quantity'],
            'stock_value': f"{grouped[category]['stock_value']:.2f}"
        })
    
    return result

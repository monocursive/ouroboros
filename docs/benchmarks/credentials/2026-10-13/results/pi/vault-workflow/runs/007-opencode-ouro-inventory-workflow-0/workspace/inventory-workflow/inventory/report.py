def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_summary(items, min_quantity=0):
    from decimal import Decimal
    from collections import defaultdict
    
    # Filter items by min_quantity first
    filtered_items = [x for x in items if x.quantity >= min_quantity]
    
    # Group by category
    categories = defaultdict(lambda: {'quantity': 0, 'stock_value': Decimal('0')})
    for item in filtered_items:
        categories[item.category]['quantity'] += item.quantity
        categories[item.category]['stock_value'] += item.quantity * item.unit_price
    
    # Build result sorted by category
    result = []
    for category in sorted(categories.keys()):
        stock_value = categories[category]['stock_value']
        # Format stock_value as decimal string with exactly 2 fractional digits
        result.append({
            'category': category,
            'quantity': categories[category]['quantity'],
            'stock_value': f'{stock_value:.2f}'
        })
    
    return result

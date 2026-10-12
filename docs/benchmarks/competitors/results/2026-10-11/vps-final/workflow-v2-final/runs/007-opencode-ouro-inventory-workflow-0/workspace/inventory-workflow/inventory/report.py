def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_report(items, min_quantity=0):
    from decimal import Decimal
    # Filter items by min_quantity first
    filtered = [x for x in items if x.quantity >= min_quantity]
    
    # Group by category
    categories = {}
    for item in filtered:
        if item.category not in categories:
            categories[item.category] = {'quantity': 0, 'stock_value': Decimal('0')}
        categories[item.category]['quantity'] += item.quantity
        categories[item.category]['stock_value'] += item.quantity * item.unit_price
    
    # Build result sorted by category
    result = []
    for cat in sorted(categories.keys()):
        result.append({
            'category': cat,
            'quantity': categories[cat]['quantity'],
            'stock_value': f"{categories[cat]['stock_value']:.2f}"
        })
    
    return result

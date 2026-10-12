from decimal import Decimal

def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_summary_report(items, min_quantity=0):
    # Filter items by min_quantity first
    filtered_items = [x for x in items if x.quantity >= min_quantity]
    
    # Group by category
    category_map = {}
    for item in filtered_items:
        if item.category not in category_map:
            category_map[item.category] = {'quantity': 0, 'stock_value': Decimal('0')}
        category_map[item.category]['quantity'] += item.quantity
        category_map[item.category]['stock_value'] += item.quantity * item.unit_price
    
    # Convert to sorted list
    result = []
    for category in sorted(category_map.keys()):
        data = category_map[category]
        result.append({
            'category': category,
            'quantity': data['quantity'],
            'stock_value': '{:.2f}'.format(data['stock_value'])
        })
    
    return result

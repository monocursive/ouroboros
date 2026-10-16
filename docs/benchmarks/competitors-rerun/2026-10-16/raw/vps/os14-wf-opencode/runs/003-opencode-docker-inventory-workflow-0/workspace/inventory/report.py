from decimal import Decimal

def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_summary(items, min_quantity=0):
    # Filter items by min_quantity first
    filtered_items = [x for x in items if x.quantity >= min_quantity]
    
    # Group by category
    category_data = {}
    for item in filtered_items:
        if item.category not in category_data:
            category_data[item.category] = {
                'quantity': 0,
                'stock_value': Decimal('0')
            }
        category_data[item.category]['quantity'] += item.quantity
        category_data[item.category]['stock_value'] += item.quantity * item.unit_price
    
    # Build result sorted by category
    result = []
    for category in sorted(category_data.keys()):
        data = category_data[category]
        result.append({
            'category': category,
            'quantity': data['quantity'],
            'stock_value': f"{data['stock_value']:.2f}"
        })
    
    return result

from decimal import Decimal

def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_summary(items, min_quantity=0):
    # Filter items by min_quantity first
    filtered = [x for x in items if x.quantity >= min_quantity]

    # Group by category
    categories = {}
    for item in filtered:
        if item.category not in categories:
            categories[item.category] = {'quantity': 0, 'stock_value': Decimal('0')}
        categories[item.category]['quantity'] += item.quantity
        categories[item.category]['stock_value'] += item.quantity * item.unit_price

    # Convert to sorted list
    result = []
    for category in sorted(categories.keys()):
        result.append({
            'category': category,
            'quantity': categories[category]['quantity'],
            'stock_value': f"{categories[category]['stock_value']:.2f}"
        })

    return result

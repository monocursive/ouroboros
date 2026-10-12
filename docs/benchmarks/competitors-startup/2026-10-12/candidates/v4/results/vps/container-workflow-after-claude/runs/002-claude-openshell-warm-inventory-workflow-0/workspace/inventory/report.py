from decimal import Decimal

def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_report(items, min_quantity=0):
    filtered = [x for x in items if x.quantity >= min_quantity]
    categories = {}
    for item in filtered:
        if item.category not in categories:
            categories[item.category] = {'quantity': 0, 'stock_value': Decimal('0')}
        categories[item.category]['quantity'] += item.quantity
        categories[item.category]['stock_value'] += item.quantity * item.unit_price

    result = [
        {
            'category': cat,
            'quantity': data['quantity'],
            'stock_value': f"{data['stock_value']:.2f}"
        }
        for cat, data in categories.items()
    ]
    return sorted(result, key=lambda x: x['category'])

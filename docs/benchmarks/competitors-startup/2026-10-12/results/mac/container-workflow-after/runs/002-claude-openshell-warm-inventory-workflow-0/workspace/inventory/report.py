from decimal import Decimal

def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_summary(items, min_quantity=0):
    filtered = [x for x in items if x.quantity >= min_quantity]
    groups = {}
    for item in filtered:
        if item.category not in groups:
            groups[item.category] = {'quantity': 0, 'value': Decimal('0')}
        groups[item.category]['quantity'] += item.quantity
        groups[item.category]['value'] += item.quantity * item.unit_price
    result = [
        {
            'category': cat,
            'quantity': data['quantity'],
            'stock_value': f"{data['value']:.2f}"
        }
        for cat, data in groups.items()
    ]
    return sorted(result, key=lambda x: x['category'])

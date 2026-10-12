from decimal import Decimal

def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_report(items, min_quantity=0):
    filtered = [x for x in items if x.quantity >= min_quantity]
    grouped = {}
    for item in filtered:
        if item.category not in grouped:
            grouped[item.category] = {'quantity': 0, 'stock_value': Decimal('0')}
        grouped[item.category]['quantity'] += item.quantity
        grouped[item.category]['stock_value'] += item.quantity * item.unit_price

    result = []
    for category in sorted(grouped.keys()):
        result.append({
            'category': category,
            'quantity': grouped[category]['quantity'],
            'stock_value': f"{grouped[category]['stock_value']:.2f}"
        })
    return result

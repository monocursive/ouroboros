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
            categories[item.category] = {'quantity': 0, 'value': Decimal('0')}
        categories[item.category]['quantity'] += item.quantity
        categories[item.category]['value'] += item.quantity * item.unit_price

    result = []
    for category in sorted(categories.keys()):
        result.append({
            'category': category,
            'quantity': categories[category]['quantity'],
            'stock_value': f"{categories[category]['value']:.2f}"
        })
    return result

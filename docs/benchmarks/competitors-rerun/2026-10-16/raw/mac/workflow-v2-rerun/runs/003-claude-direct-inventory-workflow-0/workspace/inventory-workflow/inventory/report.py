from decimal import Decimal

def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_summary(items, min_quantity=0):
    filtered = [x for x in items if x.quantity >= min_quantity]
    by_category = {}
    for item in filtered:
        if item.category not in by_category:
            by_category[item.category] = {'quantity': 0, 'stock_value': Decimal('0')}
        by_category[item.category]['quantity'] += item.quantity
        by_category[item.category]['stock_value'] += item.quantity * item.unit_price

    result = []
    for category in sorted(by_category.keys()):
        result.append({
            'category': category,
            'quantity': by_category[category]['quantity'],
            'stock_value': f"{by_category[category]['stock_value']:.2f}"
        })
    return result

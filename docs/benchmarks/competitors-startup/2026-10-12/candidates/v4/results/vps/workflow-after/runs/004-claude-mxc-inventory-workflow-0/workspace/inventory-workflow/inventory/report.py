def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_report(items, min_quantity=0):
    from decimal import Decimal
    from collections import defaultdict

    filtered = [x for x in items if x.quantity >= min_quantity]

    by_category = defaultdict(lambda: {'quantity': 0, 'stock_value': Decimal('0')})
    for item in filtered:
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

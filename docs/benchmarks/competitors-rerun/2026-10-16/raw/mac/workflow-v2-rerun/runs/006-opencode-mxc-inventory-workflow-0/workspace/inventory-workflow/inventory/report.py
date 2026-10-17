from decimal import Decimal

def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_summary(items, min_quantity=0):
    filtered = [x for x in items if x.quantity >= min_quantity]
    summaries = {}
    for item in filtered:
        if item.category not in summaries:
            summaries[item.category] = {'quantity': 0, 'stock_value': Decimal('0')}
        summaries[item.category]['quantity'] += item.quantity
        summaries[item.category]['stock_value'] += item.quantity * item.unit_price
    
    result = []
    for category in sorted(summaries.keys()):
        result.append({
            'category': category,
            'quantity': summaries[category]['quantity'],
            'stock_value': f"{summaries[category]['stock_value']:.2f}"
        })
    return result

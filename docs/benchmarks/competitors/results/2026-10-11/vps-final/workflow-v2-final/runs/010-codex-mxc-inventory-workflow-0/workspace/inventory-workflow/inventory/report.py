from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Allow every product and sum to remain exact, even beyond the default
    # Decimal context's 28 significant digits.
    lowest_exponent = min(0, min(item.unit_price.as_tuple().exponent
                                 for item in items))
    highest_position = max(item.unit_price.adjusted() + len(str(item.quantity))
                           for item in items)
    precision = max(28, highest_position - lowest_exponent
                    + len(str(len(items))) + 2)
    summaries = {}
    with localcontext() as context:
        context.prec = precision
        for item in items:
            summary = summaries.setdefault(item.category, {
                'category': item.category, 'quantity': 0,
                'stock_value': Decimal(0)})
            summary['quantity'] += item.quantity
            summary['stock_value'] += item.quantity * item.unit_price
        return [{'category': category,
                 'quantity': summaries[category]['quantity'],
                 'stock_value': format(summaries[category]['stock_value'], '.2f')}
                for category in sorted(summaries)]

from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Retain every digit in products and sums, including prices with
    # different scales and values beyond the default Decimal precision.
    lowest_exponent = min(0, *(item.unit_price.as_tuple().exponent for item in items))
    highest_position = max(
        len(item.unit_price.as_tuple().digits)
        + item.unit_price.as_tuple().exponent
        + len(str(item.quantity))
        for item in items
    )
    with localcontext() as context:
        context.prec = max(28, highest_position - lowest_exponent + len(str(len(items))) + 2)
        groups = {}
        for item in items:
            group = groups.setdefault(item.category, {'quantity': 0, 'stock_value': Decimal(0)})
            group['quantity'] += item.quantity
            group['stock_value'] += item.quantity * item.unit_price
        return [
            {'category': category, 'quantity': groups[category]['quantity'],
             'stock_value': format(groups[category]['stock_value'], '.2f')}
            for category in sorted(groups)
        ]

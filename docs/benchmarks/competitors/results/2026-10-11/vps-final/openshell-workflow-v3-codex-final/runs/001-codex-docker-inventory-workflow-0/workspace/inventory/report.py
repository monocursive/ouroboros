from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Allow every input digit, quantity multiplier, and carry from summation
    # so Decimal's default precision cannot round intermediate totals.
    integer_digits = max(
        max(1, len(item.unit_price.as_tuple().digits)
            + item.unit_price.as_tuple().exponent) + len(str(item.quantity))
        for item in items
    )
    fractional_digits = max(
        max(0, -item.unit_price.as_tuple().exponent) for item in items
    )
    with localcontext() as context:
        context.prec = integer_digits + fractional_digits + len(str(len(items))) + 2
        groups = {}
        for item in items:
            group = groups.setdefault(item.category, {'quantity': 0, 'value': Decimal(0)})
            group['quantity'] += item.quantity
            group['value'] += item.quantity * item.unit_price
        return [
            {'category': category, 'quantity': groups[category]['quantity'],
             'stock_value': format(groups[category]['value'], '.2f')}
            for category in sorted(groups)
        ]

from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    filtered = [item for item in items if item.quantity >= min_quantity]
    if not filtered:
        return []

    # Allow every product and sum to retain all digits, even beyond the
    # default Decimal precision. Include room for carries across all rows.
    integer_digits = max(
        max(0, item.unit_price.adjusted() + 1) + len(str(item.quantity))
        for item in filtered
    )
    fractional_digits = max(
        max(0, -item.unit_price.as_tuple().exponent) for item in filtered
    )
    with localcontext() as context:
        context.prec = integer_digits + max(2, fractional_digits) + len(str(len(filtered))) + 2
        groups = {}
        for item in filtered:
            group = groups.setdefault(item.category, {
                'category': item.category, 'quantity': 0, 'stock_value': Decimal(0)
            })
            group['quantity'] += item.quantity
            group['stock_value'] += item.quantity * item.unit_price
        return [
            {'category': category, 'quantity': groups[category]['quantity'],
             'stock_value': format(groups[category]['stock_value'], '.2f')}
            for category in sorted(groups)
        ]

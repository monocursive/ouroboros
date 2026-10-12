from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Allow every product and sum to fit without decimal context rounding.
    fractional_digits = max(0, -min(x.unit_price.as_tuple().exponent for x in items))
    integer_digits = max(
        1, max(x.unit_price.adjusted() + 1 + len(str(x.quantity)) for x in items)
    )
    with localcontext() as context:
        context.prec = integer_digits + fractional_digits + len(str(len(items))) + 2
        totals = {}
        for item in items:
            quantity, value = totals.get(item.category, (0, Decimal(0)))
            totals[item.category] = (
                quantity + item.quantity,
                value + item.quantity * item.unit_price,
            )
        return [
            {'category': category, 'quantity': totals[category][0],
             'stock_value': format(totals[category][1], '.2f')}
            for category in sorted(totals)
        ]

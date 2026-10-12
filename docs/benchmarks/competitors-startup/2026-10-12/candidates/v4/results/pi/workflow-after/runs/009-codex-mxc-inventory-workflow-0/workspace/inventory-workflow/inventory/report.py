from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Reserve enough precision for exact products and sums, even when prices
    # exceed the default Decimal context's precision.
    lowest_exponent = min(0, *(item.unit_price.as_tuple().exponent for item in items))
    highest_digit = max(
        len(item.unit_price.as_tuple().digits) + item.unit_price.as_tuple().exponent
        + len(str(item.quantity)) for item in items
    )
    with localcontext() as context:
        context.prec = max(28, highest_digit - lowest_exponent + len(str(len(items))) + 2)
        totals = {}
        for item in items:
            quantity, value = totals.get(item.category, (0, Decimal(0)))
            totals[item.category] = (
                quantity + item.quantity,
                value + item.quantity * item.unit_price,
            )
        return [
            {'category': category, 'quantity': quantity,
             'stock_value': format(value, '.2f')}
            for category, (quantity, value) in sorted(totals.items())
        ]

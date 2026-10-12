from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    # Reserve enough precision for exact products and sums, even for prices
    # that exceed the default Decimal context precision.
    fractional_digits = max(
        (max(0, -item.unit_price.as_tuple().exponent) for item in items),
        default=0,
    )
    integer_digits = max(
        (max(0, item.unit_price.adjusted() + 1) + len(str(item.quantity))
         for item in items),
        default=1,
    )
    with localcontext() as context:
        context.prec = max(28, integer_digits + fractional_digits
                           + len(str(len(items))) + 2)
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

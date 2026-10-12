from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Allow every product and sum to retain all digits, including prices with
    # more precision than the default Decimal context.
    fractional_digits = max(0, -min(item.unit_price.as_tuple().exponent
                                    for item in items))
    integer_digits = max(1, max(item.unit_price.adjusted()
                                + len(str(item.quantity)) + 1
                                for item in items))
    with localcontext() as context:
        context.prec = max(28, integer_digits + fractional_digits
                           + len(str(len(items))) + 2)
        totals = {}
        for item in items:
            summary = totals.setdefault(item.category, [0, Decimal(0)])
            summary[0] += item.quantity
            summary[1] += item.quantity * item.unit_price
        return [{'category': category, 'quantity': quantity,
                 'stock_value': format(value, '.2f')}
                for category, (quantity, value) in sorted(totals.items())]

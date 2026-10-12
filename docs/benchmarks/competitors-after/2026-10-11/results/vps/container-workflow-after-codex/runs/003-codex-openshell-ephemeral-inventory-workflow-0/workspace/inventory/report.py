from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    # Reserve enough digits for exact products and sums, including prices
    # with more precision than the default Decimal context permits.
    fractional_digits = max((max(0, -x.unit_price.as_tuple().exponent)
                             for x in items), default=0)
    integer_digits = max((max(0, x.unit_price.adjusted() + 1)
                          + len(str(x.quantity)) for x in items), default=0)
    with localcontext() as context:
        context.prec = max(28, integer_digits + fractional_digits
                           + len(str(len(items))) + 1)
        groups = {}
        for item in items:
            group = groups.setdefault(item.category, [0, Decimal(0)])
            group[0] += item.quantity
            group[1] += item.quantity * item.unit_price
        return [{'category': category, 'quantity': groups[category][0],
                 'stock_value': format(groups[category][1], '.2f')}
                for category in sorted(groups)]

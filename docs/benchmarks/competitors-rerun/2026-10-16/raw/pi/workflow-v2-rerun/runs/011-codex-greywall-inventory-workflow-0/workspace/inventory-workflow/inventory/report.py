from decimal import Decimal, localcontext


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Cover the full decimal span, products, and carries without rounding sums.
    fractional_digits = max(max(0, -item.unit_price.as_tuple().exponent)
                            for item in items)
    integer_digits = max(max(1, item.unit_price.adjusted() + 1)
                         + len(str(item.quantity)) for item in items)
    with localcontext() as context:
        context.prec = integer_digits + fractional_digits + len(str(len(items))) + 2
        groups = {}
        for item in items:
            group = groups.setdefault(item.category, [0, Decimal(0)])
            group[0] += item.quantity
            group[1] += item.quantity * item.unit_price
        return [{'category': category, 'quantity': groups[category][0],
                 'stock_value': format(groups[category][1], '.2f')}
                for category in sorted(groups)]


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

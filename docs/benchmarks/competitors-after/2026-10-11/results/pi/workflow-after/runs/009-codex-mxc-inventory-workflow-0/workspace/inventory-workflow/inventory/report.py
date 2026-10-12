from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Include alignment and carry digits so arithmetic stays exact even
    # when prices or totals exceed the default decimal precision.
    lowest_exponent = min(item.unit_price.as_tuple().exponent for item in items)
    highest_digit = max(item.unit_price.adjusted() + len(str(item.quantity))
                        for item in items)
    precision = max(28, highest_digit - min(lowest_exponent, -2)
                    + len(str(len(items))) + 2)
    groups = {}
    with localcontext() as context:
        context.prec = precision
        for item in items:
            group = groups.setdefault(item.category, [0, Decimal(0)])
            group[0] += item.quantity
            group[1] += item.quantity * item.unit_price
        return [{'category': category, 'quantity': groups[category][0],
                 'stock_value': format(groups[category][1], '.2f')}
                for category in sorted(groups)]

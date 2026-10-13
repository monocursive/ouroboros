from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Reserve enough digits for exact products and sums across price scales.
    lowest_exponent = min(-2, *(item.unit_price.as_tuple().exponent
                                for item in items))
    highest_position = max(item.unit_price.adjusted() + len(str(item.quantity))
                           for item in items)
    precision = max(28, highest_position - lowest_exponent
                    + len(str(len(items))) + 3)
    groups = {}
    with localcontext() as context:
        context.prec = precision
        for item in items:
            quantity, value = groups.get(item.category, (0, Decimal(0)))
            groups[item.category] = (
                quantity + item.quantity,
                value + item.quantity * item.unit_price,
            )
        return [{'category': category, 'quantity': groups[category][0],
                 'stock_value': format(groups[category][1], '.2f')}
                for category in sorted(groups)]

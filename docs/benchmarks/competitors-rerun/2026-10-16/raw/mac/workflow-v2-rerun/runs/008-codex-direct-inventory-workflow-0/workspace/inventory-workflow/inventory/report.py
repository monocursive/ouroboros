from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Cover every product's integer and fractional digits, plus carry digits
    # from summation, so the default Decimal precision cannot round totals.
    lowest_exponent = min(-2, *(item.unit_price.as_tuple().exponent for item in items))
    highest_position = max(
        item.unit_price.adjusted() + len(str(item.quantity)) for item in items
    )
    with localcontext() as context:
        context.prec = max(28, highest_position - lowest_exponent + len(str(len(items))) + 2)
        groups = {}
        for item in items:
            quantity, value = groups.get(item.category, (0, Decimal(0)))
            groups[item.category] = (
                quantity + item.quantity,
                value + item.quantity * item.unit_price,
            )
        return [
            {'category': category, 'quantity': quantity,
             'stock_value': format(value, '.2f')}
            for category, (quantity, value) in sorted(groups.items())
        ]

from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    filtered = [item for item in items if item.quantity >= min_quantity]
    if not filtered:
        return []

    # Size precision for exact products and sums across all price scales.
    lowest_exponent = min(item.unit_price.as_tuple().exponent for item in filtered)
    highest_place = max(
        item.unit_price.adjusted() + len(str(item.quantity)) for item in filtered
    )
    with localcontext() as context:
        context.prec = max(28, highest_place - lowest_exponent + len(str(len(filtered))) + 2)
        groups = {}
        for item in filtered:
            quantity, value = groups.get(item.category, (0, Decimal(0)))
            groups[item.category] = (
                quantity + item.quantity,
                value + item.quantity * item.unit_price,
            )
        return [
            {'category': category, 'quantity': quantity, 'stock_value': format(value, '.2f')}
            for category, (quantity, value) in sorted(groups.items())
        ]

from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    filtered = [item for item in items if item.quantity >= min_quantity]
    if not filtered:
        return []

    # Allow every product and sum to retain all digits, even beyond the
    # default Decimal context's 28-digit precision.
    lowest_exponent = min(-2, *(item.unit_price.as_tuple().exponent
                                for item in filtered))
    highest_place = max(0, *(item.unit_price.adjusted()
                            + len(str(item.quantity)) for item in filtered))
    with localcontext() as context:
        context.prec = highest_place - lowest_exponent + len(str(len(filtered))) + 2
        totals = {}
        for item in filtered:
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

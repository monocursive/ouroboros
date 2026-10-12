from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Allow every product and sum to remain exact, even beyond Decimal's
    # default 28 significant digits or with widely differing price scales.
    lowest_exponent = min(item.unit_price.as_tuple().exponent for item in items)
    highest_digit = max(item.unit_price.adjusted() + len(str(item.quantity))
                        for item in items)
    precision = max(28, highest_digit - lowest_exponent + len(str(len(items))) + 2)
    categories = {}
    with localcontext() as context:
        context.prec = precision
        for item in items:
            quantity, value = categories.get(item.category, (0, Decimal(0)))
            categories[item.category] = (
                quantity + item.quantity,
                value + item.quantity * item.unit_price,
            )
        return [
            {'category': category, 'quantity': quantity,
             'stock_value': format(value, '.2f')}
            for category, (quantity, value) in sorted(categories.items())
        ]

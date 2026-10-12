from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Allow every product and total to retain all digits, even when prices
    # exceed the default Decimal context's precision or have different scales.
    lowest_exponent = min(0, min(item.unit_price.as_tuple().exponent
                                 for item in items))
    highest_place = max(len(item.unit_price.as_tuple().digits)
                        + item.unit_price.as_tuple().exponent
                        + len(str(item.quantity)) for item in items)
    with localcontext() as context:
        context.prec = max(28, highest_place - lowest_exponent
                           + len(str(len(items))) + 2)
        groups = {}
        for item in items:
            quantity, value = groups.get(item.category, (0, Decimal(0)))
            groups[item.category] = (
                quantity + item.quantity,
                value + item.quantity * item.unit_price,
            )
        return [{'category': category, 'quantity': quantity,
                 'stock_value': format(value, '.2f')}
                for category, (quantity, value) in sorted(groups.items())]

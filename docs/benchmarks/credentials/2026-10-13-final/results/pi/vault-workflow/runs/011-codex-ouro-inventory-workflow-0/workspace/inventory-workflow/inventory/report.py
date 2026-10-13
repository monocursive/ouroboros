from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Allow every product and sum to remain exact, including prices with
    # more digits than the default Decimal context supports.
    lowest_exponent = min(item.unit_price.as_tuple().exponent for item in items)
    product_digits = max(
        len(item.unit_price.as_tuple().digits) + len(str(item.quantity))
        + item.unit_price.as_tuple().exponent - lowest_exponent
        for item in items
    )
    with localcontext() as context:
        context.prec = product_digits + len(str(len(items))) + 2
        groups = {}
        for item in items:
            quantity, value = groups.get(item.category, (0, Decimal(0)))
            groups[item.category] = (
                quantity + item.quantity,
                value + item.quantity * item.unit_price,
            )
        return [
            {'category': category, 'quantity': groups[category][0],
             'stock_value': format(groups[category][1], '.2f')}
            for category in sorted(groups)
        ]

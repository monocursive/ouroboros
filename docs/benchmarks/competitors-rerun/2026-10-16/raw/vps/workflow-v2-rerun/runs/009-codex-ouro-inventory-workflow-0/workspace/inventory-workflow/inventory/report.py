from decimal import Decimal, localcontext


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    # Allow every product and their sum to fit without context rounding,
    # including prices with very different decimal exponents.
    scale = min([0] + [item.unit_price.as_tuple().exponent for item in items])
    digits = max([1] + [
        len(item.unit_price.as_tuple().digits) + len(str(item.quantity))
        + item.unit_price.as_tuple().exponent - scale
        for item in items
    ])
    with localcontext() as context:
        context.prec = digits + len(str(len(items))) + 2
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


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    # Allow enough precision for every product and their sum, including prices
    # with more digits than the default Decimal context supports.
    scale = max((max(0, -item.unit_price.as_tuple().exponent)
                 for item in items), default=0)
    integer_digits = max((max(1, item.unit_price.adjusted() + 1)
                          + len(str(item.quantity)) for item in items), default=1)
    with localcontext() as context:
        context.prec = integer_digits + scale + len(str(len(items))) + 2
        categories = {}
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

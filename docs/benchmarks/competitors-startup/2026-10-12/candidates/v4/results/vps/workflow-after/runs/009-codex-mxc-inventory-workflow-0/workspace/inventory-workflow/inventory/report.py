from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    totals = {}
    # Allow enough precision for every product and sum, including prices
    # whose significant digits span widely different decimal exponents.
    precision = 2 + sum(len(item.unit_price.as_tuple().digits)
                        + abs(item.unit_price.as_tuple().exponent)
                        + len(str(item.quantity)) for item in items)
    with localcontext() as context:
        context.prec = max(context.prec, precision)
        for item in items:
            quantity, value = totals.get(item.category, (0, Decimal(0)))
            totals[item.category] = (
                quantity + item.quantity,
                value + item.quantity * item.unit_price,
            )
        return [
            {'category': category, 'quantity': totals[category][0],
             'stock_value': format(totals[category][1], '.2f')}
            for category in sorted(totals)
        ]

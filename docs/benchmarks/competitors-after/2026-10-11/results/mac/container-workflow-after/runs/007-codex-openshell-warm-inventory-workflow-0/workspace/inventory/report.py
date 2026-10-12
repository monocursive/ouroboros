from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Reserve enough digits for exact multiplication and addition, including
    # prices with widely different scales and a carry from summing all rows.
    fractional_digits = max(max(0, -item.unit_price.as_tuple().exponent)
                            for item in items)
    integer_digits = max(len(item.unit_price.as_tuple().digits)
                         + max(0, item.unit_price.as_tuple().exponent)
                         + len(str(item.quantity)) for item in items)
    with localcontext() as context:
        context.prec = max(28, integer_digits + fractional_digits
                           + len(str(len(items))))
        summaries = {}
        for item in items:
            summary = summaries.setdefault(item.category, [0, Decimal(0)])
            summary[0] += item.quantity
            summary[1] += item.quantity * item.unit_price
        return [{'category': category, 'quantity': quantity,
                 'stock_value': format(stock_value, '.2f')}
                for category, (quantity, stock_value)
                in sorted(summaries.items())]

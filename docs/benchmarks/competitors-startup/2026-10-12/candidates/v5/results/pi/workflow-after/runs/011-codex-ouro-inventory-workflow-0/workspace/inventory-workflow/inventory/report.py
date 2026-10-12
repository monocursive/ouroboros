from decimal import Decimal, localcontext


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    # Reserve all integer and fractional digits, plus carries for the sum.
    integer_digits = max((item.unit_price.adjusted() + 1 +
                          len(str(item.quantity)) for item in items), default=1)
    fractional_digits = max((max(0, -item.unit_price.as_tuple().exponent)
                             for item in items), default=0)
    with localcontext() as context:
        context.prec = max(1, integer_digits) + fractional_digits + len(str(len(items))) + 2
        groups = {}
        for item in items:
            group = groups.setdefault(item.category, {'category': item.category,
                                      'quantity': 0, 'stock_value': Decimal(0)})
            group['quantity'] += item.quantity
            group['stock_value'] += item.quantity * item.unit_price
        return [{'category': category, 'quantity': groups[category]['quantity'],
                 'stock_value': format(groups[category]['stock_value'], '.2f')}
                for category in sorted(groups)]


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

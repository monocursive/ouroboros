from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Preserve every input digit through multiplication and summation, even
    # when prices have very different scales or exceed default precision.
    fractional_digits = max(0, max(-item.unit_price.as_tuple().exponent
                                  for item in items))
    integer_digits = max(item.unit_price.adjusted() + 1
                         + len(str(item.quantity)) for item in items)
    with localcontext() as context:
        context.prec = max(1, integer_digits + fractional_digits
                           + len(str(len(items))) + 2)
        groups = {}
        for item in items:
            group = groups.setdefault(item.category, {
                'category': item.category, 'quantity': 0,
                'stock_value': Decimal(0),
            })
            group['quantity'] += item.quantity
            group['stock_value'] += item.quantity * item.unit_price
        return [dict(groups[category],
                     stock_value=format(groups[category]['stock_value'], '.2f'))
                for category in sorted(groups)]

from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    # Allow every product and sum to retain all digits, including prices with
    # more precision than the default Decimal context supports.
    fractional_places = max([2] + [-item.unit_price.as_tuple().exponent
                                      for item in items])
    integer_places = max([1] + [item.unit_price.adjusted() + 1
                                + len(str(item.quantity)) for item in items])
    with localcontext() as context:
        context.prec = max(28, integer_places + fractional_places
                           + len(str(len(items))) + 1)
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

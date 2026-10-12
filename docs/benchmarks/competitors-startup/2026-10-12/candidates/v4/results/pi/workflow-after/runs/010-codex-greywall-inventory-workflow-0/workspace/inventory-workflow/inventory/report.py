from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Size the context to keep all products and their sum exact.
    lowest_exponent = min(item.unit_price.as_tuple().exponent for item in items)
    highest_digit = max(item.unit_price.adjusted() + len(str(item.quantity))
                        for item in items)
    with localcontext() as context:
        context.prec = max(28, highest_digit - lowest_exponent
                           + len(str(len(items))) + 2)
        categories = {}
        for item in items:
            summary = categories.setdefault(item.category, {
                'category': item.category, 'quantity': 0,
                'stock_value': Decimal(0),
            })
            summary['quantity'] += item.quantity
            summary['stock_value'] += item.quantity * item.unit_price
        return [dict(categories[category],
                     stock_value=format(categories[category]['stock_value'], '.2f'))
                for category in sorted(categories)]

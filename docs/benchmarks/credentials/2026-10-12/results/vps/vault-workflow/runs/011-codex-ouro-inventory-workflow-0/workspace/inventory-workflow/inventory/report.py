from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Reserve enough precision for all product digits and sum carries.
    lowest_exponent = min(item.unit_price.as_tuple().exponent for item in items)
    highest_digit = max(item.unit_price.adjusted() + len(str(item.quantity))
                        for item in items)
    categories = {}
    with localcontext() as context:
        context.prec = max(context.prec, highest_digit - min(lowest_exponent, -2)
                           + len(str(len(items))) + 3)
        for item in items:
            summary = categories.setdefault(item.category, [0, Decimal(0)])
            summary[0] += item.quantity
            summary[1] += item.quantity * item.unit_price
        return [{'category': category, 'quantity': quantity,
                 'stock_value': format(value, '.2f')}
                for category, (quantity, value) in sorted(categories.items())]

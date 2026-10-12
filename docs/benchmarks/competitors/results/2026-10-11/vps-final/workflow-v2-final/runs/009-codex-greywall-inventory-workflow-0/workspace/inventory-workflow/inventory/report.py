from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Allow every digit of each product and sum, including fractional digits.
    lowest_exponent = min(-2, *(item.unit_price.as_tuple().exponent for item in items))
    highest_digit = max(item.unit_price.adjusted() + len(str(item.quantity))
                        for item in items)
    precision = max(28, highest_digit - lowest_exponent + len(str(len(items))) + 3)
    groups = {}
    with localcontext() as context:
        context.prec = precision
        for item in items:
            quantity, value = groups.get(item.category, (0, Decimal(0)))
            groups[item.category] = (quantity + item.quantity,
                                     value + item.quantity * item.unit_price)
        return [{'category': category, 'quantity': quantity,
                 'stock_value': format(value, '.2f')}
                for category, (quantity, value) in sorted(groups.items())]

from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Allow every input digit and carry to survive multiplication and addition,
    # even when prices exceed the default Decimal context's precision.
    lowest_exponent = min(-2, *(item.unit_price.as_tuple().exponent for item in items))
    highest_digit = max(0, *(item.unit_price.adjusted() + len(str(item.quantity))
                             for item in items))
    precision = highest_digit - lowest_exponent + len(str(len(items))) + 2
    categories = {}
    with localcontext() as context:
        context.prec = precision
        for item in items:
            summary = categories.setdefault(item.category, [0, Decimal(0)])
            summary[0] += item.quantity
            summary[1] += item.quantity * item.unit_price
        return [{'category': category, 'quantity': quantity,
                 'stock_value': format(value, '.2f')}
                for category, (quantity, value) in sorted(categories.items())]

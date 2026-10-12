from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Allow every product and sum to retain all digits, including prices
    # with widely differing exponents, regardless of Decimal's default precision.
    lowest_exponent = min(item.unit_price.as_tuple().exponent for item in items)
    highest_digit = max(item.unit_price.adjusted() + len(str(item.quantity))
                        for item in items)
    with localcontext() as context:
        context.prec = max(28, highest_digit - lowest_exponent + len(str(len(items))) + 2)
        categories = {}
        for item in items:
            summary = categories.setdefault(item.category, [0, Decimal(0)])
            summary[0] += item.quantity
            summary[1] += item.quantity * item.unit_price
        return [{'category': category, 'quantity': categories[category][0],
                 'stock_value': format(categories[category][1], '.2f')}
                for category in sorted(categories)]

from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    groups = {}
    for item in items:
        if item.quantity >= min_quantity:
            groups.setdefault(item.category, []).append(item)

    result = []
    for category, members in sorted(groups.items()):
        # Preserve all digits through multiplication and summation, including
        # possible carries, before formatting the total to two decimal places.
        lowest_exponent = min(x.unit_price.as_tuple().exponent for x in members)
        highest_digit = max(x.unit_price.adjusted() + len(str(x.quantity))
                            for x in members)
        with localcontext() as context:
            context.prec = max(28, highest_digit - lowest_exponent
                               + len(str(len(members))) + 2)
            value = sum((x.unit_price * x.quantity for x in members), Decimal(0))
            result.append({'category': category,
                           'quantity': sum(x.quantity for x in members),
                           'stock_value': format(value, '.2f')})
    return result

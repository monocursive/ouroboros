from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Allow every product and sum to retain all digits, even for prices
    # exceeding the default Decimal context's precision.
    lowest_exponent = min(0, *(item.unit_price.as_tuple().exponent for item in items))
    highest_digit = max(item.unit_price.adjusted() + len(str(item.quantity))
                        for item in items)
    with localcontext() as context:
        context.prec = max(28, highest_digit - lowest_exponent + len(str(len(items))) + 2)
        groups = {}
        for item in items:
            group = groups.setdefault(item.category, {
                'category': item.category, 'quantity': 0, 'stock_value': Decimal(0)})
            group['quantity'] += item.quantity
            group['stock_value'] += item.quantity * item.unit_price
        return [dict(group, stock_value=format(group['stock_value'], '.2f'))
                for category in sorted(groups)
                for group in [groups[category]]]

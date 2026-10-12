from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    selected = [item for item in items if item.quantity >= min_quantity]
    if not selected:
        return []

    # Allow every product and sum to retain all significant decimal digits.
    lowest_exponent = min(item.unit_price.as_tuple().exponent for item in selected)
    highest_digit = max(item.unit_price.adjusted() + len(str(item.quantity))
                        for item in selected)
    with localcontext() as context:
        context.prec = max(28, highest_digit - lowest_exponent
                           + len(str(len(selected))) + 2)
        groups = {}
        for item in selected:
            group = groups.setdefault(item.category, {
                'quantity': 0, 'stock_value': Decimal(0)})
            group['quantity'] += item.quantity
            group['stock_value'] += item.quantity * item.unit_price
        return [{'category': category,
                 'quantity': groups[category]['quantity'],
                 'stock_value': format(groups[category]['stock_value'], '.2f')}
                for category in sorted(groups)]

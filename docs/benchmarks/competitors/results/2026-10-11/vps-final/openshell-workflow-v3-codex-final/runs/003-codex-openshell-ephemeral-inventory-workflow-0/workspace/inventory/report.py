from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    filtered = [item for item in items if item.quantity >= min_quantity]
    if not filtered:
        return []

    # Preserve all product and sum digits beyond Decimal's default precision.
    lowest_exponent = min(item.unit_price.as_tuple().exponent for item in filtered)
    highest_place = max(item.unit_price.adjusted() + len(str(item.quantity))
                        for item in filtered)
    with localcontext() as context:
        context.prec = max(28, highest_place - lowest_exponent
                           + len(str(len(filtered))) + 2)
        groups = {}
        for item in filtered:
            group = groups.setdefault(item.category, {
                'category': item.category, 'quantity': 0,
                'stock_value': Decimal(0),
            })
            group['quantity'] += item.quantity
            group['stock_value'] += item.quantity * item.unit_price
        return [dict(group, stock_value=format(group['stock_value'], '.2f'))
                for category, group in sorted(groups.items())]

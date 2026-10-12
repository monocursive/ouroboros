from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Allow enough precision for exact products and sums, even for large prices
    # or quantities and prices with very different decimal scales.
    lowest_exponent = min(0, *(item.unit_price.as_tuple().exponent for item in items))
    highest_place = max(
        item.unit_price.adjusted() + len(str(item.quantity)) for item in items
    )
    with localcontext() as context:
        context.prec = max(28, highest_place - lowest_exponent + len(str(len(items))) + 3)
        categories = {}
        for item in items:
            quantity, value = categories.get(item.category, (0, Decimal(0)))
            categories[item.category] = (
                quantity + item.quantity,
                value + item.quantity * item.unit_price,
            )
        return [
            {'category': category, 'quantity': quantity, 'stock_value': format(value, '.2f')}
            for category, (quantity, value) in sorted(categories.items())
        ]

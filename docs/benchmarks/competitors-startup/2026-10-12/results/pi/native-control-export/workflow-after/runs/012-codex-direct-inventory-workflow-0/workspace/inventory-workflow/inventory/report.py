from decimal import Decimal, localcontext


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    if not items:
        return []

    # Allow every product and sum to retain all digits, even for prices and
    # quantities exceeding the default Decimal context's precision.
    fractional_digits = max(0, -min(x.unit_price.as_tuple().exponent for x in items))
    integer_digits = max(x.unit_price.adjusted() + len(str(x.quantity)) + 1
                         for x in items)
    with localcontext() as context:
        context.prec = max(28, integer_digits + fractional_digits + len(str(len(items))))
        categories = {}
        for item in items:
            summary = categories.setdefault(item.category, {
                'category': item.category, 'quantity': 0, 'stock_value': Decimal(0)})
            summary['quantity'] += item.quantity
            summary['stock_value'] += item.quantity * item.unit_price
        return [dict(categories[category],
                     stock_value=format(categories[category]['stock_value'], '.2f'))
                for category in sorted(categories)]

from decimal import Decimal, localcontext


def category_report(items, min_quantity=0):
    items = [item for item in items if item.quantity >= min_quantity]
    # Allow every significant digit of the products and their sum, even when
    # prices exceed the default Decimal context precision.
    lowest_exponent = min((x.unit_price.as_tuple().exponent for x in items), default=0)
    highest_digit = max((x.unit_price.adjusted() + len(str(x.quantity))
                         for x in items), default=0)
    with localcontext() as context:
        context.prec = max(28, highest_digit - lowest_exponent + len(str(len(items))) + 3)
        groups = {}
        for item in items:
            quantity, value = groups.get(item.category, (0, Decimal(0)))
            groups[item.category] = (quantity + item.quantity,
                                     value + item.quantity * item.unit_price)
        return [{'category': category, 'quantity': quantity,
                 'stock_value': format(value, '.2f')}
                for category, (quantity, value) in sorted(groups.items())]


def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

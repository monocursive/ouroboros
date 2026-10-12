from decimal import Decimal
from collections import defaultdict


def group_by_category(items):
    """Group items by category and calculate totals.
    
    Returns a list of dicts sorted by category, each containing:
    - category: string
    - quantity: sum of quantities (int)
    - stock_value: sum of quantity * unit_price as decimal string with 2 fractional digits
    """
    groups = defaultdict(lambda: {'quantity': 0, 'value': Decimal('0')})
    
    for item in items:
        groups[item.category]['quantity'] += item.quantity
        groups[item.category]['value'] += item.quantity * item.unit_price
    
    result = []
    for category in sorted(groups.keys()):
        result.append({
            'category': category,
            'quantity': groups[category]['quantity'],
            'stock_value': format(groups[category]['value'], '.2f')
        })
    
    return result

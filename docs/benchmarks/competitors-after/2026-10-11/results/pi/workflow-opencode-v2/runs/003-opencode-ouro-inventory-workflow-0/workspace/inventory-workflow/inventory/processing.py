from decimal import Decimal
from collections import defaultdict


def group_by_category(items):
    """Group items by category, summing quantities and stock values.
    
    Returns a list of dicts sorted by category, each containing:
    - category: string
    - quantity: sum of quantities (int)
    - stock_value: sum of quantity * unit_price formatted as string with 2 decimal places
    """
    groups = defaultdict(lambda: {'quantity': 0, 'stock_value': Decimal('0')})
    
    for item in items:
        groups[item.category]['quantity'] += item.quantity
        groups[item.category]['stock_value'] += item.quantity * item.unit_price
    
    result = []
    for category in sorted(groups.keys()):
        result.append({
            'category': category,
            'quantity': groups[category]['quantity'],
            'stock_value': format(groups[category]['stock_value'], '.2f')
        })
    
    return result

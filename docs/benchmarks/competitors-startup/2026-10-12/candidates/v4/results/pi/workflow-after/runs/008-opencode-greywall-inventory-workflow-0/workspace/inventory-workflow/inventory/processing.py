from decimal import Decimal
from collections import defaultdict


def category_summary(items, min_quantity=0):
    """
    Groups items by category after applying min_quantity filter.
    Returns a JSON array sorted by category, where each object has:
    - category (string)
    - quantity (sum of quantities)
    - stock_value (sum of quantity * unit_price as exact decimal with two fractional digits, as string)
    """
    # Apply min_quantity filter first
    filtered = [item for item in items if item.quantity >= min_quantity]
    
    # Group by category
    groups = defaultdict(lambda: {'quantity': 0, 'stock_value': Decimal('0')})
    
    for item in filtered:
        groups[item.category]['quantity'] += item.quantity
        groups[item.category]['stock_value'] += item.quantity * item.unit_price
    
    # Build result sorted by category
    result = []
    for category in sorted(groups.keys()):
        result.append({
            'category': category,
            'quantity': groups[category]['quantity'],
            'stock_value': format(groups[category]['stock_value'], '.2f')
        })
    
    return result

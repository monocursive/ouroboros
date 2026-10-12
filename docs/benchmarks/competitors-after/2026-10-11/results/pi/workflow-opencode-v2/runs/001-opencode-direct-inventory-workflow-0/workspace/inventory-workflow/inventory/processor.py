from decimal import Decimal
from collections import defaultdict

def category_summary(items, min_quantity=0):
    """Group items by category and compute summary statistics.
    
    Args:
        items: List of Item objects
        min_quantity: Minimum quantity filter applied before grouping
    
    Returns:
        List of dicts with category, quantity, and stock_value, sorted by category
    """
    # Filter items by min_quantity first
    filtered = [item for item in items if item.quantity >= min_quantity]
    
    # Group by category
    groups = defaultdict(lambda: {'quantity': 0, 'stock_value': Decimal('0')})
    for item in filtered:
        groups[item.category]['quantity'] += item.quantity
        groups[item.category]['stock_value'] += item.quantity * item.unit_price
    
    # Build result list sorted by category
    result = []
    for category in sorted(groups.keys()):
        data = groups[category]
        result.append({
            'category': category,
            'quantity': data['quantity'],
            'stock_value': f"{data['stock_value']:.2f}"
        })
    
    return result

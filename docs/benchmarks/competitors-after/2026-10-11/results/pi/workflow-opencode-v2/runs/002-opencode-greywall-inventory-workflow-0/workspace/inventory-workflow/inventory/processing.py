from decimal import Decimal
from collections import defaultdict


def group_by_category(items, min_quantity=0):
    """
    Group items by category and calculate totals.
    
    Args:
        items: List of Item objects
        min_quantity: Minimum quantity filter (applied before grouping)
    
    Returns:
        List of dicts with category, quantity (sum), and stock_value (formatted string)
        sorted by category name
    """
    # Filter by min_quantity first
    filtered = [item for item in items if item.quantity >= min_quantity]
    
    # Group by category
    categories = defaultdict(lambda: {'quantity': 0, 'stock_value': Decimal('0')})
    
    for item in filtered:
        cat = categories[item.category]
        cat['quantity'] += item.quantity
        cat['stock_value'] += item.quantity * item.unit_price
    
    # Build result sorted by category
    result = []
    for category in sorted(categories.keys()):
        cat_data = categories[category]
        result.append({
            'category': category,
            'quantity': cat_data['quantity'],
            'stock_value': f"{cat_data['stock_value']:.2f}"
        })
    
    return result

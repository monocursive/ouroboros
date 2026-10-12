from decimal import Decimal
from collections import defaultdict


def group_by_category(items, min_quantity=0):
    """
    Group items by category and calculate totals.
    
    Args:
        items: List of Item objects
        min_quantity: Minimum quantity filter applied before grouping
        
    Returns:
        List of dicts with category, quantity (sum), and stock_value (formatted string)
        sorted by category name
    """
    # Filter items by min_quantity first
    filtered_items = [item for item in items if item.quantity >= min_quantity]
    
    # Group by category
    category_data = defaultdict(lambda: {'quantity': 0, 'stock_value': Decimal('0')})
    
    for item in filtered_items:
        category_data[item.category]['quantity'] += item.quantity
        category_data[item.category]['stock_value'] += item.quantity * item.unit_price
    
    # Build result sorted by category
    result = []
    for category in sorted(category_data.keys()):
        data = category_data[category]
        result.append({
            'category': category,
            'quantity': data['quantity'],
            'stock_value': format(data['stock_value'], '.2f')
        })
    
    return result

from decimal import Decimal

def group_by_category(items):
    """Group items by category and compute aggregates.
    
    Returns a list of dicts sorted by category, each with:
    - category: string
    - quantity: sum of item quantities
    - stock_value: sum of (quantity * unit_price) as a decimal string with 2 fractional digits
    """
    categories = {}
    for item in items:
        if item.category not in categories:
            categories[item.category] = {
                'quantity': 0,
                'stock_value': Decimal('0')
            }
        categories[item.category]['quantity'] += item.quantity
        categories[item.category]['stock_value'] += item.quantity * item.unit_price
    
    result = []
    for category in sorted(categories.keys()):
        result.append({
            'category': category,
            'quantity': categories[category]['quantity'],
            'stock_value': f"{categories[category]['stock_value']:.2f}"
        })
    
    return result

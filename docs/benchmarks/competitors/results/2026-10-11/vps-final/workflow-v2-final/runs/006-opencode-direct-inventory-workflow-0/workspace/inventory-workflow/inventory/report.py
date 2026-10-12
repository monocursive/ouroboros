from decimal import Decimal

def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_summary(items, min_quantity=0):
    """Group items by category and compute summaries.
    
    Args:
        items: List of Item objects
        min_quantity: Filter items by minimum quantity before grouping
        
    Returns:
        List of dicts with category, quantity, and stock_value, sorted by category
    """
    # Filter items by min_quantity first
    filtered = [item for item in items if item.quantity >= min_quantity]
    
    # Group by category
    groups = {}
    for item in filtered:
        if item.category not in groups:
            groups[item.category] = {'total_quantity': 0, 'total_value': Decimal('0')}
        groups[item.category]['total_quantity'] += item.quantity
        groups[item.category]['total_value'] += item.quantity * item.unit_price
    
    # Build result list sorted by category
    result = []
    for category in sorted(groups.keys()):
        result.append({
            'category': category,
            'quantity': groups[category]['total_quantity'],
            'stock_value': f"{groups[category]['total_value']:.2f}"
        })
    
    return result

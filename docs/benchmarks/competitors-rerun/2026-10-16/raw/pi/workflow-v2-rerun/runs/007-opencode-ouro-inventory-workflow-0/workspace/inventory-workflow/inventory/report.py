def item_report(items, min_quantity=0):
    return [{'sku': x.sku, 'category': x.category, 'quantity': x.quantity,
             'unit_price': str(x.unit_price)}
            for x in items if x.quantity >= min_quantity]

def category_report(items, min_quantity=0):
    # Filter items by min_quantity first
    filtered_items = [x for x in items if x.quantity >= min_quantity]
    
    # Group by category
    category_groups = {}
    for item in filtered_items:
        if item.category not in category_groups:
            category_groups[item.category] = []
        category_groups[item.category].append(item)
    
    # Calculate summary for each category
    result = []
    for category, category_items in category_groups.items():
        total_quantity = sum(item.quantity for item in category_items)
        total_value = sum(item.quantity * item.unit_price for item in category_items)
        result.append({
            'category': category,
            'quantity': total_quantity,
            'stock_value': f'{total_value:.2f}'
        })
    
    # Sort by category name
    result.sort(key=lambda x: x['category'])
    
    return result

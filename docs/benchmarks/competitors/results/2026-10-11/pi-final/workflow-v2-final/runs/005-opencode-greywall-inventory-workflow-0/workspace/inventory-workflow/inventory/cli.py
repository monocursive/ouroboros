import argparse
import json
import sys
from .loader import load_items
from .report import item_report
from .processing import group_by_category

def main(argv=None):
    parser = argparse.ArgumentParser(description='Report inventory from CSV')
    parser.add_argument('csv_file')
    parser.add_argument('--min-quantity', type=int, default=0)
    parser.add_argument('--group-by-category', action='store_true')
    args = parser.parse_args(argv)
    try:
        items = load_items(args.csv_file)
        # Filter by min_quantity first
        filtered_items = [item for item in items if item.quantity >= args.min_quantity]
        
        if args.group_by_category:
            result = group_by_category(filtered_items)
        else:
            result = item_report(filtered_items, min_quantity=0)
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0

if __name__ == '__main__':
    sys.exit(main())

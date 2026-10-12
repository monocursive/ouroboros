import argparse
import json
import sys
from .loader import load_items
from .report import item_report
from .processor import category_summary

def main(argv=None):
    parser = argparse.ArgumentParser(description='Report inventory from CSV')
    parser.add_argument('csv_file')
    parser.add_argument('--min-quantity', type=int, default=0)
    parser.add_argument('--group-by-category', action='store_true')
    args = parser.parse_args(argv)
    try:
        items = load_items(args.csv_file)
        if args.group_by_category:
            result = category_summary(items, args.min_quantity)
        else:
            result = item_report(items, args.min_quantity)
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0

if __name__ == '__main__':
    sys.exit(main())

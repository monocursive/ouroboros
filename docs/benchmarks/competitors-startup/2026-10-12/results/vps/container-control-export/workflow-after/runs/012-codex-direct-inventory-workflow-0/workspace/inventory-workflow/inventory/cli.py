import argparse
import csv
import json
import sys
from .loader import load_items
from .report import category_report, item_report

def main(argv=None):
    parser = argparse.ArgumentParser(description='Report inventory from CSV')
    parser.add_argument('csv_file')
    parser.add_argument('--min-quantity', type=int, default=0)
    parser.add_argument('--group-by-category', action='store_true')
    args = parser.parse_args(argv)
    try:
        items = load_items(args.csv_file)
        report = category_report if args.group_by_category else item_report
        result = report(items, args.min_quantity)
    except (ValueError, OSError, csv.Error) as exc:
        print(f'Unable to report inventory: {exc}', file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0

if __name__ == '__main__':
    sys.exit(main())

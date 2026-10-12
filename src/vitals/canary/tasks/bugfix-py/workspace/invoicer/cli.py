"""Command-line entry point: read line items from a JSON file and print a formatted invoice.

Expected JSON shape: {"rate_bp": 825, "items": [{"description": "...", "quantity": 1,
"unit_price_cents": 100}, ...]}
"""

from __future__ import annotations

import json
import sys

from invoicer.io import format_invoice
from invoicer.models import LineItem


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: cli.py INVOICE.json", file=sys.stderr)
        return 2
    data = json.loads(open(argv[0], encoding="utf-8").read())
    items = [LineItem(**item) for item in data["items"]]
    print(format_invoice(items, data["rate_bp"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

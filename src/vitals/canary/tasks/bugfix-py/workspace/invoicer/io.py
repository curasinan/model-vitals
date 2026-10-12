"""Plain-text rendering of an invoice."""

from __future__ import annotations

from invoicer.models import LineItem
from invoicer.totals import grand_total_cents, subtotal_cents, tax_cents


def _format_cents(cents: int) -> str:
    sign = "-" if cents < 0 else ""
    cents = abs(cents)
    return f"{sign}{cents // 100}.{cents % 100:02d}"


def format_invoice(items: list[LineItem], rate_bp: int) -> str:
    lines = []
    for item in items:
        lines.append(
            f"{item.description:<20}{item.quantity:>4} x "
            f"{_format_cents(item.unit_price_cents):>8} = "
            f"{_format_cents(item.line_total_cents()):>8}"
        )
    sub = subtotal_cents(items)
    lines.append(f"{'Subtotal':<20}{'':>4}   {'':>8}   {_format_cents(sub):>8}")
    lines.append(f"{'Tax':<20}{'':>4}   {'':>8}   {_format_cents(tax_cents(sub, rate_bp)):>8}")
    lines.append(f"{'Total':<20}{'':>4}   {'':>8}   {_format_cents(grand_total_cents(items, rate_bp)):>8}")
    return "\n".join(lines)

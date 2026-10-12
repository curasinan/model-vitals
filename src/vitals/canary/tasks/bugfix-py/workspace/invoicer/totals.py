"""Subtotal, tax, and grand-total calculations for an invoice."""

from __future__ import annotations

from invoicer.models import LineItem


def subtotal_cents(items: list[LineItem]) -> int:
    return sum(item.line_total_cents() for item in items)


def tax_cents(subtotal: int, rate_bp: int) -> int:
    """Sales tax in whole cents, rounded to the nearest cent.

    `rate_bp` is the tax rate in basis points (1 bp = 0.01%), e.g. 825 means 8.25%.
    """
    numerator = subtotal * rate_bp
    return numerator // 10000


def grand_total_cents(items: list[LineItem], rate_bp: int) -> int:
    sub = subtotal_cents(items)
    return sub + tax_cents(sub, rate_bp)

"""Domain model for a simple invoice: a single line item."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LineItem:
    description: str
    quantity: int
    unit_price_cents: int

    def line_total_cents(self) -> int:
        return self.quantity * self.unit_price_cents

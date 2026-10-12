from invoicer.models import LineItem
from invoicer.totals import subtotal_cents, tax_cents

RATE_BP = 825  # 8.25% combined state + local sales tax


def test_subtotal_sums_line_totals():
    items = [LineItem("Widget", 3, 250), LineItem("Gadget", 2, 900)]
    assert subtotal_cents(items) == 3 * 250 + 2 * 900


def test_tax_cents_exact_no_rounding_needed():
    # 1600 * 825 / 10000 = 132.0 exactly.
    assert tax_cents(1600, RATE_BP) == 132


def test_tax_cents_rounds_down_small_fraction():
    # 500 * 825 / 10000 = 41.25 -> rounds down to 41.
    assert tax_cents(500, RATE_BP) == 41


def test_tax_cents_rounds_down_quarter_fraction():
    # 1300 * 825 / 10000 = 107.25 -> rounds down to 107.
    assert tax_cents(1300, RATE_BP) == 107


def test_tax_cents_rounds_down_larger_fraction():
    # 3399 * 825 / 10000 = 280.4175 -> rounds down to 280.
    assert tax_cents(3399, RATE_BP) == 280


def test_tax_cents_rounds_up_at_half_cent_boundary():
    # 1210 * 825 / 10000 = 99.825 -> rounds UP to 100 cents.
    assert tax_cents(1210, RATE_BP) == 100

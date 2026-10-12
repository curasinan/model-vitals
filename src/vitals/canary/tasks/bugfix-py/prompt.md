The `invoicer` package in this workspace has a failing test. Run the test suite to see it
(`python -m pytest -q`): `test_tax_cents_rounds_up_at_half_cent_boundary` in
`tests/test_totals.py` currently fails.

The bug is in `invoicer/totals.py`, in the `tax_cents` function, which computes sales tax
(in whole cents) from a subtotal (in cents) and a tax rate expressed in basis points
(1 basis point = 0.01%; e.g. 825 means 8.25%). The tax amount should be rounded to the
nearest whole cent, rounding a half-cent up — but the current code always rounds down
(truncates), which is why the boundary case in the failing test is off by one cent.

Fix the bug in `invoicer/totals.py` so that every test in `tests/test_totals.py` passes.

Rules:
- Only edit `invoicer/totals.py`. Do not modify any other file in the workspace.
- Do not change any test file.
- Do not add new files.

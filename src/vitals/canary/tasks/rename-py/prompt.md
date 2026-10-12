The `geo` package defines a function `haversine_km` for great-circle distance between two
latitude/longitude points, in `geo/distance.py`. It is also called from `geo/routes.py` and
`geo/cli.py`.

Rename `haversine_km` to `great_circle_km` everywhere it is defined or referenced — in
`geo/distance.py`, `geo/routes.py`, and `geo/cli.py` — including in any comments or
docstrings that mention the old name. Do not change what the function does, only its name.

The test suite in `tests/` already calls it by the new name, so it currently fails to even
collect. After the rename, run `python -m pytest -q` and make sure every test passes.

Do not rename anything else, and do not add new files.

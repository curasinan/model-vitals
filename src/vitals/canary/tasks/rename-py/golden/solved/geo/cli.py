"""Command-line entry point: print the great_circle_km distance between two coordinates."""

from __future__ import annotations

import sys

from geo.distance import great_circle_km


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("usage: cli.py LAT1 LON1 LAT2 LON2", file=sys.stderr)
        return 2
    lat1, lon1, lat2, lon2 = (float(a) for a in argv)
    print(f"{great_circle_km(lat1, lon1, lat2, lon2):.3f} km")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

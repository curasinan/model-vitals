"""Print a small, fully deterministic report table to stdout.

No wall-clock, no dict iteration, no locale-dependent formatting: the row list is a fixed
literal in source order, so this prints byte-identical output on every run and every
machine.
"""

from __future__ import annotations

_ROWS = [
    ("alpha", 1, 1),
    ("bravo", 2, 4),
    ("charlie", 3, 9),
    ("delta", 4, 16),
    ("echo", 5, 25),
]


def main() -> None:
    print(f"{'name':<10}{'rank':>6}{'square':>8}")
    for name, rank, square in _ROWS:
        print(f"{name:<10}{rank:>6}{square:>8}")


if __name__ == "__main__":
    main()

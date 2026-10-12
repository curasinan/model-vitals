from __future__ import annotations

__all__ = ["ewma_update", "update"]


def update(pos: float, neg: float, z: float, k: float, h: float) -> tuple[float, float, bool]:
    pos = max(0.0, pos + z - k)
    neg = max(0.0, neg - z - k)
    return pos, neg, bool(pos > h or neg > h)


def ewma_update(previous: float | None, value: float, lam: float) -> float:
    if previous is None:
        return float(value)
    return lam * float(value) + (1.0 - lam) * float(previous)

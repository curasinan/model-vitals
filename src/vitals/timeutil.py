from __future__ import annotations

from datetime import UTC, datetime, timedelta

ISO_FMT = "%Y-%m-%dT%H:%M:%S%z"


def utcnow_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def epoch_to_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat(timespec="seconds")


def parse_iso(iso: str) -> datetime:
    s = iso.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def hour_floor(iso: str) -> str:
    dt = parse_iso(iso).replace(minute=0, second=0, microsecond=0)
    return dt.isoformat(timespec="seconds")


def hour_add(iso: str, hours: int) -> str:
    return (parse_iso(iso) + timedelta(hours=hours)).isoformat(timespec="seconds")


def days_ago_iso(days: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).isoformat(timespec="seconds")


def local_day(iso: str | None = None) -> str:
    dt = parse_iso(iso) if iso else datetime.now(UTC)
    return dt.astimezone().strftime("%Y-%m-%d")

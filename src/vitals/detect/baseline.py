from __future__ import annotations

import math
import sqlite3
from datetime import timedelta
from typing import Any

from vitals.config import DetectCfg
from vitals.detect import signal_ids as sid
from vitals.detect.signals import percentile
from vitals.timeutil import parse_iso
from vitals.watch.status_poller import DEFAULT_PREFIXES

__all__ = ["ANY_VERSION", "collapsed_baseline", "compute_for", "robust", "window_series"]

ANY_VERSION = "any"

FALSE_POSITIVE = "false_positive"
AUTO_FALSE_POSITIVE = "auto_false_positive"
FOLDED_BACK = (FALSE_POSITIVE, AUTO_FALSE_POSITIVE)

_Span = tuple[float, float]


def _epoch(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        return parse_iso(iso).timestamp()
    except ValueError:
        return None


def _minus_days(iso: str, days: float) -> str:
    return (parse_iso(iso) - timedelta(days=days)).isoformat(timespec="seconds")


def robust(values: list[float]) -> tuple[float | None, float | None]:
    if not values:
        return None, None
    mu = percentile(values, 0.5)
    mad = percentile([abs(v - mu) for v in values], 0.5)
    iqr = percentile(values, 0.75) - percentile(values, 0.25)
    sigma = max(1.4826 * mad, iqr / 1.349, 0.05 * abs(mu))
    if sigma <= 0.0:
        return float(mu), None
    return float(mu), float(max(sigma, 1e-9))


def pooled_rate(events: float, samples: int) -> tuple[float, float]:
    if samples <= 0:
        return 0.0, 0.0
    floor = 0.5 / samples
    p0 = min(max(events / samples, floor), 1.0 - floor)
    return p0, math.sqrt(p0 * (1.0 - p0))


def _incident_spans(conn: sqlite3.Connection) -> list[_Span]:
    spans: list[_Span] = []
    for row in conn.execute("SELECT created_at, resolved_at, components FROM incidents"):
        components = (row["components"] or "").split(",")
        if not any(c.startswith(p) for c in components for p in DEFAULT_PREFIXES):
            continue
        start = _epoch(row["created_at"])
        if start is None:
            continue
        spans.append((start, _epoch(row["resolved_at"]) or math.inf))
    return spans


def _anomaly_spans(
    conn: sqlite3.Connection, signal: str, model: str, bucket: str, cc_version: str
) -> list[_Span]:
    sql = (
        "SELECT started_at, ended_at FROM anomalies WHERE signal=? AND model=? AND"
        " context_bucket=? AND status NOT IN (?, ?)"
    )
    params: list[Any] = [signal, model, bucket, *FOLDED_BACK]
    if cc_version != ANY_VERSION:
        sql += " AND cc_version = ?"
        params.append(cc_version)
    spans: list[_Span] = []
    for row in conn.execute(sql, params):
        start = _epoch(row["started_at"])
        if start is None:
            continue
        spans.append((start, _epoch(row["ended_at"]) or math.inf))
    return spans


def _healthy_from(
    conn: sqlite3.Connection, signal: str, model: str, bucket: str, cc_version: str
) -> float | None:
    row = conn.execute(
        "SELECT healthy_from FROM detector_state WHERE signal=? AND model=? AND"
        " context_bucket=? AND cc_version=?",
        (signal, model, bucket, cc_version),
    ).fetchone()
    return _epoch(row["healthy_from"]) if row else None


def window_series(
    conn: sqlite3.Connection,
    signal: str,
    model: str,
    bucket: str,
    cc_version: str,
    before_iso: str,
    since_iso: str | None = None,
    after_iso: str | None = None,
) -> list[sqlite3.Row]:
    if cc_version == ANY_VERSION:
        sql = (
            "SELECT window_start, SUM(value * n) / SUM(n) AS value, SUM(n) AS n FROM signal_windows"
        )
    else:
        sql = "SELECT window_start, value, n FROM signal_windows"
    sql += " WHERE signal=? AND model=? AND context_bucket=? AND window_start < ?"
    params: list[Any] = [signal, model, bucket, before_iso]
    if since_iso is not None:
        sql += " AND window_start >= ?"
        params.append(since_iso)
    if after_iso is not None:
        sql += " AND window_start > ?"
        params.append(after_iso)
    if cc_version != ANY_VERSION:
        sql += " AND cc_version = ?"
        params.append(cc_version)
    if cc_version == ANY_VERSION:
        sql += " GROUP BY window_start"
    return conn.execute(sql + " ORDER BY window_start", params).fetchall()


def _summarise(rows: list[sqlite3.Row], is_rate: bool) -> dict:
    samples = sum(int(r["n"]) for r in rows)
    if is_rate:
        events = sum(float(r["value"]) * int(r["n"]) for r in rows)
        mu0, sigma0 = pooled_rate(events, samples)
    else:
        mu0, sigma0 = robust([float(r["value"]) for r in rows])
    return {
        "mu0": mu0,
        "sigma0": sigma0,
        "n_windows": len(rows),
        "n_samples": samples,
        "start": rows[0]["window_start"],
        "end": rows[-1]["window_start"],
        "inherited_from": None,
        "is_rate": is_rate,
    }


def _own(
    conn: sqlite3.Connection,
    cfg: DetectCfg,
    signal: str,
    model: str,
    bucket: str,
    cc_version: str,
    now_iso: str,
    floor: float | None,
) -> dict | None:
    is_rate = signal in sid.RATE_SIGNALS
    excluded = _anomaly_spans(conn, signal, model, bucket, cc_version) + _incident_spans(conn)

    lookbacks = [cfg.baseline_days]
    if cfg.baseline_max_days > cfg.baseline_days:
        lookbacks.append(cfg.baseline_max_days)

    for days in lookbacks:
        rows = window_series(
            conn,
            signal,
            model,
            bucket,
            cc_version,
            now_iso,
            since_iso=_minus_days(now_iso, days),
        )
        healthy = []
        for row in rows:
            at = _epoch(row["window_start"])
            if at is None or (floor is not None and at < floor):
                continue
            if any(lo <= at <= hi for lo, hi in excluded):
                continue
            healthy.append(row)
        if len(healthy) >= cfg.min_windows and sum(int(r["n"]) for r in healthy) >= cfg.min_samples:
            return _summarise(healthy, is_rate)
    return None


def _ancestor(
    conn: sqlite3.Connection,
    signal: str,
    model: str,
    bucket: str,
    cc_version: str,
    now_iso: str,
    floor: float | None,
) -> dict | None:
    now = _epoch(now_iso) or math.inf
    for row in conn.execute(
        "SELECT cc_version, mu0, sigma0, baseline_n, baseline_samples, baseline_start,"
        " baseline_end FROM detector_state WHERE signal=? AND model=? AND context_bucket=?"
        " AND cc_version NOT IN (?, ?) AND mu0 IS NOT NULL AND baseline_inherited_from IS NULL"
        " AND baseline_end IS NOT NULL ORDER BY baseline_end DESC",
        (signal, model, bucket, cc_version, ANY_VERSION),
    ):
        end = _epoch(row["baseline_end"])
        if end is not None and end >= now:
            continue
        if floor is not None and (end is None or end < floor):
            continue
        return {
            "mu0": row["mu0"],
            "sigma0": row["sigma0"],
            "n_windows": row["baseline_n"],
            "n_samples": row["baseline_samples"],
            "start": row["baseline_start"],
            "end": row["baseline_end"],
            "inherited_from": row["cc_version"],
            "is_rate": signal in sid.RATE_SIGNALS,
        }
    return None


def compute_for(
    conn: sqlite3.Connection,
    cfg: DetectCfg,
    signal: str,
    model: str,
    bucket: str,
    cc_version: str,
    now_iso: str,
    *,
    own_only: bool = False,
) -> dict | None:
    floor = _healthy_from(conn, signal, model, bucket, cc_version)
    own = _own(conn, cfg, signal, model, bucket, cc_version, now_iso, floor)
    if own is not None:
        return own
    if own_only or cc_version == ANY_VERSION:
        return None

    ancestor = _ancestor(conn, signal, model, bucket, cc_version, now_iso, floor)
    if ancestor is not None:
        return ancestor
    return collapsed_baseline(conn, cfg, signal, model, bucket, now_iso, floor)


def collapsed_baseline(
    conn: sqlite3.Connection,
    cfg: DetectCfg,
    signal: str,
    model: str,
    bucket: str,
    now_iso: str,
    floor: float | None = None,
) -> dict | None:
    row = conn.execute(
        "SELECT mu0, sigma0, baseline_n, baseline_samples, baseline_start, baseline_end"
        " FROM detector_state WHERE signal=? AND model=? AND context_bucket=? AND cc_version=?"
        " AND mu0 IS NOT NULL",
        (signal, model, bucket, ANY_VERSION),
    ).fetchone()
    if row is not None:
        end = _epoch(row["baseline_end"])
        now = _epoch(now_iso)
        fresh_enough = floor is None or (end is not None and end >= floor)
        not_future = end is None or now is None or end < now
        if fresh_enough and not_future:
            return {
                "mu0": row["mu0"],
                "sigma0": row["sigma0"],
                "n_windows": row["baseline_n"],
                "n_samples": row["baseline_samples"],
                "start": row["baseline_start"],
                "end": row["baseline_end"],
                "inherited_from": ANY_VERSION,
                "is_rate": signal in sid.RATE_SIGNALS,
            }

    collapsed = _own(conn, cfg, signal, model, bucket, ANY_VERSION, now_iso, floor)
    if collapsed is not None:
        collapsed["inherited_from"] = ANY_VERSION
    return collapsed

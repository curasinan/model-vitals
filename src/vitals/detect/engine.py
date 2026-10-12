from __future__ import annotations

import json
import math
import sqlite3
from datetime import datetime, timedelta

from vitals.config import DetectCfg
from vitals.db import kv_get, kv_set, log_ingest
from vitals.detect import signal_ids as sid
from vitals.detect.baseline import (
    ANY_VERSION,
    AUTO_FALSE_POSITIVE,
    compute_for,
    robust,
    window_series,
)
from vitals.detect.cusum import ewma_update, update
from vitals.timeutil import parse_iso, utcnow_iso

__all__ = ["CANARY_MIN_CYCLES", "CANARY_SUITE_CP_KEY", "CLOSE_WINDOWS", "resolve", "tick"]

CANARY_SUITE_CP_KEY = "detector_canary_suite_cp"

CLOSE_WINDOWS = 6

RATE_MIN_EVENTS = 5
RATE_MIN_N = 10
RATE_OBSERVED_ARM_MAX_EXPECTED = 1.0

CANARY_MIN_CYCLES = 5

PROMOTION_EVERY = 24

_STATE_COLUMNS = (
    "mu0",
    "sigma0",
    "baseline_start",
    "baseline_end",
    "baseline_n",
    "baseline_samples",
    "baseline_inherited_from",
    "ewma",
    "cusum_pos",
    "cusum_neg",
    "in_alarm",
    "frozen",
    "last_window",
    "below_count",
    "open_anomaly_id",
    "healthy_from",
    "k_count",
    "last_cycle_id",
    "windows_evaluated",
)


def _load_state(
    conn: sqlite3.Connection, signal: str, model: str, bucket: str, version: str
) -> dict:
    conn.execute(
        "INSERT OR IGNORE INTO detector_state(signal, model, context_bucket, cc_version)"
        " VALUES (?,?,?,?)",
        (signal, model, bucket, version),
    )
    row = conn.execute(
        "SELECT * FROM detector_state WHERE signal=? AND model=? AND context_bucket=?"
        " AND cc_version=?",
        (signal, model, bucket, version),
    ).fetchone()
    return dict(row)


def _save_state(conn: sqlite3.Connection, state: dict) -> None:
    assignments = ", ".join(f"{c} = ?" for c in _STATE_COLUMNS)
    conn.execute(
        f"UPDATE detector_state SET {assignments} WHERE signal=? AND model=? AND"  # noqa: S608
        " context_bucket=? AND cc_version=?",
        [state[c] for c in _STATE_COLUMNS]
        + [state["signal"], state["model"], state["context_bucket"], state["cc_version"]],
    )


def _apply_baseline(state: dict, base: dict | None) -> None:
    state["mu0"] = base["mu0"] if base else None
    state["sigma0"] = base["sigma0"] if base else None
    state["baseline_start"] = base["start"] if base else None
    state["baseline_end"] = base["end"] if base else None
    state["baseline_n"] = base["n_windows"] if base else None
    state["baseline_samples"] = base["n_samples"] if base else None
    state["baseline_inherited_from"] = base["inherited_from"] if base else None


def _open_anomaly(
    conn: sqlite3.Connection,
    state: dict,
    at_iso: str,
    direction: str,
    stat: float,
    raw_z: float | None = None,
) -> int:
    cursor = conn.execute(
        "INSERT INTO anomalies(signal, model, context_bucket, cc_version, started_at,"
        " direction, peak_stat, peak_z, status) VALUES (?,?,?,?,?,?,?,?,'open')",
        (
            state["signal"],
            state["model"],
            state["context_bucket"],
            state["cc_version"],
            at_iso,
            direction,
            stat,
            abs(raw_z) if raw_z is not None else None,
        ),
    )
    state["in_alarm"] = 1
    state["frozen"] = 1
    state["below_count"] = 0
    state["open_anomaly_id"] = cursor.lastrowid
    return cursor.lastrowid


def _close_anomaly(conn: sqlite3.Connection, state: dict, at_iso: str) -> None:
    if state["open_anomaly_id"] is not None:
        conn.execute(
            "UPDATE anomalies SET ended_at = COALESCE(ended_at, ?) WHERE id = ?",
            (at_iso, state["open_anomaly_id"]),
        )
    state["in_alarm"] = 0
    state["below_count"] = 0
    state["open_anomaly_id"] = None


def _standardize(cfg: DetectCfg, signal: str, state: dict, value: float, n: int) -> float | None:
    mu0, sigma0 = state["mu0"], state["sigma0"]
    if mu0 is None or sigma0 is None:
        return None

    if signal in sid.RATE_SIGNALS:
        if n < RATE_MIN_N:
            return None
        p0 = mu0
        expected, observed = n * p0, n * value
        admissible = expected >= RATE_MIN_EVENTS or (
            expected < RATE_OBSERVED_ARM_MAX_EXPECTED and observed >= RATE_MIN_EVENTS
        )
        if not admissible:
            return None
        sd = math.sqrt(p0 * (1.0 - p0) / n)
        if sd <= 0:
            return None
        z = (value - p0) / sd
    else:
        z = (value - mu0) / sigma0
    return z


def _ensure_baseline(
    conn: sqlite3.Connection, cfg: DetectCfg, state: dict, as_of: str, promote: bool
) -> None:
    if state["frozen"]:
        return
    if state["mu0"] is None:
        base = compute_for(
            conn,
            cfg,
            state["signal"],
            state["model"],
            state["context_bucket"],
            state["cc_version"],
            as_of,
        )
        if base is not None:
            _apply_baseline(state, base)
        return
    if promote and state["baseline_inherited_from"] is not None:
        own = compute_for(
            conn,
            cfg,
            state["signal"],
            state["model"],
            state["context_bucket"],
            state["cc_version"],
            as_of,
            own_only=True,
        )
        if own is not None:
            _apply_baseline(state, own)


def _process_window(
    conn: sqlite3.Connection, cfg: DetectCfg, state: dict, row: sqlite3.Row, opened: list[int]
) -> None:
    raw_z = _standardize(cfg, state["signal"], state, float(row["value"]), int(row["n"]))
    state["last_window"] = row["window_start"]
    if raw_z is None:
        return

    state["windows_evaluated"] = (state["windows_evaluated"] or 0) + 1

    z = max(-cfg.h, min(cfg.h, raw_z))
    pos, neg, alarm = update(state["cusum_pos"], state["cusum_neg"], z, cfg.k, cfg.h)
    state["cusum_pos"], state["cusum_neg"] = pos, neg
    state["ewma"] = ewma_update(state["ewma"], float(row["value"]), cfg.lam)
    stat = max(pos, neg)

    if alarm:
        direction = "up" if pos > cfg.h else "down"
        if not state["in_alarm"]:
            opened.append(_open_anomaly(conn, state, row["window_start"], direction, stat, raw_z))
        else:
            conn.execute(
                "UPDATE anomalies SET peak_stat = MAX(COALESCE(peak_stat, 0), ?),"
                " peak_z = MAX(COALESCE(peak_z, 0), ?) WHERE id = ?",
                (stat, abs(raw_z), state["open_anomaly_id"]),
            )
            state["below_count"] = 0
    elif state["in_alarm"]:
        if stat < cfg.h / 2:
            state["below_count"] += 1
            if state["below_count"] >= CLOSE_WINDOWS:
                _close_anomaly(conn, state, row["window_start"])
        else:
            state["below_count"] = 0


def _pending_strata(conn: sqlite3.Connection, now_iso: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT DISTINCT w.signal, w.model, w.context_bucket, w.cc_version FROM signal_windows w"
        " LEFT JOIN detector_state d ON d.signal = w.signal AND d.model = w.model"
        "   AND d.context_bucket = w.context_bucket AND d.cc_version = w.cc_version"
        " WHERE w.window_start < ? AND (d.last_window IS NULL OR w.window_start > d.last_window)"
        " ORDER BY w.signal, w.model, w.context_bucket, w.cc_version",
        (now_iso,),
    ).fetchall()


def _advance_stratum(
    conn: sqlite3.Connection,
    cfg: DetectCfg,
    signal: str,
    model: str,
    bucket: str,
    version: str,
    now_iso: str,
    opened: list[int],
) -> None:
    state = _load_state(conn, signal, model, bucket, version)
    rows = window_series(
        conn, signal, model, bucket, version, now_iso, after_iso=state["last_window"]
    )
    for index, row in enumerate(rows):
        _ensure_baseline(
            conn, cfg, state, row["window_start"], promote=(index % PROMOTION_EVERY == 0)
        )
        _process_window(conn, cfg, state, row, opened)
    _save_state(conn, state)


def _tick_passive(conn: sqlite3.Connection, cfg: DetectCfg, now_iso: str) -> list[int]:
    opened: list[int] = []
    groups: dict[tuple[str, str, str], list[str]] = {}

    for stratum in _pending_strata(conn, now_iso):
        signal = stratum["signal"]
        if signal not in sid.PASSIVE_SIGNALS or stratum["cc_version"] == ANY_VERSION:
            continue
        key = (signal, stratum["model"], stratum["context_bucket"])
        groups.setdefault(key, []).append(stratum["cc_version"])

    for (signal, model, bucket), versions in sorted(groups.items()):
        _advance_stratum(conn, cfg, signal, model, bucket, ANY_VERSION, now_iso, opened)
        for version in sorted(versions):
            _advance_stratum(conn, cfg, signal, model, bucket, version, now_iso, opened)
    return opened


class _Cycle:
    __slots__ = ("cycle_id", "has_data", "invalid_reason", "model", "rate", "started_at")

    def __init__(self, cycle_id, started_at, model, rate, invalid_reason, has_data):
        self.cycle_id = cycle_id
        self.started_at = started_at
        self.model = model or "unknown"
        self.rate = rate
        self.invalid_reason = invalid_reason
        self.has_data = has_data


def _c1_cycles(conn: sqlite3.Connection, cfg: DetectCfg) -> list[_Cycle]:
    out = []
    for row in conn.execute(
        "SELECT cycle_id, started_at, model, pass_rate, aborted_reason, n_runs, n_invalid"
        " FROM canary_cycles ORDER BY cycle_id"
    ):
        reason = row["aborted_reason"] or (None if row["pass_rate"] is not None else "no-runs")
        n_runs = int(row["n_runs"] or 0)
        valid = n_runs - int(row["n_invalid"] or 0)
        if reason is None and n_runs > 0 and valid < cfg.canary_min_valid_fraction * n_runs:
            reason = f"only {valid} of {n_runs} runs valid"
        out.append(
            _Cycle(
                row["cycle_id"],
                row["started_at"],
                row["model"],
                row["pass_rate"],
                reason,
                row["pass_rate"] is not None and not reason,
            )
        )
    return out


def _c2_cycles(conn: sqlite3.Connection) -> list[_Cycle]:
    out = []
    for row in conn.execute(
        "SELECT c.cycle_id, c.started_at, c.model,"
        "       SUM(COALESCE(r.passed, 0)) AS passes, COUNT(r.run_id) AS total"
        " FROM canary_cycles c LEFT JOIN canary_runs r"
        "   ON r.cycle_id = c.cycle_id AND r.long_context = 1 AND r.invalid = 0"
        "      AND r.passed IS NOT NULL"
        " GROUP BY c.cycle_id, c.started_at, c.model ORDER BY c.cycle_id"
    ):
        total = row["total"] or 0
        out.append(
            _Cycle(
                row["cycle_id"],
                row["started_at"],
                row["model"],
                (row["passes"] / total) if total else None,
                None,
                total > 0,
            )
        )
    return out


def _within_lookback(cfg: DetectCfg, started_at: str, before: str) -> bool:
    try:
        age = (parse_iso(before) - parse_iso(started_at)).total_seconds()
    except ValueError:  # pragma: no cover
        return True
    return 0 <= age <= cfg.baseline_days * 86400


def _canary_baseline(
    cfg: DetectCfg, history: list[_Cycle], current: _Cycle, floor: str | None
) -> dict | None:
    rates = [
        c.rate
        for c in history
        if c.has_data
        and c.cycle_id < current.cycle_id
        and _within_lookback(cfg, c.started_at, current.started_at)
        and (floor is None or c.started_at >= floor)
    ]
    if len(rates) < CANARY_MIN_CYCLES:
        return None
    mu0, sigma0 = robust(rates)
    return {
        "mu0": mu0,
        "sigma0": sigma0,
        "n_windows": len(rates),
        "n_samples": len(rates),
        "start": None,
        "end": current.started_at,
        "inherited_from": None,
    }


def _canary_series(
    conn: sqlite3.Connection, cfg: DetectCfg, signal: str, cycles: list[_Cycle]
) -> list[int]:
    opened: list[int] = []
    models = sorted({c.model for c in cycles})
    for model in models:
        history = [c for c in cycles if c.model == model]
        state = _load_state(conn, signal, model, "all", ANY_VERSION)
        last = state["last_cycle_id"]
        notes: list[str] = []
        for cycle in history:
            if last is not None and cycle.cycle_id <= last:
                continue
            state["last_cycle_id"] = cycle.cycle_id

            if cycle.invalid_reason:
                notes.append(f"{signal} cycle {cycle.cycle_id} invalid: {cycle.invalid_reason}")
                continue
            if not cycle.has_data:
                continue

            if state["mu0"] is None and not state["frozen"]:
                base = _canary_baseline(cfg, history, cycle, state["healthy_from"])
                if base is not None:
                    _apply_baseline(state, base)
            if state["mu0"] is None:
                continue

            state["ewma"] = ewma_update(state["ewma"], cycle.rate, cfg.lam)
            if cycle.rate <= state["mu0"] - cfg.delta:
                state["k_count"] += 1
                if state["k_count"] >= cfg.K_cycles and not state["in_alarm"]:
                    opened.append(
                        _open_anomaly(
                            conn, state, cycle.started_at, "down", state["mu0"] - cycle.rate
                        )
                    )
            else:
                state["k_count"] = 0
                if state["in_alarm"]:
                    _close_anomaly(conn, state, cycle.started_at)
        _save_state(conn, state)
        for note in notes:
            log_ingest(conn, "canary_infra", 0, 1, note)
    return opened


def _apply_suite_change_points(conn: sqlite3.Connection) -> None:
    last = int(kv_get(conn, CANARY_SUITE_CP_KEY) or 0)
    rows = conn.execute(
        "SELECT id, ts FROM change_points WHERE kind = 'canary_suite' AND id > ? ORDER BY id",
        (last,),
    ).fetchall()
    if not rows:
        return
    latest = rows[-1]
    signals = (sid.C1_CANARY_PASS, sid.C2_CANARY_LONGCTX)
    for row in conn.execute(
        "SELECT open_anomaly_id FROM detector_state WHERE signal IN (?,?)"
        " AND open_anomaly_id IS NOT NULL",
        signals,
    ).fetchall():
        conn.execute(
            "UPDATE anomalies SET ended_at = COALESCE(ended_at, ?) WHERE id = ?",
            (latest["ts"], row["open_anomaly_id"]),
        )
    conn.execute(
        "UPDATE detector_state SET mu0=NULL, sigma0=NULL, baseline_start=NULL,"
        " baseline_end=NULL, baseline_n=NULL, baseline_samples=NULL,"
        " baseline_inherited_from=NULL, ewma=NULL, cusum_pos=0, cusum_neg=0, k_count=0,"
        " below_count=0, in_alarm=0, frozen=0, open_anomaly_id=NULL, healthy_from=?"
        " WHERE signal IN (?,?)",
        (latest["ts"], *signals),
    )
    kv_set(conn, CANARY_SUITE_CP_KEY, str(latest["id"]))


def _tick_canary(conn: sqlite3.Connection, cfg: DetectCfg) -> list[int]:
    _apply_suite_change_points(conn)
    opened = _canary_series(conn, cfg, sid.C1_CANARY_PASS, _c1_cycles(conn, cfg))
    opened += _canary_series(conn, cfg, sid.C2_CANARY_LONGCTX, _c2_cycles(conn))
    return opened


def _auto_adjudicate(conn: sqlite3.Connection, cfg: DetectCfg, now_iso: str) -> list[int]:
    cutoff = parse_iso(now_iso) - timedelta(days=cfg.auto_resolve_days)
    stale = [
        row
        for row in conn.execute(
            "SELECT * FROM anomalies WHERE status = 'open' AND ended_at IS NOT NULL"
        ).fetchall()
        if _before(row["ended_at"], cutoff)
    ]
    if not stale:
        return []

    stale.sort(key=lambda row: row["cc_version"] != ANY_VERSION)
    for row in stale:
        conn.execute(
            "UPDATE anomalies SET status = ? WHERE id = ?", (AUTO_FALSE_POSITIVE, row["id"])
        )
    for row in stale:
        _recompute_after_resolve(conn, cfg, row, "false_positive", row["ended_at"], now_iso)
    log_ingest(
        conn,
        "anomaly_auto_resolved",
        len(stale),
        0,
        f"closed episodes unadjudicated for {cfg.auto_resolve_days}d: "
        + ",".join(str(row["id"]) for row in stale),
    )
    return [row["id"] for row in stale]


def _before(iso: str | None, cutoff: datetime) -> bool:
    try:
        return parse_iso(iso).timestamp() < cutoff.timestamp() if iso else False
    except ValueError:  # pragma: no cover
        return False


def tick(conn: sqlite3.Connection, cfg: DetectCfg, now_iso: str | None = None) -> list[int]:
    now_iso = now_iso or utcnow_iso()
    _auto_adjudicate(conn, cfg, now_iso)
    opened = _tick_passive(conn, cfg, now_iso)
    opened += _tick_canary(conn, cfg)
    conn.commit()
    return opened


def resolve(
    conn: sqlite3.Connection,
    alert_id: int,
    as_: str,
    cfg: DetectCfg | None = None,
    now_iso: str | None = None,
) -> list[int]:
    cfg = cfg or DetectCfg()
    now_iso = now_iso or utcnow_iso()
    normalized = as_.replace("-", "_").lower()
    if normalized not in ("confirmed", "false_positive"):
        raise ValueError("as_ must be 'confirmed' or 'false_positive'")
    status = "resolved" if normalized == "confirmed" else "false_positive"

    alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if alert is not None:
        try:
            anomaly_ids = [int(i) for i in json.loads(alert["anomaly_ids"] or "[]")]
        except (ValueError, TypeError):
            anomaly_ids = []
        conn.execute(
            "UPDATE alerts SET resolution = ?, resolved_at = ? WHERE id = ?",
            (normalized, now_iso, alert_id),
        )
    else:
        anomaly_ids = [alert_id]

    resolved: list[int] = []
    rows: list[tuple[sqlite3.Row, str]] = []
    for anomaly_id in anomaly_ids:
        row = conn.execute("SELECT * FROM anomalies WHERE id = ?", (anomaly_id,)).fetchone()
        if row is None:
            continue
        ended_at = row["ended_at"] or now_iso
        conn.execute(
            "UPDATE anomalies SET status = ?, ended_at = ? WHERE id = ?",
            (status, ended_at, anomaly_id),
        )
        resolved.append(anomaly_id)
        rows.append((row, ended_at))

    rows.sort(key=lambda item: item[0]["cc_version"] != ANY_VERSION)
    for row, ended_at in rows:
        _recompute_after_resolve(conn, cfg, row, normalized, ended_at, now_iso)
    conn.commit()
    return resolved


def _recompute_after_resolve(
    conn: sqlite3.Connection,
    cfg: DetectCfg,
    anomaly: sqlite3.Row,
    normalized: str,
    ended_at: str,
    now_iso: str,
) -> None:
    signal, model, bucket = anomaly["signal"], anomaly["model"], anomaly["context_bucket"]
    version = anomaly["cc_version"] or ANY_VERSION
    state = _load_state(conn, signal, model, bucket, version)

    if normalized == "confirmed":
        state["healthy_from"] = ended_at
    still_open = conn.execute(
        "SELECT COUNT(*) FROM anomalies WHERE signal=? AND model=? AND context_bucket=?"
        " AND COALESCE(cc_version, ?) = ? AND status = 'open'",
        (signal, model, bucket, ANY_VERSION, version),
    ).fetchone()[0]

    state["cusum_pos"] = 0.0
    state["cusum_neg"] = 0.0
    state["below_count"] = 0
    state["in_alarm"] = 0
    state["open_anomaly_id"] = None
    state["ewma"] = None
    state["frozen"] = 1 if still_open else 0
    _save_state(conn, state)

    if not state["frozen"]:
        if signal in (sid.C1_CANARY_PASS, sid.C2_CANARY_LONGCTX):
            state["k_count"] = 0
            _apply_baseline(state, None)
        else:
            _apply_baseline(state, compute_for(conn, cfg, signal, model, bucket, version, now_iso))
    _save_state(conn, state)

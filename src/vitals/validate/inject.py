from __future__ import annotations

import json
import math
import sqlite3

from vitals.alert.rules import AlertDraft, evaluate
from vitals.canary.checkers import TaskSpec
from vitals.canary.runner import run_cycle
from vitals.config import Config
from vitals.detect import signal_ids as sid
from vitals.detect.attribution import Attribution, classify
from vitals.detect.engine import tick
from vitals.timeutil import hour_add, hour_floor, utcnow_iso

__all__ = [
    "DEFAULT_INJECT_MODEL",
    "DRILL_CYCLE_MARGIN",
    "HEALTHY_HOURS",
    "KINDS",
    "SHIFT_HOURS",
    "default_drill_cycles",
    "insert_fake_version_change_point",
    "model_swap_drill",
    "synthetic_stream",
]


_KIND_SPECS: dict[str, tuple[str, str, float, int, float, int, str]] = {
    "latency_x1.5": (
        sid.S1_LATENCY_P95,
        "lt30k",
        math.log(200.0),
        20,
        math.log(300.0),
        20,
        "up",
    ),
    "error_rate_x4": (
        sid.S2_ERROR_RATE,
        "all",
        0.05,
        100,
        0.20,
        100,
        "up",
    ),
    "tokens_drop_40pct": (
        sid.S8_OUTPUT_TOKENS,
        "lt30k",
        1000.0,
        20,
        600.0,
        20,
        "down",
    ),
    "post_compaction_2x": (
        sid.S9_POST_COMPACTION_FAIL,
        "all",
        1.0,
        20,
        2.0,
        20,
        "up",
    ),
}

KINDS: tuple[str, ...] = tuple(_KIND_SPECS)

HEALTHY_HOURS = 24 * 7
SHIFT_HOURS = 12

DEFAULT_INJECT_MODEL = "claude-haiku-4-5"

DRILL_CYCLE_MARGIN = 2


def default_drill_cycles(cfg: Config) -> int:
    return cfg.detect.K_cycles + DRILL_CYCLE_MARGIN


def _insert_window(
    conn: sqlite3.Connection,
    window_start: str,
    signal: str,
    model: str,
    bucket: str,
    cc_version: str,
    value: float,
    n: int,
) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO signal_windows(window_start, signal, model, context_bucket,"
        " value, n, cc_version) VALUES (?,?,?,?,?,?,?)",
        (window_start, signal, model, bucket, value, n, cc_version),
    )


def synthetic_stream(
    kind: str,
    conn: sqlite3.Connection,
    *,
    model: str = "claude-sonnet-5",
    cc_version: str = "1.0.0",
    now_iso: str | None = None,
    healthy_hours: int = HEALTHY_HOURS,
    shift_hours: int = SHIFT_HOURS,
) -> None:
    spec = _KIND_SPECS.get(kind)
    if spec is None:
        raise ValueError(f"unknown injection kind: {kind!r}; expected one of {sorted(KINDS)}")
    signal, bucket, healthy_value, healthy_n, shifted_value, shifted_n, _direction = spec

    now_iso = now_iso or utcnow_iso()
    end_hour = hour_floor(hour_add(now_iso, -1))
    hour = hour_add(end_hour, -(healthy_hours + shift_hours - 1))

    for _ in range(healthy_hours):
        _insert_window(conn, hour, signal, model, bucket, cc_version, healthy_value, healthy_n)
        hour = hour_add(hour, 1)
    for _ in range(shift_hours):
        _insert_window(conn, hour, signal, model, bucket, cc_version, shifted_value, shifted_n)
        hour = hour_add(hour, 1)
    conn.commit()


def insert_fake_version_change_point(
    conn: sqlite3.Connection,
    *,
    old_value: str = "0.0.0-drill-prior",
    new_value: str = "0.0.0-drill-new",
    ts: str | None = None,
) -> int:
    ts = ts or utcnow_iso()
    cur = conn.execute(
        "INSERT INTO change_points(ts, kind, old_value, new_value, detail) VALUES (?,?,?,?,?)",
        (
            ts,
            "cc_version",
            old_value,
            new_value,
            json.dumps({"source": "vitals inject --with-version-cp"}),
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def model_swap_drill(
    conn: sqlite3.Connection,
    cfg: Config,
    tasks: list[TaskSpec],
    *,
    inject_model: str = DEFAULT_INJECT_MODEL,
    claude_cmd: list[str] | None = None,
    cycles: int | None = None,
    now_iso: str | None = None,
) -> list[tuple[AlertDraft, Attribution]]:
    cycles = cycles if cycles is not None else default_drill_cycles(cfg)
    for _ in range(cycles):
        run_cycle(conn, cfg.canary, tasks, inject_model=inject_model, claude_cmd=claude_cmd)

    now_iso = now_iso or utcnow_iso()
    tick(conn, cfg.detect, now_iso)
    return [
        (draft, classify(conn, draft, now_iso)) for draft in evaluate(conn, cfg.detect, now_iso)
    ]

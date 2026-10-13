from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode

from vitals import failopen
from vitals.db import get_conn
from vitals.timeutil import utcnow_iso

if TYPE_CHECKING:
    from vitals.config import Config, DetectCfg

__all__ = [
    "BUTTONS",
    "LABELS",
    "apply_label",
    "encode_action",
    "failopen_totals",
    "false_alarm_rate",
    "handle_toast_action",
    "parse_action",
    "record_label",
    "summarize",
]

LABELS = ("real", "false_alarm", "unsure")
BUTTONS = (("Real", "real"), ("False alarm", "false_alarm"), ("Not sure", "unsure"))
_RESOLUTION = {"real": "confirmed", "false_alarm": "false_positive"}
_FAILOPEN_SITE = "toast.label"


def encode_action(alert_id: int, label: str) -> str:
    return urlencode({"alert": alert_id, "label": label})


def parse_action(arguments: str | None) -> tuple[int, str] | None:
    if not arguments:
        return None
    fields = parse_qs(arguments)
    alert = fields.get("alert", [""])[0]
    label = fields.get("label", [""])[0]
    if not alert.isdigit() or label not in LABELS:
        return None
    return int(alert), label


def record_label(
    conn: sqlite3.Connection,
    alert_id: int,
    label: str,
    source: str,
    now_iso: str | None = None,
) -> None:
    if label not in LABELS:
        raise ValueError(f"unknown label {label!r}")
    conn.execute(
        "INSERT INTO alert_labels(alert_id, label, source, ts) VALUES (?,?,?,?)",
        (alert_id, label, source, now_iso or utcnow_iso()),
    )
    conn.commit()


def apply_label(
    conn: sqlite3.Connection,
    alert_id: int,
    label: str,
    source: str,
    detect_cfg: DetectCfg | None = None,
    now_iso: str | None = None,
) -> None:
    from vitals.detect.engine import resolve

    if label not in LABELS:
        raise ValueError(f"unknown label {label!r}")
    if conn.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
        raise LookupError(f"no alert with id {alert_id}")
    now_iso = now_iso or utcnow_iso()
    if label in _RESOLUTION:
        resolve(conn, alert_id, _RESOLUTION[label], cfg=detect_cfg, now_iso=now_iso)
    record_label(conn, alert_id, label, source, now_iso=now_iso)


def handle_toast_action(cfg: Config, arguments: str | None) -> None:
    try:
        parsed = parse_action(arguments)
        if parsed is None:
            raise ValueError("not a label action")
        conn = get_conn(cfg.db_path)
        try:
            apply_label(conn, parsed[0], parsed[1], "toast", cfg.detect)
        finally:
            conn.close()
    except Exception:
        failopen.record(_FAILOPEN_SITE, cfg.data_dir)


def failopen_totals(cfg: Config) -> dict[str, int]:
    return failopen.totals(cfg.data_dir)


def summarize(conn: sqlite3.Connection, since_iso: str) -> dict[str, dict[str, int]]:
    rows = conn.execute(
        "SELECT a.severity, l.label FROM alert_labels l JOIN alerts a ON a.id = l.alert_id"
        " WHERE l.id IN (SELECT MAX(id) FROM alert_labels GROUP BY alert_id) AND l.ts >= ?",
        (since_iso,),
    ).fetchall()
    out: dict[str, dict[str, int]] = {}
    for severity, label in rows:
        bucket = out.setdefault(severity, dict.fromkeys(LABELS, 0))
        bucket[label] += 1
    return out


def false_alarm_rate(counts: dict[str, int]) -> float | None:
    judged = counts.get("real", 0) + counts.get("false_alarm", 0)
    if judged == 0:
        return None
    return counts.get("false_alarm", 0) / judged

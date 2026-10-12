from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

from vitals import failopen
from vitals.alert.rules import AlertDraft
from vitals.config import Config
from vitals.detect.attribution import Attribution
from vitals.timeutil import parse_iso

__all__ = ["NO_DATA_DEDUP_KEY", "check_no_data", "newest_activity_epoch", "newest_ingest_ts"]

NO_DATA_DEDUP_KEY = "no_data::collection"

LIVE_KINDS = ("hook_spool", "otel_spool", "transcripts")


def newest_ingest_ts(conn: sqlite3.Connection) -> str | None:
    try:
        row = conn.execute(
            "SELECT MAX(ts) FROM ingest_log WHERE kind IN (?,?,?)", LIVE_KINDS
        ).fetchone()
    except sqlite3.Error:  # pragma: no cover
        return None
    return row[0] if row else None


def newest_activity_epoch(projects_dir: Path) -> float | None:
    newest: float | None = None
    try:
        root = Path(projects_dir)
        if not root.exists():
            return None
        for path in root.glob("**/*.jsonl"):
            try:
                mtime = path.stat().st_mtime
            except OSError:  # pragma: no cover
                continue
            if newest is None or mtime > newest:
                newest = mtime
    except OSError:  # pragma: no cover
        return None
    return newest


def check_no_data(
    conn: sqlite3.Connection, cfg: Config, now_iso: str
) -> tuple[AlertDraft, Attribution] | None:
    window = timedelta(minutes=cfg.detect.no_data_window_minutes)
    now = parse_iso(now_iso)

    activity = newest_activity_epoch(cfg.projects_dir)
    if activity is None:
        return None
    idle_for = now.timestamp() - activity
    if idle_for > window.total_seconds():
        return None

    newest = newest_ingest_ts(conn)
    if newest is not None:
        try:
            if now - parse_iso(newest) <= window:
                return None
        except ValueError:  # pragma: no cover
            pass

    silent_minutes = round((now - parse_iso(newest)).total_seconds() / 60) if newest else None
    draft = AlertDraft(
        severity="WARN",
        title="vitals: no collection for "
        + (f"{silent_minutes} min" if silent_minutes is not None else "any recorded period")
        + " while Claude Code is active",
        anomaly_ids=[],
        families=["collection"],
        suppressed_by_incident=None,
        dedup_key=NO_DATA_DEDUP_KEY,
        first_seen=now_iso,
    )
    attribution = Attribution(
        cls="E",
        evidence={
            "cls": "E",
            "matched_rule": 6,
            "matched_rule_name": "inconclusive",
            "generated_at": now_iso,
            "reason": "no_data",
            "note": (
                "Transcripts were modified in the last "
                f"{round(idle_for / 60)} min, so work is happening, but no hook or OTel "
                "record has arrived within the window. The collection path is the "
                "suspect; which stage of it is not something this check can tell."
            ),
            "window_minutes": cfg.detect.no_data_window_minutes,
            "silent_minutes": silent_minutes,
            "last_ingest_ts": newest,
            "failopen_totals": failopen.totals(cfg.data_dir),
            "strata": {"signals": [], "models": [], "context_buckets": [], "cc_versions": []},
            "rules": [],
        },
    )
    return draft, attribution

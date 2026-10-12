from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from vitals.alert.channels import AlertPayload, load_channels
from vitals.alert.rules import mark_info_sent
from vitals.config import Config
from vitals.db import kv_get, kv_set, log_ingest
from vitals.detect.attribution import Attribution
from vitals.report.builder import build as build_report
from vitals.timeutil import parse_iso, utcnow_iso

__all__ = ["dispatch"]

_DISPATCH_KV_PREFIX = "alert_dispatch_last:"
_SEVERITY_RANK = {"INFO": 0, "WARN": 1, "CRITICAL": 2}


def _kv_key(dedup_key: str) -> str:
    return f"{_DISPATCH_KV_PREFIX}{dedup_key}"


def _last_dispatch(conn: sqlite3.Connection, dedup_key: str) -> dict | None:
    raw = kv_get(conn, _kv_key(dedup_key))
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _should_notify(
    conn: sqlite3.Connection,
    dedup_key: str,
    severity: str,
    now: datetime,
    cooldown_minutes: float,
) -> bool:
    if not dedup_key:
        return True
    last = _last_dispatch(conn, dedup_key)
    if last is None:
        return True
    try:
        age_min = (now - parse_iso(last["ts"])).total_seconds() / 60.0
    except (KeyError, TypeError, ValueError):
        return True
    if age_min >= cooldown_minutes:
        return True
    prev_rank = _SEVERITY_RANK.get(last.get("severity", ""), -1)
    new_rank = _SEVERITY_RANK.get(severity, -1)
    return new_rank > prev_rank


def _mark_dispatched(conn: sqlite3.Connection, dedup_key: str, severity: str, now_iso: str) -> None:
    if not dedup_key:
        return
    kv_set(conn, _kv_key(dedup_key), json.dumps({"severity": severity, "ts": now_iso}))


def _insert_alert(conn: sqlite3.Connection, draft, attribution: Attribution, now_iso: str) -> int:
    cur = conn.execute(
        "INSERT INTO alerts(ts, severity, attribution, title, evidence_json, anomaly_ids,"
        " suppressed_by_incident) VALUES (?,?,?,?,?,?,?)",
        (
            now_iso,
            draft.severity,
            attribution.cls,
            draft.title,
            json.dumps(attribution.evidence),
            json.dumps(list(draft.anomaly_ids)),
            draft.suppressed_by_incident,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def _write_local_detail(
    cfg: Config, alert_id: int, draft, attribution: Attribution, now_iso: str
) -> str:
    reports_dir = Path(cfg.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"alert-{alert_id}.json"
    detail = {
        "alert_id": alert_id,
        "ts": now_iso,
        "severity": draft.severity,
        "title": draft.title,
        "dedup_key": draft.dedup_key,
        "first_seen": draft.first_seen,
        "families": list(draft.families),
        "anomaly_ids": list(draft.anomaly_ids),
        "suppressed_by_incident": draft.suppressed_by_incident,
        "attribution": attribution.evidence,
    }
    path.write_text(json.dumps(detail, indent=2), encoding="utf-8")
    return str(path)


def _summary_text(draft, attribution: Attribution) -> str:
    evidence = attribution.evidence or {}
    strata = evidence.get("strata") or {}
    models = ", ".join(strata.get("models") or []) or "unknown"
    buckets = ", ".join(strata.get("context_buckets") or []) or "unknown"
    families = ", ".join(sorted(draft.families)) or "none"
    reason = evidence.get("matched_rule_name") or "unknown"
    return (
        f"{len(draft.anomaly_ids)} anomaly signal(s) across families=[{families}];"
        f" models=[{models}] buckets=[{buckets}]; attribution reason: {reason}"
    )


def dispatch(
    conn: sqlite3.Connection,
    cfg: Config,
    draft,
    attribution: Attribution,
    *,
    now_iso: str | None = None,
) -> int:
    now_iso = now_iso or utcnow_iso()
    now = parse_iso(now_iso)
    cooldown_minutes = cfg.alert.dedup_cooldown_minutes

    if not _should_notify(conn, draft.dedup_key, draft.severity, now, cooldown_minutes):
        return 0

    alert_id = _insert_alert(conn, draft, attribution, now_iso)

    try:
        local_detail_path: str | None = _write_local_detail(
            cfg, alert_id, draft, attribution, now_iso
        )
    except OSError as exc:
        local_detail_path = None
        log_ingest(
            conn,
            "alert_dispatch",
            ok_count=0,
            err_count=1,
            detail=f"local_detail_write: {exc}",
        )
    else:
        conn.execute(
            "UPDATE alerts SET detail_path = ? WHERE id = ?", (local_detail_path, alert_id)
        )
        conn.commit()

    if draft.severity == "CRITICAL":
        try:
            report_path, _json_path = build_report(conn, cfg, alert_id)
        except Exception as exc:
            log_ingest(
                conn, "alert_dispatch", ok_count=0, err_count=1, detail=f"report_build: {exc}"
            )
        else:
            conn.execute(
                "UPDATE alerts SET report_path = ? WHERE id = ?", (str(report_path), alert_id)
            )
            conn.commit()

    payload = AlertPayload(
        severity=draft.severity,
        attribution=attribution.cls,
        title=draft.title,
        summary_text=_summary_text(draft, attribution),
        local_detail_path=local_detail_path,
    )

    for channel in load_channels(cfg):
        try:
            channel.send(payload)
        except Exception as exc:
            log_ingest(
                conn,
                "alert_dispatch",
                ok_count=0,
                err_count=1,
                detail=f"{channel.name}: {exc}",
            )
        else:
            log_ingest(conn, "alert_dispatch", ok_count=1, err_count=0, detail=channel.name)

    _mark_dispatched(conn, draft.dedup_key, draft.severity, now_iso)
    for signal in getattr(draft, "info_dedup_signals", ()) or ():
        mark_info_sent(conn, signal, now_iso)
    return alert_id

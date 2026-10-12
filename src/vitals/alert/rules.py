from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from vitals.config import DetectCfg
from vitals.db import kv_get, kv_set
from vitals.detect.baseline import AUTO_FALSE_POSITIVE
from vitals.detect.signal_ids import FAMILY as FAMILIES
from vitals.detect.signal_ids import WEAK_SIGNALS
from vitals.timeutil import parse_iso, utcnow_iso
from vitals.watch.status_poller import active_incident

__all__ = [
    "FAMILIES",
    "AlertDraft",
    "evaluate",
    "mark_info_sent",
    "reconcile_stale_alerts",
    "signal_counts_toward_threshold",
]

_EXCLUDED_FAMILIES_FROM_THRESHOLD = frozenset({"canary", "canary-aux"})

_INFO_DEDUP_HOURS = 24
_INFO_KV_PREFIX = "alert_info_last:"


@dataclass
class AlertDraft:
    severity: str
    title: str
    anomaly_ids: list[int]
    families: list[str]
    suppressed_by_incident: str | None = None
    dedup_key: str = ""
    first_seen: str = ""
    info_dedup_signals: list[str] = field(default_factory=list)


@dataclass
class _Occurrence:
    signal: str
    model: str
    bucket: str
    family: str
    anomaly_ids: list[int]
    started: datetime
    ended: datetime | None


def signal_counts_toward_threshold(signal: str) -> bool:
    return (
        signal not in WEAK_SIGNALS
        and FAMILIES.get(signal, "unknown") not in _EXCLUDED_FAMILIES_FROM_THRESHOLD
    )


def _counts_toward_threshold(occ: _Occurrence) -> bool:
    return signal_counts_toward_threshold(occ.signal)


def _dedup_key(occurrences: list[_Occurrence]) -> str:
    triples = sorted(f"{o.signal}::{o.model}::{o.bucket}" for o in occurrences)
    return "|".join(triples)


def _first_seen(occurrences: list[_Occurrence]) -> str:
    return min(o.started for o in occurrences).isoformat(timespec="seconds")


def _occurrences(conn: sqlite3.Connection) -> list[_Occurrence]:
    rows = conn.execute(
        "SELECT id, signal, model, context_bucket, started_at, ended_at"
        " FROM anomalies WHERE status = 'open'"
    ).fetchall()
    groups: dict[tuple[str, str, str], list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        key = (row["signal"], row["model"] or "", row["context_bucket"] or "")
        groups[key].append(row)

    occurrences = []
    for (signal, model, bucket), members in sorted(groups.items()):
        started = min(parse_iso(m["started_at"]) for m in members)
        ended = (
            None
            if any(m["ended_at"] is None for m in members)
            else max(parse_iso(m["ended_at"]) for m in members)
        )
        occurrences.append(
            _Occurrence(
                signal=signal,
                model=model,
                bucket=bucket,
                family=FAMILIES.get(signal, "unknown"),
                anomaly_ids=sorted(m["id"] for m in members),
                started=started,
                ended=ended,
            )
        )
    return occurrences


def _gap_hours(a: _Occurrence, b: _Occurrence, now: datetime) -> float:
    a_end = a.ended or now
    b_end = b.ended or now
    latest_start = max(a.started, b.started)
    earliest_end = min(a_end, b_end)
    if latest_start <= earliest_end:
        return 0.0
    return (latest_start - earliest_end).total_seconds() / 3600.0


def _cluster(
    occurrences: list[_Occurrence], warn_window_h: float, now: datetime
) -> list[list[_Occurrence]]:
    n = len(occurrences)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for i in range(n):
        for j in range(i + 1, n):
            if _gap_hours(occurrences[i], occurrences[j], now) <= warn_window_h:
                union(i, j)

    groups: dict[int, list[_Occurrence]] = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(occurrences[i])
    return list(groups.values())


def _sustained_hours(cluster: list[_Occurrence], now: datetime) -> float | None:
    earliest_by_family: dict[str, datetime] = {}
    for occ in cluster:
        if occ.ended is not None or not _counts_toward_threshold(occ):
            continue
        if occ.family not in earliest_by_family or occ.started < earliest_by_family[occ.family]:
            earliest_by_family[occ.family] = occ.started
    if len(earliest_by_family) < 2:
        return None
    second_join = sorted(earliest_by_family.values())[1]
    return (now - second_join).total_seconds() / 3600.0


def _info_kv_key(signal: str) -> str:
    return f"{_INFO_KV_PREFIX}{signal}"


def _info_recently_sent(conn: sqlite3.Connection, signal: str, now: datetime) -> bool:
    last = kv_get(conn, _info_kv_key(signal))
    if last is None:
        return False
    try:
        age_h = (now - parse_iso(last)).total_seconds() / 3600.0
    except ValueError:  # pragma: no cover
        return False
    return age_h < _INFO_DEDUP_HOURS


def mark_info_sent(conn: sqlite3.Connection, signal: str, now_iso: str) -> None:
    kv_set(conn, _info_kv_key(signal), now_iso)


def reconcile_stale_alerts(conn: sqlite3.Connection, now_iso: str | None = None) -> list[int]:
    now_iso = now_iso or utcnow_iso()
    stale_ids = {
        row["id"]
        for row in conn.execute("SELECT id FROM anomalies WHERE status = ?", (AUTO_FALSE_POSITIVE,))
    }
    if not stale_ids:
        return []

    updated: list[int] = []
    for row in conn.execute("SELECT id, anomaly_ids FROM alerts WHERE resolution IS NULL"):
        try:
            ids = {int(i) for i in json.loads(row["anomaly_ids"] or "[]")}
        except (TypeError, ValueError):
            continue
        if ids & stale_ids:
            conn.execute(
                "UPDATE alerts SET resolution = ?, resolved_at = ? WHERE id = ?",
                (AUTO_FALSE_POSITIVE, now_iso, row["id"]),
            )
            updated.append(row["id"])
    if updated:
        conn.commit()
    return updated


def evaluate(
    conn: sqlite3.Connection, cfg: DetectCfg, now_iso: str | None = None
) -> list[AlertDraft]:
    now_iso = now_iso or utcnow_iso()
    now = parse_iso(now_iso)

    reconcile_stale_alerts(conn, now_iso)

    occurrences = _occurrences(conn)
    incident_id = active_incident(conn, now_iso)

    drafts: list[AlertDraft] = []
    consumed: set[int] = set()

    canary = [o for o in occurrences if o.family == "canary"]
    if canary:
        drafts.append(
            _finish(
                "CRITICAL",
                "Canary regression: pass rate below baseline for K consecutive cycles",
                canary,
                incident_id,
            )
        )
        consumed.update(i for o in canary for i in o.anomaly_ids)

    eligible = [o for o in occurrences if o.family != "canary"]
    for cluster in _cluster(eligible, cfg.warn_window_h, now):
        counted = {o.family for o in cluster if _counts_toward_threshold(o)}
        if len(counted) < 2:
            continue
        sustained = _sustained_hours(cluster, now)
        severity = "WARN"
        title = f"Multiple families degrading together: {', '.join(sorted(counted))}"
        if sustained is not None and sustained > cfg.critical_sustain_h:
            severity = "CRITICAL"
            title = (
                f"Multiple families degrading for over {cfg.critical_sustain_h}h: "
                f"{', '.join(sorted(counted))}"
            )
        drafts.append(_finish(severity, title, cluster, incident_id))
        consumed.update(i for o in cluster for i in o.anomaly_ids)

    for occ in occurrences:
        if set(occ.anomaly_ids) & consumed:
            continue
        if _info_recently_sent(conn, occ.signal, now):
            continue
        drafts.append(
            AlertDraft(
                severity="INFO",
                title=f"{occ.signal} alarm ({occ.family})",
                anomaly_ids=list(occ.anomaly_ids),
                families=[occ.family],
                suppressed_by_incident=None,
                dedup_key=_dedup_key([occ]),
                first_seen=_first_seen([occ]),
                info_dedup_signals=[occ.signal],
            )
        )

    return drafts


def _finish(
    severity: str,
    title: str,
    occurrences: list[_Occurrence],
    incident_id: str | None,
) -> AlertDraft:
    anomaly_ids = sorted({i for o in occurrences for i in o.anomaly_ids})
    families = sorted({o.family for o in occurrences})
    dedup_key = _dedup_key(occurrences)
    first_seen = _first_seen(occurrences)
    if incident_id:
        return AlertDraft(
            severity="INFO",
            title=f"Incident window ({incident_id}): {title}",
            anomaly_ids=anomaly_ids,
            families=families,
            suppressed_by_incident=incident_id,
            dedup_key=dedup_key,
            first_seen=first_seen,
        )
    return AlertDraft(
        severity=severity,
        title=title,
        anomaly_ids=anomaly_ids,
        families=families,
        suppressed_by_incident=None,
        dedup_key=dedup_key,
        first_seen=first_seen,
    )

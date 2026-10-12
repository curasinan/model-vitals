from __future__ import annotations

import math
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal

from vitals.db import kv_get
from vitals.detect import signal_ids as sid
from vitals.detect.baseline import ANY_VERSION, FOLDED_BACK
from vitals.detect.engine import CANARY_SUITE_CP_KEY
from vitals.timeutil import epoch_to_iso, parse_iso, utcnow_iso
from vitals.watch.status_poller import DEFAULT_PREFIXES, active_incident

__all__ = ["BUCKET_ORDER", "HIGH_CONTEXT_BUCKETS", "Attribution", "classify"]

BUCKET_ORDER = ("lt30k", "b30_100k", "b100_180k", "gt180k")
HIGH_CONTEXT_BUCKETS = frozenset({"b100_180k", "gt180k"})
SHORT_CONTEXT_BUCKETS = ("lt30k", "b30_100k")

CONTEXT_SIGNALS = frozenset({sid.S9_POST_COMPACTION_FAIL, sid.S5_EDIT_LOOP_RATE})

INTRINSIC_CONTRAST_SIGNALS = frozenset({sid.S9_POST_COMPACTION_FAIL})

_INTRINSIC_CONTRAST_NOTE = (
    f"{sid.S9_POST_COMPACTION_FAIL} is a RATIO by construction: the tool-failure rate inside the"
    " 15-minute post-compaction window divided by the same rate outside it (spec S9, via"
    " v_post_compaction_turns). An alarm on it therefore already means 'worse right after"
    " compaction than otherwise' -- the healthy comparison is built into the statistic, so the"
    " class A argument is self-contained and needs no lower-bucket contrast."
)

RULE2_CANARY_SIGNALS = frozenset({sid.C1_CANARY_PASS, sid.C2_CANARY_LONGCTX})

HARNESS_KINDS = ("cc_version", "settings", "plugins", "vitals_config")

CANARY_HARNESS_KINDS = ("cc_version", "vitals_config", "canary_suite")

_BARE_CANARY_NOTE = (
    "every canary run passes --bare with --model/--effort pinned from vitals' own config"
    " (canary.runner._build_args), so a change of this kind cannot reach the canary harness"
)

RULE2_LOOKBACK_H = 24.0
RULE4A_QUIET_H = 72.0
RULE4B_MIN_SESSIONS = 2

BACKEND_KV_KEY = "active_backend"
REMOTE_BACKEND = "anthropic_api"
LOCAL_BACKEND_VALUES = frozenset(
    {"local", "llama.cpp", "llamacpp", "vllm", "ollama", "lmstudio", "mlx"}
)

_INF = math.inf


@dataclass
class Attribution:
    cls: Literal["A", "B", "C", "D", "E"]
    evidence: dict = field(default_factory=dict)


def _epoch(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        return parse_iso(iso).timestamp()
    except ValueError:
        return None


def _shift(iso: str, hours: float) -> str:
    return (parse_iso(iso) + timedelta(hours=hours)).isoformat(timespec="seconds")


def _iso(epoch: float) -> str | None:
    if epoch in (_INF, -_INF):
        return None
    return epoch_to_iso(epoch)


def _overlap(a: tuple[float, float], b: tuple[float, float]) -> tuple[float, float] | None:
    lo, hi = max(a[0], b[0]), min(a[1], b[1])
    return (lo, hi) if lo <= hi else None


def _rows_to_dicts(rows) -> list[dict]:
    return [dict(r) for r in rows]


def _anomaly_span(row: dict, now_ep: float) -> tuple[float, float]:
    start = _epoch(row["started_at"]) or now_ep
    end = _epoch(row["ended_at"])
    return (start, end if end is not None else now_ep)


def _live_anomalies(conn: sqlite3.Connection) -> list[dict]:
    placeholders = ",".join("?" * len(FOLDED_BACK))
    return _rows_to_dicts(
        conn.execute(
            f"SELECT id, signal, model, context_bucket, cc_version, started_at, ended_at, status"  # noqa: S608
            f" FROM anomalies WHERE status NOT IN ({placeholders}) ORDER BY id",
            FOLDED_BACK,
        )
    )


def _in_window(rows: list[dict], window: tuple[float, float], now_ep: float) -> list[dict]:
    return [r for r in rows if _overlap(_anomaly_span(r, now_ep), window) is not None]


def _ids(rows: list[dict]) -> list[int]:
    return sorted(r["id"] for r in rows)


def _bucket_index(bucket: str | None) -> int:
    try:
        return BUCKET_ORDER.index(bucket or "")
    except ValueError:
        return len(BUCKET_ORDER)


def _sorted_buckets(buckets) -> list[str]:
    return sorted(set(buckets), key=_bucket_index)


def _entry(rule: int, cls: str, name: str, matched: bool, facts: dict) -> dict:
    if not matched:
        assert facts.get("reason"), f"rule {rule} missed without recording why"
    return {"rule": rule, "cls": cls, "name": name, "matched": bool(matched), "facts": facts}


def _rule1_incident(
    conn: sqlite3.Connection, window: tuple[float, float], span: dict, now_iso: str
) -> dict:
    overlapping: list[dict] = []
    scanned = 0
    for row in conn.execute(
        "SELECT incident_id, name, status, impact, created_at, resolved_at, components"
        " FROM incidents ORDER BY created_at DESC"
    ):
        scanned += 1
        start = _epoch(row["created_at"])
        if start is None:
            continue
        end = _epoch(row["resolved_at"])
        components = [c for c in (row["components"] or "").split(",") if c]
        prefixes = [p for c in components for p in DEFAULT_PREFIXES if c.startswith(p)]
        if not prefixes:
            continue
        hit = _overlap((start, end if end is not None else _INF), window)
        if hit is None:
            continue
        overlapping.append(
            {
                "incident_id": row["incident_id"],
                "impact": row["impact"],
                "components": components,
                "matched_prefix": prefixes[0],
                "incident_span": [row["created_at"], row["resolved_at"]],
                "overlap_span": [_iso(hit[0]), _iso(hit[1])],
                "overlap_hours": round((hit[1] - hit[0]) / 3600.0, 2),
                "unresolved": row["resolved_at"] is None,
            }
        )

    facts: dict[str, Any] = {
        "anomaly_span": [span["start"], span["end"]],
        "watched_prefixes": list(DEFAULT_PREFIXES),
        "incidents_scanned": scanned,
        "overlapping": overlapping,
        "active_at_now": active_incident(conn, now_iso),
    }
    if not overlapping:
        facts["reason"] = (
            "no status-page incident touching Claude API / Claude Code / claude.ai overlaps"
            f" the alarm window ({scanned} incident rows scanned)"
        )
        return _entry(1, "C", "status_incident", False, facts)

    best = sorted(
        overlapping,
        key=lambda i: (not i["unresolved"], -i["overlap_hours"], i["incident_span"][0] or ""),
    )[0]
    facts.update(
        {
            "incident_id": best["incident_id"],
            "components": best["components"],
            "matched_prefix": best["matched_prefix"],
            "incident_span": best["incident_span"],
            "overlap_span": best["overlap_span"],
            "overlap_hours": best["overlap_hours"],
            "unresolved": best["unresolved"],
        }
    )
    return _entry(1, "C", "status_incident", True, facts)


def _effort_shift(conn: sqlite3.Connection, cp_ts: str, now_iso: str) -> dict:
    def distribution(lo: str, hi: str) -> dict[str, int]:
        counts = Counter()
        for row in conn.execute(
            "SELECT effort, COUNT(*) AS n FROM api_requests WHERE ts >= ? AND ts < ?"
            " GROUP BY effort",
            (lo, hi),
        ):
            counts[row["effort"] or "unknown"] += row["n"]
        return dict(counts)

    before = distribution(_shift(cp_ts, -RULE2_LOOKBACK_H), cp_ts)
    after = distribution(cp_ts, _shift(now_iso, 1))
    modal_before = max(before, key=before.get) if before else None
    modal_after = max(after, key=after.get) if after else None
    return {
        "before": before,
        "after": after,
        "modal_before": modal_before,
        "modal_after": modal_after,
        "changed": bool(modal_before and modal_after and modal_before != modal_after),
    }


def _version_alarm_map(
    conn: sqlite3.Connection,
    live: list[dict],
    triples: set[tuple[str, str, str]],
    since_ep: float,
    now_ep: float,
) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for row in live:
        key = (row["signal"], row["model"] or "", row["context_bucket"] or "")
        if key not in triples:
            continue
        if _overlap(_anomaly_span(row, now_ep), (since_ep, now_ep)) is None:
            continue
        out.setdefault(row["cc_version"] or "unknown", []).append(row["id"])
    return {version: sorted(ids) for version, ids in sorted(out.items())}


def _rule2_harness(
    conn: sqlite3.Connection,
    live: list[dict],
    draft_rows: list[dict],
    span: dict,
    now_iso: str,
    now_ep: float,
) -> dict:
    start_ep = _epoch(span["start"]) or now_ep
    lo = start_ep - RULE2_LOOKBACK_H * 3600.0
    candidates = [
        {
            "id": row["id"],
            "ts": row["ts"],
            "kind": row["kind"],
            "old_value": row["old_value"],
            "new_value": row["new_value"],
        }
        for row in conn.execute(
            "SELECT id, ts, kind, old_value, new_value FROM change_points"  # noqa: S608
            f" WHERE kind IN ({','.join('?' * len(HARNESS_KINDS))}) ORDER BY ts DESC, id DESC",
            HARNESS_KINDS,
        )
        if (_epoch(row["ts"]) is not None and lo <= _epoch(row["ts"]) <= start_ep)
    ]

    canary_only = bool(draft_rows) and all(r["signal"] in RULE2_CANARY_SIGNALS for r in draft_rows)

    facts: dict[str, Any] = {
        "lookback_hours": RULE2_LOOKBACK_H,
        "window": [_iso(lo), span["start"]],
        "kinds_considered": list(HARNESS_KINDS),
        "canary_only_draft": canary_only,
        "candidates": candidates,
        "change_point": None,
        "version_alarm_map": {},
        "new_version_alarmed": [],
        "prior_version_quiet": None,
        "prior_version_alarm_ids": [],
        "collapsed_stratum_alarmed": False,
        "contrast": None,
    }
    if not candidates:
        facts["reason"] = (
            f"no change_points row of kind {'/'.join(HARNESS_KINDS)} lies in the"
            f" {RULE2_LOOKBACK_H:.0f}h before the alarm started"
        )
        return _entry(2, "B", "harness_change", False, facts)

    triples = {(r["signal"], r["model"] or "", r["context_bucket"] or "") for r in draft_rows}
    draft_versions = {r["cc_version"] or "unknown" for r in draft_rows}
    rejections: list[str] = []
    rejected: list[dict] = []

    for cand in candidates:
        cp_ep = _epoch(cand["ts"]) or start_ep
        alarm_map = _version_alarm_map(conn, live, triples, cp_ep, now_ep)
        detail: dict[str, Any] = {
            "change_point": cand,
            "version_alarm_map": alarm_map,
            "collapsed_stratum_alarmed": ANY_VERSION in alarm_map,
            "effort_shift": _effort_shift(conn, cand["ts"], now_iso),
        }
        why: str | None = None
        if cand["kind"] == "cc_version":
            new_version = cand["new_value"]
            prior = cand["old_value"]
            prior_ids = alarm_map.get(prior or "", [])
            detail.update(
                {
                    "postdates_test": "stratum_cc_version_is_the_new_value",
                    "contrast": "cross_stratum_version",
                    "new_version_alarmed": sorted(v for v in draft_versions if v == new_version),
                    "prior_version": prior,
                    "prior_version_alarm_ids": prior_ids,
                    "prior_version_quiet": not prior_ids,
                }
            )
            canary_rows = [r for r in draft_rows if r["signal"] in RULE2_CANARY_SIGNALS]
            if new_version not in draft_versions and canary_rows:
                detail.update(
                    {
                        "postdates_test": "canary_temporal_contrast",
                        "contrast": "temporal_only",
                        "canary_anomaly_ids": _ids(canary_rows),
                        "why_no_cross_stratum_contrast": (
                            "canary anomalies are recorded under cc_version='any' by"
                            " construction, so no real-version stratum exists to test against"
                            " the change point's new_value; the argument is temporal (the"
                            " regression began after the version bump), not cross-stratum"
                        ),
                    }
                )
                facts.update(detail)
                facts["rejected"] = rejected
                return _entry(2, "B", "harness_change", True, facts)
            if new_version not in draft_versions:
                why = (
                    f"change point {cand['id']} ({cand['kind']}): no alarming stratum lives on"
                    f" the new version {new_version}"
                )
            elif prior_ids:
                why = (
                    f"change point {cand['id']} ({cand['kind']}): the prior version {prior}"
                    f" was alarming too (anomaly ids {prior_ids}), so the change does not"
                    " single out the new version"
                )
        else:
            detail.update(
                {
                    "postdates_test": "alarm_starts_after_change",
                    "contrast": "none_possible_for_this_kind",
                    "why_no_cross_stratum_contrast": (
                        f"a {cand['kind']} change is not a stratum key, so there is no"
                        " 'prior' and 'new' cc_version stratum pair to contrast; the only"
                        " available test is temporal -- the alarm must begin strictly after"
                        " the change"
                    ),
                    "prior_version_quiet": None,
                    "prior_version_alarm_ids": [],
                }
            )
            if cand["kind"] not in CANARY_HARNESS_KINDS and canary_only:
                why = (
                    f"change point {cand['id']} ({cand['kind']}): every alarming anomaly is a"
                    f" canary signal, and {_BARE_CANARY_NOTE}"
                )
            elif start_ep <= cp_ep:
                why = (
                    f"change point {cand['id']} ({cand['kind']}): the alarm did not begin"
                    f" strictly after it (alarm start {span['start']}, change {cand['ts']})"
                )

        if why is None:
            facts.update(detail)
            facts["rejected"] = rejected
            return _entry(2, "B", "harness_change", True, facts)

        rejections.append(why)
        rejected.append({**detail, "reason": why})
        if len(rejected) == 1:
            facts.update(detail)
            facts["change_point"] = None

    facts["rejected"] = rejected
    facts["reason"] = "; ".join(rejections) or "no candidate change point qualified"
    return _entry(2, "B", "harness_change", False, facts)


def _live_baseline_buckets(conn: sqlite3.Connection, signals: set[str] | None) -> list[str]:
    buckets = set()
    for row in conn.execute(
        "SELECT DISTINCT signal, context_bucket FROM detector_state WHERE mu0 IS NOT NULL"
    ):
        if signals is not None and row["signal"] not in signals:
            continue
        if row["context_bucket"] in BUCKET_ORDER:
            buckets.add(row["context_bucket"])
    return _sorted_buckets(buckets)


def _canary_health(conn: sqlite3.Connection, live: list[dict], window, now_ep: float) -> dict:
    regressions = [r for r in _in_window(live, window, now_ep) if r["signal"] == sid.C1_CANARY_PASS]
    longctx = [r for r in _in_window(live, window, now_ep) if r["signal"] == sid.C2_CANARY_LONGCTX]
    latest = conn.execute(
        "SELECT cycle_id, started_at, pass_rate FROM canary_cycles WHERE pass_rate IS NOT NULL"
        " ORDER BY cycle_id DESC LIMIT 1"
    ).fetchone()
    total = conn.execute("SELECT COUNT(*) FROM canary_cycles").fetchone()[0]

    if regressions:
        state = "regressed"
    elif total == 0:
        state = "no_data"
    else:
        state = "green"
    return {
        "state": state,
        "healthy": state != "regressed",
        "cycles_recorded": total,
        "latest_cycle_id": latest["cycle_id"] if latest else None,
        "latest_pass_rate": latest["pass_rate"] if latest else None,
        "anomaly_ids": _ids(regressions),
        "long_context_anomaly_ids": _ids(longctx),
    }


def _no_intrinsic_contrast_note(signals: list[str]) -> str:
    return (
        f" {'/'.join(signals)} carries no intrinsic contrast: it is a plain rate, with nothing"
        " in its construction comparing a degraded condition against a healthy one, unlike"
        f" {sid.S9_POST_COMPACTION_FAIL}, which is itself the ratio of the post-compaction"
        " tool-failure rate to the rate outside that window. So it cannot reach class A alone"
        " and needs a lower-bucket contrast like any other signal."
    )


def _rule3_context(
    conn: sqlite3.Connection, live: list[dict], draft_rows: list[dict], span: dict, now_ep: float
) -> dict:
    window = (_epoch(span["start"]) or now_ep, now_ep)
    unconfined = [
        r
        for r in draft_rows
        if r["context_bucket"] not in HIGH_CONTEXT_BUCKETS and r["signal"] not in CONTEXT_SIGNALS
    ]
    confined = bool(draft_rows) and not unconfined

    draft_signals = {r["signal"] for r in draft_rows}
    alarmed = _sorted_buckets(
        r["context_bucket"] for r in draft_rows if r["context_bucket"] in BUCKET_ORDER
    )
    ceiling = _bucket_index(alarmed[0]) if alarmed else len(BUCKET_ORDER)

    scoped = _live_baseline_buckets(conn, draft_signals)
    any_signal = _live_baseline_buckets(conn, None)
    lower_scoped = [b for b in scoped if _bucket_index(b) < ceiling]
    lower_any = [b for b in any_signal if _bucket_index(b) < ceiling]

    contrast = lower_scoped[0] if lower_scoped else None
    scope = "draft_signals" if lower_scoped else ("any_signal" if lower_any else None)
    fallback_only = lower_any[0] if (not lower_scoped and lower_any) else None
    pool = scoped if lower_scoped else (any_signal if lower_any else (scoped or any_signal))

    contrast_alarms = (
        [r for r in _in_window(live, window, now_ep) if r["context_bucket"] == contrast]
        if contrast
        else []
    )
    canary = _canary_health(conn, live, window, now_ep)
    intrinsic_signals = sorted(draft_signals & INTRINSIC_CONTRAST_SIGNALS)
    no_intrinsic = sorted((draft_signals & CONTEXT_SIGNALS) - INTRINSIC_CONTRAST_SIGNALS)

    facts: dict[str, Any] = {
        "high_context_buckets": _sorted_buckets(HIGH_CONTEXT_BUCKETS),
        "context_signals": sorted(CONTEXT_SIGNALS),
        "contrast": None,
        "intrinsic_contrast_signals": intrinsic_signals,
        "intrinsic_contrast_note": _INTRINSIC_CONTRAST_NOTE if intrinsic_signals else None,
        "confined": confined,
        "unconfined_anomaly_ids": _ids(unconfined),
        "draft_bucket_alarm_map": {
            bucket: sorted(r["id"] for r in draft_rows if (r["context_bucket"] or "") == bucket)
            for bucket in sorted({(r["context_bucket"] or "") for r in draft_rows})
        },
        "bucket_alarm_map": {
            bucket: sorted(
                r["id"]
                for r in _in_window(live, window, now_ep)
                if (r["context_bucket"] or "") == bucket
            )
            for bucket in sorted(
                {(r["context_bucket"] or "") for r in _in_window(live, window, now_ep)}
            )
        },
        "lowest_alarmed_bucket": alarmed[0] if alarmed else None,
        "buckets_with_live_baseline": pool,
        "contrast_bucket": contrast,
        "contrast_bucket_scope": scope,
        "contrast_bucket_candidate": fallback_only,
        "contrast_bucket_rule": (
            "lowest context bucket with a live baseline for one of THIS alert's signals,"
            " strictly below the lowest alarmed bucket (finding F3: lt30k is almost always"
            " insufficient_data on this machine); a baseline held only by unrelated signals"
            " does not qualify"
        ),
        "contrast_bucket_quiet": contrast is not None and not contrast_alarms,
        "contrast_bucket_alarm_ids": _ids(contrast_alarms),
        "canary": canary,
    }

    if not confined:
        facts["reason"] = (
            "alarms are not confined to the high-context buckets or to"
            f" post_compaction_fail_rate/edit_loop_rate: anomaly ids {_ids(unconfined)} sit"
            " elsewhere"
            if draft_rows
            else "the alert carries no anomaly rows to place in a context bucket"
        )
        return _entry(3, "A", "context_confined", False, facts)

    if intrinsic_signals:
        facts["contrast"] = "intrinsic_to_signal"
        if not canary["healthy"]:
            facts["reason"] = (
                "the short-context canary suite regressed (anomaly ids"
                f" {canary['anomaly_ids']}), which contradicts a context-only explanation"
                f" even though {'/'.join(intrinsic_signals)} carries its own contrast"
            )
            return _entry(3, "A", "context_confined", False, facts)
        return _entry(3, "A", "context_confined", True, facts)

    if contrast is None and fallback_only is not None:
        facts["reason"] = (
            f"the only lower context bucket available ({fallback_only}) has no live baseline"
            f" for {'/'.join(sorted(draft_signals))}; only unrelated signals are measurable"
            " there, so its quiet cannot be distinguished from absence of data"
        ) + (_no_intrinsic_contrast_note(no_intrinsic) if no_intrinsic else "")
        return _entry(3, "A", "context_confined", False, facts)
    if contrast is None:
        facts["reason"] = (
            "no lower context bucket has a live baseline to contrast against, so confinement"
            " to long context cannot be distinguished from long context being the only"
            " measured stratum"
        ) + (_no_intrinsic_contrast_note(no_intrinsic) if no_intrinsic else "")
        return _entry(3, "A", "context_confined", False, facts)
    if contrast_alarms:
        facts["reason"] = (
            f"the contrast bucket {contrast} was itself alarming (anomaly ids"
            f" {_ids(contrast_alarms)}), so the degradation is not confined to long context"
        )
        return _entry(3, "A", "context_confined", False, facts)
    if not canary["healthy"]:
        facts["reason"] = (
            "the short-context canary suite regressed (anomaly ids"
            f" {canary['anomaly_ids']}), which contradicts a context-only explanation"
        )
        return _entry(3, "A", "context_confined", False, facts)
    facts["contrast"] = "lower_bucket"
    return _entry(3, "A", "context_confined", True, facts)


def _change_points_between(conn: sqlite3.Connection, lo_ep: float, hi_ep: float) -> list[dict]:
    return [
        {"id": row["id"], "ts": row["ts"], "kind": row["kind"]}
        for row in conn.execute("SELECT id, ts, kind FROM change_points ORDER BY ts, id")
        if (_epoch(row["ts"]) is not None and lo_ep <= _epoch(row["ts"]) <= hi_ep)
    ]


def _branch_a(conn: sqlite3.Connection, live: list[dict], window, now_ep: float) -> dict:
    canary = [r for r in _in_window(live, window, now_ep) if r["signal"] == sid.C1_CANARY_PASS]
    facts: dict[str, Any] = {
        "matched": False,
        "argument": (
            "the canary harness is fully pinned (model, effort, --bare, fixed prompts, fixed"
            " goldens); with harness and version ruled out, provider-side is what remains --"
            " and only a change point that can MOVE that pinned harness (kinds"
            f" {'/'.join(CANARY_HARNESS_KINDS)}) counts against the elimination"
        ),
        "canary_anomaly_ids": _ids(canary),
        "canary_regression_started": None,
        "quiet_hours": RULE4A_QUIET_H,
        "canary_harness_kinds": list(CANARY_HARNESS_KINDS),
        "change_points_72h": [],
        "disqualifying_change_points": [],
        "excluded_change_points": [],
        "long_context_canary_anomaly_ids": _ids(
            [r for r in _in_window(live, window, now_ep) if r["signal"] == sid.C2_CANARY_LONGCTX]
        ),
    }
    if not canary:
        facts["reason"] = (
            "the short-context canary suite (canary_pass_rate) has no K-rule regression"
            " overlapping this alert"
        )
        return facts

    anchor = min(r["started_at"] for r in canary)
    anchor_ep = _epoch(anchor) or now_ep
    changes = _change_points_between(conn, anchor_ep - RULE4A_QUIET_H * 3600.0, anchor_ep)
    applied_suite_cp = int(kv_get(conn, CANARY_SUITE_CP_KEY) or 0)
    disqualifying: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for change in changes:
        if change["kind"] not in CANARY_HARNESS_KINDS:
            excluded.append({**change, "reason": _BARE_CANARY_NOTE})
        elif change["kind"] == "canary_suite" and change["id"] <= applied_suite_cp:
            excluded.append(
                {
                    **change,
                    "reason": (
                        "the detector already reset both canary baselines at this suite edit"
                        " (engine._apply_suite_change_points, watermark"
                        f" {CANARY_SUITE_CP_KEY}={applied_suite_cp}), so the regression is"
                        " measured against the post-change suite's own normal"
                    ),
                }
            )
        else:
            disqualifying.append(change)
    facts["canary_regression_started"] = anchor
    facts["change_points_72h"] = changes
    facts["disqualifying_change_points"] = disqualifying
    facts["excluded_change_points"] = excluded
    if disqualifying:
        facts["reason"] = (
            "a change point that can move the pinned canary harness landed in the"
            f" {RULE4A_QUIET_H:.0f}h before the canary regression"
            f" (ids {[c['id'] for c in disqualifying]}), so the harness is not ruled out"
        )
        return facts
    facts["matched"] = True
    return facts


def _session_breadth(conn: sqlite3.Connection, row: dict, now_iso: str) -> tuple[set, set]:
    sql = (
        "SELECT r.session_id AS sid, s.cwd AS cwd FROM api_requests r"
        " LEFT JOIN sessions s ON s.session_id = r.session_id"
        " WHERE r.ts >= ? AND r.ts <= ? AND COALESCE(s.is_canary, 0) = 0"
    )
    params: list[Any] = [row["started_at"], row["ended_at"] or now_iso]
    if row["model"] and row["model"] != "all":
        sql += " AND r.model = ?"
        params.append(row["model"])
    if row["context_bucket"] and row["context_bucket"] != "all":
        sql += " AND r.context_bucket = ?"
        params.append(row["context_bucket"])
    if row["cc_version"] and row["cc_version"] not in (ANY_VERSION, "unknown"):
        sql += " AND r.cc_version = ?"
        params.append(row["cc_version"])

    sessions, projects = set(), set()
    for hit in conn.execute(sql, params):
        if hit["sid"]:
            sessions.add(hit["sid"])
        if hit["cwd"]:
            projects.add(hit["cwd"])
    return sessions, projects


def _branch_b(
    conn: sqlite3.Connection, draft_rows: list[dict], span: dict, now_iso: str, now_ep: float
) -> dict:
    qualifying = [
        r
        for r in draft_rows
        if r["signal"] in sid.PASSIVE_SIGNALS and r["context_bucket"] in SHORT_CONTEXT_BUCKETS
    ]
    start_ep = _epoch(span["start"]) or now_ep
    version_changes = [
        c
        for c in _change_points_between(conn, start_ep - RULE2_LOOKBACK_H * 3600.0, now_ep)
        if c["kind"] == "cc_version"
    ]
    facts: dict[str, Any] = {
        "matched": False,
        "short_context_buckets": list(SHORT_CONTEXT_BUCKETS),
        "bucket_rule": (
            "literal lt30k/b30_100k -- rule 3's lowest-live-baseline substitution is"
            " deliberately NOT reused here, because these buckets are positive evidence"
        ),
        "qualifying_anomaly_ids": _ids(qualifying),
        "distinct_sessions": 0,
        "distinct_projects": 0,
        "min_sessions": RULE4B_MIN_SESSIONS,
        "version_changed": bool(version_changes),
        "cc_version_change_points": version_changes,
    }
    if not qualifying:
        facts["reason"] = (
            "no anomaly in this alert lives in a short-context stratum"
            f" ({'/'.join(SHORT_CONTEXT_BUCKETS)}); per finding F3 those strata are usually"
            " insufficient_data on this machine"
        )
        return facts

    sessions: set = set()
    projects: set = set()
    for row in qualifying:
        got_sessions, got_projects = _session_breadth(conn, row, now_iso)
        sessions |= got_sessions
        projects |= got_projects
    facts["distinct_sessions"] = len(sessions)
    facts["distinct_projects"] = len(projects)

    if version_changes:
        facts["reason"] = (
            "the Claude Code version changed around this alert (change point ids"
            f" {[c['id'] for c in version_changes]}), so the drift is not version-independent"
        )
        return facts
    if len(sessions) < RULE4B_MIN_SESSIONS:
        facts["reason"] = (
            f"passive drift touches only {len(sessions)} distinct real session(s);"
            f" {RULE4B_MIN_SESSIONS} are required before one session's habits are ruled out"
        )
        return facts
    facts["matched"] = True
    return facts


def _rule4_provider(
    conn: sqlite3.Connection,
    live: list[dict],
    draft_rows: list[dict],
    span: dict,
    now_iso: str,
    now_ep: float,
) -> dict:
    window = (_epoch(span["start"]) or now_ep, now_ep)
    branch_a = _branch_a(conn, live, window, now_ep)
    branch_b = _branch_b(conn, draft_rows, span, now_iso, now_ep)
    matched_branches = [name for name, b in (("a", branch_a), ("b", branch_b)) if b["matched"]]

    facts: dict[str, Any] = {
        "branches": {"a": branch_a, "b": branch_b},
        "branches_matched": matched_branches,
        "confidence": (
            "high" if len(matched_branches) == 2 else "moderate" if matched_branches else None
        ),
        "note": "no status-page incident explains this alert; rule 1 already missed",
    }
    if not matched_branches:
        facts["reason"] = (
            f"neither branch matched -- (a) {branch_a['reason']}; (b) {branch_b['reason']}"
        )
        return _entry(4, "C", "provider_no_incident", False, facts)
    return _entry(4, "C", "provider_no_incident", True, facts)


def _rule5_local_backend(conn: sqlite3.Connection) -> dict:
    configured = (kv_get(conn, BACKEND_KV_KEY) or "").strip()
    local = configured.lower() in LOCAL_BACKEND_VALUES and bool(configured)
    facts = {
        "active_backend": configured or REMOTE_BACKEND,
        "local_backend": local,
        "hw_covariates": "not_collected",
        "reason": (
            "a local inference backend is configured, but no hardware covariates"
            " (thermal / memory / config) are collected yet, so the class D sub-classifier"
            " cannot run before Phase 4"
            if local
            else "the active backend is the hosted Claude API, and class D applies only to a"
            " local inference server, which arrives in Phase 4"
        ),
    }
    return _entry(5, "D", "local_backend", False, facts)


def _rule6_inconclusive(entries: list[dict], span: dict, draft_rows: list[dict]) -> dict:
    missed = [e["rule"] for e in entries if not e["matched"]]
    winner = next((e["rule"] for e in entries if e["matched"]), None)
    facts: dict[str, Any] = {
        "rules_missed": missed,
        "picture": {
            "signals": sorted({r["signal"] for r in draft_rows}),
            "models": sorted({r["model"] or "unknown" for r in draft_rows}),
            "context_buckets": sorted({r["context_bucket"] or "unknown" for r in draft_rows}),
            "cc_versions": sorted({r["cc_version"] or "unknown" for r in draft_rows}),
            "anomaly_span": [span["start"], span["end"]],
        },
    }
    if winner is not None:
        facts["reason"] = f"rule {winner} matched first, so the alert is not inconclusive"
        return _entry(6, "E", "inconclusive", False, facts)
    facts["reason"] = (
        "no attribution rule matched; the per-rule facts above record why each one missed"
    )
    return _entry(6, "E", "inconclusive", True, facts)


def classify(conn: sqlite3.Connection, draft, now_iso: str | None = None) -> Attribution:
    now_iso = now_iso or utcnow_iso()
    now_ep = _epoch(now_iso) or 0.0

    requested = list(getattr(draft, "anomaly_ids", []) or [])
    draft_rows: list[dict] = []
    if requested:
        placeholders = ",".join("?" * len(requested))
        draft_rows = _rows_to_dicts(
            conn.execute(
                f"SELECT id, signal, model, context_bucket, cc_version, started_at, ended_at,"  # noqa: S608
                f" status, direction, peak_stat, peak_z FROM anomalies WHERE id IN"
                f" ({placeholders}) ORDER BY id",
                requested,
            )
        )
    missing = sorted(set(requested) - {r["id"] for r in draft_rows})

    starts = [r["started_at"] for r in draft_rows if r["started_at"]]
    span_start = min(starts) if starts else (getattr(draft, "first_seen", "") or now_iso)
    ends = [r["ended_at"] for r in draft_rows]
    span = {
        "start": span_start,
        "end": now_iso if (not ends or any(e is None for e in ends)) else max(ends),
        "open": not ends or any(e is None for e in ends),
    }

    live = _live_anomalies(conn)

    entries = [
        _rule1_incident(conn, (_epoch(span_start) or now_ep, now_ep), span, now_iso),
        _rule2_harness(conn, live, draft_rows, span, now_iso, now_ep),
        _rule3_context(conn, live, draft_rows, span, now_ep),
        _rule4_provider(conn, live, draft_rows, span, now_iso, now_ep),
        _rule5_local_backend(conn),
    ]
    entries.append(_rule6_inconclusive(entries, span, draft_rows))

    winner = next(e for e in entries if e["matched"])

    evidence = {
        "cls": winner["cls"],
        "matched_rule": winner["rule"],
        "matched_rule_name": winner["name"],
        "generated_at": now_iso,
        "window": {"start": span["start"], "end": span["end"], "open": span["open"]},
        "draft": {
            "severity": getattr(draft, "severity", None),
            "dedup_key": getattr(draft, "dedup_key", ""),
            "families": list(getattr(draft, "families", []) or []),
            "anomaly_ids": requested,
            "first_seen": getattr(draft, "first_seen", ""),
            "suppressed_by_incident": getattr(draft, "suppressed_by_incident", None),
        },
        "strata": {
            "signals": sorted({r["signal"] for r in draft_rows}),
            "models": sorted({r["model"] or "unknown" for r in draft_rows}),
            "context_buckets": sorted({r["context_bucket"] or "unknown" for r in draft_rows}),
            "cc_versions": sorted({r["cc_version"] or "unknown" for r in draft_rows}),
        },
        "anomaly_ids_missing": missing,
        "rules": entries,
    }
    return Attribution(cls=winner["cls"], evidence=evidence)

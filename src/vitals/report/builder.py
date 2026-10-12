from __future__ import annotations

import json
import platform
import sqlite3
import string
from importlib import resources
from pathlib import Path

from vitals.canary.checkers import TaskSpec, default_tasks_dir, load_tasks
from vitals.config import CanaryCfg, Config
from vitals.db import kv_get
from vitals.detect import signal_ids as sid
from vitals.detect.baseline import AUTO_FALSE_POSITIVE, window_series
from vitals.report.redact import redact_report, redact_text
from vitals.timeutil import hour_add, parse_iso, utcnow_iso

__all__ = ["build"]

_MAX_EXCERPTS = 3
_MAX_EXCERPT_LINES = 20
_MAX_FAIL_DETAIL_LINES = 40
_CHANGE_POINT_LOOKBACK_H = 24.0
_CANARY_SIGNALS = (sid.C1_CANARY_PASS, sid.C2_CANARY_LONGCTX)
_UNAVAILABLE = "transcript unavailable (retention sweep)"

_TEMPLATE_PATH = resources.files("vitals.report") / "templates" / "report.md.tmpl"


def _epoch(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        return parse_iso(iso).timestamp()
    except ValueError:
        return None


def _fmt(value: float | None, spec: str = ".4g") -> str:
    return format(value, spec) if value is not None else "n/a"


def _ts_slug(iso: str) -> str:
    return iso.replace(":", "").replace("+00:00", "Z")


def _load_alert(conn: sqlite3.Connection, alert_id: int) -> dict:
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if row is None:
        raise ValueError(f"no alerts row with id {alert_id}")
    return dict(row)


def _load_anomalies(conn: sqlite3.Connection, anomaly_ids: list[int]) -> list[dict]:
    if not anomaly_ids:
        return []
    placeholders = ",".join("?" * len(anomaly_ids))
    rows = conn.execute(
        f"SELECT id, signal, model, context_bucket, cc_version, started_at, ended_at,"  # noqa: S608
        f" direction, peak_stat, peak_z, status FROM anomalies WHERE id IN ({placeholders})"
        f" ORDER BY id",
        anomaly_ids,
    ).fetchall()
    return [dict(r) for r in rows]


def _window(evidence: dict, alert: dict, anomalies: list[dict]) -> dict:
    ev_window = evidence.get("window") if isinstance(evidence, dict) else None
    if isinstance(ev_window, dict) and ev_window.get("start"):
        return {
            "start": ev_window["start"],
            "end": ev_window.get("end") or alert["ts"],
            "open": bool(ev_window.get("open")),
        }
    starts = [a["started_at"] for a in anomalies if a.get("started_at")]
    ends = [a.get("ended_at") for a in anomalies]
    open_ = (not ends) or any(e is None for e in ends)
    end = alert["ts"] if open_ else max(e for e in ends if e)
    return {"start": min(starts) if starts else alert["ts"], "end": end, "open": open_}


def _class_b_one_liner(facts: dict) -> str:
    cp = facts["change_point"]
    head = (
        f"change point #{cp.get('id')} ({cp.get('kind')}: {cp.get('old_value')} -> "
        f"{cp.get('new_value')}) preceded the alarm"
    )
    arm = facts.get("postdates_test")
    if arm == "stratum_cc_version_is_the_new_value":
        prior = cp.get("old_value") or facts.get("prior_version") or "the prior version"
        return f"{head}; only the new-version stratum alarmed, while strata on {prior} stayed quiet"
    if arm == "canary_temporal_contrast":
        ids = facts.get("canary_anomaly_ids") or []
        return (
            f"{head}; the pinned canary suite regressed right after it (anomaly ids {ids}). No"
            " cross-stratum version comparison was run -- canary anomalies are recorded under"
            " cc_version='any', so no per-version stratum exists to compare; the argument is"
            " temporal"
        )
    if arm == "alarm_starts_after_change":
        return (
            f"{head}; the alarm began strictly after it. No version comparison was run --"
            f" a {cp.get('kind')} change is not a stratum key, so there is no prior/new version"
            " pair to contrast"
        )
    return f"{head} (attribution arm: {arm or 'unrecorded'})"


def _evidence_one_liner(evidence: dict, cls: str) -> str:
    rules = evidence.get("rules") or []
    matched_rule = evidence.get("matched_rule")
    entry = next((r for r in rules if r.get("rule") == matched_rule and r.get("matched")), None)
    facts = (entry or {}).get("facts") or {}

    if cls == "C" and facts.get("incident_id"):
        return (
            f"status-page incident {facts['incident_id']} ({facts.get('matched_prefix', '?')})"
            f" overlapped the alarm for {facts.get('overlap_hours', '?')}h"
        )
    if cls == "B" and facts.get("change_point"):
        return _class_b_one_liner(facts)
    if cls == "A" and facts.get("contrast_bucket"):
        return (
            f"alarm confined to {facts.get('lowest_alarmed_bucket', '?')} while"
            f" {facts['contrast_bucket']} stayed quiet"
        )
    if cls == "C" and facts.get("branches_matched"):
        branches = "/".join(facts["branches_matched"])
        return f"provider drift with no status incident: branch(es) {branches} matched"
    if cls == "E":
        return facts.get("reason") or "no attribution rule matched; see the evidence checklist"

    name = entry.get("name") if entry else evidence.get("matched_rule_name", "unknown")
    return f"attribution rule {matched_rule} ({name}) matched"


def _render_summary(alert: dict, evidence: dict) -> str:
    cls = alert["attribution"]
    rule_name = evidence.get("matched_rule_name", "unknown")
    lines = [
        f"- Severity: {alert['severity']}",
        f"- Attribution: {cls} ({rule_name})",
        f"- Title: {alert['title']}",
        f"- Evidence: {_evidence_one_liner(evidence, cls)}",
    ]
    return "\n".join(lines)


def _plugins_list(conn: sqlite3.Connection) -> list[str]:
    raw = kv_get(conn, "snapshot")
    if not raw:
        return []
    try:
        snap = json.loads(raw)
        blob = json.loads(snap.get("plugins_list") or "{}")
    except (ValueError, TypeError):
        return []
    installed = blob.get("installed") or []
    try:
        return sorted(f"{name}@{version}" for name, version, *_rest in installed)
    except (TypeError, ValueError):
        return []


def _evidence_models(evidence: dict) -> list[str]:
    strata = evidence.get("strata") if isinstance(evidence, dict) else None
    if not isinstance(strata, dict):
        return []
    return sorted({m for m in (strata.get("models") or []) if m and m != "unknown"})


def _environment(conn: sqlite3.Connection, window: dict, evidence: dict) -> dict:
    models: set[str] = set()
    versions: set[str] = set()
    for row in conn.execute(
        "SELECT DISTINCT model, cc_version FROM api_requests WHERE ts >= ? AND ts <= ?",
        (window["start"], window["end"]),
    ):
        if row["model"]:
            models.add(row["model"])
        if row["cc_version"]:
            versions.add(row["cc_version"])
    for row in conn.execute(
        "SELECT DISTINCT cc_version FROM sessions WHERE COALESCE(started_at, '') <= ?"
        " AND (ended_at IS NULL OR ended_at >= ?)",
        (window["end"], window["start"]),
    ):
        if row["cc_version"]:
            versions.add(row["cc_version"])
    models_from_evidence = [] if models else _evidence_models(evidence)
    return {
        "models_seen": sorted(models),
        "models_from_evidence": models_from_evidence,
        "cc_versions_in_window": sorted(versions),
        "plugins": _plugins_list(conn),
        "os": platform.platform(),
    }


def _render_environment(env: dict) -> str:
    if env["models_seen"]:
        models_line = f"- Models seen: {', '.join(env['models_seen'])} (observed in requests)"
    elif env["models_from_evidence"]:
        models_line = (
            f"- Models seen: {', '.join(env['models_from_evidence'])}"
            " (from alert evidence, not observed in api_requests this window)"
        )
    else:
        models_line = "- Models seen: none recorded in this window"
    return "\n".join(
        [
            models_line,
            "- Claude Code versions in window: "
            f"{', '.join(env['cc_versions_in_window']) or 'none recorded'}",
            f"- Plugins: {', '.join(env['plugins']) or 'no plugin snapshot recorded'}",
            f"- OS (this machine, at report time): {env['os']}",
        ]
    )


def _render_window(window: dict) -> str:
    open_note = " (still open at report time)" if window.get("open") else ""
    return f"- Start: {window['start']}\n- End: {window['end']}{open_note}"


def _stratum_key(a: dict) -> tuple[str, str, str, str]:
    return (a["signal"], a["model"] or "", a["context_bucket"] or "", a["cc_version"] or "unknown")


def _merge_anomaly_rows(anomalies: list[dict]) -> dict[tuple, dict]:
    merged: dict[tuple, dict] = {}
    for a in anomalies:
        key = _stratum_key(a)
        cur = merged.get(key)
        if cur is None:
            merged[key] = dict(a)
            continue
        if a.get("peak_stat") is not None:
            cur["peak_stat"] = max(cur.get("peak_stat") or 0.0, a["peak_stat"])
        if a.get("peak_z") is not None:
            cur["peak_z"] = max(cur.get("peak_z") or 0.0, a["peak_z"])
        if a.get("started_at") and (
            not cur.get("started_at") or a["started_at"] < cur["started_at"]
        ):
            cur["started_at"] = a["started_at"]
    return merged


def _baseline_for(
    conn: sqlite3.Connection, signal: str, model: str, bucket: str, version: str
) -> dict | None:
    row = conn.execute(
        "SELECT mu0, sigma0, baseline_inherited_from, baseline_start, baseline_end,"
        " baseline_samples FROM detector_state WHERE signal=? AND model=? AND"
        " context_bucket=? AND cc_version=?",
        (signal, model, bucket, version),
    ).fetchone()
    return dict(row) if row is not None and row["mu0"] is not None else None


def _baseline_source_stratum(
    signal: str, model: str, bucket: str, version: str, baseline: dict
) -> tuple[str, str, str, str]:
    inherited = baseline.get("baseline_inherited_from")
    if not inherited:
        return (signal, model, bucket, version)
    return (signal, model, bucket, inherited)


def _auto_adjudicated_count(
    conn: sqlite3.Connection, signal: str, model: str, bucket: str, version: str
) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM anomalies WHERE signal=? AND model=? AND context_bucket=?"
        " AND cc_version=? AND status=?",
        (signal, model, bucket, version, AUTO_FALSE_POSITIVE),
    ).fetchone()
    return int(row[0]) if row else 0


def _current_canary_value(conn: sqlite3.Connection, signal: str, model: str) -> float | None:
    if signal == sid.C1_CANARY_PASS:
        row = conn.execute(
            "SELECT pass_rate FROM canary_cycles WHERE model=? AND pass_rate IS NOT NULL"
            " ORDER BY cycle_id DESC LIMIT 1",
            (model,),
        ).fetchone()
        return row["pass_rate"] if row else None
    row = conn.execute(
        "SELECT SUM(COALESCE(r.passed,0)) AS passes, COUNT(r.run_id) AS total"
        " FROM canary_cycles c JOIN canary_runs r ON r.cycle_id = c.cycle_id"
        " WHERE c.model=? AND r.long_context=1 AND r.invalid=0 AND r.passed IS NOT NULL"
        " GROUP BY c.cycle_id ORDER BY c.cycle_id DESC LIMIT 1",
        (model,),
    ).fetchone()
    if row is None or not row["total"]:
        return None
    return row["passes"] / row["total"]


def _current_value(
    conn: sqlite3.Connection, signal: str, model: str, bucket: str, version: str, now_iso: str
) -> float | None:
    if signal in _CANARY_SIGNALS:
        return _current_canary_value(conn, signal, model)
    rows = window_series(conn, signal, model, bucket, version, now_iso)
    return float(rows[-1]["value"]) if rows else None


def _affected_signals(conn: sqlite3.Connection, anomalies: list[dict], now_iso: str) -> list[dict]:
    rows: list[dict] = []
    for (signal, model, bucket, version), a in sorted(_merge_anomaly_rows(anomalies).items()):
        baseline = _baseline_for(conn, signal, model, bucket, version)
        auto_count = 0
        if baseline is not None:
            src = _baseline_source_stratum(signal, model, bucket, version, baseline)
            auto_count = _auto_adjudicated_count(conn, *src)
        rows.append(
            {
                "signal": signal,
                "model": model,
                "context_bucket": bucket,
                "cc_version": version,
                "baseline_mu0": baseline["mu0"] if baseline else None,
                "baseline_sigma0": baseline["sigma0"] if baseline else None,
                "baseline_inherited_from": baseline.get("baseline_inherited_from")
                if baseline
                else None,
                "baseline_auto_adjudicated_count": auto_count,
                "window_of_first_alarm": a.get("started_at"),
                "current_value": _current_value(conn, signal, model, bucket, version, now_iso),
                "cusum_peak": a.get("peak_stat"),
                "peak_z": a.get("peak_z"),
            }
        )
    return rows


def _render_affected_signals(rows: list[dict]) -> str:
    if not rows:
        return "(no anomalies are attached to this alert)"
    lines = [
        "| Signal | Stratum (model / bucket / version) | Baseline μ0±σ0 (before) |"
        " Window of first alarm | Current value (after) | CUSUM peak |",
        "|---|---|---|---|---|---|",
    ]
    auto_total = 0
    for r in rows:
        stratum = f"{r['model']} / {r['context_bucket']} / {r['cc_version']}"
        if r["baseline_mu0"] is None:
            baseline_str = "insufficient_data"
        else:
            baseline_str = f"{_fmt(r['baseline_mu0'])} ± {_fmt(r['baseline_sigma0'])}"
            if r["baseline_inherited_from"]:
                baseline_str += f" (inherited from {r['baseline_inherited_from']})"
            if r["baseline_auto_adjudicated_count"]:
                baseline_str += (
                    f" [{r['baseline_auto_adjudicated_count']} auto-adjudicated episode(s)"
                    " folded in]"
                )
                auto_total += 1
        lines.append(
            f"| {r['signal']} | {stratum} | {baseline_str} | {r['window_of_first_alarm'] or 'n/a'}"
            f" | {_fmt(r['current_value'])} | {_fmt(r['cusum_peak'], '.3g')} |"
        )
    lines.append("")
    lines.append(
        f"{auto_total} of {len(rows)} baseline(s) above rest at least partly on the detector's"
        " own auto-adjudication (`auto_false_positive`, applied after `auto_resolve_days` to an"
        " unadjudicated closed episode), not on a human `vitals resolve` call."
    )
    return "\n".join(lines)


def _canary_diffs(conn: sqlite3.Connection, window: dict) -> list[dict]:
    rows = conn.execute(
        "SELECT r.task_id, r.model, r.fail_detail, r.ts FROM canary_runs r"
        " JOIN canary_cycles c ON c.cycle_id = r.cycle_id"
        " WHERE r.passed = 0 AND r.invalid = 0 AND c.started_at >= ? AND c.started_at <= ?"
        " ORDER BY r.task_id, r.ts",
        (window["start"], window["end"]),
    ).fetchall()
    by_task: dict[str, dict] = {}
    for row in rows:
        by_task.setdefault(row["task_id"], dict(row))

    out = []
    for task_id, row in sorted(by_task.items()):
        detail = redact_text(row["fail_detail"] or "")
        lines = detail.splitlines()
        truncated = len(lines) > _MAX_FAIL_DETAIL_LINES
        clipped = "\n".join(lines[:_MAX_FAIL_DETAIL_LINES])
        if truncated:
            clipped += "\n... (truncated)"
        out.append({"task_id": task_id, "model": row["model"], "detail": clipped})
    return out


def _render_canary_diffs(rows: list[dict]) -> str:
    if not rows:
        return "no canary failures recorded in this window"
    return "\n\n".join(f"### {r['task_id']}\n```\n{r['detail']}\n```" for r in rows)


def _change_points(conn: sqlite3.Connection, window: dict) -> list[dict]:
    lo = hour_add(window["start"], -int(_CHANGE_POINT_LOOKBACK_H))
    rows = conn.execute(
        "SELECT id, ts, kind, old_value, new_value, detail FROM change_points"
        " WHERE ts >= ? AND ts <= ? ORDER BY ts, id",
        (lo, window["end"]),
    ).fetchall()
    out = []
    for row in rows:
        out.append(
            {
                "id": row["id"],
                "ts": row["ts"],
                "kind": row["kind"],
                "old_value": redact_text(row["old_value"]) if row["old_value"] else None,
                "new_value": redact_text(row["new_value"]) if row["new_value"] else None,
                "detail": redact_text(row["detail"]) if row["detail"] else None,
            }
        )
    return out


def _render_change_points(rows: list[dict]) -> str:
    if not rows:
        return (
            f"no change points in the {_CHANGE_POINT_LOOKBACK_H:.0f}h lookback through the"
            " end of the window"
        )
    lines = []
    for r in rows:
        line = f"- `{r['ts']}` **{r['kind']}**: {r['old_value']} -> {r['new_value']}"
        if r["detail"]:
            line += f" ({r['detail']})"
        lines.append(line)
    return "\n".join(lines)


def _status_incidents(conn: sqlite3.Connection, window: dict) -> list[dict]:
    start_ep, end_ep = _epoch(window["start"]), _epoch(window["end"])
    out = []
    for row in conn.execute(
        "SELECT incident_id, name, status, impact, created_at, resolved_at, components"
        " FROM incidents ORDER BY created_at DESC"
    ):
        created_ep = _epoch(row["created_at"])
        if created_ep is None or (end_ep is not None and created_ep > end_ep):
            continue
        resolved_ep = _epoch(row["resolved_at"])
        if resolved_ep is not None and start_ep is not None and resolved_ep < start_ep:
            continue
        out.append(dict(row))
    return out


def _render_status_page(rows: list[dict]) -> str:
    if not rows:
        return "no status-page incident overlapped this window"
    lines = []
    for r in rows:
        state = "unresolved" if not r["resolved_at"] else f"resolved at {r['resolved_at']}"
        lines.append(
            f"- `{r['incident_id']}` {r['name']} [{r['impact']}] components={r['components']}:"
            f" {state} (opened {r['created_at']})"
        )
    return "\n".join(lines)


def _message_text(message: dict) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts = [
        str(block.get("text") or "")
        for block in content
        if isinstance(block, dict) and block.get("type") == "text"
    ]
    return "\n".join(parts)


def _read_turn_text(transcript_path: str | None, uuid: str) -> str | None:
    if not transcript_path:
        return None
    path = Path(transcript_path)
    if not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in raw.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("uuid") == uuid:
            message = rec.get("message") if isinstance(rec.get("message"), dict) else {}
            return _message_text(message)
    return None


def _excerpts(conn: sqlite3.Connection, window: dict) -> tuple[list[dict], int, int]:
    candidates = conn.execute(
        "SELECT t.uuid, t.session_id, t.ts, t.self_corr_hits, s.transcript_path"
        " FROM transcript_turns t JOIN sessions s ON s.session_id = t.session_id"
        " WHERE t.role = 'assistant' AND COALESCE(s.is_canary, 0) = 0"
        " AND COALESCE(t.is_sidechain, 0) = 0 AND t.ts >= ? AND t.ts <= ?"
        " ORDER BY t.self_corr_hits DESC, t.ts ASC",
        (window["start"], window["end"]),
    ).fetchall()

    excerpts: list[dict] = []
    seen = 0
    unavailable = 0
    session_index: dict[str, int] = {}
    turns_per_session: dict[str, int] = {}
    for row in candidates:
        if len(excerpts) >= _MAX_EXCERPTS:
            break
        seen += 1
        text = _read_turn_text(row["transcript_path"], row["uuid"])
        if text is None:
            unavailable += 1
            continue
        redacted = redact_text(text)
        lines = redacted.splitlines() or [""]
        clipped = "\n".join(lines[:_MAX_EXCERPT_LINES])
        if len(lines) > _MAX_EXCERPT_LINES:
            clipped += "\n... (truncated)"
        raw_session = row["session_id"]
        index = session_index.setdefault(raw_session, len(session_index) + 1)
        turns_per_session[raw_session] = turns_per_session.get(raw_session, 0) + 1
        excerpts.append(
            {
                "session_index": index,
                "turn_index": turns_per_session[raw_session],
                "ts": row["ts"],
                "self_corr_hits": row["self_corr_hits"],
                "text": clipped,
            }
        )
    return excerpts, seen, unavailable


def _render_excerpts(excerpts: list[dict], seen: int, unavailable: int) -> str:
    if not excerpts:
        if seen:
            return _UNAVAILABLE
        return "no assistant turns found in this window to excerpt"
    blocks = [
        f"### Excerpt {i} (session #{e['session_index']}, turn #{e['turn_index']}, {e['ts']})"
        f"\n```\n{e['text']}\n```"
        for i, e in enumerate(excerpts, start=1)
    ]
    if unavailable:
        blocks.append(f"({unavailable} additional candidate turn(s): {_UNAVAILABLE})")
    return "\n\n".join(blocks)


def _load_task_specs() -> dict[str, TaskSpec]:
    try:
        return {t.task_id: t for t in load_tasks(default_tasks_dir())}
    except (OSError, ValueError):
        return {}


def _repro_command(canary_cfg: CanaryCfg, task: TaskSpec | None, model: str) -> str:
    parts = [
        "claude",
        "-p",
        "--output-format",
        "json",
        "--model",
        model,
        "--effort",
        canary_cfg.effort,
    ]
    max_turns = task.max_turns if task else 1
    budget = (
        task.per_run_budget_usd
        if task and task.per_run_budget_usd
        else canary_cfg.per_run_budget_usd
    )
    parts += ["--max-turns", str(max_turns), "--max-budget-usd", f"{budget:.4f}", "--bare"]
    if task and task.allowed_tools:
        parts += [
            "--allowedTools",
            ",".join(task.allowed_tools),
            "--permission-mode",
            "acceptEdits",
        ]
    if task and task.json_schema is not None:
        parts += ["--json-schema", "<schema omitted -- see golden/schema.json>"]
    parts.append(
        "< prompt.md  # prompt is delivered over stdin, never argv -- see runner docstring"
    )
    return " ".join(parts)


def _reproduction_hints(cfg: Config, canary_rows: list[dict]) -> list[dict]:
    if not canary_rows:
        return []
    tasks = _load_task_specs()
    out = []
    for row in canary_rows:
        task = tasks.get(row["task_id"])
        model = row.get("model") or cfg.canary.model
        out.append({"task_id": row["task_id"], "command": _repro_command(cfg.canary, task, model)})
    return out


def _render_reproduction_hints(rows: list[dict]) -> str:
    if not rows:
        return "no failing canary task in this window to reproduce"
    return "\n".join(f"- `{r['task_id']}`: `{r['command']}`" for r in rows)


def _fill_template(**mapping: str) -> str:
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    return string.Template(text).substitute(**mapping)


def build(conn: sqlite3.Connection, cfg: Config, alert_id: int) -> tuple[Path, Path]:
    alert = _load_alert(conn, alert_id)
    evidence = json.loads(alert["evidence_json"] or "{}") if alert.get("evidence_json") else {}
    anomaly_ids = json.loads(alert["anomaly_ids"] or "[]") if alert.get("anomaly_ids") else []
    anomalies = _load_anomalies(conn, [int(i) for i in anomaly_ids])
    window = _window(evidence, alert, anomalies)
    now_iso = utcnow_iso()

    env = _environment(conn, window, evidence)
    signals_rows = _affected_signals(conn, anomalies, now_iso)
    canary_rows = _canary_diffs(conn, window)
    change_point_rows = _change_points(conn, window)
    incident_rows = _status_incidents(conn, window)
    excerpt_rows, excerpts_seen, excerpts_unavailable = _excerpts(conn, window)
    repro_rows = _reproduction_hints(cfg, canary_rows)

    markdown = _fill_template(
        alert_id=str(alert_id),
        summary=_render_summary(alert, evidence),
        environment=_render_environment(env),
        time_window=_render_window(window),
        affected_signals=_render_affected_signals(signals_rows),
        canary_diffs=_render_canary_diffs(canary_rows),
        change_points=_render_change_points(change_point_rows),
        status_page=_render_status_page(incident_rows),
        excerpts=_render_excerpts(excerpt_rows, excerpts_seen, excerpts_unavailable),
        reproduction_hints=_render_reproduction_hints(repro_rows),
    )
    markdown = redact_text(markdown)

    payload = redact_report(
        {
            "alert_id": alert_id,
            "generated_at": now_iso,
            "severity": alert["severity"],
            "attribution": alert["attribution"],
            "title": alert["title"],
            "summary_evidence": _evidence_one_liner(evidence, alert["attribution"]),
            "window": window,
            "environment": env,
            "affected_signals": signals_rows,
            "canary_diffs": canary_rows,
            "change_points": change_point_rows,
            "status_incidents": incident_rows,
            "excerpts": {
                "items": excerpt_rows,
                "candidates_seen": excerpts_seen,
                "unavailable": excerpts_unavailable,
            },
            "reproduction_hints": repro_rows,
            "footer": "Prepared by model-vitals — review before submitting via /bug or GitHub",
        }
    )

    reports_dir = Path(cfg.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    slug = _ts_slug(alert["ts"])
    md_path = reports_dir / f"{slug}-alert{alert_id}.md"
    json_path = reports_dir / f"{slug}-alert{alert_id}.json"
    md_path.write_text(markdown, encoding="utf-8")
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return md_path, json_path

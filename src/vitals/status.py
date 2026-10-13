from __future__ import annotations

import json
import sqlite3

from vitals.alert.labels import false_alarm_rate, summarize
from vitals.db import kv_get
from vitals.timeutil import days_ago_iso, local_day, parse_iso, utcnow_iso

WIDTH = 78


def _rule(title: str = "") -> str:
    if not title:
        return "-" * WIDTH
    return f"-- {title} " + "-" * max(0, WIDTH - len(title) - 4)


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    if not rows:
        return ["  (none)"]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    out = ["  " + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))]
    out.append("  " + "  ".join("-" * w for w in widths))
    for row in rows:
        out.append("  " + "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))
    return out


def _receiver_line(conn: sqlite3.Connection) -> str:
    raw = kv_get(conn, "receiver_state")
    if not raw:
        return "receiver: unknown (daemon has not reported yet)"
    try:
        state = json.loads(raw)
    except ValueError:
        return "receiver: unreadable state"
    if state.get("state") == "up":
        return f"receiver: UP on port {state.get('port')} (last heartbeat {state.get('ts', '?')})"
    return f"receiver: DOWN - {state.get('detail', 'unknown reason')}"


HOOK_SILENCE_HOURS = 72.0


def _hook_freshness_line(conn: sqlite3.Connection) -> str:
    row = conn.execute(
        "SELECT MAX(ts) AS ts FROM ("
        "  SELECT MAX(ts) AS ts FROM tool_results WHERE source = 'hook'"
        "  UNION ALL SELECT MAX(ts) AS ts FROM compactions WHERE source = 'hook'"
        ")"
    ).fetchone()
    last = row["ts"] if row else None
    if not last:
        return (
            "hook collection: no hook-fed record has ever arrived  <- hooks may never have been"
            " registered, or their interpreter is gone; run `vitals install-hooks`"
        )
    try:
        age_h = (parse_iso(utcnow_iso()) - parse_iso(last)).total_seconds() / 3600.0
    except ValueError:
        return f"hook collection: last hook-fed record at {last} (unparseable timestamp)"
    line = f"hook collection: last hook-fed record {age_h:.1f}h ago ({last})"
    if age_h >= HOOK_SILENCE_HOURS:
        line += (
            f"  <- silent for over {HOOK_SILENCE_HOURS:.0f}h; hooks fail open and report nothing,"
            " so check `vitals install-hooks` before reading the quiet below as good news"
        )
    return line


def render_status(conn: sqlite3.Connection, hours: int = 24) -> str:
    since = days_ago_iso(hours / 24)
    lines = [
        f"model-vitals status  ({hours}h window, generated {utcnow_iso()})",
        _rule(),
        _receiver_line(conn),
        _hook_freshness_line(conn),
    ]

    sessions = conn.execute(
        "SELECT COUNT(*) AS n, SUM(is_canary) AS canary FROM sessions "
        "WHERE COALESCE(started_at, '') >= ? OR session_id IN "
        "(SELECT DISTINCT session_id FROM api_requests WHERE ts >= ?)",
        (since, since),
    ).fetchone()
    lines.append(f"sessions seen: {sessions['n'] or 0} ({sessions['canary'] or 0} canary)")

    ingest = conn.execute(
        "SELECT COALESCE(SUM(ok_count),0) AS ok, COALESCE(SUM(err_count),0) AS err "
        "FROM ingest_log WHERE ts >= ?",
        (since,),
    ).fetchone()
    total = (ingest["ok"] or 0) + (ingest["err"] or 0)
    rate = (ingest["err"] / total * 100) if total else 0.0
    lines.append(f"ingest: {ingest['ok']} ok / {ingest['err']} errors ({rate:.2f}% error rate)")

    lines += ["", _rule("requests by model x context bucket")]
    rows = []
    for row in conn.execute(
        "SELECT r.model, r.context_bucket, COUNT(*) AS n, "
        "  AVG(r.duration_ms) AS avg_ms, MAX(r.duration_ms) AS max_ms, "
        "  AVG(r.output_tokens) AS out_tok "
        "FROM api_requests r JOIN sessions s USING(session_id) "
        "WHERE s.is_canary = 0 AND r.ts >= ? GROUP BY 1,2 ORDER BY n DESC LIMIT 20",
        (since,),
    ):
        rows.append(
            [
                row["model"] or "?",
                row["context_bucket"] or "?",
                row["n"],
                f"{row['avg_ms']:.0f}" if row["avg_ms"] is not None else "-",
                f"{row['max_ms']:.0f}" if row["max_ms"] is not None else "-",
                f"{row['out_tok']:.0f}" if row["out_tok"] is not None else "-",
            ]
        )
    if not rows:
        lines.append("  no requests in window")
    else:
        lines += _table(["model", "bucket", "n", "avg ms", "max ms", "out tok"], rows)

    errors = conn.execute(
        "SELECT COUNT(*) AS n, SUM(retries_exhausted) AS exhausted FROM api_errors "
        "WHERE ts >= ? AND source = 'otel'",
        (since,),
    ).fetchone()
    client = conn.execute(
        "SELECT COUNT(*) AS n FROM api_errors WHERE ts >= ? AND source = 'transcript_synthetic'",
        (since,),
    ).fetchone()
    lines += [
        "",
        f"api errors: {errors['n'] or 0} ({errors['exhausted'] or 0} retries-exhausted)",
        f"client-side notices (session limits, dropped connections): {client['n'] or 0}",
    ]

    lines += ["", _rule("tools")]
    rows = []
    for row in conn.execute(
        "SELECT t.tool_name, COUNT(*) AS n, "
        "  SUM(CASE WHEN t.success = 0 THEN 1 ELSE 0 END) AS fails, "
        "  SUM(CASE WHEN t.success IS NULL THEN 1 ELSE 0 END) AS interrupts "
        "FROM tool_results t JOIN sessions s USING(session_id) "
        "WHERE s.is_canary = 0 AND t.ts >= ? GROUP BY 1 ORDER BY n DESC LIMIT 12",
        (since,),
    ):
        counted = row["n"] - (row["interrupts"] or 0)
        pct = f"{(row['fails'] or 0) / counted * 100:.1f}%" if counted else "-"
        rows.append([row["tool_name"], row["n"], row["fails"] or 0, pct, row["interrupts"] or 0])
    lines += _table(["tool", "n", "fails", "fail %", "interrupted"], rows)

    loops = conn.execute(
        "SELECT COUNT(*) AS n FROM v_edit_loops WHERE edits >= 3 AND first_ts >= ?", (since,)
    ).fetchone()["n"]
    compactions = conn.execute(
        "SELECT COUNT(*) AS n FROM v_compaction_episodes WHERE ts >= ?", (since,)
    ).fetchone()["n"]
    lines += [
        "",
        f"edit loops (>=3 edits of one file in one prompt): {loops}",
        f"compaction episodes: {compactions}",
    ]

    lines += ["", _rule("detector")]
    windows = conn.execute(
        "SELECT COUNT(*) AS n, COUNT(DISTINCT signal || model || context_bucket || cc_version) "
        "AS strata FROM signal_windows"
    ).fetchone()
    lines.append(f"signal windows: {windows['n']} across {windows['strata']} strata")
    ready = conn.execute(
        "SELECT COUNT(*) AS n FROM detector_state WHERE mu0 IS NOT NULL"
    ).fetchone()["n"]
    lines.append(
        f"strata with a usable baseline: {ready}"
        + ("  <- none yet: nothing can alarm" if not ready else "")
    )

    lines += ["", _rule("censored signals (baseline exists, but zero windows ever evaluated)")]
    censored = conn.execute(
        "SELECT d.signal, d.model, d.context_bucket, d.cc_version,"
        " (SELECT COUNT(*) FROM signal_windows w WHERE w.signal = d.signal"
        "    AND w.model = d.model AND w.context_bucket = d.context_bucket"
        "    AND w.cc_version = d.cc_version) AS n_windows"
        " FROM detector_state d"
        " WHERE d.mu0 IS NOT NULL AND COALESCE(d.windows_evaluated, 0) = 0"
        " ORDER BY d.signal, d.model, d.context_bucket, d.cc_version"
    ).fetchall()
    lines += _table(
        ["signal", "model", "bucket", "version", "windows seen"],
        [
            [r["signal"], r["model"], r["context_bucket"], r["cc_version"], r["n_windows"]]
            for r in censored
        ],
    )

    lines += ["", _rule("frozen strata (baseline paused pending resolve)")]
    frozen_rows = conn.execute(
        "SELECT d.signal, d.model, d.context_bucket, d.cc_version,"
        " (SELECT MIN(a.started_at) FROM anomalies a WHERE a.status = 'open'"
        "    AND a.signal = d.signal AND COALESCE(a.model, '') = d.model"
        "    AND COALESCE(a.context_bucket, '') = d.context_bucket"
        "    AND COALESCE(a.cc_version, 'any') = d.cc_version) AS frozen_since"
        " FROM detector_state d WHERE d.frozen = 1"
    ).fetchall()
    now_dt = parse_iso(utcnow_iso())
    aged: list[tuple[sqlite3.Row, float]] = []
    for row in frozen_rows:
        if not row["frozen_since"]:
            continue
        try:
            age_days = (now_dt - parse_iso(row["frozen_since"])).total_seconds() / 86400.0
        except ValueError:
            continue
        aged.append((row, age_days))
    aged.sort(key=lambda item: item[1], reverse=True)
    if aged:
        oldest, oldest_days = aged[0]
        lines.append(
            f"oldest frozen stratum: {oldest['signal']} / {oldest['model']} /"
            f" {oldest['context_bucket']} / {oldest['cc_version']} -- frozen for"
            f" {oldest_days:.1f}d (an open anomaly is blocking this baseline; resolve it, or"
            " it auto-resolves once CLOSED and unadjudicated for auto_resolve_days)"
        )
        lines += _table(
            ["signal", "model", "bucket", "version", "frozen since", "days frozen"],
            [
                [
                    r["signal"],
                    r["model"],
                    r["context_bucket"],
                    r["cc_version"],
                    r["frozen_since"],
                    f"{d:.1f}",
                ]
                for r, d in aged
            ],
        )
    else:
        lines.append("  (none)")

    anomalies = conn.execute(
        "SELECT signal, model, context_bucket, started_at, direction FROM anomalies "
        "WHERE status = 'open' ORDER BY started_at DESC LIMIT 10"
    ).fetchall()
    lines += ["", "open anomalies:"]
    lines += _table(
        ["signal", "model", "bucket", "since", "dir"],
        [
            [
                a["signal"],
                a["model"] or "-",
                a["context_bucket"] or "-",
                a["started_at"],
                a["direction"] or "-",
            ]
            for a in anomalies
        ],
    )

    alerts = conn.execute(
        "SELECT ts, severity, attribution, title, suppressed_by_incident FROM alerts "
        "WHERE ts >= ? ORDER BY ts DESC LIMIT 10",
        (since,),
    ).fetchall()
    lines += ["", "alerts:"]
    lines += _table(
        ["when", "severity", "class", "title", "suppressed"],
        [
            [
                a["ts"],
                a["severity"],
                a["attribution"],
                a["title"][:40],
                a["suppressed_by_incident"] or "-",
            ]
            for a in alerts
        ],
    )

    lines += ["", "labels (30d):"]
    summary = summarize(conn, days_ago_iso(30))
    if not summary:
        lines.append("  (none yet: use the toast buttons or `vitals label <id> ...`)")
    for severity in ("CRITICAL", "WARN", "INFO"):
        counts = summary.get(severity)
        if not counts:
            continue
        rate = false_alarm_rate(counts)
        rate_text = "n/a" if rate is None else f"{rate:.0%}"
        lines.append(
            f"  {severity}: {counts['real']} real / {counts['false_alarm']} false alarm"
            f" / {counts['unsure']} unsure  (false-alarm rate {rate_text})"
        )

    lines += ["", _rule("canaries + spend")]
    cycle = conn.execute("SELECT * FROM canary_cycles ORDER BY started_at DESC LIMIT 1").fetchone()
    if cycle:
        lines.append(
            f"last cycle {cycle['started_at']} model={cycle['model']} "
            f"pass_rate={cycle['pass_rate']} runs={cycle['n_runs']} "
            f"invalid={cycle['n_invalid']} aborted={cycle['aborted_reason'] or '-'}"
        )
        rows = []
        for row in conn.execute(
            "SELECT task_id, COUNT(*) AS n, SUM(COALESCE(passed,0)) AS passed FROM canary_runs "
            "WHERE cycle_id IN (SELECT cycle_id FROM canary_cycles ORDER BY started_at DESC "
            "LIMIT 7) AND invalid = 0 GROUP BY 1 ORDER BY 1"
        ):
            rows.append(
                [row["task_id"], row["n"], row["passed"], f"{row['passed'] / row['n']:.2f}"]
            )
        lines += _table(["task (last 7 cycles)", "runs", "passed", "pass@k"], rows)
    else:
        lines.append("no canary cycles yet (Phase 2)")

    spend = conn.execute(
        "SELECT COALESCE(SUM(cost_usd),0) AS usd, COALESCE(SUM(tokens_in),0) AS tin, "
        "COALESCE(SUM(tokens_out),0) AS tout FROM spend_ledger WHERE day = ?",
        (local_day(),),
    ).fetchone()
    lines.append(
        f"spend today: ${spend['usd']:.2f}  ({spend['tin']} in / {spend['tout']} out tokens)"
    )

    incident = conn.execute(
        "SELECT incident_id, name, components FROM incidents WHERE resolved_at IS NULL "
        "ORDER BY created_at DESC LIMIT 3"
    ).fetchall()
    lines += ["", "active status-page incidents:"]
    lines += _table(
        ["id", "name", "components"],
        [[i["incident_id"], i["name"][:40], (i["components"] or "")[:30]] for i in incident],
    )

    changes = conn.execute(
        "SELECT ts, kind, old_value, new_value FROM change_points WHERE ts >= ? "
        "ORDER BY ts DESC LIMIT 8",
        (days_ago_iso(14),),
    ).fetchall()
    lines += ["", "recent change points (14d):"]
    lines += _table(
        ["when", "kind", "from", "to"],
        [
            [c["ts"], c["kind"], (c["old_value"] or "-")[:16], (c["new_value"] or "-")[:16]]
            for c in changes
        ],
    )
    return "\n".join(lines) + "\n"

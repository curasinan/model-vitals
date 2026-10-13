from __future__ import annotations

import math
import sqlite3
from collections import defaultdict

from vitals.config import DetectCfg
from vitals.db import kv_get, kv_set
from vitals.detect import signal_ids as sid
from vitals.timeutil import hour_add, hour_floor, utcnow_iso

Key = tuple[str, str, str, str, str]
UNKNOWN = "unknown"


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    pos = (len(ordered) - 1) * p
    low = math.floor(pos)
    high = math.ceil(pos)
    if low == high:
        return float(ordered[low])
    return float(ordered[low] + (ordered[high] - ordered[low]) * (pos - low))


def _median(values: list[float]) -> float | None:
    return percentile(values, 0.5)


def _log(value: float) -> float:
    return math.log(max(float(value), 1e-3))


def _hour(ts: str) -> str:
    return f"{ts[:13]}:00:00+00:00"


def _range(conn: sqlite3.Connection, since_iso: str | None) -> tuple[str | None, str]:
    end = hour_floor(utcnow_iso())
    if since_iso:
        return hour_floor(since_iso), end
    last = kv_get(conn, "last_aggregated_hour")
    if last:
        return hour_add(last, 1), end
    earliest = conn.execute(
        "SELECT MIN(ts) FROM (SELECT MIN(ts) AS ts FROM api_requests UNION ALL "
        "SELECT MIN(ts) FROM api_errors UNION ALL SELECT MIN(ts) FROM tool_results UNION ALL "
        "SELECT MIN(ts) FROM transcript_turns)"
    ).fetchone()[0]
    return (hour_floor(earliest) if earliest else None), end


def _prompt_models(conn: sqlite3.Connection, start: str, end: str) -> dict[str, str]:
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in conn.execute(
        "SELECT prompt_id, model, COUNT(*) AS c FROM api_requests "
        "WHERE prompt_id IS NOT NULL AND model IS NOT NULL GROUP BY prompt_id, model"
    ):
        counts[row["prompt_id"]][row["model"]] += row["c"]
    return {
        prompt: max(models.items(), key=lambda kv: (kv[1], kv[0]))[0]
        for prompt, models in counts.items()
    }


def _api_signals(conn: sqlite3.Connection, start: str, end: str) -> dict[Key, tuple[float, int]]:
    out: dict[Key, tuple[float, int]] = {}
    durations: dict[tuple[str, str, str, str], list[float]] = defaultdict(list)
    tokens: dict[tuple[str, str, str, str], list[float]] = defaultdict(list)
    request_counts: dict[tuple[str, str, str], int] = defaultdict(int)

    for row in conn.execute(
        "SELECT r.ts, r.model, r.context_bucket, r.duration_ms, r.output_tokens, "
        "COALESCE(r.cc_version, s.cc_version) AS ver "
        "FROM api_requests r JOIN sessions s USING(session_id) "
        "WHERE s.is_canary = 0 AND r.ts >= ? AND r.ts < ?",
        (start, end),
    ):
        hour = _hour(row["ts"])
        model = row["model"] or UNKNOWN
        bucket = row["context_bucket"] or UNKNOWN
        version = row["ver"] or UNKNOWN
        request_counts[(hour, model, version)] += 1
        if row["duration_ms"] is not None:
            durations[(hour, model, bucket, version)].append(float(row["duration_ms"]))
        if row["output_tokens"] is not None:
            tokens[(hour, model, bucket, version)].append(float(row["output_tokens"]))

    for (hour, model, bucket, version), values in durations.items():
        p95, p50 = percentile(values, 0.95), percentile(values, 0.5)
        if p95 is not None:
            out[(hour, sid.S1_LATENCY_P95, model, bucket, version)] = (_log(p95), len(values))
        if p50 is not None:
            out[(hour, sid.S1B_LATENCY_P50, model, bucket, version)] = (_log(p50), len(values))
    for (hour, model, bucket, version), values in tokens.items():
        median = _median(values)
        if median is not None:
            out[(hour, sid.S8_OUTPUT_TOKENS, model, bucket, version)] = (median, len(values))

    error_counts: dict[tuple[str, str, str], int] = defaultdict(int)
    retried: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for row in conn.execute(
        "SELECT e.ts, e.model, e.attempt, e.retries_exhausted, "
        "COALESCE(e.cc_version, s.cc_version) AS ver "
        "FROM api_errors e JOIN sessions s USING(session_id) "
        "WHERE s.is_canary = 0 AND e.source = 'otel' AND e.ts >= ? AND e.ts < ?",
        (start, end),
    ):
        key = (_hour(row["ts"]), row["model"] or UNKNOWN, row["ver"] or UNKNOWN)
        error_counts[key] += 1
        if row["attempt"] is not None or row["retries_exhausted"]:
            on_retry = bool(row["retries_exhausted"]) or (row["attempt"] or 0) >= 1
            retried[key].append(1 if on_retry else 0)

    for key in set(request_counts) | set(error_counts):
        hour, model, version = key
        errors = error_counts.get(key, 0)
        total = request_counts.get(key, 0) + errors
        if total:
            out[(hour, sid.S2_ERROR_RATE, model, "all", version)] = (errors / total, total)
    for key, flags in retried.items():
        hour, model, version = key
        out[(hour, sid.S3_RETRY_RATE, model, "all", version)] = (
            sum(flags) / len(flags),
            len(flags),
        )
    return out


def _tool_signals(
    conn: sqlite3.Connection, rows: list[dict], models: dict[str, str], cfg: DetectCfg
) -> dict[Key, tuple[float, int]]:
    out: dict[Key, tuple[float, int]] = {}
    per_tool: dict[tuple[str, str, str, str], list[int]] = defaultdict(list)
    signal_for = {
        "Edit": sid.S4_TOOL_FAIL_EDIT,
        "Write": sid.S4_TOOL_FAIL_WRITE,
        "Bash": sid.S4_TOOL_FAIL_BASH,
    }

    for row in rows:
        if row["success"] is None:
            continue
        hour = _hour(row["ts"])
        model = models.get(row["prompt_id"] or "", "all")
        version = row["ver"] or UNKNOWN
        failed = 0 if row["success"] else 1
        per_tool[(hour, sid.S4_TOOL_FAIL_ALL, model, version)].append(failed)
        signal = signal_for.get(row["tool_name"])
        if signal:
            per_tool[(hour, signal, model, version)].append(failed)

    for (hour, signal, model, version), values in per_tool.items():
        out[(hour, signal, model, "all", version)] = (sum(values) / len(values), len(values))

    edits: dict[tuple[str, str, str], dict[str, dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(int))
    )
    for row in rows:
        if row["tool_name"] not in ("Edit", "Write", "NotebookEdit") or not row["file_path"]:
            continue
        if not row["prompt_id"]:
            continue
        key = (_hour(row["ts"]), models.get(row["prompt_id"], "all"), row["ver"] or UNKNOWN)
        edits[key][row["prompt_id"]][row["file_path"]] += 1
    for (hour, model, version), prompts in edits.items():
        looping = sum(1 for files in prompts.values() if max(files.values()) >= cfg.edit_loop_n)
        out[(hour, sid.S5_EDIT_LOOP_RATE, model, "all", version)] = (
            looping / len(prompts),
            len(prompts),
        )

    edited_prompts = {
        row["prompt_id"]
        for row in rows
        if row["tool_name"] in ("Edit", "Write", "NotebookEdit") and row["prompt_id"]
    }
    runs: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for row in rows:
        if not row["test_runner"] or row["prompt_id"] not in edited_prompts:
            continue
        key = (_hour(row["ts"]), models.get(row["prompt_id"], "all"), row["ver"] or UNKNOWN)
        runs[key].append(1 if (row["tests_failed"] or 0) > 0 else 0)
    for (hour, model, version), values in runs.items():
        out[(hour, sid.S6_TEST_FAIL_AFTER_EDIT, model, "all", version)] = (
            sum(values) / len(values),
            len(values),
        )
    return out


def _post_compaction_signal(
    conn: sqlite3.Connection, rows: list[dict], models: dict[str, str], start: str, end: str
) -> dict[Key, tuple[float, int]]:
    inside_ids = {
        row["tool_use_id"]
        for row in conn.execute(
            "SELECT tool_use_id FROM v_post_compaction_turns WHERE ts >= ? AND ts < ?",
            (start, end),
        )
        if row["tool_use_id"]
    }
    if not inside_ids:
        return {}

    inside: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    outside: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for row in rows:
        if row["success"] is None:
            continue
        key = (
            _hour(row["ts"]),
            models.get(row["prompt_id"] or "", "all"),
            row["ver"] or UNKNOWN,
        )
        bucket = inside if row.get("tool_use_id") in inside_ids else outside
        bucket[key].append(0 if row["success"] else 1)

    out: dict[Key, tuple[float, int]] = {}
    for key, values in inside.items():
        base = outside.get(key)
        if not base or len(values) < 5 or len(base) < 5:
            continue
        base_rate = sum(base) / len(base)
        if base_rate <= 0:
            continue
        hour, model, version = key
        out[(hour, sid.S9_POST_COMPACTION_FAIL, model, "all", version)] = (
            (sum(values) / len(values)) / base_rate,
            len(values),
        )
    return out


def _selfcorr_signal(
    conn: sqlite3.Connection, start: str, end: str
) -> dict[Key, tuple[float, int]]:
    counts: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for row in conn.execute(
        "SELECT t.ts, t.model, t.self_corr_hits, COALESCE(t.cc_version, s.cc_version) AS ver "
        "FROM transcript_turns t JOIN sessions s USING(session_id) "
        "WHERE s.is_canary = 0 AND t.is_sidechain = 0 AND t.role = 'assistant' "
        "AND t.ts >= ? AND t.ts < ?",
        (start, end),
    ):
        key = (_hour(row["ts"]), row["model"] or "all", row["ver"] or UNKNOWN)
        counts[key].append(int(row["self_corr_hits"] or 0))
    return {
        (hour, sid.S7_SELF_CORR_RATE, model, "all", version): (
            sum(values) / len(values),
            len(values),
        )
        for (hour, model, version), values in counts.items()
    }


def aggregate_hours(conn: sqlite3.Connection, cfg: DetectCfg, since_iso: str | None = None) -> int:
    start, end = _range(conn, since_iso)
    if not start or start >= end:
        return 0

    models = _prompt_models(conn, start, end)
    tool_rows = [
        dict(row)
        for row in conn.execute(
            "SELECT t.ts, t.prompt_id, t.tool_name, t.success, t.file_path, t.test_runner, "
            "t.tests_failed, t.tool_use_id, s.cc_version AS ver "
            "FROM tool_results t JOIN sessions s USING(session_id) "
            "WHERE s.is_canary = 0 AND t.is_sidechain = 0 AND t.ts >= ? AND t.ts < ?",
            (start, end),
        )
    ]

    windows: dict[Key, tuple[float, int]] = {}
    windows.update(_api_signals(conn, start, end))
    windows.update(_tool_signals(conn, tool_rows, models, cfg))
    windows.update(_post_compaction_signal(conn, tool_rows, models, start, end))
    windows.update(_selfcorr_signal(conn, start, end))

    inserted = 0
    for (hour, signal, model, bucket, version), (value, n) in sorted(windows.items()):
        if n <= 0:
            continue
        cursor = conn.execute(
            "INSERT OR IGNORE INTO signal_windows(window_start, signal, model, context_bucket, "
            "value, n, cc_version) VALUES (?,?,?,?,?,?,?)",
            (hour, signal, model, bucket, value, n, version),
        )
        inserted += cursor.rowcount
    kv_set(conn, "last_aggregated_hour", hour_add(end, -1))
    conn.commit()
    return inserted

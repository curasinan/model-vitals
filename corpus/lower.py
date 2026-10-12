from __future__ import annotations

import sqlite3
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from typing import TYPE_CHECKING, Any

from vitals.canary.checkers import default_tasks_dir, load_tasks
from vitals.config import DetectCfg
from vitals.db import init_db
from vitals.detect import signal_ids as sid
from vitals.detect.signals import UNKNOWN, Key, _prompt_models, aggregate_hours
from vitals.timeutil import hour_floor, utcnow_iso

if TYPE_CHECKING:  # pragma: no cover
    import pyarrow as pa

STORE_TABLES: tuple[str, ...] = (
    "sessions",
    "api_requests",
    "api_errors",
    "canary_cycles",
    "canary_runs",
    "change_points",
    "signal_windows",
)

CORPUS_TABLES: tuple[str, ...] = (
    "requests",
    "tool_results",
    "turn_features",
    "canary_cycles",
    "change_points",
)

S4_SIGNAL_FOR: dict[str, str] = {
    "Edit": sid.S4_TOOL_FAIL_EDIT,
    "Write": sid.S4_TOOL_FAIL_WRITE,
    "Bash": sid.S4_TOOL_FAIL_BASH,
}


@dataclass(frozen=True)
class LoweringReport:
    rows_written: dict[str, int]
    signals_written: dict[str, int]
    unmapped: dict[str, int]
    span_hours: int


@dataclass
class _Counters:
    rows: dict[str, int] = field(default_factory=dict)
    unmapped: dict[str, int] = field(default_factory=dict)

    def wrote(self, table: str, count: int) -> None:
        if count > 0:
            self.rows[table] = self.rows.get(table, 0) + count

    def lost(self, reason: str, count: int = 1) -> None:
        if count > 0:
            self.unmapped[reason] = self.unmapped.get(reason, 0) + count

    def lost_cells(self, rows: Iterable[Mapping[str, Any]], column: str, reason: str) -> None:
        self.lost(reason, sum(1 for row in rows if row.get(column) is not None))


def _rows(corpus: Mapping[str, pa.Table], table: str) -> list[dict[str, Any]]:
    arrow = corpus.get(table)
    if arrow is None:
        return []
    rows: list[dict[str, Any]] = list(arrow.to_pylist())
    return rows


def _hour_iso(moment: Any) -> str:
    if not isinstance(moment, datetime):  # pragma: no cover
        raise TypeError("a corpus timestamp column must lower from a datetime")
    floored = moment.astimezone(UTC).replace(minute=0, second=0, microsecond=0)
    return floored.isoformat(timespec="seconds")


def _modal(values: Sequence[str]) -> str | None:
    if not values:
        return None
    counts = Counter(values)
    return max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0]


def _prompt_id(session_hash: str, prompt_seq: int) -> str:
    return f"{session_hash}#{prompt_seq}"


def _int_or_none(value: Any) -> int | None:
    return None if value is None else int(value)


@lru_cache(maxsize=1)
def _long_context_task_ids() -> frozenset[str]:
    try:
        return frozenset(
            task.task_id for task in load_tasks(default_tasks_dir()) if task.long_context
        )
    except (OSError, ValueError):  # pragma: no cover
        return frozenset()


def _lower_sessions(
    conn: sqlite3.Connection, requests: list[dict[str, Any]], counters: _Counters
) -> dict[str, str | None]:
    versions: dict[str, list[str]] = defaultdict(list)
    plugins: dict[str, list[str]] = defaultdict(list)
    for row in requests:
        session = str(row["session_hash"])
        versions.setdefault(session, [])
        if row.get("cc_version") is not None:
            versions[session].append(str(row["cc_version"]))
        if row.get("plugins_hash") is not None:
            plugins[session].append(str(row["plugins_hash"]))

    chosen_version: dict[str, str | None] = {}
    chosen_plugins: dict[str, str | None] = {}
    written = 0
    for session in sorted(versions):
        chosen_version[session] = _modal(versions[session])
        chosen_plugins[session] = _modal(plugins.get(session, []))
        cursor = conn.execute(
            "INSERT OR IGNORE INTO sessions(session_id, cc_version, plugins_hash, is_canary)"
            " VALUES (?,?,?,0)",
            (session, chosen_version[session], chosen_plugins[session]),
        )
        written += cursor.rowcount
    counters.wrote("sessions", written)

    counters.lost(
        "requests.plugins_hash.session_grain_only",
        sum(
            1
            for row in requests
            if row.get("plugins_hash") is not None
            and row["plugins_hash"] != chosen_plugins.get(str(row["session_hash"]))
        ),
    )
    return chosen_version


def _lower_requests(
    conn: sqlite3.Connection, requests: list[dict[str, Any]], counters: _Counters
) -> None:
    successes = [row for row in requests if row.get("error_class") == "none"]
    failures = [row for row in requests if row.get("error_class") != "none"]

    written = 0
    for row in successes:
        seq = _int_or_none(row.get("prompt_seq"))
        written += conn.execute(
            "INSERT INTO api_requests(session_id, prompt_id, ts, model, input_tokens,"
            " output_tokens, cache_read_tokens, duration_ms, context_bucket, cc_version, source)"
            " VALUES (?,?,?,?,?,?,?,?,?,?, 'otel')",
            (
                str(row["session_hash"]),
                None if seq is None else _prompt_id(str(row["session_hash"]), seq),
                _hour_iso(row["ts_bucket_utc"]),
                row.get("model"),
                _int_or_none(row.get("input_tokens")),
                _int_or_none(row.get("output_tokens")),
                _int_or_none(row.get("cache_read_tokens")),
                row.get("latency_ms"),
                row.get("context_bucket"),
                row.get("cc_version"),
            ),
        ).rowcount
    counters.wrote("api_requests", written)

    written = 0
    for row in failures:
        seq = _int_or_none(row.get("prompt_seq"))
        written += conn.execute(
            "INSERT INTO api_errors(session_id, prompt_id, ts, model, attempt,"
            " retries_exhausted, duration_ms, cc_version, source) VALUES (?,?,?,?,?,0,?,?, 'otel')",
            (
                str(row["session_hash"]),
                None if seq is None else _prompt_id(str(row["session_hash"]), seq),
                _hour_iso(row["ts_bucket_utc"]),
                row.get("model"),
                _int_or_none(row.get("retries")),
                row.get("latency_ms"),
                row.get("cc_version"),
            ),
        ).rowcount
    counters.wrote("api_errors", written)

    counters.lost_cells(requests, "request_seq", "requests.request_seq.no_store_column")
    counters.lost(
        "requests.post_compaction.s9_unreachable_no_compaction_evidence",
        sum(1 for row in requests if row.get("post_compaction") is not None),
    )
    counters.lost(
        "requests.error_class.subclass_not_stored",
        sum(1 for row in requests if row.get("error_class") not in (None, "none")),
    )
    counters.lost_cells(successes, "retries", "requests.retries.no_attempt_column_on_api_requests")
    counters.lost("requests.retries.null_attempt_indistinguishable_from_zero", len(failures))
    counters.lost_cells(
        failures, "context_bucket", "requests.context_bucket.api_errors_has_no_context_bucket"
    )
    for column in ("input_tokens", "output_tokens", "cache_read_tokens"):
        counters.lost_cells(failures, column, f"requests.{column}.api_errors_has_no_token_columns")


def _prompt_hours(requests: list[dict[str, Any]]) -> dict[tuple[str, int], str]:
    hours: dict[tuple[str, int], str] = {}
    for row in requests:
        seq = _int_or_none(row.get("prompt_seq"))
        if seq is None:
            continue
        key = (str(row["session_hash"]), seq)
        moment = _hour_iso(row["ts_bucket_utc"])
        if key not in hours or moment < hours[key]:
            hours[key] = moment
    return hours


def _stratum(
    row: Mapping[str, Any],
    prompt_hours: Mapping[tuple[str, int], str],
    prompt_models: Mapping[str, str],
    session_versions: Mapping[str, str | None],
) -> tuple[str, str, str] | None:
    session = str(row["session_hash"])
    seq = _int_or_none(row.get("prompt_seq"))
    if seq is None:
        return None
    hour = prompt_hours.get((session, seq))
    if hour is None:
        return None
    model = prompt_models.get(_prompt_id(session, seq), "all")
    return hour, model, session_versions.get(session) or UNKNOWN


def _s5_windows(
    turns: list[dict[str, Any]],
    prompt_hours: Mapping[tuple[str, int], str],
    prompt_models: Mapping[str, str],
    session_versions: Mapping[str, str | None],
    cfg: DetectCfg,
    counters: _Counters,
) -> dict[Key, tuple[float, int]]:
    groups: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for row in turns:
        stratum = _stratum(row, prompt_hours, prompt_models, session_versions)
        if stratum is None:
            counters.lost("turn_features.no_request_hour")
            continue
        retry = int(row.get("edit_retry_max") or 0)
        if retry <= 0:
            continue
        groups[stratum].append(1 if retry >= cfg.edit_loop_n else 0)

    counters.lost_cells(
        turns, "self_correction", "turn_features.self_correction.s7_needs_transcript_turns"
    )
    counters.lost_cells(turns, "tool_calls", "turn_features.tool_calls.s4_uses_tool_results")
    counters.lost_cells(turns, "tool_failures", "turn_features.tool_failures.s4_uses_tool_results")
    return {
        (hour, sid.S5_EDIT_LOOP_RATE, model, "all", version): (
            sum(values) / len(values),
            len(values),
        )
        for (hour, model, version), values in groups.items()
    }


def _s4_windows(
    tools: list[dict[str, Any]],
    prompt_hours: Mapping[tuple[str, int], str],
    prompt_models: Mapping[str, str],
    session_versions: Mapping[str, str | None],
    counters: _Counters,
) -> dict[Key, tuple[float, int]]:
    per_tool: dict[tuple[str, str, str, str], list[int]] = defaultdict(list)
    for row in tools:
        stratum = _stratum(row, prompt_hours, prompt_models, session_versions)
        if stratum is None:
            counters.lost("tool_results.no_request_hour")
            continue
        ok = row.get("ok")
        if ok is None:
            continue
        hour, model, version = stratum
        failed = 0 if ok else 1
        per_tool[(hour, sid.S4_TOOL_FAIL_ALL, model, version)].append(failed)
        signal = S4_SIGNAL_FOR.get(str(row.get("tool")))
        if signal:
            per_tool[(hour, signal, model, version)].append(failed)

    counters.lost_cells(
        tools, "duration_ms", "tool_results.duration_ms.no_signal_consumes_tool_duration"
    )
    counters.lost_cells(
        tools, "file_hash", "tool_results.file_hash.s5_uses_the_turn_features_mirror"
    )
    for column in ("test_exit_code", "test_runner"):
        counters.lost_cells(tools, column, f"tool_results.{column}.s6_outside_the_fixed_routes")
    return {
        (hour, signal, model, "all", version): (sum(values) / len(values), len(values))
        for (hour, signal, model, version), values in per_tool.items()
    }


def _write_windows(conn: sqlite3.Connection, windows: Mapping[Key, tuple[float, int]]) -> None:
    end = hour_floor(utcnow_iso())
    for (hour, signal, model, bucket, version), (value, n) in sorted(windows.items()):
        if n <= 0 or hour >= end:
            continue
        conn.execute(
            "INSERT OR IGNORE INTO signal_windows(window_start, signal, model, context_bucket, "
            "value, n, cc_version) VALUES (?,?,?,?,?,?,?)",
            (hour, signal, model, bucket, value, n, version),
        )


def _lower_change_points(
    conn: sqlite3.Connection, changes: list[dict[str, Any]], counters: _Counters
) -> None:
    written = 0
    for row in sorted(changes, key=lambda r: (_hour_iso(r["ts_bucket_utc"]), str(r.get("kind")))):
        written += conn.execute(
            "INSERT INTO change_points(ts, kind, old_value, new_value) VALUES (?,?,?,?)",
            (
                _hour_iso(row["ts_bucket_utc"]),
                row.get("kind"),
                row.get("from_hash"),
                row.get("to_hash"),
            ),
        ).rowcount
    counters.wrote("change_points", written)


def _lower_canaries(
    conn: sqlite3.Connection, cycles: list[dict[str, Any]], counters: _Counters
) -> None:
    long_context = _long_context_task_ids()
    by_cycle: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in cycles:
        by_cycle[int(row["cycle_id"])].append(row)

    cycles_written = 0
    runs_written = 0
    for cycle_id in sorted(by_cycle):
        tasks = sorted(by_cycle[cycle_id], key=lambda r: str(r["task_id"]))
        started = min(_hour_iso(row["ts_bucket_utc"]) for row in tasks)
        model = _modal([str(r["model"]) for r in tasks if r.get("model") is not None])
        version = _modal([str(r["cc_version"]) for r in tasks if r.get("cc_version") is not None])
        costs = [float(r["cost_usd"]) for r in tasks if r.get("cost_usd") is not None]

        cheap = [r for r in tasks if str(r["task_id"]) not in long_context]
        n_runs = sum(int(r.get("runs") or 0) for r in cheap)
        n_pass = sum(int(r.get("passes") or 0) for r in cheap)
        n_invalid = sum(int(r.get("invalid") or 0) for r in cheap)
        valid = n_runs - n_invalid
        cycles_written += conn.execute(
            "INSERT OR IGNORE INTO canary_cycles(cycle_id, started_at, model, effort, cc_version,"
            " suite_hash, n_runs, n_pass, n_invalid, pass_rate, cost_usd)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                cycle_id,
                started,
                model or UNKNOWN,
                UNKNOWN,
                version,
                UNKNOWN,
                n_runs,
                n_pass,
                n_invalid,
                (n_pass / valid) if valid > 0 else None,
                sum(costs) if costs else None,
            ),
        ).rowcount

        for row in tasks:
            task_id = str(row["task_id"])
            runs = int(row.get("runs") or 0)
            passed = min(int(row.get("passes") or 0), runs)
            invalid = min(int(row.get("invalid") or 0), max(runs - passed, 0))
            if int(row.get("passes") or 0) + int(row.get("invalid") or 0) > runs:
                counters.lost("canary_cycles.runs.passes_plus_invalid_exceeds_runs")
            failed = max(runs - passed - invalid, 0)
            outcomes: list[int | None] = [1] * passed + [0] * failed + [None] * invalid
            for attempt, outcome in enumerate(outcomes):
                runs_written += conn.execute(
                    "INSERT INTO canary_runs(cycle_id, task_id, attempt, ts, model, passed,"
                    " invalid, long_context) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        cycle_id,
                        task_id,
                        attempt,
                        started,
                        row.get("model"),
                        outcome,
                        1 if outcome is None else 0,
                        1 if task_id in long_context else 0,
                    ),
                ).rowcount

    counters.wrote("canary_cycles", cycles_written)
    counters.wrote("canary_runs", runs_written)
    counters.lost_cells(
        cycles, "latency_ms_p50", "canary_cycles.latency_ms_p50.no_per_run_grain_in_store"
    )
    counters.lost_cells(
        cycles, "tokens_total", "canary_cycles.tokens_total.store_splits_tokens_in_and_out"
    )


def _signal_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {
        str(row[0]): int(row[1])
        for row in conn.execute("SELECT signal, COUNT(*) FROM signal_windows GROUP BY signal")
    }


def _span_hours(rows: Iterable[str]) -> int:
    stamps = sorted(rows)
    if not stamps:
        return 0
    first = datetime.fromisoformat(stamps[0])
    last = datetime.fromisoformat(stamps[-1])
    return int((last - first).total_seconds() // 3600) + 1


def lower_corpus(corpus: Mapping[str, pa.Table], conn: sqlite3.Connection) -> LoweringReport:
    init_db(conn)
    cfg = DetectCfg()
    counters = _Counters(rows=dict.fromkeys(STORE_TABLES, 0))

    tables = {name: _rows(corpus, name) for name in CORPUS_TABLES}
    requests = tables["requests"]

    session_versions = _lower_sessions(conn, requests, counters)
    _lower_requests(conn, requests, counters)
    _lower_change_points(conn, tables["change_points"], counters)
    _lower_canaries(conn, tables["canary_cycles"], counters)
    conn.commit()

    before = _signal_counts(conn)
    aggregate_hours(conn, cfg)

    prompt_hours = _prompt_hours(requests)
    prompt_models = _prompt_models(conn, "", "")
    mirrored: dict[Key, tuple[float, int]] = {}
    mirrored.update(
        _s5_windows(
            tables["turn_features"], prompt_hours, prompt_models, session_versions, cfg, counters
        )
    )
    mirrored.update(
        _s4_windows(tables["tool_results"], prompt_hours, prompt_models, session_versions, counters)
    )
    _write_windows(conn, mirrored)
    conn.commit()

    after = _signal_counts(conn)
    signals_written = {
        name: count - before.get(name, 0)
        for name, count in sorted(after.items())
        if count - before.get(name, 0) > 0
    }
    counters.wrote("signal_windows", sum(signals_written.values()))

    span = [_hour_iso(row["ts_bucket_utc"]) for row in requests]
    span += [_hour_iso(row["ts_bucket_utc"]) for row in tables["canary_cycles"]]
    span += [_hour_iso(row["ts_bucket_utc"]) for row in tables["change_points"]]
    return LoweringReport(
        rows_written=counters.rows,
        signals_written=signals_written,
        unmapped=dict(sorted(counters.unmapped.items())),
        span_hours=_span_hours(span),
    )

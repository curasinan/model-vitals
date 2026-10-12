from __future__ import annotations

import argparse
import json
import os
import sqlite3
import statistics
import sys
from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from corpus import schema  # noqa: E402
from corpus.schema import ColumnKind, Hasher, SchemaGate  # noqa: E402

EXTRACTOR_VERSION = "1.0.0"

SIZE_CAP_BYTES = 50 * 1024 * 1024

MIN_SAMPLING_RATE = 1e-4

POST_COMPACTION_WINDOW_S = 900

EDIT_TOOLS = frozenset({"Edit", "Write", "NotebookEdit"})

TABLE_ORDER = ("requests", "tool_results", "turn_features", "canary_cycles", "change_points")

Row = dict[str, Any]


class StoreNotFound(RuntimeError): ...


def resolve_db_path() -> Path:
    from vitals import config

    return Path(config.load().db_path)


def open_readonly(db_path: Path | str) -> sqlite3.Connection:
    path = Path(db_path)
    if not path.is_file():
        raise StoreNotFound(
            "the event store does not exist at the location vitals.config resolves to "
            "(path withheld: it is under the user profile). Check VITALS_DATA_DIR, or run "
            "`vitals status` to confirm collection is installed."
        )
    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    return conn


def _epoch(iso: str) -> int:
    return int(schema.parse_instant(iso).timestamp())


def _int(value: Any, column: str) -> int | None:
    if value is None:
        return None
    result: int | None = None
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = None
    if result is None:
        raise schema.unreadable(column)
    return result


def _ms(value: Any, column: str) -> int | None:
    if value is None:
        return None
    result: int | None = None
    try:
        result = int(round(float(value)))
    except (TypeError, ValueError):
        result = None
    if result is None:
        raise schema.unreadable(column)
    return result


def _float(value: Any, column: str) -> float:
    result: float | None = None
    try:
        result = float(value)
    except (TypeError, ValueError):
        result = None
    if result is None:
        raise schema.unreadable(column)
    return result


def prompt_ordinals(conn: sqlite3.Connection) -> dict[tuple[str, str], int]:
    earliest: dict[tuple[str, str], int] = {}
    for row in conn.execute(
        """
        SELECT session_id, prompt_id, ts FROM api_requests WHERE prompt_id IS NOT NULL
        UNION ALL
        SELECT session_id, prompt_id, ts FROM api_errors
          WHERE prompt_id IS NOT NULL AND source = 'otel'
        UNION ALL
        SELECT session_id, prompt_id, ts FROM tool_results WHERE prompt_id IS NOT NULL
        UNION ALL
        SELECT session_id, prompt_id, ts FROM transcript_turns
          WHERE prompt_id IS NOT NULL AND ts IS NOT NULL
        """
    ):
        key = (row["session_id"], row["prompt_id"])
        when = _epoch(row["ts"])
        if when < earliest.get(key, when + 1):
            earliest[key] = when

    by_session: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for (session_id, prompt_id), when in earliest.items():
        by_session[session_id].append((when, prompt_id))
    ordinals: dict[tuple[str, str], int] = {}
    for session_id, prompts in by_session.items():
        for seq, (_when, prompt_id) in enumerate(sorted(prompts)):
            ordinals[(session_id, prompt_id)] = seq
    return ordinals


def compaction_windows(conn: sqlite3.Connection) -> dict[str, list[int]]:
    windows: dict[str, list[int]] = defaultdict(list)
    for row in conn.execute("SELECT session_id, ts FROM v_compaction_episodes"):
        if row["session_id"] and row["ts"]:
            windows[row["session_id"]].append(_epoch(row["ts"]))
    for starts in windows.values():
        starts.sort()
    return windows


def _post_compaction(windows: dict[str, list[int]], session_id: str, when: int) -> bool:
    return any(
        start <= when <= start + POST_COMPACTION_WINDOW_S for start in windows.get(session_id, ())
    )


def build_requests(
    conn: sqlite3.Connection,
    gate: SchemaGate,
    hasher: Hasher,
    ordinals: dict[tuple[str, str], int],
    windows: dict[str, list[int]],
    plugins: dict[str, str | None],
) -> tuple[list[Row], int]:
    known_request_ids = {
        r[0]
        for r in conn.execute("SELECT request_id FROM api_requests WHERE request_id IS NOT NULL")
    }
    deduped = 0
    staged: list[tuple[str, str, int, tuple[int, int], Row]] = []

    def stage(
        session_id: str, prompt_id: str | None, ts: str, order: tuple[int, int], row: Row
    ) -> None:
        seq = ordinals.get((session_id, prompt_id)) if prompt_id else None
        row["session_hash"] = hasher.hash("session", session_id)
        row["prompt_seq"] = seq
        row["ts_bucket_utc"] = schema.hour_bucket(ts)
        plugin = plugins.get(session_id)
        row["plugins_hash"] = hasher.hash("plugins", plugin) if plugin else None
        row["post_compaction"] = _post_compaction(windows, session_id, _epoch(ts))
        staged.append((session_id, prompt_id or "", _epoch(ts), order, row))

    for r in conn.execute(
        "SELECT id, session_id, prompt_id, ts, model, input_tokens, output_tokens,"
        " cache_read_tokens, duration_ms, context_bucket, cc_version FROM api_requests"
    ):
        stage(
            r["session_id"],
            r["prompt_id"],
            r["ts"],
            (0, r["id"]),
            {
                "model": gate.enum("model", r["model"], column="requests.model"),
                "cc_version": gate.version(r["cc_version"], column="requests.cc_version"),
                "context_bucket": gate.enum(
                    "context_bucket", r["context_bucket"], column="requests.context_bucket"
                ),
                "input_tokens": _int(r["input_tokens"], "api_requests.input_tokens"),
                "output_tokens": _int(r["output_tokens"], "api_requests.output_tokens"),
                "cache_read_tokens": _int(r["cache_read_tokens"], "api_requests.cache_read_tokens"),
                "latency_ms": _ms(r["duration_ms"], "api_requests.duration_ms"),
                "retries": 0,
                "error_class": "none",
            },
        )

    for r in conn.execute(
        "SELECT id, session_id, prompt_id, ts, model, status_code, attempt, retries_exhausted,"
        " error_text, duration_ms, cc_version, request_id FROM api_errors"
        " WHERE source = 'otel'"
    ):
        if r["request_id"] is not None and r["request_id"] in known_request_ids:
            deduped += 1
            continue
        stage(
            r["session_id"],
            r["prompt_id"],
            r["ts"],
            (1, r["id"]),
            {
                "model": gate.enum("model", r["model"], column="requests.model"),
                "cc_version": gate.version(r["cc_version"], column="requests.cc_version"),
                "context_bucket": None,
                "input_tokens": None,
                "output_tokens": None,
                "cache_read_tokens": None,
                "latency_ms": _ms(r["duration_ms"], "api_errors.duration_ms"),
                "retries": schema.derive_retries(r["attempt"], r["retries_exhausted"]),
                "error_class": schema.classify_error(r["status_code"], r["error_text"]),
            },
        )

    staged.sort(key=lambda item: (item[0], item[1], item[2], item[3]))
    counters: dict[tuple[str, str], int] = defaultdict(int)
    rows: list[Row] = []
    for session_id, prompt_key, _when, _order, row in staged:
        key = (session_id, prompt_key)
        row["request_seq"] = counters[key]
        counters[key] += 1
        rows.append(row)
    return rows, deduped


def build_tool_results(
    tool_rows: Sequence[sqlite3.Row],
    gate: SchemaGate,
    hasher: Hasher,
    ordinals: dict[tuple[str, str], int],
) -> list[Row]:
    rows: list[Row] = []
    for r in tool_rows:
        seq = ordinals.get((r["session_id"], r["prompt_id"]))
        if seq is None:  # pragma: no cover
            continue
        path = r["file_path"]
        runner = gate.enum("test_runner", r["test_runner"], column="tool_results.test_runner")
        rows.append(
            {
                "session_hash": hasher.hash("session", r["session_id"]),
                "prompt_seq": seq,
                "tool": gate.enum(
                    "tool",
                    schema.normalize_tool_name(r["tool_name"]),
                    column="tool_results.tool",
                ),
                "ok": None if r["success"] is None else bool(r["success"]),
                "duration_ms": _ms(r["duration_ms"], "tool_results.duration_ms"),
                "file_hash": (
                    hasher.hash("file", schema.normalize_file_path(path)) if path else None
                ),
                "test_exit_code": (
                    _int(r["bash_exit_code"], "tool_results.bash_exit_code") if runner else None
                ),
                "test_runner": runner,
            }
        )
    return rows


def build_turn_features(
    conn: sqlite3.Connection,
    hasher: Hasher,
    ordinals: dict[tuple[str, str], int],
    tool_rows: Sequence[sqlite3.Row],
) -> list[Row]:
    calls: dict[tuple[str, str], int] = defaultdict(int)
    failures: dict[tuple[str, str], int] = defaultdict(int)
    edits: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in tool_rows:
        key = (r["session_id"], r["prompt_id"])
        calls[key] += 1
        if r["success"] == 0:
            failures[key] += 1
        if r["tool_name"] in EDIT_TOOLS and r["file_path"]:
            edits[key][schema.normalize_file_path(r["file_path"])] += 1

    corrected: set[tuple[str, str]] = set()
    for r in conn.execute(
        "SELECT session_id, prompt_id FROM transcript_turns"
        " WHERE prompt_id IS NOT NULL AND self_corr_hits > 0"
    ):
        corrected.add((r["session_id"], r["prompt_id"]))

    rows: list[Row] = []
    for (session_id, prompt_id), seq in ordinals.items():
        key = (session_id, prompt_id)
        per_file = edits.get(key)
        rows.append(
            {
                "session_hash": hasher.hash("session", session_id),
                "prompt_seq": seq,
                "self_correction": key in corrected,
                "edit_retry_max": max(per_file.values()) if per_file else 0,
                "tool_calls": calls.get(key, 0),
                "tool_failures": failures.get(key, 0),
            }
        )
    rows.sort(key=lambda row: (row["session_hash"], row["prompt_seq"]))
    return rows


def build_canary_cycles(conn: sqlite3.Connection, gate: SchemaGate) -> list[Row]:
    grouped: dict[tuple[int, str], list[sqlite3.Row]] = defaultdict(list)
    meta: dict[int, sqlite3.Row] = {}
    for r in conn.execute(
        "SELECT c.cycle_id AS cycle_id, c.started_at AS started_at, c.model AS model,"
        " c.cc_version AS cc_version, r.task_id AS task_id, r.passed AS passed,"
        " r.invalid AS invalid, r.duration_ms AS duration_ms, r.input_tokens AS input_tokens,"
        " r.output_tokens AS output_tokens, r.cost_usd AS cost_usd"
        " FROM canary_runs r JOIN canary_cycles c ON c.cycle_id = r.cycle_id"
    ):
        grouped[(r["cycle_id"], r["task_id"])].append(r)
        meta[r["cycle_id"]] = r

    rows: list[Row] = []
    for (cycle_id, task_id), runs in sorted(grouped.items()):
        head = meta[cycle_id]
        latencies = [
            _float(r["duration_ms"], "canary_runs.duration_ms")
            for r in runs
            if r["duration_ms"] is not None
        ]
        token_rows = [
            r for r in runs if r["input_tokens"] is not None or r["output_tokens"] is not None
        ]
        costs = [
            _float(r["cost_usd"], "canary_runs.cost_usd") for r in runs if r["cost_usd"] is not None
        ]
        rows.append(
            {
                "cycle_id": _int(cycle_id, "canary_cycles.cycle_id"),
                "ts_bucket_utc": schema.hour_bucket(head["started_at"]),
                "model": gate.enum("model", head["model"], column="canary_cycles.model"),
                "cc_version": gate.version(head["cc_version"], column="canary_cycles.cc_version"),
                "task_id": gate.enum("canary_task_id", task_id, column="canary_cycles.task_id"),
                "runs": len(runs),
                "passes": sum(1 for r in runs if r["passed"] == 1),
                "invalid": sum(1 for r in runs if r["invalid"] == 1),
                "latency_ms_p50": (int(round(statistics.median(latencies))) if latencies else None),
                "tokens_total": (
                    sum(
                        (_int(r["input_tokens"], "canary_runs.input_tokens") or 0)
                        + (_int(r["output_tokens"], "canary_runs.output_tokens") or 0)
                        for r in token_rows
                    )
                    if token_rows
                    else None
                ),
                "cost_usd": sum(costs) if costs else None,
            }
        )
    return rows


def build_change_points(conn: sqlite3.Connection, gate: SchemaGate, hasher: Hasher) -> list[Row]:
    rows: list[Row] = []
    for r in conn.execute(
        "SELECT ts, kind, old_value, new_value FROM change_points ORDER BY ts, id"
    ):
        rows.append(
            {
                "ts_bucket_utc": schema.hour_bucket(r["ts"]),
                "kind": gate.enum("change_point_kind", r["kind"], column="change_points.kind"),
                "from_hash": (hasher.hash("change", r["old_value"]) if r["old_value"] else None),
                "to_hash": hasher.hash("change", r["new_value"]) if r["new_value"] else None,
            }
        )
    return rows


def _validate(table: str, rows: Iterable[Row]) -> None:
    columns = schema.TABLES[table]
    for row in rows:
        for col in columns:
            value = row.get(col.name)
            if value is None:
                if not col.nullable:
                    raise ValueError(f"{table}.{col.name} is not nullable but a row is null")
                continue
            ok: bool
            match col.kind:
                case ColumnKind.INT:
                    ok = isinstance(value, int) and not isinstance(value, bool)
                case ColumnKind.FLOAT:
                    ok = isinstance(value, float | int) and not isinstance(value, bool)
                case ColumnKind.BOOL:
                    ok = isinstance(value, bool)
                case ColumnKind.TIMESTAMP:
                    ok = isinstance(value, datetime) and value.tzinfo is not None
                case ColumnKind.ENUM:
                    ok = isinstance(value, str) and value in schema.ENUMS[str(col.enum)]
                case ColumnKind.HASH:
                    ok = isinstance(value, str) and bool(schema.HASH_RE.match(value))
                case ColumnKind.VERSION:
                    ok = isinstance(value, str) and bool(schema.CC_VERSION_RE.match(value))
            if not ok:
                raise ValueError(
                    f"{table}.{col.name} holds a value that is not a valid"
                    f" {col.kind.value} (value withheld by design)"
                )


def keep_session(session_hash: str, rate: float) -> bool:
    if rate >= 1.0:
        return True
    if rate <= 0.0:
        return False
    return int(session_hash[:8], 16) < rate * (1 << 32)


def _write_table(out_dir: Path, table: str, rows: Sequence[Row]) -> int:
    import pyarrow as pa
    import pyarrow.parquet as pq

    _validate(table, rows)
    arrow = schema.arrow_schema(table)
    path = out_dir / f"{table}.parquet"
    pq.write_table(
        pa.Table.from_pylist([dict(r) for r in rows], schema=arrow), path, compression="zstd"
    )
    return path.stat().st_size


def extract(
    conn: sqlite3.Connection,
    out_dir: Path | str,
    hasher: Hasher,
    *,
    size_cap_bytes: int = SIZE_CAP_BYTES,
    now: datetime | None = None,
) -> dict[str, Any]:
    out_path = Path(out_dir)
    gate = SchemaGate(hasher)

    ordinals = prompt_ordinals(conn)
    windows = compaction_windows(conn)
    plugins = {
        r["session_id"]: r["plugins_hash"]
        for r in conn.execute("SELECT session_id, plugins_hash FROM sessions")
    }
    tool_rows = conn.execute(
        "SELECT session_id, prompt_id, ts, tool_name, success, duration_ms, file_path,"
        " bash_exit_code, test_runner FROM tool_results"
        " WHERE prompt_id IS NOT NULL AND is_sidechain = 0"
        " ORDER BY session_id, ts, id"
    ).fetchall()

    request_rows, error_rows_deduped = build_requests(
        conn, gate, hasher, ordinals, windows, plugins
    )
    tables: dict[str, list[Row]] = {
        "requests": request_rows,
        "tool_results": build_tool_results(tool_rows, gate, hasher, ordinals),
        "turn_features": build_turn_features(conn, hasher, ordinals, tool_rows),
        "canary_cycles": build_canary_cycles(conn, gate),
        "change_points": build_change_points(conn, gate, hasher),
    }
    gate.raise_if_violations()

    excluded = {
        "api_errors_transcript_synthetic": conn.execute(
            "SELECT COUNT(*) FROM api_errors WHERE source <> 'otel'"
        ).fetchone()[0],
        "tool_results_without_prompt_id": conn.execute(
            "SELECT COUNT(*) FROM tool_results WHERE prompt_id IS NULL"
        ).fetchone()[0],
        "tool_results_sidechain": conn.execute(
            "SELECT COUNT(*) FROM tool_results WHERE prompt_id IS NOT NULL AND is_sidechain = 1"
        ).fetchone()[0],
        "requests_error_rows_deduped": error_rows_deduped,
    }

    all_sessions = {
        row["session_hash"]
        for name in ("requests", "tool_results", "turn_features")
        for row in tables[name]
    }

    out_path.mkdir(parents=True, exist_ok=True)
    rate = 1.0
    while True:
        kept = {s for s in all_sessions if keep_session(s, rate)}
        written = {
            name: _write_table(out_path, name, _sample(name, rows, kept))
            for name, rows in tables.items()
        }
        total = sum(written.values())
        if total <= size_cap_bytes or rate <= MIN_SAMPLING_RATE:
            break
        rate = max(MIN_SAMPLING_RATE, rate * max(0.1, min(0.9, size_cap_bytes / total)))

    final = {name: _sample(name, rows, kept) for name, rows in tables.items()}
    manifest = _manifest(
        final,
        written,
        hasher=hasher,
        now=now or datetime.now(UTC),
        sessions_in_store=len(all_sessions),
        sessions_included=len(kept),
        sampling_rate=rate,
        cap_met=total <= size_cap_bytes,
        excluded=excluded,
        source_spans=_source_spans(conn),
    )
    (out_path / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def _sample(table: str, rows: Sequence[Row], kept: set[str]) -> list[Row]:
    if table in ("canary_cycles", "change_points"):
        return list(rows)
    return [r for r in rows if r["session_hash"] in kept]


def _source_spans(conn: sqlite3.Connection) -> dict[str, dict[str, str | None]]:
    spans: dict[str, dict[str, str | None]] = {}
    for table, column in (
        ("api_requests", "ts"),
        ("api_errors", "ts"),
        ("tool_results", "ts"),
        ("transcript_turns", "ts"),
        ("canary_runs", "ts"),
        ("change_points", "ts"),
    ):
        low, high = conn.execute(
            f"SELECT MIN({column}), MAX({column}) FROM {table}"  # noqa: S608
        ).fetchone()
        spans[table] = {
            "start": schema.hour_bucket(low).isoformat() if low else None,
            "end": schema.hour_bucket(high).isoformat() if high else None,
        }
    return spans


def _manifest(
    tables: dict[str, list[Row]],
    sizes: dict[str, int],
    *,
    hasher: Hasher,
    now: datetime,
    sessions_in_store: int,
    sessions_included: int,
    sampling_rate: float,
    cap_met: bool,
    excluded: dict[str, int],
    source_spans: dict[str, dict[str, str | None]],
) -> dict[str, Any]:
    per_table: dict[str, dict[str, str]] = {}
    moments: list[datetime] = []
    for name, rows in tables.items():
        stamps = [r["ts_bucket_utc"] for r in rows if r.get("ts_bucket_utc") is not None]
        if stamps:
            per_table[name] = {
                "start": min(stamps).isoformat(),
                "end": max(stamps).isoformat(),
            }
            moments.extend(stamps)

    observed: dict[str, set[str]] = defaultdict(set)
    for name, rows in tables.items():
        for col in schema.TABLES[name]:
            if col.kind is ColumnKind.ENUM and col.enum:
                observed[col.enum].update(r[col.name] for r in rows if r[col.name] is not None)

    span: dict[str, Any] = {"per_table": per_table, "per_source_table": source_spans}
    if moments:
        span["start"] = min(moments).isoformat()
        span["end"] = max(moments).isoformat()
        span["days"] = round((max(moments) - min(moments)).total_seconds() / 86400.0, 2)

    return {
        "corpus_schema_version": schema.SCHEMA_VERSION,
        "extractor_version": EXTRACTOR_VERSION,
        "extracted_at_utc": now.replace(microsecond=0).isoformat(),
        "hmac_key_id": hasher.key_id,
        "hmac_key_env": schema.HMAC_KEY_ENV,
        "row_counts": {name: len(rows) for name, rows in tables.items()},
        "time_span_utc": span,
        "enums": {
            name: {
                "declared_cardinality": len(members),
                "observed_cardinality": len(observed.get(name, set())),
            }
            for name, members in schema.ENUMS.items()
        },
        "sessions": {
            "in_store": sessions_in_store,
            "included": sessions_included,
            "sampling_rate": round(sampling_rate, 6),
            "cap_met": cap_met,
        },
        "size_bytes": {**sizes, "total": sum(sizes.values()), "cap": SIZE_CAP_BYTES},
        "excluded": excluded,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the Phase B corpus. Local only.")
    parser.add_argument(
        "--out", default=str(_REPO_ROOT / "corpus"), help="output directory (default: corpus/)"
    )
    parser.add_argument("--db", default=None, help="override the store path (a copy, say)")
    parser.add_argument("--size-cap-bytes", type=int, default=SIZE_CAP_BYTES)
    args = parser.parse_args(argv)

    try:
        hasher = Hasher.from_env(os.environ)
        conn = open_readonly(Path(args.db) if args.db else resolve_db_path())
    except (schema.MissingKeyError, StoreNotFound) as exc:
        print(f"extract_corpus: {exc}", file=sys.stderr)
        return 2
    try:
        manifest = extract(conn, args.out, hasher, size_cap_bytes=args.size_cap_bytes)
    except (schema.EnumViolation, schema.UnreadableValue) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        conn.close()

    span = manifest["time_span_utc"]
    print(f"corpus schema {manifest['corpus_schema_version']} / extractor {EXTRACTOR_VERSION}")
    print(f"hmac key id: {manifest['hmac_key_id']}")
    for name in TABLE_ORDER:
        print(
            f"  {name:<14} {manifest['row_counts'][name]:>8} rows"
            f"  {manifest['size_bytes'][name] / 1024:>9.1f} KiB"
        )
    print(f"  {'total':<14} {'':>8}       {manifest['size_bytes']['total'] / 1024:>9.1f} KiB")
    print(f"span: {span.get('start')} .. {span.get('end')}  ({span.get('days')} days)")
    print(
        f"sessions: {manifest['sessions']['included']}/{manifest['sessions']['in_store']}"
        f" at rate {manifest['sessions']['sampling_rate']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

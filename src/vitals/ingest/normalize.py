from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path

from vitals.db import log_ingest, upsert_session
from vitals.timeutil import epoch_to_iso, parse_iso, utcnow_iso

PII_ATTRS = frozenset(
    {"user.email", "user.id", "user.account_id", "user.account_uuid", "organization.id"}
)

CONTEXT_EDGES = ((30_000, "lt30k"), (100_000, "b30_100k"), (180_001, "b100_180k"))


def context_bucket(total_input: int) -> str:
    for edge, name in CONTEXT_EDGES:
        if total_input < edge:
            return name
    return "gt180k"


def _attr_val(value: dict):
    if not isinstance(value, dict):
        return None
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:
        try:
            return int(value["intValue"])
        except (TypeError, ValueError):
            return None
    if "doubleValue" in value:
        try:
            return float(value["doubleValue"])
        except (TypeError, ValueError):
            return None
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "arrayValue" in value:
        return [_attr_val(v) for v in value["arrayValue"].get("values", [])]
    if "kvlistValue" in value:
        return {
            kv.get("key"): _attr_val(kv.get("value", {}))
            for kv in value["kvlistValue"].get("values", [])
        }
    return None


def _flatten_attrs(attrs, into: dict) -> None:
    for attr in attrs or []:
        key = attr.get("key")
        if not key or key in PII_ATTRS:
            continue
        into[key] = _attr_val(attr.get("value", {}))


def _ts_from(record: dict, attrs: dict) -> str:
    nano = record.get("timeUnixNano") or record.get("observedTimeUnixNano")
    if nano:
        try:
            return epoch_to_iso(int(nano) / 1e9)
        except (TypeError, ValueError):
            pass
    stamp = attrs.get("event.timestamp")
    if stamp:
        try:
            return parse_iso(str(stamp)).isoformat(timespec="seconds")
        except ValueError:
            pass
    return utcnow_iso()


def iter_log_records(body: dict) -> Iterator[dict]:
    if not isinstance(body, dict):
        return
    for resource_logs in body.get("resourceLogs") or []:
        resource_attrs: dict = {}
        _flatten_attrs((resource_logs.get("resource") or {}).get("attributes"), resource_attrs)
        for scope_logs in resource_logs.get("scopeLogs") or []:
            for record in scope_logs.get("logRecords") or []:
                flat = dict(resource_attrs)
                _flatten_attrs(record.get("attributes"), flat)
                name = (record.get("body") or {}).get("stringValue")
                if not name and flat.get("event.name"):
                    name = f"claude_code.{flat['event.name']}"
                flat["_event_name"] = name or ""
                flat["_ts_iso"] = _ts_from(record, flat)
                yield flat


def _num(rec: dict, key: str, cast=int):
    value = rec.get(key)
    if value is None or isinstance(value, bool):
        return None
    try:
        return cast(float(value)) if cast is int else cast(value)
    except (TypeError, ValueError):
        return None


def _version(rec: dict) -> str | None:
    return rec.get("app.version") or rec.get("service.version")


def _touch_session(conn: sqlite3.Connection, rec: dict) -> str | None:
    session_id = rec.get("session.id")
    if not session_id:
        return None
    upsert_session(
        conn,
        session_id,
        cc_version=_version(rec),
        entrypoint=rec.get("app.entrypoint") or rec.get("terminal.type"),
    )
    return session_id


def _handle_api_request(conn: sqlite3.Connection, rec: dict) -> str | None:
    session_id = _touch_session(conn, rec)
    if not session_id:
        return None
    tokens = sum(
        _num(rec, key) or 0
        for key in ("input_tokens", "cache_read_tokens", "cache_creation_tokens")
    )
    conn.execute(
        "INSERT OR IGNORE INTO api_requests(session_id, prompt_id, request_id, ts, model, "
        "effort, speed, query_source, input_tokens, output_tokens, cache_read_tokens, "
        "cache_creation_tokens, duration_ms, cost_usd, context_bucket, cc_version, source) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'otel')",
        (
            session_id,
            rec.get("prompt.id"),
            rec.get("request_id"),
            rec["_ts_iso"],
            rec.get("model"),
            rec.get("effort"),
            rec.get("speed"),
            rec.get("query_source"),
            _num(rec, "input_tokens"),
            _num(rec, "output_tokens"),
            _num(rec, "cache_read_tokens"),
            _num(rec, "cache_creation_tokens"),
            _num(rec, "duration_ms", float),
            _num(rec, "cost_usd", float),
            context_bucket(tokens),
            _version(rec),
        ),
    )
    return "api_requests"


def _handle_api_error(conn: sqlite3.Connection, rec: dict, exhausted: bool) -> str | None:
    session_id = _touch_session(conn, rec)
    if not session_id:
        return None
    attempt = _num(rec, "total_attempts") if exhausted else _num(rec, "attempt")
    duration = (
        _num(rec, "total_retry_duration_ms", float)
        if exhausted
        else _num(rec, "duration_ms", float)
    )
    conn.execute(
        "INSERT INTO api_errors(session_id, prompt_id, request_id, ts, model, status_code, "
        "attempt, retries_exhausted, error_text, duration_ms, cc_version) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            session_id,
            rec.get("prompt.id"),
            rec.get("request_id"),
            rec["_ts_iso"],
            rec.get("model"),
            _num(rec, "status_code"),
            attempt,
            1 if exhausted else 0,
            (rec.get("error") or None),
            duration,
            _version(rec),
        ),
    )
    return "api_errors"


def _handle_tool_result(conn: sqlite3.Connection, rec: dict) -> str | None:
    session_id = _touch_session(conn, rec)
    tool_use_id = rec.get("tool_use_id")
    if not session_id or not rec.get("tool_name"):
        return None
    success = rec.get("success")
    success_int = 1 if str(success).lower() == "true" else (0 if success is not None else None)
    conn.execute(
        "INSERT INTO tool_results(session_id, prompt_id, tool_use_id, ts, tool_name, success, "
        "duration_ms, error_type, source) VALUES (?,?,?,?,?,?,?,?,'otel') "
        "ON CONFLICT(tool_use_id) WHERE tool_use_id IS NOT NULL DO UPDATE SET "
        "  prompt_id   = COALESCE(prompt_id, excluded.prompt_id), "
        "  success     = COALESCE(success, excluded.success), "
        "  duration_ms = COALESCE(duration_ms, excluded.duration_ms), "
        "  error_type  = COALESCE(error_type, excluded.error_type)",
        (
            session_id,
            rec.get("prompt.id"),
            tool_use_id,
            rec["_ts_iso"],
            rec.get("tool_name"),
            success_int,
            _num(rec, "duration_ms", float),
            rec.get("error_type"),
        ),
    )
    return "tool_results"


def _handle_compaction(conn: sqlite3.Connection, rec: dict) -> str | None:
    session_id = _touch_session(conn, rec)
    if not session_id:
        return None
    success = rec.get("success")
    conn.execute(
        "INSERT INTO compactions(session_id, ts, source, trigger, success, duration_ms, "
        "pre_tokens, post_tokens) VALUES (?,?, 'otel', ?,?,?,?,?)",
        (
            session_id,
            rec["_ts_iso"],
            rec.get("trigger"),
            1 if str(success).lower() == "true" else (0 if success is not None else None),
            _num(rec, "duration_ms", float),
            _num(rec, "pre_tokens"),
            _num(rec, "post_tokens"),
        ),
    )
    return "compactions"


def handle_log_record(conn: sqlite3.Connection, rec: dict) -> str | None:
    try:
        event = rec.get("_event_name") or ""
        if event == "claude_code.api_request":
            return _handle_api_request(conn, rec)
        if event == "claude_code.api_error":
            return _handle_api_error(conn, rec, exhausted=False)
        if event == "claude_code.api_retries_exhausted":
            return _handle_api_error(conn, rec, exhausted=True)
        if event == "claude_code.tool_result":
            return _handle_tool_result(conn, rec)
        if event == "claude_code.compaction":
            return _handle_compaction(conn, rec)
        if event == "claude_code.user_prompt":
            return "sessions" if _touch_session(conn, rec) else None
        return None
    except (sqlite3.Error, KeyError, TypeError, ValueError):
        return None


def _load_state(state_path: Path) -> dict:
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_state(state_path: Path, state: dict) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_suffix(state_path.suffix + ".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    tmp.replace(state_path)


def ingest_otel_spool(
    conn: sqlite3.Connection, spool_dir: Path, state_path: Path
) -> tuple[int, int]:
    spool = Path(spool_dir) / "otel"
    state = _load_state(Path(state_path))
    ok = err = 0
    for path in sorted(spool.glob("otel-*.jsonl")):
        offset = int(state.get(path.name, 0))
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size < offset:
            offset = 0
        if size == offset:
            continue
        try:
            with path.open("rb") as fh:
                fh.seek(offset)
                chunk = fh.read()
        except OSError:
            continue
        consumed = chunk.rfind(b"\n") + 1
        if consumed <= 0:
            continue
        for raw in chunk[:consumed].splitlines():
            if not raw.strip():
                continue
            try:
                line = json.loads(raw)
            except ValueError:
                err += 1
                continue
            if "body" not in line:
                err += 1
                continue
            for rec in iter_log_records(line["body"]):
                if handle_log_record(conn, rec) is not None:
                    ok += 1
        state[path.name] = offset + consumed
    conn.commit()
    _save_state(Path(state_path), state)
    if ok or err:
        log_ingest(conn, "otel_spool", ok, err)
    return ok, err

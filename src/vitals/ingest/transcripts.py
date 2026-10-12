from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from vitals.db import log_ingest, upsert_session
from vitals.ingest.normalize import context_bucket
from vitals.ingest.selfcorr import count_hits
from vitals.timeutil import parse_iso

TURN_TYPES = frozenset({"user", "assistant"})


def _iso(value) -> str | None:
    if not value:
        return None
    try:
        return parse_iso(str(value)).isoformat(timespec="seconds")
    except ValueError:
        return None


def _text_of(message: dict) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text") or ""))
    return "\n".join(parts)


def _turn_row(rec: dict) -> tuple | None:
    uuid = rec.get("uuid")
    session_id = rec.get("sessionId")
    if not uuid or not session_id:
        return None
    message = rec.get("message") if isinstance(rec.get("message"), dict) else {}
    usage = message.get("usage") if isinstance(message.get("usage"), dict) else {}
    text = _text_of(message)
    return (
        uuid,
        session_id,
        rec.get("parentUuid"),
        _iso(rec.get("timestamp")),
        rec.get("type"),
        message.get("model"),
        rec.get("effort"),
        rec.get("version"),
        rec.get("requestId"),
        rec.get("promptId"),
        usage.get("input_tokens"),
        usage.get("output_tokens"),
        usage.get("cache_read_input_tokens"),
        message.get("stop_reason"),
        1 if rec.get("isSidechain") else 0,
        count_hits(text),
        len(text),
    )


SYNTHETIC_MODEL = "<synthetic>"


def _backfill_request(conn: sqlite3.Connection, rec: dict, row: tuple) -> None:
    if rec.get("type") != "assistant":
        return
    message = rec.get("message") if isinstance(rec.get("message"), dict) else {}
    if message.get("model") == SYNTHETIC_MODEL:
        _record_synthetic_error(conn, message, row)
        return
    request_id = rec.get("requestId")
    if not request_id:
        return
    usage = message.get("usage") if isinstance(message.get("usage"), dict) else {}
    tokens = sum(
        int(usage.get(key) or 0)
        for key in ("input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
    )
    conn.execute(
        "INSERT OR IGNORE INTO api_requests(session_id, prompt_id, request_id, ts, model, "
        "effort, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, "
        "context_bucket, cc_version, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'transcript')",
        (
            row[1],
            rec.get("promptId"),
            request_id,
            row[3],
            message.get("model"),
            rec.get("effort"),
            usage.get("input_tokens"),
            usage.get("output_tokens"),
            usage.get("cache_read_input_tokens"),
            usage.get("cache_creation_input_tokens"),
            context_bucket(tokens),
            rec.get("version"),
        ),
    )


def _record_synthetic_error(conn: sqlite3.Connection, message: dict, row: tuple) -> None:
    text = _text_of(message).strip()
    if not text:
        return
    conn.execute(
        "INSERT INTO api_errors(session_id, ts, model, error_text, cc_version, source) "
        "VALUES (?,?,?,?,?, 'transcript_synthetic')",
        (row[1], row[3], SYNTHETIC_MODEL, text[:300], row[7]),
    )


def _rollup(conn: sqlite3.Connection, session_ids: set[str]) -> None:
    for session_id in session_ids:
        row = conn.execute(
            "SELECT COUNT(*) AS n, MIN(ts) AS first_ts, MAX(ts) AS last_ts "
            "FROM transcript_turns WHERE session_id = ? AND is_sidechain = 0",
            (session_id,),
        ).fetchone()
        version = conn.execute(
            "SELECT cc_version FROM transcript_turns WHERE session_id = ? AND cc_version "
            "IS NOT NULL ORDER BY ts DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        wall = None
        if row["first_ts"] and row["last_ts"]:
            wall = (parse_iso(row["last_ts"]) - parse_iso(row["first_ts"])).total_seconds()
        conn.execute("INSERT OR IGNORE INTO sessions(session_id) VALUES (?)", (session_id,))
        conn.execute(
            "UPDATE sessions SET num_turns = ?, wall_seconds = ? WHERE session_id = ?",
            (row["n"], wall, session_id),
        )
        if version:
            upsert_session(conn, session_id, cc_version=version["cc_version"])


def scan_file(conn: sqlite3.Connection, path: Path) -> int:
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0

    inserted = 0
    errors = 0
    touched: set[str] = set()
    for line in raw.split("\n"):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            errors += 1
            continue
        if not isinstance(rec, dict) or rec.get("type") not in TURN_TYPES:
            continue
        row = _turn_row(rec)
        if row is None:
            continue
        try:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO transcript_turns(uuid, session_id, parent_uuid, ts, role, "
                "model, effort, cc_version, request_id, prompt_id, input_tokens, output_tokens, "
                "cache_read_tokens, stop_reason, is_sidechain, self_corr_hits, text_len) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                row,
            )
            if cursor.rowcount:
                inserted += 1
                _backfill_request(conn, rec, row)
            touched.add(row[1])
        except sqlite3.Error:
            errors += 1

    if touched:
        _rollup(conn, touched)
    conn.commit()
    if errors:
        log_ingest(conn, "transcript_parse_error", inserted, errors, str(path))
    return inserted


def scan_all(conn: sqlite3.Connection, projects_dir: Path, since_days: int = 3) -> int:
    import time

    cutoff = time.time() - since_days * 86400
    total = 0
    root = Path(projects_dir)
    if not root.exists():
        return 0
    for path in root.glob("**/*.jsonl"):
        try:
            if path.stat().st_mtime < cutoff:
                continue
        except OSError:
            continue
        total += scan_file(conn, path)
    return total

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from vitals.db import kv_get, log_ingest, upsert_session
from vitals.ingest.testparse import detect_runner, parse_result
from vitals.timeutil import epoch_to_iso, utcnow_iso

EDIT_TOOLS = frozenset({"Edit", "Write", "NotebookEdit", "MultiEdit"})


def _ts(rec: dict) -> str:
    recv = rec.get("_recv_ts")
    if isinstance(recv, (int, float)):
        return epoch_to_iso(float(recv))
    return utcnow_iso()


def _norm_path(path: str | None) -> str | None:
    return path.replace("\\", "/") if isinstance(path, str) and path else None


def _snapshot(conn: sqlite3.Connection) -> dict:
    raw = kv_get(conn, "snapshot")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except ValueError:
        return {}


def _handle_session_start(conn: sqlite3.Connection, rec: dict) -> bool:
    snap = _snapshot(conn)
    upsert_session(
        conn,
        rec["session_id"],
        started_at=_ts(rec),
        source=rec.get("source"),
        model_default=rec.get("model"),
        cwd=_norm_path(rec.get("cwd")),
        transcript_path=_norm_path(rec.get("transcript_path")),
        settings_hash=snap.get("settings_hash"),
        plugins_hash=snap.get("plugins_hash"),
    )
    return True


def _handle_tool(conn: sqlite3.Connection, rec: dict, failed: bool) -> bool:
    tool_name = rec.get("tool_name")
    if not tool_name:
        return False
    tool_input = rec.get("tool_input") if isinstance(rec.get("tool_input"), dict) else {}
    command = tool_input.get("command")
    error_text = rec.get("error") if isinstance(rec.get("error"), str) else None
    response = rec.get("tool_response") if isinstance(rec.get("tool_response"), str) else None

    runner = detect_runner(command)
    exit_code, tests_failed = parse_result(runner, response, error_text)

    interrupted = bool(rec.get("is_interrupt"))
    if interrupted:
        success: int | None = None
        error_type: str | None = "interrupt"
    else:
        success = 0 if failed else 1
        error_type = "tool_error" if failed else None

    file_path = _norm_path(tool_input.get("file_path") or tool_input.get("notebook_path"))
    conn.execute(
        "INSERT INTO tool_results(session_id, prompt_id, tool_use_id, ts, tool_name, success, "
        "duration_ms, error_type, file_path, bash_command_hash, bash_exit_code, test_runner, "
        "tests_failed, is_sidechain, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'hook') "
        "ON CONFLICT(tool_use_id) WHERE tool_use_id IS NOT NULL DO UPDATE SET "
        "  prompt_id         = COALESCE(prompt_id, excluded.prompt_id), "
        "  success           = COALESCE(success, excluded.success), "
        "  duration_ms       = COALESCE(duration_ms, excluded.duration_ms), "
        "  error_type        = COALESCE(error_type, excluded.error_type), "
        "  file_path         = COALESCE(file_path, excluded.file_path), "
        "  bash_command_hash = COALESCE(bash_command_hash, excluded.bash_command_hash), "
        "  bash_exit_code    = COALESCE(bash_exit_code, excluded.bash_exit_code), "
        "  test_runner       = COALESCE(test_runner, excluded.test_runner), "
        "  tests_failed      = COALESCE(tests_failed, excluded.tests_failed), "
        "  is_sidechain      = MAX(is_sidechain, excluded.is_sidechain)",
        (
            rec.get("session_id"),
            rec.get("prompt_id"),
            rec.get("tool_use_id"),
            _ts(rec),
            tool_name,
            success,
            rec.get("duration_ms"),
            error_type,
            file_path if tool_name in EDIT_TOOLS or file_path else None,
            hashlib.sha256(command.encode("utf-8")).hexdigest()[:16] if command else None,
            exit_code,
            runner,
            tests_failed,
            1 if rec.get("agent_id") else 0,
        ),
    )
    return True


def _handle_compaction(conn: sqlite3.Connection, rec: dict) -> bool:
    conn.execute(
        "INSERT INTO compactions(session_id, ts, source, trigger) VALUES (?,?, 'hook', ?)",
        (rec.get("session_id"), _ts(rec), rec.get("trigger")),
    )
    return True


def handle_hook_record(conn: sqlite3.Connection, rec: dict) -> bool:
    event = rec.get("hook_event_name")
    session_id = rec.get("session_id")
    if not event or not session_id:
        return False

    if event == "SessionStart":
        return _handle_session_start(conn, rec)
    if event in ("PostToolUse", "PostToolUseFailure"):
        upsert_session(conn, session_id, transcript_path=_norm_path(rec.get("transcript_path")))
        return _handle_tool(conn, rec, failed=event == "PostToolUseFailure")
    if event == "Stop":
        upsert_session(conn, session_id, transcript_path=_norm_path(rec.get("transcript_path")))
        conn.execute(
            "UPDATE sessions SET num_prompts = num_prompts + 1 WHERE session_id = ?",
            (session_id,),
        )
        return True
    if event in ("PreCompact", "PostCompact"):
        upsert_session(conn, session_id)
        return _handle_compaction(conn, rec)
    if event == "SessionEnd":
        conn.execute("INSERT OR IGNORE INTO sessions(session_id) VALUES (?)", (session_id,))
        conn.execute(
            "UPDATE sessions SET ended_at = ?, end_reason = COALESCE(end_reason, ?) "
            "WHERE session_id = ?",
            (_ts(rec), rec.get("reason"), session_id),
        )
        return True
    if event == "ConfigChange":
        conn.execute(
            "INSERT INTO change_points(ts, kind, detail) VALUES (?, 'settings', ?)",
            (_ts(rec), "ConfigChange hook"),
        )
        return True
    return False


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


def ingest_hook_spool(
    conn: sqlite3.Connection, spool_dir: Path, state_path: Path
) -> tuple[int, int]:
    spool = Path(spool_dir) / "hooks"
    state = _load_state(Path(state_path))
    ok = err = 0
    for path in sorted(spool.glob("hooks-*.jsonl")):
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
                rec = json.loads(raw)
            except ValueError:
                err += 1
                continue
            try:
                if handle_hook_record(conn, rec):
                    ok += 1
            except sqlite3.Error:
                err += 1
        state[path.name] = offset + consumed
    conn.commit()
    _save_state(Path(state_path), state)
    if ok or err:
        log_ingest(conn, "hook_spool", ok, err)
    return ok, err

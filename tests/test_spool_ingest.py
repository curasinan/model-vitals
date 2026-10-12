import json

from vitals.db import get_conn, init_db
from vitals.ingest.spool import ingest_hook_spool

TS = 1_787_618_400.0


def _conn(tmp_path):
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)
    return conn


def _write(tmp_path, *records, name="hooks-20260825.jsonl"):
    spool = tmp_path / "spool" / "hooks"
    spool.mkdir(parents=True, exist_ok=True)
    with (spool / name).open("a", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


def _ingest(conn, tmp_path):
    return ingest_hook_spool(conn, tmp_path / "spool", tmp_path / "state.json")


def test_posttooluse_bash_parses_tests(tmp_path):
    conn = _conn(tmp_path)
    _write(
        tmp_path,
        {
            "hook_event_name": "PostToolUse",
            "session_id": "s1",
            "prompt_id": "p1",
            "tool_name": "Bash",
            "tool_use_id": "t1",
            "duration_ms": 900,
            "tool_input": {"command": "uv run pytest -q"},
            "tool_response": "1 failed, 9 passed",
            "_recv_ts": TS,
        },
    )
    assert _ingest(conn, tmp_path) == (1, 0)
    row = conn.execute("SELECT * FROM tool_results").fetchone()
    assert row["test_runner"] == "pytest"
    assert row["tests_failed"] == 1
    assert row["file_path"] is None
    assert row["bash_command_hash"]
    assert row["success"] == 1
    assert row["source"] == "hook"


def test_edit_records_forward_slashed_path(tmp_path):
    conn = _conn(tmp_path)
    _write(
        tmp_path,
        {
            "hook_event_name": "PostToolUse",
            "session_id": "s1",
            "prompt_id": "p1",
            "tool_name": "Edit",
            "tool_use_id": "t2",
            "tool_input": {"file_path": "C:\\proj\\src\\a.py"},
            "_recv_ts": TS,
        },
    )
    _ingest(conn, tmp_path)
    row = conn.execute("SELECT * FROM tool_results WHERE tool_use_id='t2'").fetchone()
    assert row["file_path"] == "C:/proj/src/a.py"


def test_posttoolusefailure_marks_failure_and_exit_code(tmp_path):
    conn = _conn(tmp_path)
    _write(
        tmp_path,
        {
            "hook_event_name": "PostToolUseFailure",
            "session_id": "s1",
            "prompt_id": "p1",
            "tool_name": "Bash",
            "tool_use_id": "t3",
            "tool_input": {"command": "python -m pytest"},
            "error": "Exit code 1\nFAILED tests/a.py::test_x",
            "is_interrupt": False,
            "_recv_ts": TS,
        },
    )
    _ingest(conn, tmp_path)
    row = conn.execute("SELECT * FROM tool_results WHERE tool_use_id='t3'").fetchone()
    assert row["success"] == 0
    assert row["bash_exit_code"] == 1
    assert row["tests_failed"] == 1


def test_interrupted_tool_is_not_counted_as_a_failure(tmp_path):
    conn = _conn(tmp_path)
    _write(
        tmp_path,
        {
            "hook_event_name": "PostToolUseFailure",
            "session_id": "s1",
            "tool_name": "Bash",
            "tool_use_id": "t4",
            "tool_input": {"command": "sleep 100"},
            "error": "Interrupted by user",
            "is_interrupt": True,
            "_recv_ts": TS,
        },
    )
    _ingest(conn, tmp_path)
    row = conn.execute("SELECT * FROM tool_results WHERE tool_use_id='t4'").fetchone()
    assert row["success"] is None
    assert row["error_type"] == "interrupt"


def test_subagent_tool_calls_are_flagged_sidechain(tmp_path):
    conn = _conn(tmp_path)
    _write(
        tmp_path,
        {
            "hook_event_name": "PostToolUse",
            "session_id": "s1",
            "agent_id": "agent_7",
            "tool_name": "Edit",
            "tool_use_id": "t5",
            "tool_input": {"file_path": "a.py"},
            "_recv_ts": TS,
        },
    )
    _ingest(conn, tmp_path)
    row = conn.execute("SELECT * FROM tool_results WHERE tool_use_id='t5'").fetchone()
    assert row["is_sidechain"] == 1


def test_session_lifecycle(tmp_path):
    conn = _conn(tmp_path)
    conn.execute(
        "INSERT INTO vitals_kv(key,value) VALUES ('snapshot', ?)",
        (json.dumps({"settings_hash": "sh1", "plugins_hash": "ph1"}),),
    )
    _write(
        tmp_path,
        {
            "hook_event_name": "SessionStart",
            "session_id": "s9",
            "source": "startup",
            "model": "claude-sonnet-5",
            "cwd": "C:\\proj",
            "transcript_path": "C:\\t\\s9.jsonl",
            "_recv_ts": TS,
        },
        {"hook_event_name": "Stop", "session_id": "s9", "_recv_ts": TS + 10},
        {"hook_event_name": "Stop", "session_id": "s9", "_recv_ts": TS + 20},
        {
            "hook_event_name": "SessionEnd",
            "session_id": "s9",
            "reason": "clear",
            "_recv_ts": TS + 30,
        },
    )
    _ingest(conn, tmp_path)
    row = conn.execute("SELECT * FROM sessions WHERE session_id='s9'").fetchone()
    assert row["source"] == "startup"
    assert row["model_default"] == "claude-sonnet-5"
    assert row["num_prompts"] == 2
    assert row["end_reason"] == "clear"
    assert row["ended_at"]
    assert row["transcript_path"] == "C:/t/s9.jsonl"
    assert row["settings_hash"] == "sh1" and row["plugins_hash"] == "ph1"
    assert row["num_turns"] is None


def test_compaction_hooks_are_source_hook_and_collapse_in_the_view(tmp_path):
    conn = _conn(tmp_path)
    _write(
        tmp_path,
        {
            "hook_event_name": "PreCompact",
            "session_id": "s1",
            "trigger": "auto",
            "_recv_ts": TS,
        },
        {
            "hook_event_name": "PostCompact",
            "session_id": "s1",
            "trigger": "auto",
            "compact_summary": "...",
            "_recv_ts": TS + 30,
        },
    )
    _ingest(conn, tmp_path)
    assert conn.execute("SELECT COUNT(*) FROM compactions").fetchone()[0] == 2
    assert all(r["source"] == "hook" for r in conn.execute("SELECT source FROM compactions"))
    assert conn.execute("SELECT COUNT(*) FROM v_compaction_episodes").fetchone()[0] == 1


def test_configchange_records_a_change_point(tmp_path):
    conn = _conn(tmp_path)
    _write(tmp_path, {"hook_event_name": "ConfigChange", "session_id": "s1", "_recv_ts": TS})
    _ingest(conn, tmp_path)
    row = conn.execute("SELECT * FROM change_points").fetchone()
    assert row["kind"] == "settings"


def test_subagentstop_is_ignored(tmp_path):
    conn = _conn(tmp_path)
    _write(tmp_path, {"hook_event_name": "SubagentStop", "session_id": "s1", "_recv_ts": TS})
    ok, err = _ingest(conn, tmp_path)
    assert (ok, err) == (0, 0)


def test_offsets_resume_and_bad_lines_counted(tmp_path):
    conn = _conn(tmp_path)
    _write(tmp_path, {"hook_event_name": "Stop", "session_id": "s1", "_recv_ts": TS})
    assert _ingest(conn, tmp_path) == (1, 0)
    assert _ingest(conn, tmp_path) == (0, 0)

    spool = tmp_path / "spool" / "hooks"
    with (spool / "hooks-20260825.jsonl").open("a", encoding="utf-8") as fh:
        fh.write("not json{\n")
    _write(tmp_path, {"hook_event_name": "Stop", "session_id": "s1", "_recv_ts": TS})
    ok, err = _ingest(conn, tmp_path)
    assert (ok, err) == (1, 1)
    assert conn.execute("SELECT num_prompts FROM sessions WHERE session_id='s1'").fetchone()[0] == 2


def test_per_process_fallback_files_are_ingested_too(tmp_path):
    conn = _conn(tmp_path)
    _write(
        tmp_path,
        {"hook_event_name": "Stop", "session_id": "s1", "_recv_ts": TS},
        name="hooks-20260825.p1234.jsonl",
    )
    assert _ingest(conn, tmp_path) == (1, 0)


def test_hook_row_then_otel_row_merge(tmp_path):
    from vitals.ingest.normalize import handle_log_record

    conn = _conn(tmp_path)
    _write(
        tmp_path,
        {
            "hook_event_name": "PostToolUse",
            "session_id": "s1",
            "prompt_id": "p1",
            "tool_name": "Edit",
            "tool_use_id": "shared_1",
            "tool_input": {"file_path": "a.py"},
            "_recv_ts": TS,
        },
    )
    _ingest(conn, tmp_path)
    handle_log_record(
        conn,
        {
            "_event_name": "claude_code.tool_result",
            "_ts_iso": "2026-08-25T00:00:00+00:00",
            "session.id": "s1",
            "tool_name": "Edit",
            "tool_use_id": "shared_1",
            "success": "true",
            "duration_ms": 42,
        },
    )
    rows = conn.execute("SELECT * FROM tool_results WHERE tool_use_id='shared_1'").fetchall()
    assert len(rows) == 1
    assert rows[0]["file_path"] == "a.py" and rows[0]["duration_ms"] == 42

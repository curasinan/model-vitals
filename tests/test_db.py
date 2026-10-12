from pathlib import Path

import pytest

from vitals.db import get_conn, init_db, upsert_session


def test_init_db_creates_tables_and_is_idempotent(tmp_path: Path):
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)
    init_db(conn)
    names = {
        r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")
    }
    for t in [
        "sessions",
        "api_requests",
        "api_errors",
        "tool_results",
        "compactions",
        "transcript_turns",
        "canary_cycles",
        "canary_runs",
        "incidents",
        "change_points",
        "signal_windows",
        "detector_state",
        "anomalies",
        "alerts",
        "spend_ledger",
        "ingest_log",
        "vitals_kv",
        "v_edit_loops",
        "v_compaction_episodes",
        "v_post_compaction_turns",
    ]:
        assert t in names, t
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_compaction_episodes_collapse_and_15min_window(tmp_path: Path):
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)
    for src, pre, post, ts in [
        ("hook", None, None, "2026-08-25T10:00:00+00:00"),
        ("otel", 150_000, 40_000, "2026-08-25T10:00:20+00:00"),
        ("hook", None, None, "2026-08-25T10:00:40+00:00"),
    ]:
        conn.execute(
            "INSERT INTO compactions(session_id, ts, source, trigger, pre_tokens, post_tokens) "
            "VALUES ('s1', ?, ?, 'auto', ?, ?)",
            (ts, src, pre, post),
        )
    episodes = conn.execute("SELECT * FROM v_compaction_episodes").fetchall()
    assert len(episodes) == 1
    assert episodes[0]["pre_tokens"] == 150_000
    assert episodes[0]["ts"] == "2026-08-25T10:00:00+00:00"

    for tool_ts in ["2026-08-25T10:05:00+00:00", "2026-08-25T10:40:00+00:00"]:
        conn.execute(
            "INSERT INTO tool_results(session_id, tool_use_id, ts, tool_name, success, source) "
            "VALUES ('s1', ?, ?, 'Edit', 0, 'hook')",
            (f"t{tool_ts}", tool_ts),
        )
    inside = conn.execute("SELECT ts FROM v_post_compaction_turns").fetchall()
    assert [r["ts"] for r in inside] == ["2026-08-25T10:05:00+00:00"]


def test_unique_indexes_enforce_dedup(tmp_path: Path):
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)
    conn.execute("INSERT INTO api_requests(session_id, request_id, ts) VALUES ('s', 'req_1', 't')")
    conn.execute(
        "INSERT OR IGNORE INTO api_requests(session_id, request_id, ts) VALUES ('s', 'req_1', 't')"
    )
    assert conn.execute("SELECT COUNT(*) FROM api_requests").fetchone()[0] == 1
    for _ in range(2):
        conn.execute("INSERT INTO api_requests(session_id, ts) VALUES ('s', 't')")
    assert conn.execute("SELECT COUNT(*) FROM api_requests").fetchone()[0] == 3


def test_upsert_session_refuses_a_column_name_it_does_not_recognise(tmp_path):
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)

    with pytest.raises(ValueError, match="not a sessions column"):
        upsert_session(conn, "s1", **{"cc_version = 'x', started_at": "boom"})

    with pytest.raises(ValueError, match="not a sessions column"):
        upsert_session(conn, "s1", no_such_column="x")

    upsert_session(conn, "s1", cc_version="2.1.250")
    row = conn.execute("SELECT cc_version FROM sessions WHERE session_id='s1'").fetchone()
    assert row["cc_version"] == "2.1.250"

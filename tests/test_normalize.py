import json
from pathlib import Path

import pytest

from vitals.db import get_conn, init_db
from vitals.ingest.normalize import (
    context_bucket,
    handle_log_record,
    ingest_otel_spool,
    iter_log_records,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _conn(tmp_path):
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)
    return conn


def _synthetic():
    return json.loads((FIXTURES / "otlp_logs_synthetic.json").read_text(encoding="utf-8"))


def _real():
    return json.loads((FIXTURES / "otlp_logs_sample.json").read_text(encoding="utf-8"))


def test_context_bucket_edges():
    assert context_bucket(0) == "lt30k"
    assert context_bucket(29_999) == "lt30k"
    assert context_bucket(30_000) == "b30_100k"
    assert context_bucket(99_999) == "b30_100k"
    assert context_bucket(100_000) == "b100_180k"
    assert context_bucket(180_000) == "b100_180k"
    assert context_bucket(180_001) == "gt180k"


def test_iter_log_records_flattens_and_merges_attributes():
    recs = list(iter_log_records(_synthetic()))
    assert len(recs) == 7
    first = recs[0]
    assert first["_event_name"] == "claude_code.api_request"
    assert first["_ts_iso"].startswith("2026-")
    assert first["service.version"] == "2.1.226"
    assert first["session.id"] == "11111111-1111-4111-8111-111111111111"


def test_int_value_parses_as_both_number_and_string():
    req = next(
        r for r in iter_log_records(_synthetic()) if r["_event_name"] == "claude_code.api_request"
    )
    assert req["input_tokens"] == 1200
    assert req["output_tokens"] == 350
    assert isinstance(req["output_tokens"], int)


def test_pii_attributes_never_leave_the_parser():
    for rec in iter_log_records(_real()):
        for banned in (
            "user.email",
            "user.id",
            "user.account_id",
            "user.account_uuid",
            "organization.id",
        ):
            assert banned not in rec, banned
        assert "@" not in json.dumps(rec)


def test_api_request_event_lands_in_api_requests(tmp_path):
    conn = _conn(tmp_path)
    n = sum(
        1
        for rec in iter_log_records(_synthetic())
        if handle_log_record(conn, rec) == "api_requests"
    )
    assert n == 2
    row = conn.execute("SELECT * FROM api_requests WHERE request_id='req_synth_001'").fetchone()
    assert row["model"] == "claude-sonnet-5"
    assert row["duration_ms"] == 2400
    assert row["input_tokens"] == 1200
    assert row["cost_usd"] == pytest.approx(0.0123)
    assert row["effort"] == "medium"
    assert row["cc_version"] == "2.1.226"
    assert row["prompt_id"] == "22222222-2222-4222-8222-222222222222"
    assert row["context_bucket"] == "lt30k"


def test_context_bucket_uses_the_token_sum_not_input_alone(tmp_path):
    conn = _conn(tmp_path)
    for rec in iter_log_records(_synthetic()):
        handle_log_record(conn, rec)
    row = conn.execute("SELECT * FROM api_requests WHERE request_id='req_synth_002'").fetchone()
    assert row["context_bucket"] == "gt180k"


def test_duplicate_request_id_is_ignored(tmp_path):
    conn = _conn(tmp_path)
    for _ in range(3):
        for rec in iter_log_records(_synthetic()):
            handle_log_record(conn, rec)
    assert conn.execute("SELECT COUNT(*) FROM api_requests").fetchone()[0] == 2


def test_errors_and_retries_exhausted(tmp_path):
    conn = _conn(tmp_path)
    for rec in iter_log_records(_synthetic()):
        handle_log_record(conn, rec)
    rows = conn.execute("SELECT * FROM api_errors ORDER BY retries_exhausted").fetchall()
    assert len(rows) == 2
    plain = rows[0]
    assert plain["status_code"] == 429
    assert plain["attempt"] == 1
    exhausted = rows[1]
    assert exhausted["retries_exhausted"] == 1
    assert exhausted["status_code"] == 529
    assert exhausted["attempt"] == 4


def test_tool_results_and_compaction(tmp_path):
    conn = _conn(tmp_path)
    for rec in iter_log_records(_synthetic()):
        handle_log_record(conn, rec)
    edit = conn.execute(
        "SELECT * FROM tool_results WHERE tool_use_id='toolu_synth_edit_1'"
    ).fetchone()
    assert edit["success"] == 1 and edit["tool_name"] == "Edit" and edit["source"] == "otel"
    bash = conn.execute(
        "SELECT * FROM tool_results WHERE tool_use_id='toolu_synth_bash_1'"
    ).fetchone()
    assert bash["success"] == 0 and bash["error_type"] == "command_failed"
    comp = conn.execute("SELECT * FROM compactions").fetchone()
    assert comp["source"] == "otel" and comp["pre_tokens"] == 178_000 and comp["trigger"] == "auto"


def test_hook_row_first_then_otel_merges_into_one_row(tmp_path):
    conn = _conn(tmp_path)
    conn.execute(
        "INSERT INTO tool_results(session_id, tool_use_id, ts, tool_name, success, "
        "file_path, source) VALUES ('s1','toolu_synth_edit_1','2026-08-25T00:00:00+00:00',"
        "'Edit', 1, 'c:/proj/a.py', 'hook')"
    )
    for rec in iter_log_records(_synthetic()):
        handle_log_record(conn, rec)
    rows = conn.execute(
        "SELECT * FROM tool_results WHERE tool_use_id='toolu_synth_edit_1'"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0]["file_path"] == "c:/proj/a.py"
    assert rows[0]["duration_ms"] == 120
    assert rows[0]["source"] == "hook"


def test_otel_row_first_then_hook_also_merges(tmp_path):
    conn = _conn(tmp_path)
    for rec in iter_log_records(_synthetic()):
        handle_log_record(conn, rec)
    conn.execute(
        "INSERT INTO tool_results(session_id, tool_use_id, ts, tool_name, file_path, source) "
        "VALUES ('s1','toolu_synth_edit_1','2026-08-25T00:00:00+00:00','Edit','c:/x.py','hook') "
        "ON CONFLICT(tool_use_id) WHERE tool_use_id IS NOT NULL "
        "DO UPDATE SET file_path = COALESCE(file_path, excluded.file_path)"
    )
    rows = conn.execute(
        "SELECT * FROM tool_results WHERE tool_use_id='toolu_synth_edit_1'"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0]["file_path"] == "c:/x.py"
    assert rows[0]["duration_ms"] == 120


def test_canary_sessions_stay_flagged(tmp_path):
    conn = _conn(tmp_path)
    conn.execute("INSERT INTO sessions(session_id, is_canary) VALUES ('csid', 1)")
    rec = {
        "_event_name": "claude_code.api_request",
        "_ts_iso": "2026-08-25T00:00:00+00:00",
        "session.id": "csid",
        "model": "claude-sonnet-5",
        "duration_ms": 100.0,
        "input_tokens": 10,
        "output_tokens": 5,
        "cache_read_tokens": 0,
        "cache_creation_tokens": 0,
        "cost_usd": 0.001,
        "request_id": "req_c1",
    }
    assert handle_log_record(conn, rec) == "api_requests"
    row = conn.execute(
        "SELECT s.is_canary FROM api_requests a JOIN sessions s USING(session_id)"
    ).fetchone()
    assert row[0] == 1


def test_unknown_events_are_ignored_not_fatal(tmp_path):
    conn = _conn(tmp_path)
    handled = [handle_log_record(conn, r) for r in iter_log_records(_real())]
    assert set(handled) <= {None, "sessions", "api_errors"}
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1


def test_malformed_record_does_not_raise(tmp_path):
    conn = _conn(tmp_path)
    assert handle_log_record(conn, {"_event_name": "claude_code.api_request"}) is None
    assert handle_log_record(conn, {}) is None


def test_ingest_spool_resumes_from_offset(tmp_path):
    conn = _conn(tmp_path)
    spool = tmp_path / "spool" / "otel"
    spool.mkdir(parents=True)
    day = spool / "otel-20260825.jsonl"
    body = _synthetic()
    day.write_text(json.dumps({"path": "/v1/logs", "recv_ts": 1.0, "body": body}) + "\n")
    state = tmp_path / "state.json"

    ok, err = ingest_otel_spool(conn, tmp_path / "spool", state)
    assert (ok, err) == (7, 0)
    assert conn.execute("SELECT COUNT(*) FROM api_requests").fetchone()[0] == 2

    ok2, err2 = ingest_otel_spool(conn, tmp_path / "spool", state)
    assert (ok2, err2) == (0, 0)

    with day.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"path": "/v1/logs", "recv_ts": 2.0, "body": body}) + "\n")
    ok3, _ = ingest_otel_spool(conn, tmp_path / "spool", state)
    assert ok3 == 7
    assert conn.execute("SELECT COUNT(*) FROM api_requests").fetchone()[0] == 2


def test_ingest_spool_counts_bad_lines_and_keeps_going(tmp_path):
    conn = _conn(tmp_path)
    spool = tmp_path / "spool" / "otel"
    spool.mkdir(parents=True)
    day = spool / "otel-20260825.jsonl"
    good = json.dumps({"path": "/v1/logs", "recv_ts": 1.0, "body": _synthetic()})
    day.write_text("not json{\n" + good + "\n" + '{"parse_error": "json: x"}\n')
    ok, err = ingest_otel_spool(conn, tmp_path / "spool", tmp_path / "state.json")
    assert ok == 7
    assert err >= 1
    assert conn.execute("SELECT COUNT(*) FROM ingest_log").fetchone()[0] >= 1


def test_ingest_spool_ignores_partial_trailing_line(tmp_path):
    conn = _conn(tmp_path)
    spool = tmp_path / "spool" / "otel"
    spool.mkdir(parents=True)
    day = spool / "otel-20260825.jsonl"
    good = json.dumps({"path": "/v1/logs", "recv_ts": 1.0, "body": _synthetic()})
    day.write_text(good + "\n" + '{"path": "/v1/logs", "recv_ts": 2.0, "bo')
    state = tmp_path / "state.json"
    ok, err = ingest_otel_spool(conn, tmp_path / "spool", state)
    assert (ok, err) == (7, 0)

    with day.open("a", encoding="utf-8") as fh:
        fh.write('dy": {"resourceLogs": []}}\n')
    ok2, err2 = ingest_otel_spool(conn, tmp_path / "spool", state)
    assert err2 == 0

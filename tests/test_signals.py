import math

from vitals.config import load
from vitals.db import get_conn, init_db
from vitals.detect import signal_ids as sid
from vitals.detect.signals import aggregate_hours, percentile

HOUR = "2026-08-20T10"
VER = "2.1.226"
MODEL = "claude-sonnet-5"


def _seeded_conn(tmp_path):
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)
    conn.execute(
        "INSERT INTO sessions(session_id, cc_version, is_canary) VALUES ('s1', ?, 0)", (VER,)
    )
    conn.execute(
        "INSERT INTO sessions(session_id, cc_version, is_canary) VALUES ('cs1', ?, 1)", (VER,)
    )

    def add_request(session, i, bucket, duration, tokens=100, minute=0):
        conn.execute(
            "INSERT INTO api_requests(session_id, prompt_id, request_id, ts, model, "
            "input_tokens, output_tokens, duration_ms, context_bucket, cc_version, source) "
            "VALUES (?,?,?,?,?,?,?,?,?,?, 'otel')",
            (
                session,
                f"p{i}",
                f"req_{session}_{bucket}_{i}",
                f"{HOUR}:{minute:02d}:00+00:00",
                MODEL,
                1000,
                tokens,
                duration,
                bucket,
                VER,
            ),
        )

    for i in range(20):
        add_request("s1", i, "lt30k", (i + 1) * 100, minute=i % 60)
    for i in range(20):
        add_request("s1", 100 + i, "gt180k", 5000, minute=i % 60)
    for i in range(2):
        add_request("cs1", 200 + i, "lt30k", 999_999, minute=i)

    conn.execute(
        "INSERT INTO api_errors(session_id, ts, model, status_code, attempt, cc_version, source) "
        "VALUES ('s1', ?, ?, 429, 2, ?, 'otel')",
        (f"{HOUR}:05:00+00:00", MODEL, VER),
    )
    conn.commit()
    return conn


def _window(conn, signal, bucket="all", model=MODEL):
    return conn.execute(
        "SELECT * FROM signal_windows WHERE signal=? AND model=? AND context_bucket=?",
        (signal, model, bucket),
    ).fetchone()


def test_percentile_is_linearly_interpolated():
    data = [(i + 1) * 100 for i in range(20)]
    assert percentile(data, 0.95) == 1905.0
    assert percentile(data, 0.5) == 1050.0
    assert percentile([5.0], 0.95) == 5.0
    assert percentile([], 0.5) is None


def test_hourly_p95_error_rate_and_canary_exclusion(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    conn = _seeded_conn(tmp_path)
    n = aggregate_hours(conn, load().detect)
    assert n > 0

    row = _window(conn, sid.S1_LATENCY_P95, "lt30k")
    assert row["n"] == 20
    assert abs(row["value"] - math.log(1905.0)) < 0.1
    assert row["cc_version"] == VER
    assert row["window_start"] == f"{HOUR}:00:00+00:00"

    p50 = _window(conn, sid.S1B_LATENCY_P50, "lt30k")
    assert abs(p50["value"] - math.log(1050.0)) < 0.1

    err = _window(conn, sid.S2_ERROR_RATE)
    assert abs(err["value"] - 1 / 41) < 1e-9
    assert err["n"] == 41

    assert aggregate_hours(conn, load().detect) == 0


def test_canary_latency_never_reaches_a_window(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    conn = _seeded_conn(tmp_path)
    aggregate_hours(conn, load().detect)
    for row in conn.execute(
        "SELECT value FROM signal_windows WHERE signal=?", (sid.S1_LATENCY_P95,)
    ):
        assert row["value"] < math.log(999_999)


def test_output_tokens_median(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    conn = _seeded_conn(tmp_path)
    aggregate_hours(conn, load().detect)
    row = _window(conn, sid.S8_OUTPUT_TOKENS, "lt30k")
    assert row["value"] == 100.0 and row["n"] == 20


def test_retry_rate_uses_observed_attempt_field(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    conn = _seeded_conn(tmp_path)
    aggregate_hours(conn, load().detect)
    row = _window(conn, sid.S3_RETRY_RATE)
    assert row["value"] == 2.0 and row["n"] == 1


def test_synthetic_client_errors_are_excluded_from_the_error_rate(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    conn = _seeded_conn(tmp_path)
    conn.execute(
        "INSERT INTO api_errors(session_id, ts, model, error_text, cc_version, source) "
        "VALUES ('s1', ?, '<synthetic>', 'session limit', ?, 'transcript_synthetic')",
        (f"{HOUR}:07:00+00:00", VER),
    )
    conn.commit()
    aggregate_hours(conn, load().detect)
    assert abs(_window(conn, sid.S2_ERROR_RATE)["value"] - 1 / 41) < 1e-9


def _seed_tools(conn, rows):
    for i, (tool, success, minute, prompt, path, runner, failed) in enumerate(rows):
        conn.execute(
            "INSERT INTO tool_results(session_id, prompt_id, tool_use_id, ts, tool_name, "
            "success, file_path, test_runner, tests_failed, source) "
            "VALUES ('s1',?,?,?,?,?,?,?,?, 'hook')",
            (prompt, f"t{i}", f"{HOUR}:{minute:02d}:00+00:00", tool, success, path, runner, failed),
        )
    conn.commit()


def test_tool_fail_rates_per_tool_and_overall(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    conn = _seeded_conn(tmp_path)
    _seed_tools(
        conn,
        [("Edit", 1, i, "p1", "a.py", None, None) for i in range(8)]
        + [("Edit", 0, 10 + i, "p1", "a.py", None, None) for i in range(2)]
        + [("Bash", 1, 20 + i, "p1", None, None, None) for i in range(5)],
    )
    aggregate_hours(conn, load().detect)
    edit = _window(conn, sid.S4_TOOL_FAIL_EDIT)
    assert edit["n"] == 10 and abs(edit["value"] - 0.2) < 1e-9
    every = _window(conn, sid.S4_TOOL_FAIL_ALL)
    assert every["n"] == 15 and abs(every["value"] - 2 / 15) < 1e-9
    bash = _window(conn, sid.S4_TOOL_FAIL_BASH)
    assert bash["n"] == 5 and bash["value"] == 0.0


def test_interrupted_tools_are_excluded_from_the_denominator(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    conn = _seeded_conn(tmp_path)
    _seed_tools(conn, [("Edit", 1, 1, "p1", "a.py", None, None)] * 1)
    conn.execute(
        "INSERT INTO tool_results(session_id, prompt_id, tool_use_id, ts, tool_name, success, "
        "error_type, source) VALUES ('s1','p1','ti', ?, 'Edit', NULL, 'interrupt', 'hook')",
        (f"{HOUR}:02:00+00:00",),
    )
    conn.commit()
    aggregate_hours(conn, load().detect)
    assert _window(conn, sid.S4_TOOL_FAIL_EDIT)["n"] == 1


def test_tool_signals_inherit_model_via_prompt_id(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    conn = _seeded_conn(tmp_path)
    _seed_tools(
        conn,
        [
            ("Edit", 1, 1, "p0", "a.py", None, None),
            ("Edit", 0, 2, "unknown-prompt", "a.py", None, None),
        ],
    )
    aggregate_hours(conn, load().detect)
    known = _window(conn, sid.S4_TOOL_FAIL_EDIT, model=MODEL)
    unknown = _window(conn, sid.S4_TOOL_FAIL_EDIT, model="all")
    assert known["n"] == 1 and unknown["n"] == 1


def test_edit_loop_rate(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    conn = _seeded_conn(tmp_path)
    _seed_tools(
        conn,
        [("Edit", 1, i, "p0", "a.py", None, None) for i in range(3)]
        + [("Edit", 1, 30, "p1", "b.py", None, None)],
    )
    aggregate_hours(conn, load().detect)
    row = _window(conn, sid.S5_EDIT_LOOP_RATE)
    assert row["n"] == 2 and abs(row["value"] - 0.5) < 1e-9


def test_test_fail_after_edit_rate(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    conn = _seeded_conn(tmp_path)
    _seed_tools(
        conn,
        [
            ("Edit", 1, 1, "p0", "a.py", None, None),
            ("Bash", 0, 2, "p0", None, "pytest", 3),
            ("Bash", 1, 3, "p0", None, "pytest", 0),
            ("Bash", 0, 4, "p1", None, "pytest", 1),
        ],
    )
    aggregate_hours(conn, load().detect)
    row = _window(conn, sid.S6_TEST_FAIL_AFTER_EDIT)
    assert row["n"] == 2 and abs(row["value"] - 0.5) < 1e-9


def test_self_correction_rate(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    conn = _seeded_conn(tmp_path)
    for i in range(4):
        conn.execute(
            "INSERT INTO transcript_turns(uuid, session_id, ts, role, model, cc_version, "
            "self_corr_hits, text_len) VALUES (?, 's1', ?, 'assistant', ?, ?, ?, 100)",
            (f"u{i}", f"{HOUR}:{i:02d}:00+00:00", MODEL, VER, 1 if i < 2 else 0),
        )
    conn.commit()
    aggregate_hours(conn, load().detect)
    row = _window(conn, sid.S7_SELF_CORR_RATE)
    assert row["n"] == 4 and abs(row["value"] - 0.5) < 1e-9


def test_post_compaction_fail_ratio(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    conn = _seeded_conn(tmp_path)
    conn.execute(
        "INSERT INTO compactions(session_id, ts, source, trigger) VALUES ('s1', ?, 'otel', 'auto')",
        (f"{HOUR}:00:00+00:00",),
    )
    _seed_tools(
        conn,
        [("Edit", 0 if i < 3 else 1, 1 + i, "p0", "a.py", None, None) for i in range(6)]
        + [("Edit", 0 if i < 1 else 1, 30 + i, "p1", "b.py", None, None) for i in range(6)],
    )
    aggregate_hours(conn, load().detect)
    row = _window(conn, sid.S9_POST_COMPACTION_FAIL)
    assert abs(row["value"] - (0.5 / (1 / 6))) < 1e-6
    assert row["n"] == 6


def test_empty_database_aggregates_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)
    assert aggregate_hours(conn, load().detect) == 0


def test_current_incomplete_hour_is_not_aggregated(tmp_path, monkeypatch):
    from vitals.timeutil import utcnow_iso

    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    conn = _seeded_conn(tmp_path)
    conn.execute(
        "INSERT INTO api_requests(session_id, request_id, ts, model, duration_ms, "
        "context_bucket, cc_version, source) VALUES ('s1','req_now', ?, ?, 100, 'lt30k', ?, 'otel')",
        (utcnow_iso(), MODEL, VER),
    )
    conn.commit()
    aggregate_hours(conn, load().detect)
    hours = {r[0] for r in conn.execute("SELECT DISTINCT window_start FROM signal_windows")}
    assert utcnow_iso()[:13] not in {h[:13] for h in hours}

from __future__ import annotations

import math
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from conftest import build_corpus, fixture_hash

from corpus.lower import LoweringReport, lower_corpus
from vitals import config as vitals_config
from vitals.config import DetectCfg
from vitals.db import get_conn, init_db, kv_get
from vitals.detect import signal_ids as sid
from vitals.detect.signals import aggregate_hours, percentile

MODEL = "claude-opus-5"
OTHER_MODEL = "claude-sonnet-5"
VERSION = "2.1.250"
BUCKET = "lt30k"

S1 = fixture_hash("session", "s1")
S2 = fixture_hash("session", "s2")


def hour(index: int) -> datetime:
    base = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    return base - timedelta(hours=48) + timedelta(hours=index)


def iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


def store(tmp_path, name: str = "lowered") -> sqlite3.Connection:
    conn = get_conn(tmp_path / name / "vitals.db")
    init_db(conn)
    return conn


def request_row(session: str, seq: int | None, at: datetime, **overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "session_hash": session,
        "prompt_seq": seq,
        "request_seq": 0,
        "ts_bucket_utc": at,
        "model": MODEL,
        "cc_version": VERSION,
        "context_bucket": BUCKET,
        "error_class": "none",
        "retries": 0,
        "post_compaction": False,
    }
    row.update(overrides)
    return row


def turn_row(session: str, seq: int, edit_retry_max: int, **overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "session_hash": session,
        "prompt_seq": seq,
        "self_correction": False,
        "edit_retry_max": edit_retry_max,
        "tool_calls": 0,
        "tool_failures": 0,
    }
    row.update(overrides)
    return row


def windows(conn: sqlite3.Connection, signal: str) -> list[tuple[Any, ...]]:
    return [
        (r["window_start"], r["model"], r["context_bucket"], r["value"], r["n"], r["cc_version"])
        for r in conn.execute(
            "SELECT * FROM signal_windows WHERE signal = ?"
            " ORDER BY window_start, model, context_bucket, cc_version",
            (signal,),
        )
    ]


def produced_signals(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT DISTINCT signal FROM signal_windows")}


def test_lowering_writes_signal_windows_for_request_signals(tmp_path):
    rows = []
    for session in (S1, S2):
        for h in range(3):
            for seq in range(2):
                rows.append(
                    request_row(
                        session, seq, hour(h), latency_ms=100 + 50 * seq, output_tokens=10 + seq
                    )
                )
            rows.append(
                request_row(
                    session,
                    0,
                    hour(h),
                    error_class="rate_limit",
                    retries=1,
                    context_bucket=None,
                    latency_ms=None,
                )
            )
    conn = store(tmp_path)

    report = lower_corpus(build_corpus(requests=rows), conn)

    expected = {
        sid.S1_LATENCY_P95,
        sid.S1B_LATENCY_P50,
        sid.S2_ERROR_RATE,
        sid.S3_RETRY_RATE,
        sid.S8_OUTPUT_TOKENS,
    }
    produced = produced_signals(conn)
    assert expected <= produced
    assert produced <= set(sid.FAMILY)
    for name in expected:
        assert report.signals_written[name] == 3, name
    assert report.rows_written["sessions"] == 2
    assert report.rows_written["api_requests"] == 12
    assert report.rows_written["api_errors"] == 6
    assert report.span_hours == 3


def test_lowering_matches_the_real_aggregator_for_one_hour(tmp_path):
    at = hour(0)
    rows = [
        request_row(S1, 0, at, latency_ms=latency, output_tokens=tokens)
        for latency, tokens in ((100, 10), (200, 20), (300, 30))
    ]
    rows.append(
        request_row(
            S1, 0, at, error_class="server", retries=2, context_bucket=None, latency_ms=None
        )
    )
    conn = store(tmp_path)

    lower_corpus(build_corpus(requests=rows), conn)

    assert kv_get(conn, "last_aggregated_hour") is not None

    latencies = [100.0, 200.0, 300.0]
    start = iso(at)
    assert windows(conn, sid.S1_LATENCY_P95) == [
        (start, MODEL, BUCKET, math.log(percentile(latencies, 0.95)), 3, VERSION)
    ]
    assert windows(conn, sid.S1B_LATENCY_P50) == [
        (start, MODEL, BUCKET, math.log(percentile(latencies, 0.5)), 3, VERSION)
    ]
    assert windows(conn, sid.S8_OUTPUT_TOKENS) == [
        (start, MODEL, BUCKET, percentile([10.0, 20.0, 30.0], 0.5), 3, VERSION)
    ]
    assert windows(conn, sid.S2_ERROR_RATE) == [(start, MODEL, "all", 0.25, 4, VERSION)]
    assert windows(conn, sid.S3_RETRY_RATE) == [(start, MODEL, "all", 1.0, 1, VERSION)]


def test_error_rows_and_success_rows_land_in_disjoint_store_tables(tmp_path):
    at = hour(0)
    rows = [
        request_row(S1, 0, at, latency_ms=120),
        request_row(
            S1, 0, at, error_class="timeout", retries=1, context_bucket=None, latency_ms=90
        ),
    ]
    conn = store(tmp_path)

    report = lower_corpus(build_corpus(requests=rows), conn)

    assert conn.execute("SELECT COUNT(*) FROM api_requests").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM api_errors").fetchone()[0] == 1
    error = conn.execute("SELECT * FROM api_errors").fetchone()
    assert error["source"] == "otel"
    assert error["attempt"] == 1
    assert error["duration_ms"] == 90.0
    assert conn.execute("SELECT ts FROM api_requests").fetchone()[0] == iso(at)


def test_every_rehydrated_attempt_is_counted_as_a_lossy_reconstruction(tmp_path):
    at = hour(0)
    rows = [
        request_row(S1, 0, at, latency_ms=120),
        request_row(S1, 0, at, error_class="server", retries=0, context_bucket=None),
        request_row(S1, 0, at, error_class="rate_limit", retries=2, context_bucket=None),
    ]
    conn = store(tmp_path)

    report = lower_corpus(build_corpus(requests=rows), conn)

    reason = "requests.retries.null_attempt_indistinguishable_from_zero"
    assert report.unmapped[reason] == 2
    assert report.unmapped["requests.retries.no_attempt_column_on_api_requests"] == 1


def build_real_edit_loop_store(tmp_path, at: datetime, prompts: dict[str, dict[str, int]]):
    conn = store(tmp_path, "real")
    conn.execute(
        "INSERT INTO sessions(session_id, cc_version, is_canary) VALUES (?,?,0)", ("real", VERSION)
    )
    ts = iso(at)
    for prompt_id, files in prompts.items():
        conn.execute(
            "INSERT INTO api_requests(session_id, prompt_id, ts, model, context_bucket,"
            " cc_version, source) VALUES (?,?,?,?,?,?, 'otel')",
            ("real", prompt_id, ts, MODEL, BUCKET, VERSION),
        )
        for path, count in files.items():
            for attempt in range(count):
                conn.execute(
                    "INSERT INTO tool_results(session_id, prompt_id, tool_use_id, ts, tool_name,"
                    " success, file_path, is_sidechain, source)"
                    " VALUES (?,?,?,?, 'Edit', 1, ?, 0, 'hook')",
                    ("real", prompt_id, f"{prompt_id}:{path}:{attempt}", ts, path),
                )
    conn.commit()
    return conn


def test_s5_mirror_matches_the_real_aggregator_semantics(tmp_path):
    at = hour(0)
    prompts = {
        "p0": {"a.py": 3},
        "p1": {"b.py": 1},
        "p2": {"c.py": 2, "d.py": 1},
        "p3": {},
    }
    real = build_real_edit_loop_store(tmp_path, at, prompts)
    aggregate_hours(real, DetectCfg())

    corpus = build_corpus(
        requests=[request_row(S1, seq, at) for seq in range(len(prompts))],
        turn_features=[
            turn_row(S1, seq, max(files.values()) if files else 0)
            for seq, files in enumerate(prompts.values())
        ],
    )
    mirrored = store(tmp_path, "mirror")
    lower_corpus(corpus, mirrored)

    assert windows(real, sid.S5_EDIT_LOOP_RATE) == windows(mirrored, sid.S5_EDIT_LOOP_RATE)
    assert windows(mirrored, sid.S5_EDIT_LOOP_RATE) == [(iso(at), MODEL, "all", 1 / 3, 3, VERSION)]


def test_s5_mirror_strata_follow_the_prompt_model_and_session_version(tmp_path):
    at = hour(0)
    corpus = build_corpus(
        requests=[
            request_row(S1, 0, at, model=MODEL),
            request_row(S1, 1, at, model=OTHER_MODEL),
        ],
        turn_features=[turn_row(S1, 0, 4), turn_row(S1, 1, 1)],
    )
    conn = store(tmp_path)

    lower_corpus(corpus, conn)

    assert windows(conn, sid.S5_EDIT_LOOP_RATE) == [
        (iso(at), MODEL, "all", 1.0, 1, VERSION),
        (iso(at), OTHER_MODEL, "all", 0.0, 1, VERSION),
    ]


def test_s5_mirror_diverges_predictably_for_a_prompt_spanning_two_hours(tmp_path):
    early, late = hour(0), hour(1)
    real = store(tmp_path, "real")
    real.execute(
        "INSERT INTO sessions(session_id, cc_version, is_canary) VALUES ('real',?,0)", (VERSION,)
    )
    for at in (early, late):
        real.execute(
            "INSERT INTO api_requests(session_id, prompt_id, ts, model, context_bucket,"
            " cc_version, source) VALUES ('real','p0',?,?,?,?, 'otel')",
            (iso(at), MODEL, BUCKET, VERSION),
        )
    for at, edits in ((early, 2), (late, 1)):
        for index in range(edits):
            real.execute(
                "INSERT INTO tool_results(session_id, prompt_id, tool_use_id, ts, tool_name,"
                " success, file_path, is_sidechain, source)"
                " VALUES ('real','p0',?,?, 'Edit', 1, 'a.py', 0, 'hook')",
                (f"{iso(at)}:{index}", iso(at)),
            )
    real.commit()
    aggregate_hours(real, DetectCfg())

    corpus = build_corpus(
        requests=[request_row(S1, 0, early), request_row(S1, 0, late)],
        turn_features=[turn_row(S1, 0, 3)],
    )
    mirrored = store(tmp_path, "mirror")
    lower_corpus(corpus, mirrored)

    real_windows = windows(real, sid.S5_EDIT_LOOP_RATE)
    mirror_windows = windows(mirrored, sid.S5_EDIT_LOOP_RATE)

    assert real_windows == [
        (iso(early), MODEL, "all", 0.0, 1, VERSION),
        (iso(late), MODEL, "all", 0.0, 1, VERSION),
    ]
    assert mirror_windows == [(iso(early), MODEL, "all", 1.0, 1, VERSION)]

    real_by_hour = {row[0]: row for row in real_windows}
    mirror_by_hour = {row[0]: row for row in mirror_windows}
    assert set(mirror_by_hour) == {iso(early)} <= set(real_by_hour)
    for start, row in mirror_by_hour.items():
        assert row[3] >= real_by_hour[start][3]
    assert sum(row[4] for row in mirror_windows) < sum(row[4] for row in real_windows)


def test_s4_tool_fail_signals_are_mirrored_from_tool_results(tmp_path):
    at = hour(0)
    corpus = build_corpus(
        requests=[request_row(S1, 0, at)],
        tool_results=[
            {"session_hash": S1, "prompt_seq": 0, "tool": "Edit", "ok": False},
            {"session_hash": S1, "prompt_seq": 0, "tool": "Edit", "ok": True},
            {"session_hash": S1, "prompt_seq": 0, "tool": "Bash", "ok": True},
            {"session_hash": S1, "prompt_seq": 0, "tool": "Read", "ok": None},
        ],
    )
    conn = store(tmp_path)

    lower_corpus(corpus, conn)

    assert windows(conn, sid.S4_TOOL_FAIL_ALL) == [(iso(at), MODEL, "all", 1 / 3, 3, VERSION)]
    assert windows(conn, sid.S4_TOOL_FAIL_EDIT) == [(iso(at), MODEL, "all", 0.5, 2, VERSION)]
    assert windows(conn, sid.S4_TOOL_FAIL_BASH) == [(iso(at), MODEL, "all", 0.0, 1, VERSION)]


def test_post_compaction_is_never_lowered_into_a_signal(tmp_path):
    at = hour(0)
    rows = [request_row(S1, 0, at, post_compaction=True, latency_ms=120) for _ in range(6)]
    conn = store(tmp_path)

    report = lower_corpus(build_corpus(requests=rows), conn)

    assert sid.S9_POST_COMPACTION_FAIL not in produced_signals(conn)
    assert sid.S9_POST_COMPACTION_FAIL not in report.signals_written
    reason = "requests.post_compaction.s9_unreachable_no_compaction_evidence"
    assert report.unmapped[reason] == 6


def canary_row(cycle: int, task: str, at: datetime, runs: int, passes: int, invalid: int):
    return {
        "cycle_id": cycle,
        "ts_bucket_utc": at,
        "model": MODEL,
        "cc_version": VERSION,
        "task_id": task,
        "runs": runs,
        "passes": passes,
        "invalid": invalid,
    }


def test_canary_rows_land_in_both_cycle_and_run_tables(tmp_path):
    at = hour(0)
    corpus = build_corpus(
        canary_cycles=[
            canary_row(1, "arith-exact", at, runs=4, passes=3, invalid=0),
            canary_row(1, "longctx-needle", at, runs=2, passes=1, invalid=1),
            canary_row(2, "arith-exact", hour(8), runs=4, passes=4, invalid=0),
        ]
    )
    conn = store(tmp_path)

    report = lower_corpus(corpus, conn)

    cycles = conn.execute("SELECT * FROM canary_cycles ORDER BY cycle_id").fetchall()
    assert [c["cycle_id"] for c in cycles] == [1, 2]
    assert (cycles[0]["n_runs"], cycles[0]["n_pass"], cycles[0]["n_invalid"]) == (4, 3, 0)
    assert cycles[0]["pass_rate"] == pytest.approx(3 / 4)
    assert cycles[0]["started_at"] == iso(at)
    assert cycles[0]["model"] == MODEL

    runs = conn.execute("SELECT * FROM canary_runs ORDER BY cycle_id, task_id, attempt").fetchall()
    assert len(runs) == 10
    first = [r for r in runs if r["cycle_id"] == 1]
    assert sum(1 for r in first if r["passed"] == 1 and not r["invalid"]) == 4
    assert sum(1 for r in first if r["passed"] == 0 and not r["invalid"]) == 1
    assert sum(1 for r in first if r["invalid"] == 1) == 1
    assert {r["task_id"] for r in runs if r["long_context"]} == {"longctx-needle"}
    assert [r["attempt"] for r in first if r["task_id"] == "arith-exact"] == [0, 1, 2, 3]
    assert report.rows_written["canary_cycles"] == 2
    assert report.rows_written["canary_runs"] == 10


def test_a_long_context_task_never_moves_the_cheap_suite_pass_rate(tmp_path):
    at = hour(0)
    corpus = build_corpus(
        canary_cycles=[
            canary_row(1, "arith-exact", at, runs=4, passes=3, invalid=0),
            canary_row(2, "arith-exact", hour(8), runs=4, passes=3, invalid=0),
            canary_row(2, "longctx-edit", hour(8), runs=4, passes=0, invalid=1),
        ]
    )
    conn = store(tmp_path)

    lower_corpus(corpus, conn)

    rollups = [
        (c["n_runs"], c["n_pass"], c["n_invalid"], c["pass_rate"])
        for c in conn.execute("SELECT * FROM canary_cycles ORDER BY cycle_id")
    ]
    assert rollups[0] == rollups[1] == (4, 3, 0, pytest.approx(3 / 4))
    assert (
        conn.execute("SELECT COUNT(*) FROM canary_runs WHERE long_context = 1").fetchone()[0] == 4
    )
    c2 = conn.execute(
        "SELECT SUM(COALESCE(r.passed, 0)) AS passes, COUNT(r.run_id) AS total"
        " FROM canary_cycles c JOIN canary_runs r ON r.cycle_id = c.cycle_id"
        " AND r.long_context = 1 AND r.invalid = 0 AND r.passed IS NOT NULL"
        " WHERE c.cycle_id = 2"
    ).fetchone()
    assert (c2["passes"], c2["total"]) == (0, 3)


def test_change_points_pass_through(tmp_path):
    from_hash = fixture_hash("cc_version", "old")
    to_hash = fixture_hash("cc_version", "new")
    corpus = build_corpus(
        change_points=[
            {
                "ts_bucket_utc": hour(0),
                "kind": "cc_version",
                "from_hash": from_hash,
                "to_hash": to_hash,
            },
            {
                "ts_bucket_utc": hour(2),
                "kind": "canary_suite",
                "from_hash": None,
                "to_hash": to_hash,
            },
        ]
    )
    conn = store(tmp_path)

    report = lower_corpus(corpus, conn)

    rows = conn.execute("SELECT * FROM change_points ORDER BY id").fetchall()
    assert [r["kind"] for r in rows] == ["cc_version", "canary_suite"]
    assert [r["ts"] for r in rows] == [iso(hour(0)), iso(hour(2))]
    assert (rows[0]["old_value"], rows[0]["new_value"]) == (from_hash, to_hash)
    assert rows[1]["old_value"] is None
    assert report.rows_written["change_points"] == 2


def test_unmapped_features_are_counted_not_dropped(tmp_path):
    at = hour(0)
    corpus = build_corpus(
        requests=[request_row(S1, 0, at, latency_ms=120)],
        turn_features=[
            turn_row(S1, 0, 1, self_correction=True, tool_calls=5, tool_failures=2),
        ],
    )
    conn = store(tmp_path)

    report = lower_corpus(corpus, conn)

    assert report.unmapped["turn_features.self_correction.s7_needs_transcript_turns"] == 1
    assert report.unmapped["turn_features.tool_calls.s4_uses_tool_results"] == 1
    assert report.unmapped["turn_features.tool_failures.s4_uses_tool_results"] == 1
    assert all(count > 0 for count in report.unmapped.values())
    tables = {key.split(".", 1)[0] for key in report.unmapped}
    from corpus import schema

    assert tables <= set(schema.TABLES)


def test_turn_features_with_no_matching_request_are_counted_not_dropped(tmp_path):
    at = hour(0)
    corpus = build_corpus(
        requests=[request_row(S1, 0, at)],
        turn_features=[turn_row(S1, 0, 4), turn_row(S1, 9, 4), turn_row(S2, 0, 4)],
        tool_results=[{"session_hash": S2, "prompt_seq": 3, "tool": "Edit", "ok": False}],
    )
    conn = store(tmp_path)

    report = lower_corpus(corpus, conn)

    assert report.unmapped["turn_features.no_request_hour"] == 2
    assert report.unmapped["tool_results.no_request_hour"] == 1
    assert windows(conn, sid.S5_EDIT_LOOP_RATE) == [(iso(at), MODEL, "all", 1.0, 1, VERSION)]


def test_lowering_never_touches_the_live_store(tmp_path, monkeypatch):
    fake_live = tmp_path / "fake-live-data-dir"
    fake_live.mkdir()
    monkeypatch.setenv("VITALS_DATA_DIR", str(fake_live))

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("lower_corpus resolved the live config")

    monkeypatch.setattr(vitals_config, "load", refuse)

    corpus = build_corpus(
        requests=[request_row(S1, 0, hour(0), latency_ms=120)],
        canary_cycles=[canary_row(1, "arith-exact", hour(0), runs=2, passes=2, invalid=0)],
        change_points=[{"ts_bucket_utc": hour(0), "kind": "settings"}],
    )
    conn = store(tmp_path)

    report = lower_corpus(corpus, conn)

    assert isinstance(report, LoweringReport)
    assert list(fake_live.iterdir()) == []


def test_an_empty_corpus_lowers_to_an_empty_store_without_raising(tmp_path):
    conn = store(tmp_path)

    report = lower_corpus(build_corpus(), conn)

    assert report.span_hours == 0
    assert report.signals_written == {}
    assert all(count == 0 for count in report.rows_written.values())

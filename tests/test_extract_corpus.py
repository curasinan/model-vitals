from __future__ import annotations

import json
from datetime import UTC, datetime

import extract_corpus
import pyarrow.parquet as pq
import pytest

from corpus import schema
from vitals.db import get_conn, init_db

KEY = b"extractor-unit-test-key-not-a-secret"

PLANTED_USER = "planted-user"
PLANTED_REPO = "private-client-repo"
PLANTED_BRANCH = "feature/planted-branch"
PLANTED_PATH = f"C:/Users/{PLANTED_USER}/{PLANTED_REPO}/a.py"
PLANTED_ERROR = f"rate limit exceeded while writing {PLANTED_PATH}"
S1 = "11111111-1111-4111-8111-111111111111"
S2 = "22222222-2222-4222-8222-222222222222"
P1 = "prompt-aaaaaaaa-planted"
P2 = "prompt-bbbbbbbb-planted"

PLANTED = (
    PLANTED_USER,
    PLANTED_REPO,
    PLANTED_BRANCH,
    PLANTED_PATH,
    PLANTED_ERROR,
    S1,
    S2,
    P1,
    P2,
    "req-1",
    "req-2",
    "req-3",
    "req-4",
    "err-1",
    "tu-1",
    "tt-1",
    "2.1.246 (Claude Code)",
    "2.1.247 (Claude Code)",
)


def _insert(conn, table, **cols):
    names = ", ".join(cols)
    marks = ", ".join("?" for _ in cols)
    conn.execute(f"INSERT INTO {table}({names}) VALUES ({marks})", list(cols.values()))  # noqa: S608


@pytest.fixture
def store(tmp_path):
    conn = get_conn(tmp_path / "vitals.db")
    init_db(conn)

    _insert(
        conn,
        "sessions",
        session_id=S1,
        started_at="2026-08-25T17:00:00+00:00",
        source="startup",
        cwd=f"C:/Users/{PLANTED_USER}/{PLANTED_REPO}",
        git_branch=PLANTED_BRANCH,
        cc_version="2.1.250",
        model_default="claude-opus-5",
        plugins_hash="a" * 32,
        settings_hash="b" * 32,
        is_canary=0,
        transcript_path=f"C:/Users/{PLANTED_USER}/.claude/projects/x.jsonl",
    )
    _insert(
        conn,
        "sessions",
        session_id=S2,
        started_at="2026-08-27T14:00:00+00:00",
        cc_version="2.1.250",
        is_canary=1,
    )

    _insert(
        conn,
        "api_requests",
        session_id=S1,
        prompt_id=P1,
        request_id="req-1",
        ts="2026-08-25T17:31:45+00:00",
        model="claude-opus-5",
        effort="xhigh",
        speed="normal",
        query_source="sdk",
        input_tokens=1000,
        output_tokens=200,
        cache_read_tokens=5000,
        cache_creation_tokens=0,
        duration_ms=1234.6,
        cost_usd=0.02,
        context_bucket="b30_100k",
        cc_version="2.1.250",
        source="otel",
    )
    _insert(
        conn,
        "api_requests",
        session_id=S1,
        prompt_id=P1,
        request_id="req-2",
        ts="2026-08-25T17:35:00+00:00",
        model="claude-sonnet-5",
        input_tokens=10,
        output_tokens=20,
        cache_read_tokens=0,
        duration_ms=99.4,
        context_bucket="lt30k",
        cc_version="2.1.250",
        source="otel",
    )
    _insert(
        conn,
        "api_requests",
        session_id=S1,
        prompt_id=P2,
        request_id="req-3",
        ts="2026-08-25T18:05:00+00:00",
        model="claude-opus-5",
        input_tokens=190000,
        output_tokens=500,
        cache_read_tokens=1000,
        duration_ms=4000.0,
        context_bucket="gt180k",
        cc_version="2.1.250",
        source="otel",
    )
    _insert(
        conn,
        "api_requests",
        session_id=S1,
        request_id="req-4",
        ts="2026-04-21T04:15:31+00:00",
        model="claude-fable-5",
        input_tokens=50,
        output_tokens=5,
        cache_read_tokens=0,
        context_bucket="b100_180k",
        cc_version="2.1.181",
        source="transcript",
    )

    _insert(
        conn,
        "api_errors",
        session_id=S1,
        prompt_id=P1,
        request_id="err-1",
        ts="2026-08-25T17:33:00+00:00",
        model="claude-sonnet-5",
        status_code=429,
        attempt=1,
        retries_exhausted=0,
        error_text=PLANTED_ERROR,
        duration_ms=50.0,
        cc_version="2.1.250",
        source="otel",
    )
    _insert(
        conn,
        "api_errors",
        session_id=S1,
        ts="2026-08-25T17:34:00+00:00",
        model="<synthetic>",
        error_text="You've hit your session limit",
        source="transcript_synthetic",
    )

    _insert(
        conn,
        "compactions",
        session_id=S1,
        ts="2026-08-25T18:00:00+00:00",
        source="otel",
        trigger="manual",
        success=1,
        duration_ms=900.0,
        pre_tokens=180000,
        post_tokens=30000,
    )

    _insert(
        conn,
        "tool_results",
        session_id=S1,
        prompt_id=P1,
        tool_use_id="tu-1",
        ts="2026-08-25T17:32:00+00:00",
        tool_name="Edit",
        success=1,
        duration_ms=12.4,
        file_path=PLANTED_PATH,
        is_sidechain=0,
        source="hook",
    )
    _insert(
        conn,
        "tool_results",
        session_id=S1,
        prompt_id=P1,
        tool_use_id="tu-2",
        ts="2026-08-25T17:32:30+00:00",
        tool_name="Edit",
        success=1,
        duration_ms=8.0,
        file_path=PLANTED_PATH.replace("/", "\\").upper(),
        is_sidechain=0,
        source="hook",
    )
    _insert(
        conn,
        "tool_results",
        session_id=S1,
        prompt_id=P1,
        tool_use_id="tu-3",
        ts="2026-08-25T17:33:10+00:00",
        tool_name="mcp__44444444-4444-4444-8444-444444444444__list_teams",
        success=0,
        duration_ms=99.9,
        error_type="McpToolCallError",
        is_sidechain=0,
        source="otel",
    )
    _insert(
        conn,
        "tool_results",
        session_id=S1,
        prompt_id=P1,
        tool_use_id="tu-4",
        ts="2026-08-25T17:34:10+00:00",
        tool_name="Bash",
        success=0,
        duration_ms=2500.0,
        bash_command_hash="c" * 16,
        bash_exit_code=1,
        test_runner="pytest",
        tests_failed=3,
        is_sidechain=0,
        source="hook",
    )
    _insert(
        conn,
        "tool_results",
        session_id=S1,
        prompt_id=P2,
        tool_use_id="tu-5",
        ts="2026-08-25T18:06:00+00:00",
        tool_name="Read",
        success=1,
        duration_ms=5.0,
        is_sidechain=0,
        source="hook",
    )
    _insert(
        conn,
        "tool_results",
        session_id=S1,
        prompt_id=P1,
        tool_use_id="tu-6",
        ts="2026-08-25T17:32:45+00:00",
        tool_name="Edit",
        success=1,
        duration_ms=7.0,
        file_path=PLANTED_PATH,
        is_sidechain=1,
        source="otel",
    )

    _insert(
        conn,
        "transcript_turns",
        uuid="tt-1",
        session_id=S1,
        prompt_id=P1,
        ts="2026-08-25T17:32:10+00:00",
        role="assistant",
        model="claude-opus-5",
        cc_version="2.1.250",
        self_corr_hits=1,
        text_len=400,
        stop_reason="tool_use",
    )
    _insert(
        conn,
        "transcript_turns",
        uuid="tt-2",
        session_id=S1,
        prompt_id=P2,
        ts="2026-08-25T18:05:30+00:00",
        role="assistant",
        model="claude-opus-5",
        cc_version="2.1.250",
        self_corr_hits=0,
        text_len=50,
        stop_reason="end_turn",
    )

    _insert(
        conn,
        "canary_cycles",
        cycle_id=7,
        started_at="2026-08-27T14:14:38+00:00",
        finished_at="2026-08-27T14:50:00+00:00",
        model="claude-sonnet-5",
        effort="medium",
        suite_hash="d" * 64,
        n_runs=3,
        n_pass=1,
        n_invalid=1,
        pass_rate=0.5,
        tokens_in=300,
        tokens_out=60,
        cost_usd=0.03,
    )
    _insert(
        conn,
        "canary_runs",
        run_id=1,
        cycle_id=7,
        task_id="arith-exact",
        attempt=1,
        session_id=S2,
        ts="2026-08-27T14:15:00+00:00",
        model="claude-sonnet-5",
        passed=1,
        invalid=0,
        duration_ms=100.0,
        input_tokens=100,
        output_tokens=20,
        cost_usd=0.01,
        terminal_reason="success",
    )
    _insert(
        conn,
        "canary_runs",
        run_id=2,
        cycle_id=7,
        task_id="arith-exact",
        attempt=2,
        session_id=S2,
        ts="2026-08-27T14:20:00+00:00",
        model="claude-sonnet-5",
        passed=0,
        invalid=0,
        duration_ms=300.0,
        input_tokens=100,
        output_tokens=20,
        cost_usd=0.01,
        terminal_reason="error_max_turns",
    )
    _insert(
        conn,
        "canary_runs",
        run_id=3,
        cycle_id=7,
        task_id="bugfix-py",
        attempt=1,
        session_id=S2,
        ts="2026-08-27T14:25:00+00:00",
        model="claude-sonnet-5",
        invalid=1,
        terminal_reason="parse-error",
    )

    _insert(
        conn,
        "change_points",
        ts="2026-08-25T17:07:37+00:00",
        kind="cc_version",
        old_value="2.1.246 (Claude Code)",
        new_value="2.1.247 (Claude Code)",
    )
    _insert(conn, "change_points", ts="2026-08-30T00:04:12+00:00", kind="settings")

    conn.commit()
    return conn


@pytest.fixture
def out(tmp_path):
    return tmp_path / "corpus_out"


@pytest.fixture
def hasher():
    return schema.Hasher(KEY)


def _run(store, out, hasher, **kw):
    return extract_corpus.extract(store, out, hasher, **kw)


def _table(out, name):
    return pq.read_table(out / f"{name}.parquet").to_pylist()


def test_requests_carry_hashed_identities_only(store, out, hasher):
    _run(store, out, hasher)
    rows = _table(out, "requests")
    for row in rows:
        assert row["session_hash"] == hasher.hash("session", S1)
        assert schema.HASH_RE.match(row["session_hash"])


def test_requests_bucket_timestamps_to_the_hour(store, out, hasher):
    _run(store, out, hasher)
    buckets = {r["ts_bucket_utc"] for r in _table(out, "requests")}
    assert datetime(2026, 8, 25, 17, tzinfo=UTC) in buckets
    assert all(b.minute == 0 and b.second == 0 for b in buckets)


def test_prompt_seq_is_a_per_session_ordinal_in_time_order(store, out, hasher):
    _run(store, out, hasher)
    by_request = {(r["ts_bucket_utc"], r["model"]): r for r in _table(out, "requests")}
    assert by_request[(datetime(2026, 8, 25, 17, tzinfo=UTC), "claude-opus-5")]["prompt_seq"] == 0
    assert by_request[(datetime(2026, 8, 25, 18, tzinfo=UTC), "claude-opus-5")]["prompt_seq"] == 1


def test_a_request_with_no_prompt_id_gets_a_null_prompt_seq(store, out, hasher):
    _run(store, out, hasher)
    orphan = [r for r in _table(out, "requests") if r["model"] == "claude-fable-5"]
    assert len(orphan) == 1
    assert orphan[0]["prompt_seq"] is None
    assert orphan[0]["latency_ms"] is None


def test_request_seq_orders_attempts_within_one_prompt(store, out, hasher):
    _run(store, out, hasher)
    p1 = sorted(
        (r for r in _table(out, "requests") if r["prompt_seq"] == 0),
        key=lambda r: r["request_seq"],
    )
    assert [r["request_seq"] for r in p1] == list(range(len(p1)))


def test_provider_errors_become_request_rows_with_a_class_and_retries(store, out, hasher):
    _run(store, out, hasher)
    errors = [r for r in _table(out, "requests") if r["error_class"] != "none"]
    assert len(errors) == 1
    assert errors[0]["error_class"] == "rate_limit"
    assert errors[0]["retries"] == 1
    assert errors[0]["input_tokens"] is None
    assert errors[0]["latency_ms"] == 50


def test_successful_requests_are_classed_none_with_zero_retries(store, out, hasher):
    _run(store, out, hasher)
    ok = [r for r in _table(out, "requests") if r["error_class"] == "none"]
    assert len(ok) == 4
    assert all(r["retries"] == 0 for r in ok)


def test_a_disjoint_union_records_a_zero_overlap(store, out, hasher):
    manifest = _run(store, out, hasher)
    assert manifest["excluded"]["requests_error_rows_deduped"] == 0


def test_an_error_sharing_a_request_id_is_deduped_and_counted(store, out, hasher):
    store.execute("UPDATE api_errors SET request_id = 'req-2' WHERE request_id = 'err-1'")
    store.commit()
    manifest = _run(store, out, hasher)
    assert manifest["excluded"]["requests_error_rows_deduped"] == 1
    rows = _table(out, "requests")
    assert manifest["row_counts"]["requests"] == len(rows) == 4
    assert all(r["error_class"] == "none" for r in rows)


def test_an_error_with_no_request_id_is_never_treated_as_a_duplicate(store, out, hasher):
    store.execute("UPDATE api_errors SET request_id = NULL WHERE request_id = 'err-1'")
    store.commit()
    manifest = _run(store, out, hasher)
    assert manifest["excluded"]["requests_error_rows_deduped"] == 0
    assert sum(1 for r in _table(out, "requests") if r["error_class"] != "none") == 1


def test_client_side_synthetic_errors_are_excluded_and_counted(store, out, hasher):
    manifest = _run(store, out, hasher)
    assert manifest["excluded"]["api_errors_transcript_synthetic"] == 1
    assert all(r["model"] != "<synthetic>" for r in _table(out, "requests"))


def test_post_compaction_marks_only_the_window_after_a_compaction(store, out, hasher):
    _run(store, out, hasher)
    flags = {
        (r["ts_bucket_utc"].hour, r["model"]): r["post_compaction"] for r in _table(out, "requests")
    }
    assert flags[(18, "claude-opus-5")] is True
    assert flags[(17, "claude-opus-5")] is False


def test_latency_is_a_whole_millisecond_count(store, out, hasher):
    _run(store, out, hasher)
    latencies = {r["latency_ms"] for r in _table(out, "requests")}
    assert 1235 in latencies
    assert all(v is None or isinstance(v, int) for v in latencies)


def test_plugins_hash_is_rehashed_not_passed_through(store, out, hasher):
    _run(store, out, hasher)
    row = _table(out, "requests")[0]
    assert row["plugins_hash"] != "a" * 32
    assert row["plugins_hash"] == hasher.hash("plugins", "a" * 32)


def test_tool_names_are_normalized_before_the_enum(store, out, hasher):
    _run(store, out, hasher)
    tools = {r["tool"] for r in _table(out, "tool_results")}
    assert "mcp__list_teams" in tools
    assert not any("44444444-4444" in t for t in tools)


def test_file_hash_folds_separators_and_case_to_one_identity(store, out, hasher):
    _run(store, out, hasher)
    edits = [r for r in _table(out, "tool_results") if r["tool"] == "Edit"]
    assert len(edits) == 2
    assert edits[0]["file_hash"] == edits[1]["file_hash"]
    assert edits[0]["file_hash"] == hasher.hash("file", schema.normalize_file_path(PLANTED_PATH))


def test_tool_rows_carry_ok_duration_and_test_fields(store, out, hasher):
    _run(store, out, hasher)
    bash = next(r for r in _table(out, "tool_results") if r["tool"] == "Bash")
    assert bash["ok"] is False
    assert bash["duration_ms"] == 2500
    assert bash["test_runner"] == "pytest"
    assert bash["test_exit_code"] == 1
    assert bash["file_hash"] is None


def test_sidechain_tool_calls_are_excluded_and_counted(store, out, hasher):
    manifest = _run(store, out, hasher)
    assert manifest["excluded"]["tool_results_sidechain"] == 1
    rows = _table(out, "tool_results")
    assert len(rows) == 5
    by_seq = {r["prompt_seq"]: r for r in _table(out, "turn_features")}
    assert by_seq[0]["tool_calls"] == 4
    assert by_seq[0]["edit_retry_max"] == 2


def test_a_prompt_with_only_sidechain_activity_still_exists_as_a_turn(store, out, hasher):
    _insert(
        store,
        "tool_results",
        session_id=S1,
        prompt_id="p-sidechain-only",
        tool_use_id="tu-7",
        ts="2026-08-25T19:00:00+00:00",
        tool_name="Edit",
        success=1,
        duration_ms=3.0,
        file_path=PLANTED_PATH,
        is_sidechain=1,
        source="otel",
    )
    store.commit()
    _run(store, out, hasher)
    rows = _table(out, "turn_features")
    assert len(rows) == 3
    lonely = next(r for r in rows if r["prompt_seq"] == 2)
    assert lonely["tool_calls"] == 0
    assert lonely["edit_retry_max"] == 0


def test_a_tool_row_with_no_recorded_exit_code_says_so(store, out, hasher):
    _run(store, out, hasher)
    read = next(r for r in _table(out, "tool_results") if r["tool"] == "Read")
    assert read["test_exit_code"] is None
    assert read["test_runner"] is None


def test_turn_features_count_calls_and_failures_per_prompt(store, out, hasher):
    _run(store, out, hasher)
    by_seq = {r["prompt_seq"]: r for r in _table(out, "turn_features")}
    assert by_seq[0]["tool_calls"] == 4
    assert by_seq[0]["tool_failures"] == 2
    assert by_seq[1]["tool_calls"] == 1
    assert by_seq[1]["tool_failures"] == 0


def test_edit_retry_max_is_the_deepest_single_file_loop(store, out, hasher):
    _run(store, out, hasher)
    by_seq = {r["prompt_seq"]: r for r in _table(out, "turn_features")}
    assert by_seq[0]["edit_retry_max"] == 2
    assert by_seq[1]["edit_retry_max"] == 0


def test_self_correction_comes_from_the_transcript_scanner(store, out, hasher):
    _run(store, out, hasher)
    by_seq = {r["prompt_seq"]: r for r in _table(out, "turn_features")}
    assert by_seq[0]["self_correction"] is True
    assert by_seq[1]["self_correction"] is False


def test_one_turn_feature_row_per_prompt(store, out, hasher):
    manifest = _run(store, out, hasher)
    rows = _table(out, "turn_features")
    assert len(rows) == 2
    assert manifest["row_counts"]["turn_features"] == 2
    assert len({(r["session_hash"], r["prompt_seq"]) for r in rows}) == 2


def test_canary_rows_are_one_per_cycle_and_task(store, out, hasher):
    _run(store, out, hasher)
    rows = _table(out, "canary_cycles")
    assert {(r["cycle_id"], r["task_id"]) for r in rows} == {(7, "arith-exact"), (7, "bugfix-py")}


def test_canary_aggregates_runs_passes_invalid_and_p50(store, out, hasher):
    _run(store, out, hasher)
    by_task = {r["task_id"]: r for r in _table(out, "canary_cycles")}
    arith = by_task["arith-exact"]
    assert (arith["runs"], arith["passes"], arith["invalid"]) == (2, 1, 0)
    assert arith["latency_ms_p50"] == 200
    assert arith["tokens_total"] == 240
    assert arith["cost_usd"] == pytest.approx(0.02)
    invalid = by_task["bugfix-py"]
    assert (invalid["runs"], invalid["passes"], invalid["invalid"]) == (1, 0, 1)
    assert invalid["latency_ms_p50"] is None
    assert invalid["tokens_total"] is None


def test_change_point_values_are_hashed_not_copied(store, out, hasher):
    _run(store, out, hasher)
    rows = sorted(_table(out, "change_points"), key=lambda r: r["ts_bucket_utc"])
    assert rows[0]["kind"] == "cc_version"
    assert rows[0]["from_hash"] == hasher.hash("change", "2.1.246 (Claude Code)")
    assert rows[0]["to_hash"] != rows[0]["from_hash"]
    assert rows[1]["from_hash"] is None and rows[1]["to_hash"] is None


def test_an_unknown_tool_aborts_the_run_and_writes_nothing(store, out, hasher):
    store.execute(
        "UPDATE tool_results SET tool_name = ? WHERE tool_use_id = 'tu-5'",
        (f"Tool_{PLANTED_REPO}",),
    )
    store.commit()
    with pytest.raises(schema.EnumViolation) as exc:
        _run(store, out, hasher)
    assert "tool" in str(exc.value)
    assert PLANTED_REPO not in str(exc.value)
    assert not out.exists() or not list(out.glob("*.parquet"))


def test_an_unknown_model_aborts_the_run(store, out, hasher):
    store.execute("UPDATE api_requests SET model = 'claude-nextgen-9' WHERE request_id='req-1'")
    store.commit()
    with pytest.raises(schema.EnumViolation) as exc:
        _run(store, out, hasher)
    assert "model" in str(exc.value)
    assert "claude-nextgen-9" not in str(exc.value)


def test_a_non_numeric_token_count_aborts_without_echoing_it(store, out, hasher):
    store.execute(
        "UPDATE api_requests SET input_tokens = ? WHERE request_id = 'req-1'", (PLANTED_PATH,)
    )
    store.commit()
    with pytest.raises(schema.UnreadableValue) as exc:
        _run(store, out, hasher)
    assert PLANTED_PATH not in str(exc.value)
    assert PLANTED_USER not in str(exc.value)
    assert "api_requests.input_tokens" in str(exc.value)
    assert exc.value.__cause__ is None and exc.value.__context__ is None


def test_a_corrupt_timestamp_aborts_without_echoing_it(store, out, hasher):
    store.execute("UPDATE api_requests SET ts = ? WHERE request_id = 'req-1'", (PLANTED_PATH,))
    store.commit()
    with pytest.raises(schema.UnreadableValue) as exc:
        _run(store, out, hasher)
    assert PLANTED_PATH not in str(exc.value)
    assert PLANTED_USER not in str(exc.value)


def test_a_corrupt_timestamp_never_reaches_the_manifest_verbatim(store, out, hasher):
    store.execute("UPDATE change_points SET ts = ? WHERE kind = 'settings'", (PLANTED_PATH,))
    store.commit()
    with pytest.raises(schema.UnreadableValue):
        _run(store, out, hasher)
    assert not (out / "manifest.json").exists()


def test_a_prose_cc_version_aborts_the_run(store, out, hasher):
    store.execute(
        "UPDATE api_requests SET cc_version = ? WHERE request_id='req-1'",
        (f"2.1.250 from C:/Users/{PLANTED_USER}",),
    )
    store.commit()
    with pytest.raises(schema.EnumViolation) as exc:
        _run(store, out, hasher)
    assert PLANTED_USER not in str(exc.value)


def test_a_request_and_an_error_sharing_a_timestamp_and_an_id_still_sort(store, out, hasher):
    store.execute("DELETE FROM api_requests")
    store.execute("DELETE FROM api_errors")
    _insert(
        store,
        "api_requests",
        id=1,
        session_id=S1,
        prompt_id=P1,
        request_id="req-x",
        ts="2026-08-25T17:31:45+00:00",
        model="claude-opus-5",
        input_tokens=1,
        output_tokens=1,
        cache_read_tokens=0,
        duration_ms=1.0,
        context_bucket="lt30k",
        cc_version="2.1.250",
        source="otel",
    )
    _insert(
        store,
        "api_errors",
        id=1,
        session_id=S1,
        prompt_id=P1,
        request_id="err-x",
        ts="2026-08-25T17:31:45+00:00",
        model="claude-opus-5",
        status_code=500,
        attempt=0,
        retries_exhausted=0,
        error_text="boom",
        duration_ms=1.0,
        cc_version="2.1.250",
        source="otel",
    )
    store.commit()
    _run(store, out, hasher)
    rows = sorted(_table(out, "requests"), key=lambda r: r["request_seq"])
    assert [r["request_seq"] for r in rows] == [0, 1]
    assert [r["error_class"] for r in rows] == ["none", "server"]


def test_prompt_order_follows_the_instant_not_the_string(store):
    store.execute("DELETE FROM transcript_turns")
    _insert(
        store,
        "transcript_turns",
        uuid="tt-early",
        session_id=S2,
        prompt_id="zz-earlier",
        ts="2026-08-27T09:30:00+02:00",
        role="assistant",
        self_corr_hits=0,
    )
    _insert(
        store,
        "transcript_turns",
        uuid="tt-late",
        session_id=S2,
        prompt_id="aa-later",
        ts="2026-08-27T08:00:00+00:00",
        role="assistant",
        self_corr_hits=0,
    )
    store.commit()
    ordinals = extract_corpus.prompt_ordinals(store)
    assert ordinals[(S2, "zz-earlier")] == 0
    assert ordinals[(S2, "aa-later")] == 1


def test_the_per_prompt_minimum_is_taken_on_the_instant_too(store):
    store.execute("DELETE FROM transcript_turns")
    _insert(
        store,
        "transcript_turns",
        uuid="tt-a",
        session_id=S2,
        prompt_id="zz-earlier",
        ts="2026-08-27T09:30:00+02:00",
        role="assistant",
        self_corr_hits=0,
    )
    _insert(
        store,
        "transcript_turns",
        uuid="tt-b",
        session_id=S2,
        prompt_id="zz-earlier",
        ts="2026-08-27T08:30:00+00:00",
        role="assistant",
        self_corr_hits=0,
    )
    _insert(
        store,
        "transcript_turns",
        uuid="tt-c",
        session_id=S2,
        prompt_id="aa-later",
        ts="2026-08-27T08:00:00+00:00",
        role="assistant",
        self_corr_hits=0,
    )
    store.commit()

    lexical_min = store.execute(
        "SELECT MIN(ts) FROM transcript_turns WHERE prompt_id = 'zz-earlier'"
    ).fetchone()[0]
    assert lexical_min == "2026-08-27T08:30:00+00:00"

    ordinals = extract_corpus.prompt_ordinals(store)
    assert ordinals[(S2, "zz-earlier")] == 0
    assert ordinals[(S2, "aa-later")] == 1


def test_an_exit_code_without_a_test_runner_is_not_called_a_test_exit_code(store, out, hasher):
    store.execute(
        "UPDATE tool_results SET test_runner = NULL, bash_exit_code = 7 WHERE tool_use_id = 'tu-4'"
    )
    store.commit()
    _run(store, out, hasher)
    bash = next(r for r in _table(out, "tool_results") if r["tool"] == "Bash")
    assert bash["test_runner"] is None
    assert bash["test_exit_code"] is None


def test_manifest_is_written_and_matches_the_returned_value(store, out, hasher):
    manifest = _run(store, out, hasher)
    on_disk = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert on_disk["row_counts"] == manifest["row_counts"]


def test_manifest_row_counts_match_the_parquet_files(store, out, hasher):
    manifest = _run(store, out, hasher)
    for table in schema.TABLES:
        assert manifest["row_counts"][table] == len(_table(out, table))


def test_manifest_records_the_span_it_actually_covers(store, out, hasher):
    manifest = _run(store, out, hasher)
    span = manifest["time_span_utc"]
    assert span["start"] == "2026-04-21T04:00:00+00:00"
    assert span["end"] == "2026-08-30T00:00:00+00:00"
    assert span["days"] == pytest.approx(130.83, abs=0.1)
    assert span["per_table"]["change_points"]["end"] == "2026-08-30T00:00:00+00:00"


def test_source_spans_are_hour_floored_like_every_other_instant(store, out, hasher):
    manifest = _run(store, out, hasher)
    sources = manifest["time_span_utc"]["per_source_table"]
    assert sources["tool_results"]["start"] == "2026-08-25T17:00:00+00:00"
    assert sources["tool_results"]["end"] == "2026-08-25T18:00:00+00:00"
    for span in sources.values():
        for endpoint in span.values():
            assert endpoint is None or endpoint.endswith(":00:00+00:00")


def test_manifest_records_enums_and_their_cardinalities(store, out, hasher):
    manifest = _run(store, out, hasher)
    enums = manifest["enums"]
    assert set(enums) == set(schema.ENUMS)
    assert enums["tool"]["declared_cardinality"] == len(schema.TOOLS)
    assert enums["tool"]["observed_cardinality"] == 4


def test_manifest_carries_the_key_id_and_never_the_key(store, out, hasher):
    manifest = _run(store, out, hasher)
    assert manifest["hmac_key_id"] == hasher.key_id
    assert manifest["hmac_key_env"] == schema.HMAC_KEY_ENV
    raw = (out / "manifest.json").read_text(encoding="utf-8")
    assert KEY.decode() not in raw
    assert "hmac_key" not in raw.replace("hmac_key_id", "").replace("hmac_key_env", "")


def test_manifest_records_versions_and_an_extraction_date(store, out, hasher):
    manifest = _run(store, out, hasher, now=datetime(2026, 9, 1, 6, 0, tzinfo=UTC))
    assert manifest["corpus_schema_version"] == schema.SCHEMA_VERSION
    assert manifest["extractor_version"] == extract_corpus.EXTRACTOR_VERSION
    assert manifest["extracted_at_utc"] == "2026-09-01T06:00:00+00:00"


def test_manifest_reports_full_sampling_when_under_the_cap(store, out, hasher):
    manifest = _run(store, out, hasher)
    assert manifest["sessions"]["sampling_rate"] == 1.0
    assert manifest["sessions"]["included"] == manifest["sessions"]["in_store"]
    assert manifest["sessions"]["cap_met"] is True
    assert manifest["size_bytes"]["total"] < extract_corpus.SIZE_CAP_BYTES


def test_keep_session_is_deterministic_and_monotone_in_the_rate():
    hashes = [f"{i:08x}" + "0" * 56 for i in range(0, 2**32, 2**32 // 400)][:400]
    for h in hashes:
        assert extract_corpus.keep_session(h, 0.5) == extract_corpus.keep_session(h, 0.5)
        if extract_corpus.keep_session(h, 0.25):
            assert extract_corpus.keep_session(h, 0.75)
    assert all(extract_corpus.keep_session(h, 1.0) for h in hashes)
    assert not any(extract_corpus.keep_session(h, 0.0) for h in hashes)
    kept = sum(extract_corpus.keep_session(h, 0.5) for h in hashes)
    assert 0.4 < kept / len(hashes) < 0.6


def test_a_size_cap_downsamples_sessions_and_records_the_rate(store, out, hasher):
    manifest = _run(store, out, hasher, size_cap_bytes=1)
    assert manifest["sessions"]["sampling_rate"] < 1.0
    assert manifest["sessions"]["cap_met"] is False
    for table in schema.TABLES:
        assert pq.read_table(out / f"{table}.parquet").schema.equals(
            schema.arrow_schema(table), check_metadata=False
        )


def test_downsampling_drops_whole_sessions_not_individual_rows(store, out, hasher):
    manifest = _run(store, out, hasher, size_cap_bytes=1)
    rate = manifest["sessions"]["sampling_rate"]
    survivor = hasher.hash("session", S1)
    expected = 5 if extract_corpus.keep_session(survivor, rate) else 0
    assert len(_table(out, "tool_results")) == expected


def test_no_planted_string_survives_into_the_corpus(store, out, hasher):
    _run(store, out, hasher)
    for table in schema.TABLES:
        blob = (out / f"{table}.parquet").read_bytes()
        for secret in PLANTED:
            assert secret.encode() not in blob, f"{secret!r} reached {table}.parquet"


def test_every_string_cell_is_an_enum_member_a_hash_or_a_version(store, out, hasher):
    _run(store, out, hasher)
    for table, columns in schema.TABLES.items():
        rows = _table(out, table)
        for col in columns:
            values = [r[col.name] for r in rows]
            if col.kind is schema.ColumnKind.ENUM:
                assert all(v is None or v in schema.ENUMS[col.enum] for v in values)
            elif col.kind is schema.ColumnKind.HASH:
                assert all(v is None or schema.HASH_RE.match(v) for v in values)
            elif col.kind is schema.ColumnKind.VERSION:
                assert all(v is None or schema.CC_VERSION_RE.match(v) for v in values)
            else:
                assert all(not isinstance(v, str) for v in values)


def test_non_nullable_columns_are_never_null(store, out, hasher):
    _run(store, out, hasher)
    for table, columns in schema.TABLES.items():
        for row in _table(out, table):
            for col in columns:
                if not col.nullable:
                    assert row[col.name] is not None, f"{table}.{col.name}"


def test_written_schema_is_exactly_the_declared_schema(store, out, hasher):
    _run(store, out, hasher)
    for table in schema.TABLES:
        assert pq.read_table(out / f"{table}.parquet").schema.equals(
            schema.arrow_schema(table), check_metadata=False
        )


def test_open_readonly_refuses_to_write(tmp_path):
    import sqlite3

    path = tmp_path / "live.db"
    init_db(get_conn(path))
    conn = extract_corpus.open_readonly(path)
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("INSERT INTO sessions(session_id) VALUES ('x')")


def test_open_readonly_does_not_create_a_missing_database(tmp_path):
    missing = tmp_path / "not-there.db"
    with pytest.raises(extract_corpus.StoreNotFound):
        extract_corpus.open_readonly(missing)
    assert not missing.exists()


def test_extraction_is_repeatable(store, out, hasher, tmp_path):
    first = _run(store, out, hasher)
    second_dir = tmp_path / "again"
    second = _run(store, second_dir, hasher)
    assert first["row_counts"] == second["row_counts"]
    for table in schema.TABLES:
        assert _table(out, table) == _table(second_dir, table)


def test_error_messages_never_name_the_store_path(tmp_path):
    weird = tmp_path / f"{PLANTED_USER}-store.db"
    with pytest.raises(extract_corpus.StoreNotFound) as exc:
        extract_corpus.open_readonly(weird)
    assert PLANTED_USER not in str(exc.value)
    assert str(tmp_path) not in str(exc.value)

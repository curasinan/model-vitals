from __future__ import annotations

import math
import re
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Literal

import pytest
from conftest import FIXTURE_EPOCH, build_corpus, fixture_hash

from corpus import schema
from corpus.inject import CorpusTables, inject
from corpus.lower import lower_corpus
from vitals.db import get_conn, init_db
from vitals.detect import signal_ids as sid

HASH_RE = re.compile(r"^[0-9a-f]{64}$")

S1 = fixture_hash("session", "s1")
S2 = fixture_hash("session", "s2")


def hour(index: int) -> datetime:
    return FIXTURE_EPOCH + timedelta(hours=index)


def turn_row(session: str, seq: int, tool_failures: int, edit_retry_max: int) -> dict[str, Any]:
    return {
        "session_hash": session,
        "prompt_seq": seq,
        "self_correction": False,
        "edit_retry_max": edit_retry_max,
        "tool_calls": 1,
        "tool_failures": tool_failures,
    }


def request_row(session: str, seq: int, bucket: str, **overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "session_hash": session,
        "prompt_seq": seq,
        "request_seq": 0,
        "ts_bucket_utc": FIXTURE_EPOCH,
        "context_bucket": bucket,
        "error_class": "none",
        "retries": 0,
        "post_compaction": False,
    }
    row.update(overrides)
    return row


def canary_row(cycle_id: int, task_id: str, passes: int, **overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "cycle_id": cycle_id,
        "ts_bucket_utc": FIXTURE_EPOCH,
        "cc_version": "9.9.9",
        "task_id": task_id,
        "runs": passes,
        "passes": passes,
        "invalid": 0,
    }
    row.update(overrides)
    return row


def _store(tmp_path, name: str = "lowered") -> sqlite3.Connection:
    conn = get_conn(tmp_path / name / "vitals.db")
    init_db(conn)
    return conn


def _assert_schema_preserved(
    corpus: CorpusTables, cls: Literal["A", "B", "C"], params: dict[str, object]
) -> None:
    before_schemas = {name: table.schema for name, table in corpus.items()}
    after = inject(corpus, cls, params)
    assert set(after) == set(before_schemas)
    for name, sch in before_schemas.items():
        assert after[name].schema.equals(sch), name


def test_class_a_preserves_schema():
    corpus = build_corpus(
        turn_features=[turn_row(S1, 0, tool_failures=1, edit_retry_max=1)],
        requests=[request_row(S1, 0, "gt180k", latency_ms=100)],
    )
    _assert_schema_preserved(corpus, "A", {"seed": 1, "n_sessions": 1, "n_prompts": 1})


def test_class_b_preserves_schema():
    _assert_schema_preserved(_class_b_corpus(), "B", {"seed": 1, "at_frac": 0.5})


def test_class_c_preserves_schema():
    _assert_schema_preserved(_class_c_corpus(), "C", {"seed": 1, "drop_to": 0.4})


def test_class_d_raises_not_implemented_naming_the_local_backend(synthetic_corpus):
    with pytest.raises(NotImplementedError, match="local backend"):
        inject(synthetic_corpus, "D", {})


@pytest.mark.parametrize("cls", ["A", "B", "C"])
def test_missing_seed_is_an_error(synthetic_corpus, cls):
    with pytest.raises(ValueError, match="seed"):
        inject(synthetic_corpus, cls, {})


def _class_a_corpus():
    turn_rows = []
    request_rows = []
    for session in (S1, S2):
        for seq in range(5):
            turn_rows.append(turn_row(session, seq, tool_failures=1, edit_retry_max=1))
            bucket = "lt30k" if seq < 2 else "gt180k"
            request_rows.append(request_row(session, seq, bucket, latency_ms=100))
    return build_corpus(turn_features=turn_rows, requests=request_rows)


def test_class_a_perturbs_what_its_docstring_says():
    corpus = _class_a_corpus()
    before = dict(corpus)

    result = inject(corpus, "A", {"seed": 7, "n_sessions": 1, "n_prompts": 4, "bucket": "gt180k"})

    changed_by_session: dict[str, list[int]] = {S1: [], S2: []}
    turn_after = result["turn_features"].to_pylist()
    turn_before = before["turn_features"].to_pylist()
    for after_row, before_row in zip(turn_after, turn_before, strict=True):
        if after_row != before_row:
            changed_by_session[after_row["session_hash"]].append(after_row["prompt_seq"])

    touched_sessions = [s for s, seqs in changed_by_session.items() if seqs]
    assert len(touched_sessions) == 1, changed_by_session
    session = touched_sessions[0]
    other = S2 if session == S1 else S1

    assert sorted(changed_by_session[session]) == [2, 3, 4]
    assert changed_by_session[other] == []

    for row in turn_after:
        if row["session_hash"] == session and row["prompt_seq"] in (2, 3, 4):
            assert row["tool_failures"] == 4
            assert row["edit_retry_max"] == 4
        else:
            assert row["tool_failures"] == 1
            assert row["edit_retry_max"] == 1

    req_after = result["requests"].to_pylist()
    req_before = before["requests"].to_pylist()
    for after_row, before_row in zip(req_after, req_before, strict=True):
        in_window_target = after_row["session_hash"] == session and after_row["prompt_seq"] in (
            2,
            3,
            4,
        )
        if in_window_target:
            assert after_row["latency_ms"] == 180
            assert isinstance(after_row["latency_ms"], int)
            assert after_row["error_class"] == "none"
        else:
            assert after_row == before_row

    assert result["tool_results"].equals(before["tool_results"])
    assert result["canary_cycles"].equals(before["canary_cycles"])
    assert result["change_points"].equals(before["change_points"])

    assert corpus["turn_features"].equals(before["turn_features"])
    assert corpus["requests"].equals(before["requests"])


def test_class_a_error_frac_flips_a_seeded_fraction_when_requested():
    corpus = _class_a_corpus()
    params = {
        "seed": 7,
        "n_sessions": 1,
        "n_prompts": 4,
        "bucket": "gt180k",
        "error_frac": 0.25,
    }
    result = inject(corpus, "A", params)

    req_after = result["requests"].to_pylist()
    req_before = _class_a_corpus()["requests"].to_pylist()
    flipped = [
        after_row["prompt_seq"]
        for after_row, before_row in zip(req_after, req_before, strict=True)
        if after_row["error_class"] != before_row["error_class"]
    ]
    assert len(flipped) == 1

    second = inject(_class_a_corpus(), "A", params)
    for table in schema.TABLES:
        assert result[table].equals(second[table]), table


def test_class_a_can_cross_the_edit_loop_threshold_at_clear_magnitude():
    corpus = build_corpus(
        turn_features=[turn_row(S1, 0, tool_failures=0, edit_retry_max=1)],
        requests=[request_row(S1, 0, "gt180k", latency_ms=50)],
    )
    result = inject(corpus, "A", {"seed": 1, "n_sessions": 1, "n_prompts": 1})
    row = result["turn_features"].to_pylist()[0]
    assert row["edit_retry_max"] >= 3


def test_class_a_is_deterministic():
    corpus = _class_a_corpus()
    params = {"seed": 99, "n_sessions": 1, "n_prompts": 4, "bucket": "gt180k"}
    first = inject(corpus, "A", params)
    second = inject(corpus, "A", params)
    for table in schema.TABLES:
        assert first[table].equals(second[table]), table


def test_class_a_default_bucket_is_the_most_populated_high_one():
    corpus = build_corpus(
        turn_features=[turn_row(S1, 0, tool_failures=1, edit_retry_max=1)],
        requests=[
            request_row(S1, 0, "gt180k", latency_ms=100),
            request_row(S2, 0, "gt180k", latency_ms=100),
            request_row(S2, 1, "b100_180k", latency_ms=100),
            request_row(S2, 2, "lt30k"),
            request_row(S2, 3, "lt30k"),
            request_row(S2, 4, "lt30k"),
        ],
    )
    result = inject(corpus, "A", {"seed": 1, "n_sessions": 1, "n_prompts": 1})
    row = result["turn_features"].to_pylist()[0]
    assert row["edit_retry_max"] == 4


def test_class_a_rejects_a_non_high_bucket():
    corpus = build_corpus(
        turn_features=[turn_row(S1, 0, tool_failures=1, edit_retry_max=1)],
        requests=[request_row(S1, 0, "lt30k", latency_ms=100)],
    )
    with pytest.raises(ValueError, match=r"HIGH context bucket"):
        inject(corpus, "A", {"seed": 1, "n_sessions": 1, "n_prompts": 1, "bucket": "lt30k"})


def test_class_a_raises_when_the_selection_is_empty():
    corpus = build_corpus(
        turn_features=[turn_row(S1, 0, tool_failures=1, edit_retry_max=1)],
        requests=[request_row(S1, 0, "b100_180k", latency_ms=100)],
    )
    with pytest.raises(ValueError, match=r"zero turn_features rows.*bucket='gt180k'.*n_prompts=1"):
        inject(corpus, "A", {"seed": 1, "n_sessions": 1, "n_prompts": 1, "bucket": "gt180k"})


def test_class_a_raises_when_the_request_layer_has_no_effect():
    corpus = build_corpus(
        turn_features=[turn_row(S1, 0, tool_failures=1, edit_retry_max=1)],
        requests=[request_row(S1, 0, "gt180k", latency_ms=None, error_class="server")],
    )
    with pytest.raises(ValueError, match="request-level layer changed no requests values"):
        inject(corpus, "A", {"seed": 1, "n_sessions": 1, "n_prompts": 1})


def test_class_a_high_context_buckets_matches_attribution_module():
    from corpus.inject import _CLASS_A_HIGH_CONTEXT_BUCKETS
    from vitals.detect.attribution import HIGH_CONTEXT_BUCKETS

    assert _CLASS_A_HIGH_CONTEXT_BUCKETS == HIGH_CONTEXT_BUCKETS


def test_class_a_bucket_predicate_aligns_with_lowerings_prompt_to_request_join(tmp_path):
    turn_rows = [turn_row(S1, 0, tool_failures=1, edit_retry_max=1)]
    request_rows = [
        request_row(S1, 0, "b100_180k", request_seq=0, ts_bucket_utc=hour(0), latency_ms=100),
        request_row(S1, 0, "gt180k", request_seq=1, ts_bucket_utc=hour(1), latency_ms=100),
    ]
    corpus = build_corpus(turn_features=turn_rows, requests=request_rows)

    perturbed = inject(
        corpus, "A", {"seed": 1, "n_sessions": 1, "n_prompts": 1, "bucket": "b100_180k"}
    )
    turn_row_after = perturbed["turn_features"].to_pylist()[0]
    assert turn_row_after["edit_retry_max"] == 4
    req_after = {row["request_seq"]: row for row in perturbed["requests"].to_pylist()}
    assert req_after[0]["latency_ms"] == 180
    assert req_after[1]["latency_ms"] == 100

    with pytest.raises(ValueError, match="zero turn_features rows"):
        inject(corpus, "A", {"seed": 1, "n_sessions": 1, "n_prompts": 1, "bucket": "gt180k"})

    conn = _store(tmp_path)
    lower_corpus(perturbed, conn)

    s5_windows = conn.execute(
        "SELECT context_bucket, value, n FROM signal_windows WHERE signal = ?",
        (sid.S5_EDIT_LOOP_RATE,),
    ).fetchall()
    assert len(s5_windows) == 1
    assert s5_windows[0]["context_bucket"] == "all"
    assert s5_windows[0]["value"] == 1.0
    assert s5_windows[0]["n"] == 1

    s1_windows = {
        row["context_bucket"]: row["value"]
        for row in conn.execute(
            "SELECT context_bucket, value FROM signal_windows WHERE signal = ?",
            (sid.S1_LATENCY_P95,),
        )
    }
    assert s1_windows.keys() == {"b100_180k", "gt180k"}
    assert s1_windows["b100_180k"] == pytest.approx(math.log(180))
    assert s1_windows["gt180k"] == pytest.approx(math.log(100))
    assert s1_windows["b100_180k"] > s1_windows["gt180k"]


def _class_b_corpus():
    rows = [
        request_row(S1, seq, "lt30k", ts_bucket_utc=hour(seq), output_tokens=100, latency_ms=200)
        for seq in range(4)
    ]
    return build_corpus(requests=rows)


def test_class_b_perturbs_what_its_docstring_says():
    corpus = _class_b_corpus()
    before = dict(corpus)

    result = inject(corpus, "B", {"seed": 3, "at_frac": 0.5, "kind": "settings"})

    after_requests = result["requests"].to_pylist()
    for row in after_requests:
        if row["ts_bucket_utc"] < hour(2):
            assert row["output_tokens"] == 100
            assert row["latency_ms"] == 200
        else:
            assert row["output_tokens"] == 160
            assert row["latency_ms"] == 300
    assert len(after_requests) == 4

    before_cps = before["change_points"].to_pylist()
    after_cps = result["change_points"].to_pylist()
    assert len(after_cps) == len(before_cps) + 1
    new_rows = [r for r in after_cps if r not in before_cps]
    assert len(new_rows) == 1
    new_row = new_rows[0]
    assert new_row["kind"] == "settings"
    assert new_row["ts_bucket_utc"] == hour(2)
    assert HASH_RE.match(new_row["from_hash"])
    assert HASH_RE.match(new_row["to_hash"])
    assert new_row["from_hash"] != new_row["to_hash"]

    assert result["turn_features"].equals(before["turn_features"])
    assert result["tool_results"].equals(before["tool_results"])
    assert result["canary_cycles"].equals(before["canary_cycles"])

    assert corpus["requests"].equals(before["requests"])
    assert corpus["change_points"].equals(before["change_points"])


def test_class_b_cc_version_raises_hash_vs_plaintext_unreachability():
    corpus = _class_b_corpus()
    with pytest.raises(ValueError, match="cc_version"):
        inject(corpus, "B", {"seed": 1, "kind": "cc_version"})


def test_class_b_rejects_a_kind_outside_the_allowed_vocabulary():
    corpus = _class_b_corpus()
    with pytest.raises(ValueError, match="canary_suite"):
        inject(corpus, "B", {"seed": 1, "kind": "canary_suite"})


def test_class_b_is_deterministic():
    corpus = _class_b_corpus()
    params = {"seed": 42, "at_frac": 0.5}
    first = inject(corpus, "B", params)
    second = inject(corpus, "B", params)
    for table in schema.TABLES:
        assert first[table].equals(second[table]), table


def test_class_b_raises_when_the_step_changes_nothing():
    corpus = build_corpus(
        requests=[
            request_row(S1, 0, "lt30k", ts_bucket_utc=hour(0), output_tokens=None, latency_ms=None),
            request_row(S1, 1, "lt30k", ts_bucket_utc=hour(1), output_tokens=None, latency_ms=None),
        ]
    )
    with pytest.raises(ValueError, match="changed no requests values"):
        inject(corpus, "B", {"seed": 1, "at_frac": 0.5})


def test_class_b_hashes_are_deterministic_and_seed_sensitive():
    corpus = _class_b_corpus()
    params = {"seed": 7, "at_frac": 0.5, "kind": "plugins"}

    first_cp = inject(corpus, "B", params)["change_points"].to_pylist()[0]
    second_cp = inject(corpus, "B", params)["change_points"].to_pylist()[0]
    assert first_cp["from_hash"] == second_cp["from_hash"]
    assert first_cp["to_hash"] == second_cp["to_hash"]
    assert first_cp["from_hash"] != first_cp["to_hash"]

    other_seed_cp = inject(corpus, "B", {**params, "seed": 8})["change_points"].to_pylist()[0]
    assert other_seed_cp["from_hash"] != first_cp["from_hash"]
    assert other_seed_cp["to_hash"] != first_cp["to_hash"]

    other_kind_cp = inject(corpus, "B", {**params, "kind": "settings"})[
        "change_points"
    ].to_pylist()[0]
    assert other_kind_cp["from_hash"] != first_cp["from_hash"]

    other_frac_cp = inject(corpus, "B", {**params, "at_frac": 0.25})["change_points"].to_pylist()[0]
    assert other_frac_cp["from_hash"] != first_cp["from_hash"]


def _class_c_corpus():
    rows = []
    for cycle_id in range(6):
        for task_id in ("arith-exact", "bugfix-py"):
            rows.append(canary_row(cycle_id, task_id, passes=10))
    return build_corpus(canary_cycles=rows)


def test_class_c_perturbs_what_its_docstring_says():
    corpus = _class_c_corpus()
    before = dict(corpus)

    result = inject(corpus, "C", {"seed": 5, "drop_to": 0.4})

    after_rows = result["canary_cycles"].to_pylist()
    before_rows = before["canary_cycles"].to_pylist()
    assert len(after_rows) == len(before_rows) == 12
    for after_row, before_row in zip(after_rows, before_rows, strict=True):
        assert after_row["cc_version"] == before_row["cc_version"] == "9.9.9"
        if after_row["cycle_id"] in (2, 3, 4, 5):
            assert after_row["passes"] == math.floor(10 * 0.4) == 4
        else:
            assert after_row["passes"] == 10

    assert result["change_points"].equals(before["change_points"])
    assert result["requests"].equals(before["requests"])
    assert result["tool_results"].equals(before["tool_results"])
    assert result["turn_features"].equals(before["turn_features"])

    assert corpus["canary_cycles"].equals(before["canary_cycles"])


def test_class_c_is_deterministic():
    corpus = _class_c_corpus()
    params = {"seed": 11, "drop_to": 0.4}
    first = inject(corpus, "C", params)
    second = inject(corpus, "C", params)
    for table in schema.TABLES:
        assert first[table].equals(second[table]), table


def test_class_c_raises_when_the_drop_changes_nothing():
    corpus = build_corpus(
        canary_cycles=[
            canary_row(0, "arith-exact", passes=0),
            canary_row(1, "bugfix-py", passes=0),
        ]
    )
    with pytest.raises(ValueError, match="zero canary_cycles rows"):
        inject(corpus, "C", {"seed": 1, "drop_to": 0.5})

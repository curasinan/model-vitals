from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest

from vitals.canary.checkers import TaskSpec, default_tasks_dir, load_tasks
from vitals.canary.longctx import NEEDLE_SEED, generate_log
from vitals.canary.runner import _build_args, run_cycle, run_task
from vitals.config import CanaryCfg
from vitals.db import get_conn, init_db
from vitals.timeutil import utcnow_iso

_LONG_STDIN_THRESHOLD = 10_000

_STUB_SOURCE = """\
import json
import os
import sys
import time


sleep_s = os.environ.get("VITALS_STUB_SLEEP_S")
if sleep_s:
    time.sleep(float(sleep_s))


def _read_stdin():
    try:
        if not sys.stdin.isatty():
            return sys.stdin.read()
    except Exception:
        pass
    return ""


stdin_data = _read_stdin()

record_path = os.environ.get("VITALS_STUB_RECORD")
if record_path:
    with open(record_path, "a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "argv": sys.argv[1:],
                    "stdin_len": len(stdin_data),
                    "cwd": os.getcwd(),
                    "telemetry_env": os.environ.get("CLAUDE_CODE_ENABLE_TELEMETRY"),
                }
            )
            + "\\n"
        )

_default = json.dumps({"is_error": False, "subtype": "success", "result": "unset"})
result_json = os.environ.get("VITALS_STUB_RESULT")
if result_json is None:
    long_threshold = int(os.environ.get("VITALS_STUB_LONG_THRESHOLD", "10000"))
    env_key = "VITALS_STUB_RESULT_LONG" if len(stdin_data) > long_threshold else "VITALS_STUB_RESULT_CHEAP"
    result_json = os.environ.get(env_key, _default)
sys.stdout.write(result_json)
"""


def _write_stub(tmp_path: Path) -> Path:
    stub_path = tmp_path / "stub.py"
    stub_path.write_text(_STUB_SOURCE, encoding="utf-8")
    return stub_path


def _write_claude_shim(bin_dir: Path, stub_py: Path) -> Path:
    if os.name == "nt":
        path = bin_dir / "claude.cmd"
        path.write_text(f'@echo off\n"{sys.executable}" "{stub_py}" %*\n', encoding="utf-8")
        return path
    path = bin_dir / "claude"
    path.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{stub_py}" "$@"\n', encoding="utf-8")
    path.chmod(0o755)
    return path


def _conn(tmp_path: Path):
    conn = get_conn(tmp_path / "vitals.db")
    init_db(conn)
    return conn


def _cfg(**overrides) -> CanaryCfg:
    return CanaryCfg(**overrides)


def _make_cycle(conn) -> int:
    cur = conn.execute(
        "INSERT INTO canary_cycles(started_at, model, effort, suite_hash) VALUES (?,?,?,?)",
        (utcnow_iso(), "claude-sonnet-5", "medium", "deadbeef"),
    )
    conn.commit()
    return cur.lastrowid


def _make_exact_task(
    tmp_path: Path, task_id: str, prompt: str, golden: str, **overrides
) -> TaskSpec:
    golden_dir = tmp_path / "tasks" / task_id / "golden"
    golden_dir.mkdir(parents=True)
    (golden_dir / "answer.txt").write_text(golden + "\n", encoding="utf-8")
    return TaskSpec(
        task_id=task_id,
        checker="exact",
        prompt=prompt,
        allowed_tools=[],
        max_turns=1,
        golden_dir=golden_dir,
        **overrides,
    )


def _read_last_record(record_path: Path) -> dict:
    return json.loads(record_path.read_text(encoding="utf-8").splitlines()[-1])


def test_run_task_records_passed_run_with_modelusage_accounting(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    task = _make_exact_task(tmp_path, "arith-mini", "2+2?", "4")
    stub = _write_stub(tmp_path)
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps(
            {
                "is_error": False,
                "subtype": "success",
                "result": "4",
                "duration_ms": 1200,
                "duration_api_ms": 900,
                "num_turns": 1,
                "total_cost_usd": 0.0021,
                "modelUsage": {
                    "claude-sonnet-5-20260101": {
                        "inputTokens": 120,
                        "outputTokens": 15,
                        "cacheReadInputTokens": 30,
                        "costUSD": 0.0021,
                    }
                },
            }
        ),
    )
    cfg = _cfg()

    row = run_task(task, cfg, conn, cycle_id, attempt=1, claude_cmd=[sys.executable, str(stub)])

    assert row.passed == 1
    assert row.invalid == 0
    assert row.input_tokens == 120
    assert row.output_tokens == 15
    assert row.cache_read_tokens == 30
    assert row.cost_usd == 0.0021
    assert row.model == cfg.model

    session = conn.execute(
        "SELECT is_canary FROM sessions WHERE session_id=?", (row.session_id,)
    ).fetchone()
    assert session is not None and session["is_canary"] == 1

    db_row = conn.execute(
        "SELECT passed, invalid, cost_usd, input_tokens FROM canary_runs "
        "WHERE cycle_id=? AND task_id=?",
        (cycle_id, task.task_id),
    ).fetchone()
    assert db_row["passed"] == 1
    assert db_row["invalid"] == 0
    assert db_row["cost_usd"] == 0.0021
    assert db_row["input_tokens"] == 120


def test_run_task_falls_back_to_price_table_when_total_cost_usd_is_zero(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    task = _make_exact_task(tmp_path, "t", "prompt", "OK")
    stub = _write_stub(tmp_path)
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps(
            {
                "is_error": False,
                "subtype": "success",
                "result": "OK",
                "total_cost_usd": 0,
                "modelUsage": {
                    "claude-sonnet-5-20260101": {
                        "inputTokens": 1_000_000,
                        "outputTokens": 1_000_000,
                        "costUSD": 0,
                    }
                },
            }
        ),
    )
    cfg = _cfg(model="claude-sonnet-5")

    row = run_task(task, cfg, conn, cycle_id, attempt=1, claude_cmd=[sys.executable, str(stub)])

    assert row.cost_usd == 12.0


def test_cache_read_tokens_are_priced_in_the_fallback(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    task = _make_exact_task(tmp_path, "t", "prompt", "OK")
    stub = _write_stub(tmp_path)
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps(
            {
                "is_error": False,
                "subtype": "success",
                "result": "OK",
                "total_cost_usd": 0,
                "modelUsage": {
                    "claude-sonnet-5-20260101": {
                        "inputTokens": 0,
                        "outputTokens": 0,
                        "cacheReadInputTokens": 1_000_000,
                        "costUSD": 0,
                    }
                },
            }
        ),
    )
    cfg = _cfg(model="claude-sonnet-5")

    row = run_task(task, cfg, conn, cycle_id, attempt=1, claude_cmd=[sys.executable, str(stub)])

    assert row.cache_read_tokens == 1_000_000
    assert row.cost_usd == pytest.approx(0.20)


def test_an_unpriced_model_yields_no_cost_so_the_estimate_can_stand_in(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    task = _make_exact_task(tmp_path, "t", "prompt", "OK")
    stub = _write_stub(tmp_path)
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps(
            {
                "is_error": False,
                "subtype": "success",
                "result": "OK",
                "total_cost_usd": 0,
                "modelUsage": {
                    "claude-newmodel-9": {
                        "inputTokens": 1_000_000,
                        "outputTokens": 1_000_000,
                        "costUSD": 0,
                    }
                },
            }
        ),
    )
    cfg = _cfg(model="claude-newmodel-9")

    row = run_task(task, cfg, conn, cycle_id, attempt=1, claude_cmd=[sys.executable, str(stub)])

    assert row.cost_usd is None, "an unpriced model must not settle at a confident $0"


def test_run_cycle_aborts_and_records_auth_on_live_probe_error_shape(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    task_a = _make_exact_task(tmp_path, "task-a", "prompt a", "A")
    task_b = _make_exact_task(tmp_path, "task-b", "prompt b", "B")
    stub = _write_stub(tmp_path)
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps(
            {
                "is_error": True,
                "subtype": "success",
                "result": "OAuth refresh token is no longer valid; run /login to re-authenticate",
            }
        ),
    )
    cfg = _cfg(runs_per_task=1, long_context_daily=False)

    cycle_id = run_cycle(conn, cfg, [task_a, task_b], claude_cmd=[sys.executable, str(stub)])

    cycle = conn.execute("SELECT * FROM canary_cycles WHERE cycle_id=?", (cycle_id,)).fetchone()
    assert cycle["aborted_reason"] == "auth"
    assert cycle["pass_rate"] is None
    assert cycle["n_runs"] == 1
    assert cycle["n_invalid"] == 1

    runs = conn.execute(
        "SELECT task_id, invalid, is_error, subtype FROM canary_runs WHERE cycle_id=?", (cycle_id,)
    ).fetchall()
    assert [r["task_id"] for r in runs] == ["task-a"]
    assert runs[0]["invalid"] == 1
    assert runs[0]["is_error"] == 1
    assert runs[0]["subtype"] == "success"


def test_inject_model_changes_argv_but_not_recorded_model(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    task = _make_exact_task(tmp_path, "t", "prompt", "golden")
    stub = _write_stub(tmp_path)
    record_path = tmp_path / "record.jsonl"
    monkeypatch.setenv("VITALS_STUB_RECORD", str(record_path))
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps({"is_error": False, "subtype": "success", "result": "golden"}),
    )
    cfg = _cfg(model="claude-sonnet-5")

    row = run_task(
        task,
        cfg,
        conn,
        cycle_id,
        attempt=1,
        claude_cmd=[sys.executable, str(stub)],
        inject_model="claude-haiku-4-5",
    )

    assert row.model == cfg.model
    record = _read_last_record(record_path)
    assert "claude-haiku-4-5" in record["argv"]
    assert "claude-sonnet-5" not in record["argv"]

    db_model = conn.execute(
        "SELECT model FROM canary_runs WHERE cycle_id=? AND task_id=?", (cycle_id, task.task_id)
    ).fetchone()["model"]
    assert db_model == "claude-sonnet-5"


def test_run_cycle_stops_mid_way_when_budget_exhausted(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    task_a = _make_exact_task(tmp_path, "task-a", "prompt a", "A", per_run_budget_usd=0.5)
    task_b = _make_exact_task(tmp_path, "task-b", "prompt b", "B", per_run_budget_usd=0.5)
    stub = _write_stub(tmp_path)
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps({"is_error": False, "subtype": "success", "result": "A", "total_cost_usd": 0.5}),
    )
    cfg = _cfg(runs_per_task=1, long_context_daily=False, daily_budget_usd=0.5)

    cycle_id = run_cycle(conn, cfg, [task_a, task_b], claude_cmd=[sys.executable, str(stub)])

    cycle = conn.execute("SELECT * FROM canary_cycles WHERE cycle_id=?", (cycle_id,)).fetchone()
    assert cycle["aborted_reason"] == "budget"
    runs = conn.execute("SELECT task_id FROM canary_runs WHERE cycle_id=?", (cycle_id,)).fetchall()
    assert [r["task_id"] for r in runs] == ["task-a"]
    ledger_rows = conn.execute("SELECT COUNT(*) c FROM spend_ledger").fetchone()["c"]
    assert ledger_rows == 1


def test_run_task_marks_timeout_as_invalid(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    task = _make_exact_task(tmp_path, "t", "prompt", "OK", per_run_timeout_s=1)
    stub = _write_stub(tmp_path)
    monkeypatch.setenv("VITALS_STUB_SLEEP_S", "5")

    row = run_task(task, _cfg(), conn, cycle_id, attempt=1, claude_cmd=[sys.executable, str(stub)])

    assert row.invalid == 1
    assert row.passed is None
    assert row.terminal_reason == "timeout"
    assert row.cost_usd is None


def test_run_cycle_settles_a_timeout_at_the_reservation_estimate_not_zero(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    task = _make_exact_task(
        tmp_path, "t", "prompt", "OK", per_run_budget_usd=0.4, per_run_timeout_s=1
    )
    stub = _write_stub(tmp_path)
    monkeypatch.setenv("VITALS_STUB_SLEEP_S", "5")
    cfg = _cfg(runs_per_task=1, long_context_daily=False, daily_budget_usd=10.0)

    cycle_id = run_cycle(conn, cfg, [task], claude_cmd=[sys.executable, str(stub)])

    ledger_cost = conn.execute("SELECT cost_usd FROM spend_ledger").fetchone()[0]
    assert ledger_cost == 0.4

    cycle = conn.execute(
        "SELECT cost_usd, aborted_reason FROM canary_cycles WHERE cycle_id=?", (cycle_id,)
    ).fetchone()
    assert cycle["cost_usd"] == 0.4
    assert cycle["aborted_reason"] is None


def test_run_task_marks_invalid_when_stdout_is_not_json(tmp_path):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    task = _make_exact_task(tmp_path, "t", "prompt", "OK")
    broken_stub = tmp_path / "broken.py"
    broken_stub.write_text('print("not json at all")\n', encoding="utf-8")

    row = run_task(
        task,
        cfg=_cfg(),
        conn=conn,
        cycle_id=cycle_id,
        attempt=1,
        claude_cmd=[sys.executable, str(broken_stub)],
    )

    assert row.invalid == 1
    assert row.passed is None
    assert row.terminal_reason == "parse-error"


def test_run_task_marks_invalid_when_result_json_is_not_an_object(tmp_path):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    task = _make_exact_task(tmp_path, "t", "prompt", "OK")
    not_an_object_stub = tmp_path / "not_an_object.py"
    not_an_object_stub.write_text('print("123")\n', encoding="utf-8")

    row = run_task(
        task,
        cfg=_cfg(),
        conn=conn,
        cycle_id=cycle_id,
        attempt=1,
        claude_cmd=[sys.executable, str(not_an_object_stub)],
    )

    assert row.invalid == 1
    assert row.passed is None
    assert row.terminal_reason == "parse-error"


def test_parse_error_detail_names_the_exit_code(tmp_path):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    task = _make_exact_task(tmp_path, "t", "prompt", "OK")
    silent_stub = tmp_path / "silent.py"
    silent_stub.write_text("import sys; sys.exit(37)", encoding="utf-8")

    row = run_task(
        task,
        cfg=_cfg(),
        conn=conn,
        cycle_id=cycle_id,
        attempt=1,
        claude_cmd=[sys.executable, str(silent_stub)],
    )

    assert row.terminal_reason == "parse-error"
    assert "37" in (row.fail_detail or ""), f"exit code missing from: {row.fail_detail!r}"


def test_long_context_task_prompt_goes_via_stdin_not_argv(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    golden_dir = tmp_path / "golden-lc"
    golden_dir.mkdir()
    (golden_dir / "answer.txt").write_text("whatever\n", encoding="utf-8")
    task = TaskSpec(
        task_id="lc",
        checker="exact",
        prompt="prefixmarker {LOG} suffixmarker",
        allowed_tools=[],
        max_turns=1,
        golden_dir=golden_dir,
        long_context=True,
        per_run_timeout_s=60,
    )
    stub = _write_stub(tmp_path)
    record_path = tmp_path / "record.jsonl"
    monkeypatch.setenv("VITALS_STUB_RECORD", str(record_path))
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps({"is_error": False, "subtype": "success", "result": "whatever"}),
    )
    cfg = _cfg()

    row = run_task(task, cfg, conn, cycle_id, attempt=1, claude_cmd=[sys.executable, str(stub)])

    assert row.passed == 1
    expected_prompt = "prefixmarker " + generate_log(NEEDLE_SEED) + " suffixmarker"
    record = _read_last_record(record_path)
    assert not any("prefixmarker" in a or "suffixmarker" in a for a in record["argv"])
    assert not any("{LOG}" in a for a in record["argv"])
    assert record["stdin_len"] == len(expected_prompt)


def test_shutil_which_resolves_claude_and_delivers_the_full_multiline_prompt_via_stdin(
    tmp_path, monkeypatch
):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    real_prompt = (default_tasks_dir() / "diff-golden" / "prompt.md").read_text(encoding="utf-8")
    assert real_prompt.count("\n") > 3

    task = _make_exact_task(tmp_path, "t", real_prompt, "OK")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = _write_stub(tmp_path)
    _write_claude_shim(bin_dir, stub)
    monkeypatch.setenv("PATH", str(bin_dir))
    record_path = tmp_path / "record.jsonl"
    monkeypatch.setenv("VITALS_STUB_RECORD", str(record_path))
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps({"is_error": False, "subtype": "success", "result": "OK"}),
    )
    cfg = _cfg()

    row = run_task(task, cfg, conn, cycle_id, attempt=1)

    assert row.invalid == 0
    assert row.passed == 1
    assert row.terminal_reason != "claude-not-found"

    record = _read_last_record(record_path)
    full_argv = record["argv"]
    for flag in (
        "-p",
        "--output-format",
        "json",
        "--model",
        "--effort",
        "--max-turns",
        "--max-budget-usd",
        "--session-id",
        "--bare",
    ):
        assert flag in full_argv, f"{flag!r} missing from argv -- looks truncated: {full_argv!r}"
    assert "--allowedTools" not in full_argv
    assert not any(real_prompt.splitlines()[0] in a for a in full_argv)
    assert record["stdin_len"] == len(real_prompt)


def test_run_task_marks_invalid_when_claude_executable_is_missing(tmp_path, monkeypatch):
    import vitals.canary.runner as runner_module

    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    task = _make_exact_task(tmp_path, "t", "prompt", "OK")
    monkeypatch.setattr(runner_module.shutil, "which", lambda name: None)
    cfg = _cfg()

    row = run_task(task, cfg, conn, cycle_id, attempt=1)

    assert row.invalid == 1
    assert row.passed is None
    assert row.terminal_reason == "claude-not-found"
    assert row.session_id is None


def test_run_cycle_aborts_with_claude_not_found_and_does_not_burn_through_the_suite(
    tmp_path, monkeypatch
):
    import vitals.canary.runner as runner_module

    conn = _conn(tmp_path)
    task_a = _make_exact_task(tmp_path, "task-a", "prompt a", "A")
    task_b = _make_exact_task(tmp_path, "task-b", "prompt b", "B")
    monkeypatch.setattr(runner_module.shutil, "which", lambda name: None)
    cfg = _cfg(runs_per_task=2, long_context_daily=False)

    cycle_id = run_cycle(conn, cfg, [task_a, task_b])

    cycle = conn.execute("SELECT * FROM canary_cycles WHERE cycle_id=?", (cycle_id,)).fetchone()
    assert cycle["aborted_reason"] == "claude-not-found"
    n_runs = conn.execute(
        "SELECT COUNT(*) c FROM canary_runs WHERE cycle_id=?", (cycle_id,)
    ).fetchone()["c"]
    assert n_runs == 1


def test_run_cycle_excludes_long_context_failures_from_cheap_pass_rate(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    cheap = _make_exact_task(tmp_path, "cheap", "cheap prompt", "OK")
    golden_dir = tmp_path / "golden-lc2"
    golden_dir.mkdir()
    (golden_dir / "answer.txt").write_text("right\n", encoding="utf-8")
    long_task = TaskSpec(
        task_id="lc",
        checker="exact",
        prompt="ctx {LOG} end",
        allowed_tools=[],
        max_turns=1,
        golden_dir=golden_dir,
        long_context=True,
        per_run_timeout_s=60,
    )
    stub = _write_stub(tmp_path)
    monkeypatch.setenv(
        "VITALS_STUB_RESULT_CHEAP",
        json.dumps({"is_error": False, "subtype": "success", "result": "OK"}),
    )
    monkeypatch.setenv(
        "VITALS_STUB_RESULT_LONG",
        json.dumps({"is_error": False, "subtype": "success", "result": "WRONG ANSWER"}),
    )
    cfg = _cfg(runs_per_task=2, long_context_daily=True)

    cycle_id = run_cycle(conn, cfg, [cheap, long_task], claude_cmd=[sys.executable, str(stub)])

    cycle = conn.execute("SELECT * FROM canary_cycles WHERE cycle_id=?", (cycle_id,)).fetchone()
    assert cycle["n_runs"] == 2
    assert cycle["n_pass"] == 2
    assert cycle["n_invalid"] == 0
    assert cycle["pass_rate"] == 1.0

    lc_run = conn.execute(
        "SELECT passed, invalid, long_context FROM canary_runs WHERE task_id='lc'"
    ).fetchone()
    assert lc_run["long_context"] == 1
    assert lc_run["passed"] == 0

    cheap_runs = conn.execute(
        "SELECT long_context FROM canary_runs WHERE task_id='cheap'"
    ).fetchall()
    assert len(cheap_runs) == 2
    assert all(r["long_context"] == 0 for r in cheap_runs)


def test_run_task_marks_checker_infra_failure_as_invalid_not_failed(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    golden_dir = tmp_path / "golden-infra"
    golden_dir.mkdir()
    task = TaskSpec(
        task_id="infra-t",
        checker="pytest",
        prompt="do something",
        allowed_tools=[],
        max_turns=1,
        golden_dir=golden_dir,
        workspace_template=None,
    )
    stub = _write_stub(tmp_path)
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps({"is_error": False, "subtype": "success", "result": "done"}),
    )
    cfg = _cfg()

    row = run_task(task, cfg, conn, cycle_id, attempt=1, claude_cmd=[sys.executable, str(stub)])

    assert row.invalid == 1
    assert row.passed is None
    assert row.fail_detail.startswith("INFRA:")


def test_run_task_removes_the_workspace_after_the_checker_runs(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    template = tmp_path / "template"
    template.mkdir()
    (template / "a.txt").write_text("hello\n", encoding="utf-8")
    golden_dir = tmp_path / "golden-ws"
    golden_dir.mkdir()
    task = TaskSpec(
        task_id="ws",
        checker="pytest",
        prompt="do something",
        allowed_tools=[],
        max_turns=1,
        golden_dir=golden_dir,
        workspace_template=template,
    )
    stub = _write_stub(tmp_path)
    record_path = tmp_path / "record.jsonl"
    monkeypatch.setenv("VITALS_STUB_RECORD", str(record_path))
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps({"is_error": False, "subtype": "success", "result": "done"}),
    )

    row = run_task(task, _cfg(), conn, cycle_id, attempt=1, claude_cmd=[sys.executable, str(stub)])

    assert row.fail_detail is None or isinstance(row.fail_detail, str)

    record = _read_last_record(record_path)
    workspace_cwd = Path(record["cwd"])
    assert not workspace_cwd.exists()


def test_run_task_removes_the_workspace_even_when_the_run_errors_out(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    template = tmp_path / "template2"
    template.mkdir()
    (template / "a.txt").write_text("hello\n", encoding="utf-8")
    golden_dir = tmp_path / "golden-ws2"
    golden_dir.mkdir()
    task = TaskSpec(
        task_id="ws2",
        checker="pytest",
        prompt="do something",
        allowed_tools=[],
        max_turns=1,
        golden_dir=golden_dir,
        workspace_template=template,
    )
    stub = _write_stub(tmp_path)
    record_path = tmp_path / "record.jsonl"
    monkeypatch.setenv("VITALS_STUB_RECORD", str(record_path))
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps({"is_error": True, "subtype": "success", "result": "some failure"}),
    )

    run_task(task, _cfg(), conn, cycle_id, attempt=1, claude_cmd=[sys.executable, str(stub)])

    record = _read_last_record(record_path)
    assert not Path(record["cwd"]).exists()


def test_run_task_disables_telemetry_in_child_env(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    task = _make_exact_task(tmp_path, "t", "prompt", "OK")
    stub = _write_stub(tmp_path)
    record_path = tmp_path / "record.jsonl"
    monkeypatch.setenv("VITALS_STUB_RECORD", str(record_path))
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps({"is_error": False, "subtype": "success", "result": "OK"}),
    )
    monkeypatch.setenv("CLAUDE_CODE_ENABLE_TELEMETRY", "1")

    run_task(task, _cfg(), conn, cycle_id, attempt=1, claude_cmd=[sys.executable, str(stub)])

    record = _read_last_record(record_path)
    assert record["telemetry_env"] == "0"


def test_run_cycle_spends_nothing_when_canary_is_disabled(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    task = _make_exact_task(tmp_path, "t", "prompt", "OK")
    stub = _write_stub(tmp_path)
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps({"is_error": False, "subtype": "success", "result": "OK"}),
    )
    cfg = _cfg(enabled=False)

    cycle_id = run_cycle(conn, cfg, [task], claude_cmd=[sys.executable, str(stub)])

    cycle = conn.execute("SELECT * FROM canary_cycles WHERE cycle_id=?", (cycle_id,)).fetchone()
    assert cycle["aborted_reason"] == "disabled"
    assert cycle["n_runs"] == 0
    assert cycle["finished_at"] is not None

    n_runs = conn.execute("SELECT COUNT(*) c FROM canary_runs").fetchone()["c"]
    assert n_runs == 0
    n_ledger = conn.execute("SELECT COUNT(*) c FROM spend_ledger").fetchone()["c"]
    assert n_ledger == 0


def test_run_task_marks_an_unexpected_checker_exception_as_invalid_not_a_crash(
    tmp_path, monkeypatch
):
    import vitals.canary.runner as runner_module

    conn = _conn(tmp_path)
    cycle_id = _make_cycle(conn)
    golden_dir = tmp_path / "golden-boom"
    golden_dir.mkdir()
    task = TaskSpec(
        task_id="boom-task",
        checker="boom",
        prompt="do something",
        allowed_tools=[],
        max_turns=1,
        golden_dir=golden_dir,
    )
    stub = _write_stub(tmp_path)
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps({"is_error": False, "subtype": "success", "result": "done"}),
    )

    def _exploding_checker(task, artifacts):
        raise RuntimeError("checker exploded unexpectedly")

    monkeypatch.setitem(runner_module.CHECKERS, "boom", _exploding_checker)

    row = run_task(task, _cfg(), conn, cycle_id, attempt=1, claude_cmd=[sys.executable, str(stub)])

    assert row.invalid == 1
    assert row.passed is None
    assert row.terminal_reason not in ("timeout", "claude-not-found")
    assert "checker exploded unexpectedly" in row.fail_detail
    assert "RuntimeError" in row.fail_detail

    db_row = conn.execute(
        "SELECT passed, invalid, fail_detail FROM canary_runs WHERE cycle_id=? AND task_id=?",
        (cycle_id, task.task_id),
    ).fetchone()
    assert db_row is not None
    assert db_row["invalid"] == 1
    assert db_row["passed"] is None


def test_run_cycle_settles_the_reservation_when_a_checker_raises_unexpectedly(
    tmp_path, monkeypatch
):
    import vitals.canary.runner as runner_module

    conn = _conn(tmp_path)
    golden_dir = tmp_path / "golden-boom2"
    golden_dir.mkdir()
    boom_task = TaskSpec(
        task_id="boom-task",
        checker="boom",
        prompt="do something",
        allowed_tools=[],
        max_turns=1,
        golden_dir=golden_dir,
        per_run_budget_usd=0.3,
    )
    ok_task = _make_exact_task(tmp_path, "ok-task", "prompt", "OK", per_run_budget_usd=0.3)
    stub = _write_stub(tmp_path)
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps(
            {"is_error": False, "subtype": "success", "result": "OK", "total_cost_usd": 0.1}
        ),
    )
    monkeypatch.setitem(
        runner_module.CHECKERS,
        "boom",
        lambda task, artifacts: (_ for _ in ()).throw(RuntimeError("checker exploded")),
    )
    cfg = _cfg(runs_per_task=1, long_context_daily=False, daily_budget_usd=10.0)

    cycle_id = run_cycle(conn, cfg, [boom_task, ok_task], claude_cmd=[sys.executable, str(stub)])

    cycle = conn.execute("SELECT * FROM canary_cycles WHERE cycle_id=?", (cycle_id,)).fetchone()
    assert cycle["aborted_reason"] is None
    assert cycle["finished_at"] is not None

    runs = conn.execute(
        "SELECT task_id FROM canary_runs WHERE cycle_id=? ORDER BY run_id", (cycle_id,)
    ).fetchall()
    assert [r["task_id"] for r in runs] == ["boom-task", "ok-task"]

    ledger_rows = conn.execute("SELECT cost_usd FROM spend_ledger ORDER BY id").fetchall()
    assert len(ledger_rows) == 2
    assert ledger_rows[0]["cost_usd"] == 0.1


def _schema_task(**over):
    base = dict(
        task_id="t",
        checker="json_schema",
        prompt="p",
        allowed_tools=[],
        max_turns=1,
        golden_dir=Path("."),
        json_schema={"type": "object"},
    )
    base.update(over)
    return TaskSpec(**base)


def test_structured_output_is_opt_in_so_a_schema_file_cannot_silently_cost_a_turn():
    args = _build_args(["claude"], _schema_task(), CanaryCfg(), "sid", "claude-sonnet-5", 0.1)

    assert "--json-schema" not in args


def test_a_task_that_opts_in_still_gets_the_structured_output_flag():
    args = _build_args(
        ["claude"],
        _schema_task(structured_output=True, max_turns=2),
        CanaryCfg(),
        "sid",
        "claude-sonnet-5",
        0.1,
    )

    assert "--json-schema" in args


def test_the_real_json_extract_task_does_not_request_structured_output():
    task = next(t for t in load_tasks(default_tasks_dir()) if t.task_id == "json-extract")
    args = _build_args(["claude"], task, CanaryCfg(), "sid", "claude-sonnet-5", 0.1)

    assert task.max_turns == 1
    assert "--json-schema" not in args
    assert task.json_schema is not None, "the schema must still be there to validate against"


def test_a_crash_inside_run_task_still_finalises_the_cycle_and_settles_its_reservation(
    tmp_path, monkeypatch
):
    import vitals.canary.runner as runner_module

    conn = _conn(tmp_path)
    task_a = _make_exact_task(tmp_path, "task-a", "prompt a", "A", per_run_budget_usd=0.3)
    task_b = _make_exact_task(tmp_path, "task-b", "prompt b", "B", per_run_budget_usd=0.3)
    stub = _write_stub(tmp_path)
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps({"is_error": False, "subtype": "success", "result": "A", "total_cost_usd": 0.1}),
    )

    reserved: list[int] = []
    settled: list[int] = []
    real_reserve, real_settle = runner_module.check_and_reserve, runner_module.settle

    def counting_reserve(*args, **kwargs):
        rid = real_reserve(*args, **kwargs)
        if rid is not None:
            reserved.append(rid)
        return rid

    def counting_settle(conn_, reservation_id, *args, **kwargs):
        settled.append(reservation_id)
        return real_settle(conn_, reservation_id, *args, **kwargs)

    monkeypatch.setattr(runner_module, "check_and_reserve", counting_reserve)
    monkeypatch.setattr(runner_module, "settle", counting_settle)

    real_run_task = runner_module.run_task
    calls = {"n": 0}

    def exploding_run_task(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise sqlite3.OperationalError("database is locked")
        return real_run_task(*args, **kwargs)

    monkeypatch.setattr(runner_module, "run_task", exploding_run_task)

    cfg = _cfg(runs_per_task=1, long_context_daily=False, daily_budget_usd=10.0)

    cycle_id = run_cycle(conn, cfg, [task_a, task_b], claude_cmd=[sys.executable, str(stub)])

    cycle = conn.execute("SELECT * FROM canary_cycles WHERE cycle_id=?", (cycle_id,)).fetchone()
    assert cycle["finished_at"] is not None, "a crashed cycle must still record that it ended"

    assert sorted(settled) == sorted(reserved), "every reservation must be settled, none leaked"

    infra = conn.execute("SELECT COUNT(*) FROM ingest_log WHERE kind = 'canary_infra'").fetchone()[
        0
    ]
    assert infra >= 1, "the lost run must be recorded, not silently dropped"

    runs = conn.execute("SELECT task_id FROM canary_runs WHERE cycle_id=?", (cycle_id,)).fetchall()
    assert [r["task_id"] for r in runs] == ["task-a"]


def _three_tasks(tmp_path, monkeypatch):
    tasks = [
        _make_exact_task(tmp_path, f"task-{c}", f"prompt {c}", "A", per_run_budget_usd=0.3)
        for c in "abc"
    ]
    monkeypatch.setenv(
        "VITALS_STUB_RESULT",
        json.dumps({"is_error": False, "subtype": "success", "result": "A", "total_cost_usd": 0.1}),
    )
    return tasks


def test_a_real_lock_on_a_run_insert_costs_one_run_not_the_cycle(tmp_path, monkeypatch):
    import vitals.canary.runner as runner_module

    conn = _conn(tmp_path)
    conn.execute("PRAGMA busy_timeout=200")
    other = get_conn(tmp_path / "vitals.db")
    tasks = _three_tasks(tmp_path, monkeypatch)
    stub = _write_stub(tmp_path)

    real_insert = runner_module._insert_run
    calls = {"n": 0}

    def insert_under_lock(conn_, row):
        calls["n"] += 1
        if calls["n"] != 2:
            return real_insert(conn_, row)
        other.execute("BEGIN IMMEDIATE")
        try:
            return real_insert(conn_, row)
        finally:
            other.rollback()

    monkeypatch.setattr(runner_module, "_insert_run", insert_under_lock)
    cfg = _cfg(runs_per_task=1, long_context_daily=False, daily_budget_usd=10.0)

    cycle_id = run_cycle(conn, cfg, tasks, claude_cmd=[sys.executable, str(stub)])

    cycle = conn.execute("SELECT * FROM canary_cycles WHERE cycle_id=?", (cycle_id,)).fetchone()
    assert cycle["finished_at"] is not None
    assert cycle["aborted_reason"] is None
    runs = conn.execute("SELECT task_id FROM canary_runs WHERE cycle_id=?", (cycle_id,)).fetchall()
    assert [r["task_id"] for r in runs] == ["task-a", "task-c"]
    costs = sorted(r[0] for r in conn.execute("SELECT cost_usd FROM spend_ledger"))
    assert costs == pytest.approx([0.1, 0.1, 0.3])
    infra = conn.execute("SELECT COUNT(*) FROM ingest_log WHERE kind = 'canary_infra'").fetchone()
    assert infra[0] == 1


def test_a_real_lock_on_the_budget_check_skips_one_run(tmp_path, monkeypatch):
    import vitals.canary.runner as runner_module

    conn = _conn(tmp_path)
    conn.execute("PRAGMA busy_timeout=200")
    other = get_conn(tmp_path / "vitals.db")
    tasks = _three_tasks(tmp_path, monkeypatch)
    stub = _write_stub(tmp_path)

    real_reserve = runner_module.check_and_reserve
    calls = {"n": 0}

    def reserve_under_lock(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] != 2:
            return real_reserve(*args, **kwargs)
        other.execute("BEGIN IMMEDIATE")
        try:
            return real_reserve(*args, **kwargs)
        finally:
            other.rollback()

    monkeypatch.setattr(runner_module, "check_and_reserve", reserve_under_lock)
    cfg = _cfg(runs_per_task=1, long_context_daily=False, daily_budget_usd=10.0)

    cycle_id = run_cycle(conn, cfg, tasks, claude_cmd=[sys.executable, str(stub)])

    cycle = conn.execute("SELECT * FROM canary_cycles WHERE cycle_id=?", (cycle_id,)).fetchone()
    assert cycle["aborted_reason"] is None
    runs = conn.execute("SELECT task_id FROM canary_runs WHERE cycle_id=?", (cycle_id,)).fetchall()
    assert [r["task_id"] for r in runs] == ["task-a", "task-c"]
    assert conn.execute("SELECT COUNT(*) FROM spend_ledger").fetchone()[0] == 2

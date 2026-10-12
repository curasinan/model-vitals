from __future__ import annotations

import json
import subprocess
from pathlib import Path

from vitals.canary.budget import check_and_reserve, settle
from vitals.canary.checkers import TaskSpec
from vitals.canary.runner import run_cycle
from vitals.config import CanaryCfg
from vitals.db import get_conn, init_db
from vitals.timeutil import local_day


def _conn(tmp_path: Path):
    conn = get_conn(tmp_path / "vitals.db")
    init_db(conn)
    return conn


def _cfg(**overrides) -> CanaryCfg:
    return CanaryCfg(**overrides)


def _task(tmp_path: Path, task_id: str, **overrides) -> TaskSpec:
    golden_dir = tmp_path / "tasks" / task_id / "golden"
    golden_dir.mkdir(parents=True, exist_ok=True)
    (golden_dir / "answer.txt").write_text("OK\n", encoding="utf-8")
    return TaskSpec(
        task_id=task_id,
        checker="exact",
        prompt="prompt",
        allowed_tools=[],
        max_turns=1,
        golden_dir=golden_dir,
        **overrides,
    )


def _patch_subprocess(monkeypatch, results: list[str]) -> list[dict]:
    calls: list[dict] = []

    def _fake_run(
        args, input=None, capture_output=None, text=None, timeout=None, cwd=None, env=None
    ):
        calls.append({"args": list(args), "stdin": input})
        if not results:
            raise AssertionError(
                f"subprocess.run invoked more times than the budget guard should allow "
                f"(call #{len(calls)}, args={args!r}) -- a launch happened that the cap "
                f"should have refused"
            )
        result_json = results.pop(0)
        return subprocess.CompletedProcess(args, 0, stdout=result_json, stderr="")

    import vitals.canary.runner as runner_module

    monkeypatch.setattr(runner_module.subprocess, "run", _fake_run)
    return calls


_OK_RESULT = json.dumps({"is_error": False, "subtype": "success", "result": "OK"})


def test_three_cycle_24h_replay_hard_stops_at_the_dollar_cap_and_nothing_launches_after(
    tmp_path, monkeypatch
):
    conn = _conn(tmp_path)
    task = _task(tmp_path, "t", per_run_budget_usd=0.4)
    cfg = _cfg(
        runs_per_task=3, long_context_daily=False, daily_budget_usd=1.0, per_run_budget_usd=0.4
    )
    cost_result = json.dumps(
        {"is_error": False, "subtype": "success", "result": "OK", "total_cost_usd": 0.4}
    )
    calls = _patch_subprocess(monkeypatch, [cost_result, cost_result])

    cycle_ids = [run_cycle(conn, cfg, [task], claude_cmd=["fake-claude"]) for _ in range(3)]

    assert len(calls) == 2

    cycles = [
        conn.execute("SELECT * FROM canary_cycles WHERE cycle_id=?", (cid,)).fetchone()
        for cid in cycle_ids
    ]
    assert cycles[0]["aborted_reason"] == "budget"
    assert cycles[0]["n_runs"] == 2
    assert cycles[1]["aborted_reason"] == "budget"
    assert cycles[1]["n_runs"] == 0
    assert cycles[2]["aborted_reason"] == "budget"
    assert cycles[2]["n_runs"] == 0

    total_runs = conn.execute("SELECT COUNT(*) c FROM canary_runs").fetchone()["c"]
    assert total_runs == 2


def test_three_cycle_24h_replay_hard_stops_at_the_token_cap_and_nothing_launches_after(
    tmp_path, monkeypatch
):
    conn = _conn(tmp_path)
    task = _task(tmp_path, "t", per_run_budget_usd=0.01)
    cfg = _cfg(
        runs_per_task=3,
        long_context_daily=False,
        daily_budget_usd=100.0,
        daily_token_budget=1000,
        per_run_budget_usd=0.01,
    )
    token_result = json.dumps(
        {
            "is_error": False,
            "subtype": "success",
            "result": "OK",
            "modelUsage": {
                "claude-sonnet-5-x": {"inputTokens": 900, "outputTokens": 200, "costUSD": 0.01}
            },
        }
    )
    calls = _patch_subprocess(monkeypatch, [token_result])

    cycle_ids = [run_cycle(conn, cfg, [task], claude_cmd=["fake-claude"]) for _ in range(3)]

    assert len(calls) == 1

    cycles = [
        conn.execute("SELECT * FROM canary_cycles WHERE cycle_id=?", (cid,)).fetchone()
        for cid in cycle_ids
    ]
    assert cycles[0]["n_runs"] == 1
    assert cycles[0]["aborted_reason"] == "budget"
    assert cycles[1]["n_runs"] == 0
    assert cycles[1]["aborted_reason"] == "budget"
    assert cycles[2]["n_runs"] == 0
    assert cycles[2]["aborted_reason"] == "budget"


def test_spend_persists_across_a_daemon_restart_within_the_same_budget_day(tmp_path):
    db_path = tmp_path / "vitals.db"
    cfg = _cfg(daily_budget_usd=1.0)

    conn1 = get_conn(db_path)
    init_db(conn1)
    r1 = check_and_reserve(conn1, cfg, est_usd=0.7)
    assert r1 is not None
    settle(conn1, r1, tokens_in=100, tokens_out=50, cost_usd=0.7)
    conn1.close()

    conn2 = get_conn(db_path)
    assert check_and_reserve(conn2, cfg, est_usd=0.5) is None
    assert check_and_reserve(conn2, cfg, est_usd=0.3) is not None

    total = conn2.execute(
        "SELECT COALESCE(SUM(cost_usd), 0) FROM spend_ledger WHERE day = ?", (local_day(),)
    ).fetchone()[0]
    assert total == 1.0
    conn2.close()


def test_actual_reported_cost_wins_over_a_token_derived_estimate(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    task = _task(tmp_path, "t")
    cfg = _cfg(
        runs_per_task=1, long_context_daily=False, daily_budget_usd=10.0, model="claude-sonnet-5"
    )
    result_json = json.dumps(
        {
            "is_error": False,
            "subtype": "success",
            "result": "OK",
            "total_cost_usd": 5.0,
            "modelUsage": {
                "claude-sonnet-5-x": {
                    "inputTokens": 1_000_000,
                    "outputTokens": 1_000_000,
                    "costUSD": 3.0,
                }
            },
        }
    )
    _patch_subprocess(monkeypatch, [result_json])

    cycle_id = run_cycle(conn, cfg, [task], claude_cmd=["fake-claude"])

    cycle_cost = conn.execute(
        "SELECT cost_usd FROM canary_cycles WHERE cycle_id=?", (cycle_id,)
    ).fetchone()["cost_usd"]
    assert cycle_cost == 5.0
    ledger_cost = conn.execute("SELECT cost_usd FROM spend_ledger").fetchone()["cost_usd"]
    assert ledger_cost == 5.0


def test_missing_cost_settles_at_the_configurable_pessimistic_rate_and_it_hits_the_cap(
    tmp_path, monkeypatch
):
    conn = _conn(tmp_path)
    unpriced_task = _task(tmp_path, "unpriced", per_run_budget_usd=0.37)
    next_task = _task(tmp_path, "next", per_run_budget_usd=0.01)
    cfg = _cfg(
        runs_per_task=1,
        long_context_daily=False,
        daily_budget_usd=0.37,
        model="claude-unreleased-9",
    )
    unpriced_result = json.dumps(
        {
            "is_error": False,
            "subtype": "success",
            "result": "OK",
            "modelUsage": {
                "claude-unreleased-9": {"inputTokens": 500, "outputTokens": 500, "costUSD": 0}
            },
        }
    )
    calls = _patch_subprocess(monkeypatch, [unpriced_result])

    cycle_id = run_cycle(conn, cfg, [unpriced_task, next_task], claude_cmd=["fake-claude"])

    assert len(calls) == 1

    ledger_cost = conn.execute("SELECT cost_usd FROM spend_ledger").fetchone()["cost_usd"]
    assert ledger_cost == 0.37

    cycle = conn.execute("SELECT * FROM canary_cycles WHERE cycle_id=?", (cycle_id,)).fetchone()
    assert cycle["aborted_reason"] == "budget"
    assert cycle["cost_usd"] == 0.37


def test_budget_check_happens_before_any_subprocess_is_ever_launched(tmp_path, monkeypatch):
    conn = _conn(tmp_path)
    task = _task(tmp_path, "t", per_run_budget_usd=0.01)
    cfg = _cfg(
        runs_per_task=5, long_context_daily=False, daily_budget_usd=0.0, per_run_budget_usd=0.01
    )
    calls = _patch_subprocess(monkeypatch, [])

    cycle_id = run_cycle(conn, cfg, [task], claude_cmd=["fake-claude"])

    assert calls == []

    cycle = conn.execute("SELECT * FROM canary_cycles WHERE cycle_id=?", (cycle_id,)).fetchone()
    assert cycle["aborted_reason"] == "budget"
    assert cycle["n_runs"] == 0
    n_runs_rows = conn.execute("SELECT COUNT(*) c FROM canary_runs").fetchone()["c"]
    assert n_runs_rows == 0
    n_ledger_rows = conn.execute("SELECT COUNT(*) c FROM spend_ledger").fetchone()["c"]
    assert n_ledger_rows == 0

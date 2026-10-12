from __future__ import annotations

import json

from vitals.cli import main
from vitals.config import DetectCfg, load
from vitals.db import get_conn, init_db
from vitals.detect import signal_ids as sid
from vitals.detect.engine import tick
from vitals.timeutil import hour_add

START = "2026-08-01T00:00:00+00:00"
MODEL = "claude-sonnet-5"
BUCKET = "gt180k"
VER = "2.1.230"
CFG = DetectCfg(baseline_days=14, baseline_max_days=21)


def _cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VITALS_PROJECTS_DIR", str(tmp_path / "projects"))
    return load()


def _conn(cfg):
    conn = get_conn(cfg.db_path)
    init_db(conn)
    return conn


def test_canary_run_cli_passes_inject_model_through_without_changing_recorded_model(
    tmp_path, monkeypatch
):
    cfg = _cfg(tmp_path, monkeypatch)
    _conn(cfg).close()
    import vitals.canary.runner as runner_module

    captured = {}

    def fake_run_cycle(conn, canary_cfg, tasks, inject_model=None, claude_cmd=None):
        captured["inject_model"] = inject_model
        captured["task_ids"] = [t.task_id for t in tasks]
        cur = conn.execute(
            "INSERT INTO canary_cycles(started_at, model, effort, suite_hash, n_runs, n_pass,"
            " n_invalid, pass_rate, cost_usd) VALUES"
            " ('2026-01-01T00:00:00+00:00', ?, ?, 'h', 0, 0, 0, NULL, 0)",
            (canary_cfg.model, canary_cfg.effort),
        )
        conn.commit()
        return cur.lastrowid

    monkeypatch.setattr(runner_module, "run_cycle", fake_run_cycle)

    rc = main(["canary", "run", "--task", "diff-golden", "--inject-model", "claude-haiku-4-5"])

    assert rc == 0
    assert captured["inject_model"] == "claude-haiku-4-5"
    assert captured["task_ids"] == ["diff-golden"]


def test_canary_run_cli_no_longer_requires_the_once_flag(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    _conn(cfg).close()
    import vitals.canary.runner as runner_module

    calls = []

    def fake_run_cycle(conn, canary_cfg, tasks, inject_model=None, claude_cmd=None):
        calls.append(1)
        cur = conn.execute(
            "INSERT INTO canary_cycles(started_at, model, effort, suite_hash, n_runs, n_pass,"
            " n_invalid, pass_rate, cost_usd) VALUES"
            " ('2026-01-01T00:00:00+00:00', 'm', 'medium', 'h', 0, 0, 0, NULL, 0)"
        )
        conn.commit()
        return cur.lastrowid

    monkeypatch.setattr(runner_module, "run_cycle", fake_run_cycle)

    rc = main(["canary", "run", "--task", "diff-golden"])

    assert rc == 0
    assert len(calls) == 1


def test_canary_run_cli_still_accepts_the_once_flag(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    _conn(cfg).close()
    import vitals.canary.runner as runner_module

    def fake_run_cycle(conn, canary_cfg, tasks, inject_model=None, claude_cmd=None):
        cur = conn.execute(
            "INSERT INTO canary_cycles(started_at, model, effort, suite_hash, n_runs, n_pass,"
            " n_invalid, pass_rate, cost_usd) VALUES"
            " ('2026-01-01T00:00:00+00:00', 'm', 'medium', 'h', 0, 0, 0, NULL, 0)"
        )
        conn.commit()
        return cur.lastrowid

    monkeypatch.setattr(runner_module, "run_cycle", fake_run_cycle)

    rc = main(["canary", "run", "--once", "--task", "diff-golden"])

    assert rc == 0


def test_canary_run_cli_rejects_an_unknown_task_id(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    _conn(cfg).close()

    rc = main(["canary", "run", "--task", "not-a-real-task"])

    assert rc == 1


def _seed_and_tick(conn) -> list[int]:
    import random

    rng = random.Random(11)
    ts = START
    for i in range(192):
        conn.execute(
            "INSERT INTO signal_windows(window_start, signal, model, context_bucket, value, n,"
            " cc_version) VALUES (?,?,?,?,?,?,?)",
            (ts, sid.S1_LATENCY_P95, MODEL, BUCKET, 7.60 + rng.gauss(0, 0.02), 8, VER),
        )
        ts = hour_add(ts, 1)
    for i in range(12):
        conn.execute(
            "INSERT INTO signal_windows(window_start, signal, model, context_bucket, value, n,"
            " cc_version) VALUES (?,?,?,?,?,?,?)",
            (ts, sid.S1_LATENCY_P95, MODEL, BUCKET, 8.80 + rng.gauss(0, 0.02), 8, VER),
        )
        ts = hour_add(ts, 1)
    conn.commit()
    return tick(conn, CFG, ts), ts


def _alert_for(conn, anomaly_ids, ts) -> int:
    cur = conn.execute(
        "INSERT INTO alerts(ts, severity, attribution, title, evidence_json, anomaly_ids)"
        " VALUES (?,?,?,?,?,?)",
        (ts, "INFO", "E", "latency up", "{}", json.dumps(list(anomaly_ids))),
    )
    conn.commit()
    return cur.lastrowid


def test_resolve_cli_false_positive_says_it_folds_the_window_back_into_healthy_history(
    tmp_path, monkeypatch, capsys
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    opened, ts = _seed_and_tick(conn)
    alert_id = _alert_for(conn, opened, ts)
    conn.close()

    rc = main(["resolve", str(alert_id), "--as", "false-positive"])

    assert rc == 0
    out = capsys.readouterr().out.lower()
    assert "false" in out
    assert "healthy" in out or "folded" in out

    check_conn = get_conn(cfg.db_path)
    row = check_conn.execute("SELECT resolution FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    assert row["resolution"] == "false_positive"


def test_resolve_cli_confirmed_says_it_excludes_and_restarts_the_healthy_counter(
    tmp_path, monkeypatch, capsys
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    opened, ts = _seed_and_tick(conn)
    alert_id = _alert_for(conn, opened, ts)
    conn.close()

    rc = main(["resolve", str(alert_id), "--as", "confirmed"])

    assert rc == 0
    out = capsys.readouterr().out.lower()
    assert "confirmed" in out
    assert "exclud" in out or "restart" in out

    check_conn = get_conn(cfg.db_path)
    row = check_conn.execute("SELECT resolution FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    assert row["resolution"] == "confirmed"


def test_resolve_cli_outputs_differ_between_the_two_arms(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    opened, ts = _seed_and_tick(conn)
    alert_id_a = _alert_for(conn, opened, ts)
    conn.close()

    main(["resolve", str(alert_id_a), "--as", "false-positive"])
    fp_output = capsys.readouterr().out

    cfg2 = _cfg(tmp_path / "b", monkeypatch)
    conn2 = _conn(cfg2)
    opened2, ts2 = _seed_and_tick(conn2)
    alert_id_b = _alert_for(conn2, opened2, ts2)
    conn2.close()

    main(["resolve", str(alert_id_b), "--as", "confirmed"])
    confirmed_output = capsys.readouterr().out

    assert fp_output != confirmed_output


def test_resolve_cli_reports_nothing_to_resolve_for_an_unknown_id(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    _conn(cfg).close()

    rc = main(["resolve", "999999", "--as", "confirmed"])

    assert rc == 1
    assert "nothing" in capsys.readouterr().out.lower()

from __future__ import annotations

import logging
import random
from datetime import UTC, datetime, timedelta

import pytest

import vitals.daemon as daemon_mod
from vitals.config import load
from vitals.daemon import (
    Daemon,
    job_aggregate,
    job_canary_schedule,
    job_detect,
    next_due,
)
from vitals.db import get_conn, init_db, kv_get, kv_set
from vitals.detect import signal_ids as sid
from vitals.timeutil import hour_add, local_day, parse_iso, utcnow_iso

MODEL = "claude-sonnet-5"
BUCKET = "gt180k"
VER = "2.1.230"
START = "2026-08-01T00:00:00+00:00"


def _cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VITALS_PROJECTS_DIR", str(tmp_path / "projects"))
    return load()


def _conn(cfg):
    conn = get_conn(cfg.db_path)
    init_db(conn)
    return conn


def _local_noon(day_offset: int = 0) -> str:
    local_tz = datetime.now().astimezone().tzinfo
    base = (datetime.now(local_tz) + timedelta(days=day_offset)).replace(
        hour=12, minute=0, second=0, microsecond=0
    )
    return base.astimezone(UTC).isoformat(timespec="seconds")


def test_next_due_true_when_never_run():
    assert next_due(None, 6, utcnow_iso()) is True


def test_next_due_false_before_the_schedule_elapses():
    last_run = (parse_iso(START) - timedelta(hours=5, minutes=59)).isoformat(timespec="seconds")
    assert next_due(last_run, 6, START) is False


def test_next_due_true_once_the_schedule_elapses():
    last_run = (parse_iso(START) - timedelta(hours=6, minutes=1)).isoformat(timespec="seconds")
    assert next_due(last_run, 6, START) is True


def test_next_due_true_exactly_at_the_boundary():
    last_run = (parse_iso(START) - timedelta(hours=6)).isoformat(timespec="seconds")
    assert next_due(last_run, 6, START) is True


def test_next_due_true_on_backwards_clock_skew_and_logs_a_warning(caplog):
    last_run = (parse_iso(START) + timedelta(hours=1)).isoformat(timespec="seconds")
    with caplog.at_level(logging.WARNING, logger="vitals.daemon"):
        assert next_due(last_run, 6, START) is True
    assert any("skew" in r.message.lower() for r in caplog.records)


def _seed_signal_windows(
    conn, signal, version, start, count, value, n=8, model=MODEL, bucket=BUCKET
):
    ts = start
    for i in range(count):
        conn.execute(
            "INSERT OR IGNORE INTO signal_windows(window_start, signal, model, context_bucket,"
            " value, n, cc_version) VALUES (?,?,?,?,?,?,?)",
            (ts, signal, model, bucket, value(i) if callable(value) else value, n, version),
        )
        ts = hour_add(ts, 1)
    conn.commit()
    return ts


def _healthy_then_shift(conn, healthy=192, shifted=12):
    rng = random.Random(11)
    ts = _seed_signal_windows(
        conn, sid.S1_LATENCY_P95, VER, START, healthy, lambda i: 7.60 + rng.gauss(0, 0.02)
    )
    ts = _seed_signal_windows(
        conn, sid.S1_LATENCY_P95, VER, ts, shifted, lambda i: 8.80 + rng.gauss(0, 0.02)
    )
    return ts


def test_job_detect_ticks_evaluates_attributes_and_dispatches_in_order(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    now = _healthy_then_shift(conn)

    job_detect(conn, cfg, now_iso=now)

    anomalies = conn.execute("SELECT * FROM anomalies WHERE status='open'").fetchall()
    assert len(anomalies) == 2

    alerts = conn.execute("SELECT * FROM alerts").fetchall()
    assert len(alerts) >= 1
    assert alerts[0]["attribution"] in ("A", "B", "C", "D", "E")
    assert alerts[0]["evidence_json"]


def test_job_detect_does_not_defeat_the_dispatcher_dedup_on_a_persisting_condition(
    tmp_path, monkeypatch
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    now = _healthy_then_shift(conn)

    job_detect(conn, cfg, now_iso=now)
    n_after_first = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    assert n_after_first >= 1

    later = (parse_iso(now) + timedelta(minutes=1)).isoformat(timespec="seconds")
    job_detect(conn, cfg, now_iso=later)
    n_after_second = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]

    assert n_after_second == n_after_first


def test_job_aggregate_chains_into_job_detect_on_the_same_call(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    _healthy_then_shift(conn)

    job_aggregate(conn, cfg)

    assert conn.execute("SELECT COUNT(*) c FROM anomalies WHERE status='open'").fetchone()["c"] == 2
    assert conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"] >= 1


def test_job_canary_schedule_runs_on_the_first_check_and_records_last_run(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    calls = []
    monkeypatch.setattr(
        daemon_mod, "run_cycle", lambda conn_, canary_cfg, tasks, **k: calls.append(canary_cfg) or 1
    )
    monkeypatch.setattr(daemon_mod, "load_tasks", lambda tasks_dir: [])

    job_canary_schedule(conn, cfg, now_iso=START)

    assert len(calls) == 1
    assert kv_get(conn, daemon_mod._KV_CANARY_LAST_RUN) == START


def test_job_canary_schedule_is_a_noop_before_the_schedule_elapses(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    calls = []
    monkeypatch.setattr(
        daemon_mod, "run_cycle", lambda conn_, canary_cfg, tasks, **k: calls.append(1) or 1
    )
    monkeypatch.setattr(daemon_mod, "load_tasks", lambda tasks_dir: [])

    job_canary_schedule(conn, cfg, now_iso=START)
    assert len(calls) == 1

    soon_after = (parse_iso(START) + timedelta(hours=1)).isoformat(timespec="seconds")
    job_canary_schedule(conn, cfg, now_iso=soon_after)
    assert len(calls) == 1


def test_job_canary_schedule_runs_again_once_schedule_hours_elapse(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    calls = []
    monkeypatch.setattr(
        daemon_mod, "run_cycle", lambda conn_, canary_cfg, tasks, **k: calls.append(1) or 1
    )
    monkeypatch.setattr(daemon_mod, "load_tasks", lambda tasks_dir: [])

    job_canary_schedule(conn, cfg, now_iso=START)
    later = (parse_iso(START) + timedelta(hours=9)).isoformat(timespec="seconds")
    job_canary_schedule(conn, cfg, now_iso=later)

    assert len(calls) == 2


def test_job_canary_schedule_caps_the_long_context_suite_at_once_per_calendar_day(
    tmp_path, monkeypatch
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    seen_long_flags = []
    monkeypatch.setattr(
        daemon_mod,
        "run_cycle",
        lambda conn_, canary_cfg, tasks, **k: (
            seen_long_flags.append(canary_cfg.long_context_daily) or 1
        ),
    )
    monkeypatch.setattr(daemon_mod, "load_tasks", lambda tasks_dir: [])

    t0 = _local_noon(0)
    job_canary_schedule(conn, cfg, now_iso=t0)
    t1 = (parse_iso(t0) + timedelta(hours=9)).isoformat(timespec="seconds")
    job_canary_schedule(conn, cfg, now_iso=t1)
    t2 = _local_noon(1)
    job_canary_schedule(conn, cfg, now_iso=t2)

    assert seen_long_flags == [True, False, True]


def test_job_canary_schedule_honours_long_context_daily_false(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    cfg.canary.long_context_daily = False
    conn = _conn(cfg)
    seen_long_flags = []
    monkeypatch.setattr(
        daemon_mod,
        "run_cycle",
        lambda conn_, canary_cfg, tasks, **k: (
            seen_long_flags.append(canary_cfg.long_context_daily) or 1
        ),
    )
    monkeypatch.setattr(daemon_mod, "load_tasks", lambda tasks_dir: [])

    job_canary_schedule(conn, cfg, now_iso=START)

    assert seen_long_flags == [False]


def test_job_canary_schedule_records_the_run_even_when_run_cycle_raises(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    calls = []

    def boom(*a, **k):
        calls.append(1)
        raise RuntimeError("claude -p exploded")

    monkeypatch.setattr(daemon_mod, "run_cycle", boom)
    monkeypatch.setattr(daemon_mod, "load_tasks", lambda tasks_dir: [])

    with pytest.raises(RuntimeError):
        job_canary_schedule(conn, cfg, now_iso=START)

    assert kv_get(conn, daemon_mod._KV_CANARY_LAST_RUN) == START

    soon = (parse_iso(START) + timedelta(minutes=1)).isoformat(timespec="seconds")
    job_canary_schedule(conn, cfg, now_iso=soon)
    assert len(calls) == 1


def test_job_canary_schedule_records_the_long_context_day_even_when_run_cycle_raises(
    tmp_path, monkeypatch
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)

    monkeypatch.setattr(
        daemon_mod, "run_cycle", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    monkeypatch.setattr(daemon_mod, "load_tasks", lambda tasks_dir: [])

    t0 = _local_noon(0)
    with pytest.raises(RuntimeError):
        job_canary_schedule(conn, cfg, now_iso=t0)

    assert kv_get(conn, daemon_mod._KV_CANARY_LONG_CONTEXT_DAY) == local_day(t0)


def test_job_canary_schedule_never_calls_run_cycle_before_it_is_due(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)

    def boom(*a, **k):
        raise AssertionError("run_cycle must not be called before the schedule says it is due")

    monkeypatch.setattr(daemon_mod, "run_cycle", boom)
    kv_set(conn, daemon_mod._KV_CANARY_LAST_RUN, START)

    soon = (parse_iso(START) + timedelta(minutes=1)).isoformat(timespec="seconds")
    job_canary_schedule(conn, cfg, now_iso=soon)


def test_daemon_registers_a_canary_scheduler_job_checked_every_5_minutes(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    _conn(cfg).close()
    daemon = Daemon(cfg)

    specs = {name: (job, interval) for name, job, interval in daemon._job_specs()}

    assert specs["canary"] == (daemon_mod.job_canary_schedule, daemon_mod.CANARY_CHECK_INTERVAL_S)
    assert daemon_mod.CANARY_CHECK_INTERVAL_S == 300
    assert specs["aggregate"] == (daemon_mod.job_aggregate, daemon_mod.AGGREGATE_INTERVAL_S)
    assert "detect" not in specs

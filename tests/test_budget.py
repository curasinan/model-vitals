from __future__ import annotations

import threading
import time
from pathlib import Path

from vitals.canary.budget import check_and_reserve, settle
from vitals.config import CanaryCfg
from vitals.db import get_conn, init_db
from vitals.timeutil import local_day, utcnow_iso


def _conn(tmp_path: Path):
    conn = get_conn(tmp_path / "vitals.db")
    init_db(conn)
    return conn


def _cfg(**overrides) -> CanaryCfg:
    return CanaryCfg(**overrides)


def test_hard_stop_at_daily_budget_is_atomic(tmp_path):
    conn = _conn(tmp_path)
    cfg = _cfg(daily_budget_usd=1.0)
    r1 = check_and_reserve(conn, cfg, est_usd=0.6)
    assert r1 is not None
    assert check_and_reserve(conn, cfg, est_usd=0.5) is None
    settle(conn, r1, tokens_in=1000, tokens_out=200, cost_usd=0.4)
    assert check_and_reserve(conn, cfg, est_usd=0.5) is not None


def test_settle_replaces_reservation_with_actuals(tmp_path):
    conn = _conn(tmp_path)
    cfg = _cfg(daily_budget_usd=5.0)
    rid = check_and_reserve(conn, cfg, est_usd=0.5)
    assert rid is not None
    settle(conn, rid, tokens_in=1234, tokens_out=567, cost_usd=0.37)
    row = conn.execute(
        "SELECT tokens_in, tokens_out, cost_usd, day FROM spend_ledger WHERE id = ?", (rid,)
    ).fetchone()
    assert row["tokens_in"] == 1234
    assert row["tokens_out"] == 567
    assert row["cost_usd"] == 0.37
    assert row["day"] == local_day()


def test_daily_token_budget_also_gates_reservations(tmp_path):
    conn = _conn(tmp_path)
    cfg = _cfg(daily_budget_usd=100.0, daily_token_budget=1000)
    r1 = check_and_reserve(conn, cfg, est_usd=0.01)
    assert r1 is not None
    settle(conn, r1, tokens_in=900, tokens_out=200, cost_usd=0.01)
    assert check_and_reserve(conn, cfg, est_usd=0.01) is None


def test_reservation_ids_are_stable_and_distinct(tmp_path):
    conn = _conn(tmp_path)
    cfg = _cfg(daily_budget_usd=10.0)
    r1 = check_and_reserve(conn, cfg, est_usd=0.1)
    r2 = check_and_reserve(conn, cfg, est_usd=0.1)
    assert r1 != r2
    rows = conn.execute("SELECT id FROM spend_ledger ORDER BY id").fetchall()
    assert [r["id"] for r in rows] == [r1, r2]


def _naive_check_then_reserve(
    db_path: Path, barrier: threading.Barrier, est_usd: float, cap: float
) -> str | None:
    conn = get_conn(db_path)
    try:
        day = local_day()
        cum = conn.execute(
            "SELECT COALESCE(SUM(cost_usd), 0) FROM spend_ledger WHERE day = ?", (day,)
        ).fetchone()[0]
        barrier.wait(timeout=5)
        time.sleep(0.05)
        if cum + est_usd > cap:
            return None
        conn.execute(
            "INSERT INTO spend_ledger(ts, day, source, tokens_in, tokens_out, cost_usd, cum_day_usd) "
            "VALUES (?, ?, 'canary', 0, 0, ?, ?)",
            (utcnow_iso(), day, est_usd, cum + est_usd),
        )
        conn.commit()
        return "reserved"
    finally:
        conn.close()


def test_naive_check_then_act_over_reserves_under_concurrency(tmp_path):
    db_path = tmp_path / "vitals.db"
    conn0 = get_conn(db_path)
    init_db(conn0)
    conn0.close()

    barrier = threading.Barrier(2)
    results: dict[str, str | None] = {}

    def _worker(name: str) -> None:
        results[name] = _naive_check_then_reserve(db_path, barrier, est_usd=0.6, cap=1.0)

    t1 = threading.Thread(target=_worker, args=("a",))
    t2 = threading.Thread(target=_worker, args=("b",))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert results["a"] == "reserved"
    assert results["b"] == "reserved"
    conn = get_conn(db_path)
    total = conn.execute(
        "SELECT COALESCE(SUM(cost_usd), 0) FROM spend_ledger WHERE day = ?", (local_day(),)
    ).fetchone()[0]
    assert total == 1.2
    conn.close()


def test_check_and_reserve_serializes_concurrent_callers_under_the_same_race(tmp_path):
    db_path = tmp_path / "vitals.db"
    conn0 = get_conn(db_path)
    init_db(conn0)
    conn0.close()
    cfg = _cfg(daily_budget_usd=1.0)

    barrier = threading.Barrier(2)
    results: dict[str, int | None] = {}

    def _worker(name: str) -> None:
        conn = get_conn(db_path)
        try:
            barrier.wait(timeout=5)
            results[name] = check_and_reserve(conn, cfg, est_usd=0.6)
        finally:
            conn.close()

    t1 = threading.Thread(target=_worker, args=("a",))
    t2 = threading.Thread(target=_worker, args=("b",))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    succeeded = [v for v in results.values() if v is not None]
    assert len(succeeded) == 1

    conn = get_conn(db_path)
    total = conn.execute(
        "SELECT COALESCE(SUM(cost_usd), 0) FROM spend_ledger WHERE day = ?", (local_day(),)
    ).fetchone()[0]
    assert total == 0.6
    conn.close()

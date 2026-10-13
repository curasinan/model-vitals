from __future__ import annotations

import sqlite3

from vitals.config import CanaryCfg
from vitals.timeutil import local_day, utcnow_iso

__all__ = ["check_and_reserve", "settle"]


def check_and_reserve(conn: sqlite3.Connection, cfg: CanaryCfg, est_usd: float) -> int | None:
    day = local_day()
    if conn.in_transaction:
        conn.rollback()
    conn.execute("BEGIN IMMEDIATE")
    try:
        cum_usd, cum_tokens = conn.execute(
            "SELECT COALESCE(SUM(cost_usd), 0), "
            "       COALESCE(SUM(tokens_in), 0) + COALESCE(SUM(tokens_out), 0) "
            "FROM spend_ledger WHERE day = ?",
            (day,),
        ).fetchone()

        if cum_usd + est_usd > cfg.daily_budget_usd or cum_tokens >= cfg.daily_token_budget:
            conn.rollback()
            return None

        cur = conn.execute(
            "INSERT INTO spend_ledger(ts, day, source, tokens_in, tokens_out, cost_usd, cum_day_usd) "
            "VALUES (?, ?, 'canary', 0, 0, ?, ?)",
            (utcnow_iso(), day, est_usd, cum_usd + est_usd),
        )
        conn.commit()
        return cur.lastrowid
    except BaseException:
        conn.rollback()
        raise


def settle(
    conn: sqlite3.Connection,
    reservation_id: int,
    tokens_in: int,
    tokens_out: int,
    cost_usd: float,
) -> None:
    if conn.in_transaction:
        conn.rollback()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT day FROM spend_ledger WHERE id = ?", (reservation_id,)
        ).fetchone()
        if row is None:
            conn.rollback()
            raise ValueError(f"no spend_ledger row with id={reservation_id}")
        day = row[0]
        prior_usd = conn.execute(
            "SELECT COALESCE(SUM(cost_usd), 0) FROM spend_ledger WHERE day = ? AND id < ?",
            (day, reservation_id),
        ).fetchone()[0]
        conn.execute(
            "UPDATE spend_ledger SET tokens_in = ?, tokens_out = ?, cost_usd = ?, cum_day_usd = ? "
            "WHERE id = ?",
            (tokens_in, tokens_out, cost_usd, prior_usd + cost_usd, reservation_id),
        )
        conn.commit()
    except BaseException:
        conn.rollback()
        raise

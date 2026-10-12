from __future__ import annotations

import sqlite3
from importlib import resources
from pathlib import Path

from vitals import failopen
from vitals.timeutil import utcnow_iso


def get_conn(db_path: Path) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY)")
    applied = {r[0] for r in conn.execute("SELECT version FROM schema_version")}
    mig_dir = resources.files("vitals") / "migrations"
    for name in sorted(p.name for p in mig_dir.iterdir() if p.name.endswith(".sql")):
        ver = int(name.split("_")[0])
        if ver in applied:
            continue
        conn.executescript((mig_dir / name).read_text(encoding="utf-8"))
        conn.execute("INSERT INTO schema_version VALUES (?)", (ver,))
    conn.commit()


def log_ingest(
    conn: sqlite3.Connection,
    kind: str,
    ok_count: int = 0,
    err_count: int = 0,
    detail: str | None = None,
) -> None:
    try:
        conn.execute(
            "INSERT INTO ingest_log(ts, kind, ok_count, err_count, detail) VALUES (?,?,?,?,?)",
            (utcnow_iso(), kind, ok_count, err_count, detail),
        )
        conn.commit()
    except Exception:  # pragma: no cover
        failopen.record("db.log_ingest", _data_dir_of(conn))


def _data_dir_of(conn: sqlite3.Connection) -> Path | None:
    try:
        row = conn.execute("PRAGMA database_list").fetchone()
        raw = row["file"] if row is not None else None
        return Path(raw).parent if raw else None
    except Exception:
        return None


def kv_get(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM vitals_kv WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def kv_set(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO vitals_kv(key, value) VALUES (?,?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()


def upsert_session(conn: sqlite3.Connection, session_id: str, **fields: object) -> None:
    conn.execute("INSERT OR IGNORE INTO sessions(session_id) VALUES (?)", (session_id,))
    fields = {k: v for k, v in fields.items() if v is not None}
    if not fields:
        return

    allowed = {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}
    unknown = sorted(set(fields) - allowed)
    if unknown:
        raise ValueError(f"not a sessions column: {', '.join(unknown)}")

    sets = []
    params: list[object] = []
    for col, val in fields.items():
        if col == "is_canary":
            sets.append("is_canary = MAX(is_canary, ?)")
        else:
            sets.append(f"{col} = COALESCE({col}, ?)")
        params.append(val)
    params.append(session_id)
    conn.execute(f"UPDATE sessions SET {', '.join(sets)} WHERE session_id = ?", params)  # noqa: S608

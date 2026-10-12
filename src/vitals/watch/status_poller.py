from __future__ import annotations

import json
import sqlite3
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path  # noqa: F401

from vitals.db import log_ingest
from vitals.timeutil import parse_iso, utcnow_iso

BASE = "https://status.claude.com/api/v2"
UNRESOLVED_URL = f"{BASE}/incidents/unresolved.json"
RECENT_URL = f"{BASE}/incidents.json"

DEFAULT_PREFIXES = ("Claude API", "Claude Code", "claude.ai", "Claude Console")


def default_fetch(url: str) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "model-vitals/0.1"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def _upsert(conn: sqlite3.Connection, incident: dict, now: str) -> None:
    components = ",".join(
        str(c.get("name")) for c in incident.get("components") or [] if c.get("name")
    )
    conn.execute(
        "INSERT INTO incidents(incident_id, name, status, impact, created_at, resolved_at, "
        "components, raw_json, last_seen) VALUES (?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(incident_id) DO UPDATE SET "
        "  name = excluded.name, status = excluded.status, impact = excluded.impact, "
        "  resolved_at = excluded.resolved_at, components = excluded.components, "
        "  raw_json = excluded.raw_json, last_seen = excluded.last_seen",
        (
            incident.get("id"),
            incident.get("name"),
            incident.get("status"),
            incident.get("impact"),
            incident.get("created_at"),
            incident.get("resolved_at"),
            components,
            json.dumps(incident)[:20000],
            now,
        ),
    )


def poll(
    conn: sqlite3.Connection,
    fetch: Callable[[str], dict] = default_fetch,
    now_iso: str | None = None,
) -> int:
    now = now_iso or utcnow_iso()
    seen: set[str] = set()
    count = 0
    try:
        for url in (UNRESOLVED_URL, RECENT_URL):
            payload = fetch(url) or {}
            for incident in payload.get("incidents") or []:
                incident_id = incident.get("id")
                if not incident_id or incident_id in seen:
                    continue
                seen.add(incident_id)
                _upsert(conn, incident, now)
                count += 1
    except (OSError, urllib.error.URLError, ValueError) as exc:
        conn.commit()
        log_ingest(conn, "status_poll", 0, 1, f"{type(exc).__name__}: {exc}"[:300])
        return 0

    if seen:
        placeholders = ",".join("?" * len(seen))
        conn.execute(
            f"UPDATE incidents SET resolved_at = ?, status = 'resolved' "  # noqa: S608
            f"WHERE resolved_at IS NULL AND incident_id NOT IN ({placeholders})",
            (now, *seen),
        )
    else:
        conn.execute(
            "UPDATE incidents SET resolved_at = ?, status = 'resolved' WHERE resolved_at IS NULL",
            (now,),
        )
    conn.commit()
    log_ingest(conn, "status_poll", count, 0)
    return count


def active_incident(
    conn: sqlite3.Connection, at_iso: str, prefixes: tuple[str, ...] = DEFAULT_PREFIXES
) -> str | None:
    try:
        at = parse_iso(at_iso)
    except ValueError:
        return None
    for row in conn.execute(
        "SELECT incident_id, created_at, resolved_at, components FROM incidents "
        "ORDER BY created_at DESC"
    ):
        try:
            started = parse_iso(row["created_at"]) if row["created_at"] else None
        except ValueError:
            continue
        if started is None or at < started:
            continue
        if row["resolved_at"]:
            try:
                if at > parse_iso(row["resolved_at"]):
                    continue
            except ValueError:
                continue
        components = (row["components"] or "").split(",")
        if any(c.startswith(p) for c in components for p in prefixes):
            return row["incident_id"]
    return None

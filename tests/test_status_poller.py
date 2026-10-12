import json
from pathlib import Path

from vitals.db import get_conn, init_db
from vitals.watch.status_poller import active_incident, poll

FIXTURE = Path(__file__).parent / "fixtures" / "statuspage_incidents.json"


def _conn(tmp_path):
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)
    return conn


def fake_fetch_factory(unresolved, recent=None):
    def fetch(url):
        if "unresolved" in url:
            return {"incidents": unresolved}
        return {"incidents": recent if recent is not None else unresolved}

    return fetch


INC = {
    "id": "abc123",
    "name": "Elevated errors on Claude Code",
    "status": "investigating",
    "impact": "major",
    "created_at": "2026-08-25T10:00:00.000Z",
    "resolved_at": None,
    "components": [{"name": "Claude Code"}],
}


def test_poll_upserts_and_active_incident(tmp_path):
    conn = _conn(tmp_path)
    assert poll(conn, fetch=fake_fetch_factory([INC])) == 1
    assert active_incident(conn, "2026-08-25T11:00:00+00:00") == "abc123"
    assert active_incident(conn, "2026-08-25T09:00:00+00:00") is None
    resolved = dict(INC, status="resolved", resolved_at="2026-08-25T12:00:00.000Z")
    poll(conn, fetch=fake_fetch_factory([], recent=[resolved]))
    assert active_incident(conn, "2026-08-25T13:00:00+00:00") is None
    assert active_incident(conn, "2026-08-25T11:00:00+00:00") == "abc123"


def test_component_prefix_matching(tmp_path):
    conn = _conn(tmp_path)
    inc = dict(
        INC,
        id="api9",
        name="Elevated 529s",
        status="identified",
        components=[{"name": "Claude API (api.anthropic.com)"}],
    )
    poll(conn, fetch=fake_fetch_factory([inc]))
    assert active_incident(conn, "2026-08-25T11:00:00+00:00") == "api9"


def test_unrelated_component_does_not_suppress(tmp_path):
    conn = _conn(tmp_path)
    inc = dict(INC, id="con1", components=[{"name": "Claude Console (platform.claude.com)"}])
    poll(conn, fetch=fake_fetch_factory([inc]))
    assert active_incident(conn, "2026-08-25T11:00:00+00:00", prefixes=("Claude Code",)) is None


def test_disappeared_incident_is_marked_resolved(tmp_path):
    conn = _conn(tmp_path)
    poll(conn, fetch=fake_fetch_factory([INC]))
    resolved_now = "2026-08-25T12:00:00+00:00"
    poll(conn, fetch=fake_fetch_factory([], recent=[]), now_iso=resolved_now)
    row = conn.execute("SELECT * FROM incidents WHERE incident_id='abc123'").fetchone()
    assert row["resolved_at"] == resolved_now
    assert active_incident(conn, "2026-08-25T13:00:00+00:00") is None
    assert active_incident(conn, "2026-08-25T11:00:00+00:00") == "abc123"


def test_repoll_updates_status_without_duplicating(tmp_path):
    conn = _conn(tmp_path)
    poll(conn, fetch=fake_fetch_factory([INC]))
    poll(conn, fetch=fake_fetch_factory([dict(INC, status="identified")]))
    rows = conn.execute("SELECT * FROM incidents").fetchall()
    assert len(rows) == 1
    assert rows[0]["status"] == "identified"


def test_network_failure_is_survivable(tmp_path):
    conn = _conn(tmp_path)

    def boom(url):
        raise OSError("no network")

    assert poll(conn, fetch=boom) == 0
    assert (
        conn.execute("SELECT COUNT(*) FROM ingest_log WHERE kind='status_poll'").fetchone()[0] >= 1
    )


def test_real_statuspage_payload_parses(tmp_path):
    conn = _conn(tmp_path)
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    n = poll(conn, fetch=lambda url: payload)
    assert n == len(payload["incidents"])
    row = conn.execute("SELECT * FROM incidents LIMIT 1").fetchone()
    assert row["name"] and row["components"] and row["created_at"]

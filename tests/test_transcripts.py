import json
from pathlib import Path

from vitals.db import get_conn, init_db
from vitals.ingest.selfcorr import SELF_CORR_PATTERNS
from vitals.ingest.transcripts import scan_all, scan_file

FIXTURE = Path(__file__).parent / "fixtures" / "transcript_sample.jsonl"


def _conn(tmp_path):
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)
    return conn


def test_selfcorr_patterns_hit_known_phrases():
    text = "I apologize - let me try again. Actually, the previous edit was wrong; reverting."
    hits = sum(1 for p in SELF_CORR_PATTERNS if p.search(text))
    assert hits >= 3


def test_scan_ingests_assistant_turns_and_is_idempotent(tmp_path):
    conn = _conn(tmp_path)
    n1 = scan_file(conn, FIXTURE)
    n2 = scan_file(conn, FIXTURE)
    assert n1 > 0 and n2 == 0
    row = conn.execute(
        "SELECT model, cc_version, input_tokens, output_tokens, cache_read_tokens "
        "FROM transcript_turns WHERE role='assistant' AND model IS NOT NULL LIMIT 1"
    ).fetchone()
    assert row["model"] and row["cc_version"]
    assert row["output_tokens"] is not None
    sess = conn.execute("SELECT cc_version, num_turns, wall_seconds FROM sessions").fetchone()
    assert sess["cc_version"] and sess["num_turns"] > 0
    assert sess["wall_seconds"] >= 0


def test_transcript_text_is_never_stored(tmp_path):
    conn = _conn(tmp_path)
    scan_file(conn, FIXTURE)
    columns = {r[1] for r in conn.execute("PRAGMA table_info(transcript_turns)")}
    assert "text" not in columns and "content" not in columns
    row = conn.execute(
        "SELECT text_len, self_corr_hits FROM transcript_turns WHERE role='assistant' "
        "ORDER BY self_corr_hits DESC LIMIT 1"
    ).fetchone()
    assert row["text_len"] is not None
    assert row["self_corr_hits"] >= 1


def test_requests_are_backfilled_from_transcripts(tmp_path):
    conn = _conn(tmp_path)
    scan_file(conn, FIXTURE)
    rows = conn.execute("SELECT * FROM api_requests WHERE source='transcript'").fetchall()
    assert rows, "assistant records carry requestId and usage; that is a request we can count"
    assert rows[0]["context_bucket"]
    assert rows[0]["model"]


def test_otel_request_wins_over_transcript_backfill(tmp_path):
    conn = _conn(tmp_path)
    request_id = None
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        if rec.get("type") == "assistant" and rec.get("requestId"):
            request_id = rec["requestId"]
            break
    assert request_id
    conn.execute(
        "INSERT INTO api_requests(session_id, request_id, ts, model, duration_ms, source) "
        "VALUES ('s', ?, '2026-08-05T00:00:00+00:00', 'otel-model', 1234, 'otel')",
        (request_id,),
    )
    scan_file(conn, FIXTURE)
    rows = conn.execute("SELECT * FROM api_requests WHERE request_id = ?", (request_id,)).fetchall()
    assert len(rows) == 1
    assert rows[0]["source"] == "otel"
    assert rows[0]["duration_ms"] == 1234


def test_synthetic_client_notices_are_errors_not_requests(tmp_path):
    conn = _conn(tmp_path)
    path = tmp_path / "t.jsonl"
    path.write_text(
        json.dumps(
            {
                "type": "assistant",
                "uuid": "u1",
                "sessionId": "s1",
                "requestId": "req_synth_client",
                "timestamp": "2026-08-25T10:00:00.000Z",
                "version": "2.1.237",
                "message": {
                    "role": "assistant",
                    "model": "<synthetic>",
                    "stop_reason": "stop_sequence",
                    "content": [
                        {"type": "text", "text": "You've hit your session limit · resets 7:10pm"}
                    ],
                    "usage": {"input_tokens": 0, "output_tokens": 0},
                },
            }
        )
        + "\n"
    )
    assert scan_file(conn, path) == 1
    assert conn.execute("SELECT COUNT(*) FROM api_requests").fetchone()[0] == 0
    err = conn.execute("SELECT * FROM api_errors").fetchone()
    assert err["source"] == "transcript_synthetic"
    assert "session limit" in err["error_text"]
    assert err["cc_version"] == "2.1.237"

    scan_file(conn, path)
    assert conn.execute("SELECT COUNT(*) FROM api_errors").fetchone()[0] == 1


def test_unknown_record_types_are_skipped_not_fatal(tmp_path):
    conn = _conn(tmp_path)
    path = tmp_path / "t.jsonl"
    path.write_text('{"type":"future-record-kind","sessionId":"s"}\n{"broken json\n')
    assert scan_file(conn, path) == 0


def test_parse_failures_are_logged_as_their_own_canary(tmp_path):
    conn = _conn(tmp_path)
    path = tmp_path / "t.jsonl"
    path.write_text("{broken\n{also broken\n")
    scan_file(conn, path)
    row = conn.execute("SELECT * FROM ingest_log WHERE kind='transcript_parse_error'").fetchone()
    assert row["err_count"] == 2


def test_a_record_is_not_torn_apart_by_a_unicode_line_boundary_in_its_content(tmp_path):
    conn = _conn(tmp_path)
    path = tmp_path / "t.jsonl"
    nel = chr(0x85)
    record = (
        '{"type":"assistant","uuid":"u-nel","sessionId":"s-nel","timestamp":'
        '"2026-08-29T10:00:00.000Z","message":{"role":"assistant","model":"claude-opus-5",'
        '"content":[{"type":"text","text":"before' + nel + 'after"}],'
        '"usage":{"input_tokens":10,"output_tokens":5}}}'
    )
    path.write_text(record + "\n", encoding="utf-8")

    inserted = scan_file(conn, path)

    assert inserted == 1, "the record must survive a NEL inside its own content"
    err = conn.execute(
        "SELECT COUNT(*) FROM ingest_log WHERE kind='transcript_parse_error'"
    ).fetchone()[0]
    assert err == 0, "and must not be logged as a parse failure"


def test_sidechain_turns_excluded_from_num_turns(tmp_path):
    conn = _conn(tmp_path)
    path = tmp_path / "t.jsonl"
    records = [
        {
            "type": "assistant",
            "uuid": "u1",
            "sessionId": "s1",
            "timestamp": "2026-08-25T10:00:00.000Z",
            "version": "2.1.226",
            "isSidechain": False,
            "message": {"role": "assistant", "model": "m", "usage": {"output_tokens": 5}},
        },
        {
            "type": "assistant",
            "uuid": "u2",
            "sessionId": "s1",
            "timestamp": "2026-08-25T10:01:00.000Z",
            "version": "2.1.226",
            "isSidechain": True,
            "message": {"role": "assistant", "model": "m", "usage": {"output_tokens": 5}},
        },
    ]
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    assert scan_file(conn, path) == 2
    assert conn.execute("SELECT num_turns FROM sessions WHERE session_id='s1'").fetchone()[0] == 1
    assert (
        conn.execute("SELECT COUNT(*) FROM transcript_turns WHERE is_sidechain=1").fetchone()[0]
        == 1
    )


def test_appended_records_are_picked_up_on_rescan(tmp_path):
    conn = _conn(tmp_path)
    path = tmp_path / "t.jsonl"
    base = {
        "type": "assistant",
        "sessionId": "s1",
        "version": "2.1.226",
        "message": {"role": "assistant", "model": "m", "usage": {"output_tokens": 1}},
    }
    path.write_text(
        json.dumps({**base, "uuid": "a", "timestamp": "2026-08-25T10:00:00.000Z"}) + "\n"
    )
    assert scan_file(conn, path) == 1
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({**base, "uuid": "b", "timestamp": "2026-08-25T10:05:00.000Z"}) + "\n")
    assert scan_file(conn, path) == 1
    assert conn.execute("SELECT num_turns FROM sessions").fetchone()[0] == 2
    assert conn.execute("SELECT wall_seconds FROM sessions").fetchone()[0] == 300


def test_scan_all_is_mtime_filtered(tmp_path):
    import os
    import time

    conn = _conn(tmp_path)
    projects = tmp_path / "projects" / "proj"
    projects.mkdir(parents=True)
    fresh = projects / "fresh.jsonl"
    fresh.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    stale = projects / "stale.jsonl"
    stale.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    old = time.time() - 30 * 86400
    os.utime(stale, (old, old))

    scanned = scan_all(conn, tmp_path / "projects", since_days=3)
    assert scanned > 0
    sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    assert sessions == 1
    assert scan_all(conn, tmp_path / "projects", since_days=3) == 0

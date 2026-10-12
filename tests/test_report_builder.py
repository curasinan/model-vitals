from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from vitals.canary.checkers import default_tasks_dir, load_tasks
from vitals.db import get_conn, init_db, kv_set
from vitals.detect import signal_ids as sid
from vitals.detect.baseline import AUTO_FALSE_POSITIVE
from vitals.report.builder import build
from vitals.timeutil import hour_add

MODEL = "claude-sonnet-5"
VERSION = "2.1.237"
BUCKET = "gt180k"
START = "2026-08-01T00:00:00+00:00"
MID = hour_add(START, 1)
END = hour_add(START, 3)

_SECRET_RE = re.compile(r"sk-ant-|@gmail|C:\\Users\\asus")


def _cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VITALS_PROJECTS_DIR", str(tmp_path / "projects"))
    from vitals.config import load

    return load()


def _conn(cfg):
    conn = get_conn(cfg.db_path)
    init_db(conn)
    return conn


def _write_transcript(path: Path, uuid: str, session_id: str, ts: str) -> None:
    rec = {
        "uuid": uuid,
        "sessionId": session_id,
        "parentUuid": None,
        "timestamp": ts,
        "type": "assistant",
        "message": {
            "model": MODEL,
            "content": [
                {
                    "type": "text",
                    "text": (
                        "I tried the request with key sk-ant-api03-REALSECRETVALUE1234567890 "
                        "and it still failed; contact ops@gmail.com or see "
                        "C:\\Users\\asus\\project\\notes.txt for the run log."
                    ),
                }
            ],
        },
    }
    path.write_text(json.dumps(rec) + "\n", encoding="utf-8")


def _seed(conn, tmp_path, *, evidence_overrides: dict | None = None):
    session_id = "sess-1"
    transcript_path = tmp_path / "transcript.jsonl"
    turn_uuid = "turn-1"
    _write_transcript(transcript_path, turn_uuid, session_id, MID)

    conn.execute(
        "INSERT INTO sessions(session_id, started_at, cwd, cc_version, transcript_path)"
        " VALUES (?,?,?,?,?)",
        (session_id, START, "C:/work/proj", VERSION, str(transcript_path)),
    )
    conn.execute(
        "INSERT INTO transcript_turns(uuid, session_id, ts, role, self_corr_hits, text_len)"
        " VALUES (?,?,?,?,?,?)",
        (turn_uuid, session_id, MID, "assistant", 2, 180),
    )

    conn.execute(
        "INSERT INTO detector_state(signal, model, context_bucket, cc_version, mu0, sigma0,"
        " baseline_start, baseline_end, baseline_samples, baseline_inherited_from)"
        " VALUES (?,?,?,?,?,?,?,?,?,NULL)",
        (sid.S1_LATENCY_P95, MODEL, BUCKET, VERSION, 1.5, 0.3, hour_add(START, -168), START, 900),
    )
    conn.execute(
        "INSERT INTO signal_windows(window_start, signal, model, context_bucket, value, n,"
        " cc_version) VALUES (?,?,?,?,?,?,?)",
        (START, sid.S1_LATENCY_P95, MODEL, BUCKET, 9.9, 120, VERSION),
    )
    cur = conn.execute(
        "INSERT INTO anomalies(signal, model, context_bucket, cc_version, started_at, ended_at,"
        " direction, peak_stat, peak_z, status) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (sid.S1_LATENCY_P95, MODEL, BUCKET, VERSION, START, END, "up", 7.2, 15.4, "open"),
    )
    anomaly_id = cur.lastrowid

    cur = conn.execute(
        "INSERT INTO canary_cycles(started_at, finished_at, model, effort, suite_hash, n_runs,"
        " n_pass, n_invalid, pass_rate) VALUES (?,?,?,?,?,?,?,?,?)",
        (MID, MID, MODEL, "medium", "hash1", 4, 2, 0, 0.5),
    )
    cycle_id = cur.lastrowid
    conn.execute(
        "INSERT INTO canary_runs(cycle_id, task_id, attempt, session_id, ts, model, passed,"
        " invalid, fail_detail, long_context) VALUES (?,?,?,?,?,?,?,?,?,0)",
        (
            cycle_id,
            "diff-golden",
            1,
            "canary-sess-1",
            MID,
            MODEL,
            0,
            0,
            "diff for out/b.txt did not match golden/expected.diff:\n"
            "expected 'clean output', got 'contact ops@gmail.com or use "
            "sk-ant-api03-OTHERSECRETVALUE for retry, see C:\\Users\\asus\\log.txt'",
        ),
    )

    kv_set(
        conn,
        "snapshot",
        json.dumps(
            {"plugins_list": json.dumps({"installed": [["my-plugin", "1.0.0", ""]], "enabled": []})}
        ),
    )

    evidence = {
        "cls": "C",
        "matched_rule": 4,
        "matched_rule_name": "provider_no_incident",
        "generated_at": END,
        "window": {"start": START, "end": END, "open": False},
        "strata": {
            "signals": [sid.S1_LATENCY_P95],
            "models": [MODEL],
            "context_buckets": [BUCKET],
            "cc_versions": [VERSION],
        },
        "rules": [
            {
                "rule": 4,
                "cls": "C",
                "name": "provider_no_incident",
                "matched": True,
                "facts": {"branches_matched": ["a"]},
            }
        ],
        "anomaly_ids_missing": [],
    }
    if evidence_overrides:
        evidence.update(evidence_overrides)

    conn.execute(
        "INSERT INTO alerts(ts, severity, attribution, title, evidence_json, anomaly_ids,"
        " suppressed_by_incident) VALUES (?,?,?,?,?,?,?)",
        (
            END,
            "CRITICAL",
            "C",
            "Provider drift, no status incident",
            json.dumps(evidence),
            json.dumps([anomaly_id]),
            None,
        ),
    )
    conn.commit()
    alert_id = conn.execute("SELECT id FROM alerts ORDER BY id DESC LIMIT 1").fetchone()[0]
    return alert_id, transcript_path


def test_build_returns_two_existing_paths(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)

    md_path, json_path = build(conn, cfg, alert_id)

    assert isinstance(md_path, Path) and isinstance(json_path, Path)
    assert md_path.exists()
    assert json_path.exists()
    assert md_path.suffix == ".md"
    assert json_path.suffix == ".json"


def test_markdown_carries_attribution_and_no_secret_survives(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)

    md_path, _ = build(conn, cfg, alert_id)
    text = md_path.read_text(encoding="utf-8")

    assert "Attribution: C" in text
    assert not _SECRET_RE.search(text)


def test_json_mirror_round_trips_the_alert_id_and_has_no_secret(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)

    _, json_path = build(conn, cfg, alert_id)
    payload = json.loads(json_path.read_text(encoding="utf-8"))

    assert payload["alert_id"] == alert_id
    assert payload["severity"] == "CRITICAL"
    assert payload["attribution"] == "C"
    raw = json.dumps(payload)
    assert not _SECRET_RE.search(raw)


def test_affected_signals_table_shows_before_and_after_numbers(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)

    md_path, json_path = build(conn, cfg, alert_id)
    text = md_path.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))

    assert "1.5" in text and "0.3" in text
    assert "9.9" in text
    assert "7.2" in text
    row = payload["affected_signals"][0]
    assert row["baseline_mu0"] == 1.5
    assert row["current_value"] == 9.9
    assert row["cusum_peak"] == 7.2


def test_transcript_excerpt_is_redacted_before_it_ever_reaches_disk(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, transcript_path = _seed(conn, tmp_path)

    md_path, json_path = build(conn, cfg, alert_id)
    text = md_path.read_text(encoding="utf-8")

    assert "<REDACTED:key>" in text or "<REDACTED:email>" in text or "<REDACTED:path>" in text
    assert "REALSECRETVALUE" not in text
    assert "ops@gmail.com" not in text
    assert not _SECRET_RE.search(json.dumps(json.loads(json_path.read_text(encoding="utf-8"))))


def test_missing_transcript_reports_retention_sweep_not_a_crash(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, transcript_path = _seed(conn, tmp_path)
    transcript_path.unlink()

    md_path, _ = build(conn, cfg, alert_id)
    text = md_path.read_text(encoding="utf-8")

    assert "transcript unavailable (retention sweep)" in text
    assert "REALSECRETVALUE" not in text


def test_build_is_idempotent_overwrites_rather_than_accumulates(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)

    md1, json1 = build(conn, cfg, alert_id)
    md2, json2 = build(conn, cfg, alert_id)

    assert md1 == md2
    assert json1 == json2
    assert len(list(cfg.reports_dir.glob(f"*alert{alert_id}.md"))) == 1
    assert len(list(cfg.reports_dir.glob(f"*alert{alert_id}.json"))) == 1


def test_canary_diff_section_names_the_failing_task_and_is_redacted(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)

    md_path, json_path = build(conn, cfg, alert_id)
    text = md_path.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))

    assert "diff-golden" in text
    assert "OTHERSECRETVALUE" not in text
    assert any(row["task_id"] == "diff-golden" for row in payload["canary_diffs"])


def test_environment_falls_back_to_evidence_strata_models_when_api_requests_is_empty(
    tmp_path, monkeypatch
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)

    md_path, json_path = build(conn, cfg, alert_id)
    text = md_path.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))

    assert "none recorded in this window" not in text
    assert MODEL in text
    assert "from alert evidence" in text
    assert payload["environment"]["models_seen"] == []
    assert payload["environment"]["models_from_evidence"] == [MODEL]


def test_environment_prefers_api_requests_over_evidence_when_both_are_present(
    tmp_path, monkeypatch
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)
    conn.execute(
        "INSERT INTO api_requests(session_id, ts, model, effort, context_bucket, cc_version,"
        " duration_ms) VALUES (?,?,?,?,?,?,?)",
        ("sess-1", MID, MODEL, "medium", BUCKET, VERSION, 1200.0),
    )
    conn.commit()

    md_path, json_path = build(conn, cfg, alert_id)
    text = md_path.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))

    assert "observed in requests" in text
    assert "from alert evidence" not in text
    assert payload["environment"]["models_seen"] == [MODEL]


def test_baseline_auto_adjudication_is_disclosed(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)
    conn.execute(
        "INSERT INTO anomalies(signal, model, context_bucket, cc_version, started_at, ended_at,"
        " status) VALUES (?,?,?,?,?,?,?)",
        (
            sid.S1_LATENCY_P95,
            MODEL,
            BUCKET,
            VERSION,
            hour_add(START, -200),
            hour_add(START, -190),
            AUTO_FALSE_POSITIVE,
        ),
    )
    conn.commit()

    md_path, json_path = build(conn, cfg, alert_id)
    text = md_path.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))

    assert "auto-adjudicated" in text
    assert payload["affected_signals"][0]["baseline_auto_adjudicated_count"] >= 1


def test_no_anomalies_attached_degrades_gracefully(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    evidence = {
        "cls": "E",
        "matched_rule": 6,
        "matched_rule_name": "inconclusive",
        "generated_at": END,
        "window": {"start": START, "end": END, "open": False},
        "strata": {"signals": [], "models": [], "context_buckets": [], "cc_versions": []},
        "rules": [
            {
                "rule": 6,
                "cls": "E",
                "name": "inconclusive",
                "matched": True,
                "facts": {"reason": "no attribution rule matched"},
            }
        ],
    }
    conn.execute(
        "INSERT INTO alerts(ts, severity, attribution, title, evidence_json, anomaly_ids,"
        " suppressed_by_incident) VALUES (?,?,?,?,?,?,?)",
        (END, "WARN", "E", "synthetic", json.dumps(evidence), json.dumps([]), None),
    )
    conn.commit()
    alert_id = conn.execute("SELECT id FROM alerts ORDER BY id DESC LIMIT 1").fetchone()[0]

    md_path, json_path = build(conn, cfg, alert_id)

    text = md_path.read_text(encoding="utf-8")
    assert "Attribution: E" in text
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["affected_signals"] == []


def test_final_line_is_exactly_the_briefs_disclaimer(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)

    md_path, _ = build(conn, cfg, alert_id)
    text = md_path.read_text(encoding="utf-8")

    assert "Prepared by model-vitals — review before submitting via /bug or GitHub" in text


def test_section_order_matches_the_brief(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)

    md_path, _ = build(conn, cfg, alert_id)
    text = md_path.read_text(encoding="utf-8")

    headings = [
        "Summary",
        "Environment",
        "Time window",
        "Affected signals",
        "Canary diffs",
        "Change points in window",
        "Status-page state during window",
        "Example excerpts",
        "Reproduction hints",
    ]
    positions = [text.index(h) for h in headings]
    assert positions == sorted(positions)


def test_reproduction_hint_omits_session_id(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)

    md_path, json_path = build(conn, cfg, alert_id)
    text = md_path.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))

    assert "--session-id" not in text
    assert all("--session-id" not in r["command"] for r in payload["reproduction_hints"])
    assert "diff-golden" in text


def _b_evidence(facts: dict) -> dict:
    return {
        "cls": "B",
        "matched_rule": 2,
        "matched_rule_name": "harness_change",
        "rules": [
            {"rule": 2, "cls": "B", "name": "harness_change", "matched": True, "facts": facts}
        ],
    }


def _cp(kind: str) -> dict:
    return {"id": 7, "kind": kind, "old_value": "2.1.230", "new_value": "2.1.237"}


def test_one_liner_version_arm_may_claim_the_new_version_stratum_alarmed():
    from vitals.report.builder import _evidence_one_liner

    line = _evidence_one_liner(
        _b_evidence(
            {
                "change_point": _cp("cc_version"),
                "postdates_test": "stratum_cc_version_is_the_new_value",
                "prior_version": "2.1.230",
                "prior_version_quiet": True,
            }
        ),
        "B",
    )

    assert "#7" in line and "cc_version" in line
    assert "2.1.237" in line
    assert "new-version stratum" in line
    assert "2.1.230" in line


def test_one_liner_settings_arm_does_not_claim_a_version_contrast_that_never_ran():
    from vitals.report.builder import _evidence_one_liner

    line = _evidence_one_liner(
        _b_evidence(
            {
                "change_point": _cp("settings"),
                "postdates_test": "alarm_starts_after_change",
                "prior_version_quiet": None,
            }
        ),
        "B",
    )

    assert "new-version stratum" not in line
    assert "#7" in line and "settings" in line
    assert "began" in line or "began after" in line
    assert "no version" in line.lower()


def test_one_liner_canary_arm_says_the_argument_is_temporal_not_cross_stratum():
    from vitals.report.builder import _evidence_one_liner

    line = _evidence_one_liner(
        _b_evidence(
            {
                "change_point": _cp("cc_version"),
                "postdates_test": "canary_temporal_contrast",
                "canary_anomaly_ids": [4],
                "prior_version_quiet": None,
            }
        ),
        "B",
    )

    assert "new-version stratum" not in line
    assert "canary" in line.lower()
    assert "#7" in line
    assert "2.1.237" in line


def test_one_liner_class_b_falls_back_when_the_arm_is_unrecognised():
    from vitals.report.builder import _evidence_one_liner

    line = _evidence_one_liner(
        _b_evidence({"change_point": _cp("settings"), "postdates_test": "something_new"}), "B"
    )

    assert "#7" in line and "settings" in line
    assert "new-version stratum" not in line


def test_report_for_a_settings_change_alert_never_claims_a_version_contrast(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(
        conn,
        tmp_path,
        evidence_overrides={
            "cls": "B",
            "matched_rule": 2,
            "matched_rule_name": "harness_change",
            "rules": [
                {
                    "rule": 2,
                    "cls": "B",
                    "name": "harness_change",
                    "matched": True,
                    "facts": {
                        "change_point": _cp("settings"),
                        "postdates_test": "alarm_starts_after_change",
                        "prior_version_quiet": None,
                    },
                }
            ],
        },
    )
    conn.execute("UPDATE alerts SET attribution = 'B' WHERE id = ?", (alert_id,))
    conn.commit()

    md_path, json_path = build(conn, cfg, alert_id)
    text = md_path.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))

    assert "only the new-version stratum alarmed" not in text
    assert "only the new-version stratum alarmed" not in payload["summary_evidence"]
    assert "settings" in payload["summary_evidence"]


def _add_session_with_turns(conn, tmp_path, session_id: str, turns: list[tuple[str, str, int]]):
    path = tmp_path / f"transcript-{session_id}.jsonl"
    records = [
        json.dumps(
            {
                "uuid": uuid,
                "sessionId": session_id,
                "parentUuid": None,
                "timestamp": ts,
                "type": "assistant",
                "message": {"model": MODEL, "content": [{"type": "text", "text": f"body at {ts}"}]},
            }
        )
        for uuid, ts, _hits in turns
    ]
    path.write_text("\n".join(records) + "\n", encoding="utf-8")
    conn.execute(
        "INSERT INTO sessions(session_id, started_at, cwd, cc_version, transcript_path)"
        " VALUES (?,?,?,?,?)",
        (session_id, START, "C:/work/other", VERSION, str(path)),
    )
    for uuid, ts, hits in turns:
        conn.execute(
            "INSERT INTO transcript_turns(uuid, session_id, ts, role, self_corr_hits, text_len)"
            " VALUES (?,?,?,?,?,?)",
            (uuid, session_id, ts, "assistant", hits, 40),
        )
    conn.commit()


def test_report_never_prints_a_session_id_or_a_turn_uuid(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)

    md_path, json_path = build(conn, cfg, alert_id)
    text = md_path.read_text(encoding="utf-8")
    blob = json.dumps(json.loads(json_path.read_text(encoding="utf-8")))

    assert "sess-1" not in text and "turn-1" not in text
    assert "sess-1" not in blob and "turn-1" not in blob
    assert "session #1" in text
    assert "turn #1" in text


def test_excerpt_indices_are_per_report_and_group_by_session(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)
    _add_session_with_turns(
        conn, tmp_path, "sess-2", [("turn-2a", MID, 1), ("turn-2b", hour_add(START, 2), 0)]
    )

    md_path, json_path = build(conn, cfg, alert_id)
    text = md_path.read_text(encoding="utf-8")
    items = json.loads(json_path.read_text(encoding="utf-8"))["excerpts"]["items"]

    assert [(i["session_index"], i["turn_index"]) for i in items] == [(1, 1), (2, 1), (2, 2)]
    assert "session #1, turn #1" in text
    assert "session #2, turn #1" in text
    assert "session #2, turn #2" in text
    for raw in ("sess-1", "sess-2", "turn-1", "turn-2a", "turn-2b"):
        assert raw not in text, raw


def test_excerpt_indices_are_stable_across_rebuilds(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id, _ = _seed(conn, tmp_path)
    _add_session_with_turns(conn, tmp_path, "sess-2", [("turn-2a", MID, 1)])

    first = build(conn, cfg, alert_id)[0].read_text(encoding="utf-8")
    second = build(conn, cfg, alert_id)[0].read_text(encoding="utf-8")

    def excerpt_headings(text: str) -> list[str]:
        return [ln for ln in text.splitlines() if ln.startswith("### Excerpt")]

    assert excerpt_headings(first) == excerpt_headings(second)
    assert len(excerpt_headings(first)) == 2


def test_real_task_fixtures_still_load(tmp_path):
    tasks = load_tasks(default_tasks_dir())
    assert any(t.task_id == "diff-golden" for t in tasks)


def test_alert_not_found_raises(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    with pytest.raises(ValueError):
        build(conn, cfg, 999999)

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from vitals import config as config_mod
from vitals.config import DetectCfg
from vitals.db import get_conn, init_db
from vitals.validate.replay import (
    ReplayReport,
    _suggest_thresholds,
    backfill,
    open_replay_db,
)

FIXTURE = Path(__file__).parent / "fixtures" / "transcript_sample.jsonl"


def _conn(tmp_path: Path, name: str = "replay.db"):
    conn = get_conn(tmp_path / name)
    init_db(conn)
    return conn


def _clone_fixture_with_new_session(dst_path: Path, session_id: str, uuid_suffix: str) -> None:
    lines = []
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        if "sessionId" in rec:
            rec["sessionId"] = session_id
        if rec.get("uuid"):
            rec["uuid"] = rec["uuid"] + uuid_suffix
        if rec.get("parentUuid"):
            rec["parentUuid"] = rec["parentUuid"] + uuid_suffix
        lines.append(json.dumps(rec))
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    dst_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _two_session_projects_dir(tmp_path: Path) -> Path:
    projects = tmp_path / "fake-claude-projects"
    session1 = projects / "proj-a" / "session-1.jsonl"
    session1.parent.mkdir(parents=True, exist_ok=True)
    session1.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    session2 = projects / "proj-b" / "session-2.jsonl"
    _clone_fixture_with_new_session(session2, "22222222-2222-2222-2222-222222222222", "-s2")
    return projects


def test_open_replay_db_is_fresh_and_distinct_each_call(tmp_path):
    conn1, path1 = open_replay_db(base_dir=tmp_path)
    conn2, path2 = open_replay_db(base_dir=tmp_path)
    try:
        assert path1 != path2
        assert path1.exists() and path2.exists()
        conn1.execute("SELECT 1")
        conn2.execute("SELECT 1")
    finally:
        conn1.close()
        conn2.close()


def test_open_replay_db_never_resolves_to_the_configured_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path / "not-really-real"))
    real_db = config_mod.default_data_dir() / "vitals.db"
    conn, path = open_replay_db(base_dir=tmp_path)
    try:
        assert path.resolve() != real_db.resolve()
    finally:
        conn.close()


def test_backfill_refuses_a_connection_pointed_at_the_configured_db_path(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path / "data"))
    real_db_path = config_mod.default_data_dir() / "vitals.db"
    conn = get_conn(real_db_path)
    init_db(conn)
    try:
        with pytest.raises(RuntimeError, match="refusing to replay"):
            backfill(conn, tmp_path / "empty-projects", since_days=90)
    finally:
        conn.close()


def test_backfill_accepts_a_conn_that_is_not_the_configured_path(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path / "unrelated-data-dir"))
    conn = _conn(tmp_path, "clearly-a-replay.db")
    report = backfill(conn, tmp_path / "empty-projects", since_days=90)
    assert isinstance(report, ReplayReport)


def test_backfill_never_modifies_the_projects_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path / "data"))
    projects = _two_session_projects_dir(tmp_path)
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in sorted(projects.rglob("*.jsonl"))}
    assert len(before) == 2

    conn = _conn(tmp_path)
    backfill(conn, projects, since_days=90)

    after = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in sorted(projects.rglob("*.jsonl"))}
    assert before == after
    assert set(before) == set(after)


def test_replay_runs_on_fixture_transcripts(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path / "data"))
    projects = _two_session_projects_dir(tmp_path)
    conn = _conn(tmp_path)

    report = backfill(conn, projects, since_days=90)

    assert isinstance(report, ReplayReport)
    assert report.windows_aggregated >= 1
    assert report.strata >= 1
    assert isinstance(report.anomalies, list)
    assert isinstance(report.would_be_alerts, list)
    assert isinstance(report.weekly_info, list)
    assert isinstance(report.weekly_warn, list)
    for a in report.anomalies:
        assert {"signal", "stratum", "span", "direction"} <= a.keys()
    for wa in report.would_be_alerts:
        assert {"severity", "attribution", "ts"} <= wa.keys()

    n_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    assert n_sessions == 2


def test_replay_on_an_empty_projects_dir_does_not_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path / "data"))
    conn = _conn(tmp_path)
    report = backfill(conn, tmp_path / "nonexistent-projects-dir", since_days=90)
    assert report.windows_aggregated == 0
    assert report.would_be_alerts == []
    assert report.weekly_warn == []


def test_suggest_thresholds_is_none_under_the_acceptance_criterion():
    assert _suggest_thresholds([0, 1, 0, 1], DetectCfg()) is None


def test_suggest_thresholds_fires_and_names_h_and_delta_when_exceeded():
    suggestion = _suggest_thresholds([2, 3, 2, 4], DetectCfg())
    assert suggestion is not None
    assert suggestion["options"]["h"] > DetectCfg().h
    assert suggestion["options"]["delta"] > DetectCfg().delta
    assert re.search(r"\d", suggestion["reason"])


def test_suggest_thresholds_handles_an_empty_history():
    assert _suggest_thresholds([], DetectCfg()) is None


def test_replay_cli_never_touches_configured_db_path_and_prints_the_report(tmp_path, monkeypatch):
    import vitals.validate.replay as replay_module
    from vitals.cli import main

    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VITALS_PROJECTS_DIR", str(tmp_path / "projects"))

    captured = {}

    def fake_backfill(conn, projects_dir, since_days=90, *, detect_cfg=None):
        captured["projects_dir"] = Path(projects_dir)
        captured["since_days"] = since_days
        captured["db_file"] = conn.execute("PRAGMA database_list").fetchone()["file"]
        return ReplayReport(
            windows_aggregated=3,
            strata=2,
            anomalies=[],
            would_be_alerts=[{"severity": "INFO", "attribution": "E", "ts": "x", "title": "t"}],
            weekly_info=[1],
            weekly_warn=[0],
            suggested_thresholds=None,
        )

    monkeypatch.setattr(replay_module, "backfill", fake_backfill)

    rc = main(["replay", "--since-days", "42"])

    assert rc == 0
    assert captured["since_days"] == 42
    assert captured["projects_dir"] == (tmp_path / "projects")
    real_configured_db = (tmp_path / "data" / "vitals.db").resolve()
    assert Path(captured["db_file"]).resolve() != real_configured_db


def test_replay_cli_prints_suggested_thresholds_when_present(tmp_path, monkeypatch, capsys):
    import vitals.validate.replay as replay_module
    from vitals.cli import main

    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VITALS_PROJECTS_DIR", str(tmp_path / "projects"))

    def fake_backfill(conn, projects_dir, since_days=90, *, detect_cfg=None):
        return ReplayReport(
            windows_aggregated=10,
            strata=4,
            weekly_warn=[2, 3],
            weekly_info=[1, 1],
            suggested_thresholds={
                "reason": "observed 2.50 WARN/week averaged over 2 week(s)",
                "options": {"h": 6.0, "delta": 0.2},
            },
        )

    monkeypatch.setattr(replay_module, "backfill", fake_backfill)

    rc = main(["replay"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "NOT MET" in out
    assert "h -> 6.0" in out


def _report(**overrides) -> ReplayReport:
    fields = dict(
        windows_aggregated=120,
        strata=4,
        anomalies=[],
        would_be_alerts=[],
        weekly_info=[1, 0],
        weekly_warn=[0, 0],
        suggested_thresholds=None,
    )
    fields.update(overrides)
    return ReplayReport(**fields)


def test_render_says_the_warn_rule_was_not_exercised_when_only_one_family_had_windows():
    from vitals.validate.replay import render_replay_report

    out = render_replay_report(
        _report(families_with_windows=["verbosity", "weak"], warn_rule_exercised=False), 90
    )

    assert "MET" not in out
    assert "WARN rule not exercised by this replay" in out
    assert "verbosity" in out and "weak" in out


def test_render_names_the_families_that_actually_had_windows():
    from vitals.validate.replay import render_replay_report

    out = render_replay_report(
        _report(families_with_windows=["errors", "latency", "verbosity"], warn_rule_exercised=True),
        90,
    )

    assert "errors" in out and "latency" in out
    assert "acceptance criterion:" in out
    assert "MET" in out


def test_render_still_reports_not_met_when_thresholds_are_suggested():
    from vitals.validate.replay import render_replay_report

    out = render_replay_report(
        _report(
            weekly_warn=[3, 4],
            suggested_thresholds={
                "reason": "observed 3.50 WARN/week",
                "observed_warn_per_week": 3.5,
                "options": {"h": 6.0, "delta": 0.195},
            },
            families_with_windows=["errors", "latency"],
            warn_rule_exercised=True,
        ),
        90,
    )

    assert "NOT MET" in out
    assert "h -> 6.0" in out


def test_backfill_records_which_families_had_windows_and_whether_warn_was_exercised(tmp_path):
    projects = tmp_path / "projects" / "proj-a"
    projects.mkdir(parents=True)
    (projects / "sample.jsonl").write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    conn = _conn(tmp_path)

    report = backfill(conn, tmp_path / "projects", since_days=3650)

    assert "weak" in report.families_with_windows
    assert "errors" in report.families_with_windows
    assert report.families_with_live_baseline == []
    assert report.warn_rule_exercised is False


def test_since_days_help_says_it_filters_by_file_mtime_not_content_date():
    from vitals.cli import build_parser

    action = next(
        a
        for a in build_parser()._subparsers._group_actions[0].choices["replay"]._actions
        if "--since-days" in (a.option_strings or [])
    )

    assert "mtime" in action.help
    assert "modified" in action.help.lower()

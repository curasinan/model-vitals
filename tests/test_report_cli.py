from __future__ import annotations

import io
import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import vitals.cli as cli_mod
from vitals.cli import main
from vitals.config import load
from vitals.db import get_conn, init_db

REPO = "anthropics/claude-code"


def _cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VITALS_PROJECTS_DIR", str(tmp_path / "projects"))
    return load()


def _conn(cfg):
    conn = get_conn(cfg.db_path)
    init_db(conn)
    return conn


def _insert_alert(
    conn: sqlite3.Connection,
    *,
    report_path: str | None,
    detail_path: str | None = None,
    evidence: dict | None = None,
    title: str = "latency regression at gt180k",
) -> int:
    cur = conn.execute(
        "INSERT INTO alerts(ts, severity, attribution, title, evidence_json, anomaly_ids,"
        " report_path, detail_path) VALUES (?,?,?,?,?,?,?,?)",
        (
            "2026-08-01T00:00:00+00:00",
            "CRITICAL",
            "B",
            title,
            json.dumps(evidence or {"cls": "B", "matched_rule": 2}),
            json.dumps([1, 2]),
            report_path,
            detail_path,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def _make_report(tmp_path: Path, name: str = "report.md") -> Path:
    path = tmp_path / name
    path.write_text("# Report\n\nSummary: latency regressed.\n", encoding="utf-8")
    return path


class FakeGh:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.calls: list[list[str]] = []
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    def __call__(self, cmd: list[str]):
        self.calls.append(list(cmd))
        return SimpleNamespace(returncode=self.returncode, stdout=self.stdout, stderr=self.stderr)


def test_report_issue_without_yes_post_never_calls_runner_and_prints_command(
    tmp_path, monkeypatch, capsys
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    report_path = _make_report(tmp_path)
    alert_id = _insert_alert(conn, report_path=str(report_path))
    conn.close()

    fake = FakeGh()
    monkeypatch.setattr(cli_mod, "run_gh", fake)

    rc = main(["report", "issue", str(alert_id)])

    assert rc == 0
    assert fake.calls == []
    out = capsys.readouterr().out
    assert "gh issue create" in out
    assert f"--repo {REPO}" in out
    assert str(report_path) in out
    assert "--body-file" in out


def test_report_issue_yes_post_plus_typed_yes_calls_runner_once_with_repo_and_body_file(
    tmp_path, monkeypatch, capsys
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    report_path = _make_report(tmp_path)
    alert_id = _insert_alert(conn, report_path=str(report_path))
    conn.close()

    fake = FakeGh(stdout="https://github.com/anthropics/claude-code/issues/4242\n")
    monkeypatch.setattr(cli_mod, "run_gh", fake)
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "yes")
    import io
    import sys

    monkeypatch.setattr(sys, "stdin", io.StringIO("yes\n"))

    rc = main(["report", "issue", str(alert_id), "--yes-post"])

    assert rc == 0
    assert len(fake.calls) == 1
    (cmd,) = fake.calls
    assert cmd[:3] == ["gh", "issue", "create"]
    assert "--repo" in cmd and cmd[cmd.index("--repo") + 1] == REPO
    assert "--body-file" in cmd and cmd[cmd.index("--body-file") + 1] == str(report_path)
    out = capsys.readouterr().out
    assert "https://github.com/anthropics/claude-code/issues/4242" in out


def test_report_issue_yes_post_plus_typed_no_does_not_call_runner(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    report_path = _make_report(tmp_path)
    alert_id = _insert_alert(conn, report_path=str(report_path))
    conn.close()

    fake = FakeGh()
    monkeypatch.setattr(cli_mod, "run_gh", fake)
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "no")

    rc = main(["report", "issue", str(alert_id), "--yes-post"])

    assert fake.calls == []
    out = capsys.readouterr().out.lower()
    assert "abort" in out


def test_report_issue_yes_post_alone_is_not_consent_without_typed_yes(
    tmp_path, monkeypatch, capsys
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    report_path = _make_report(tmp_path)
    alert_id = _insert_alert(conn, report_path=str(report_path))
    conn.close()

    fake = FakeGh()
    monkeypatch.setattr(cli_mod, "run_gh", fake)
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "")

    rc = main(["report", "issue", str(alert_id), "--yes-post"])

    assert fake.calls == []


@pytest.mark.parametrize(
    "typed,should_fire",
    [
        ("yes", True),
        ("YES", True),
        ("Yes", True),
        (" yes ", True),
        ("y", False),
        ("   ", False),
        ("yess", False),
        ("no", False),
        ("", False),
    ],
)
def test_typed_confirmation_gate_fires_only_for_yes_case_and_whitespace_insensitive(
    tmp_path, monkeypatch, capsys, typed, should_fire
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    report_path = _make_report(tmp_path)
    alert_id = _insert_alert(conn, report_path=str(report_path))
    conn.close()

    fake = FakeGh(stdout="https://github.com/anthropics/claude-code/issues/1\n")
    monkeypatch.setattr(cli_mod, "run_gh", fake)
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"{typed}\n"))

    rc = main(["report", "issue", str(alert_id), "--yes-post"])

    assert rc == 0
    if should_fire:
        assert len(fake.calls) == 1
    else:
        assert fake.calls == []
        out = capsys.readouterr().out.lower()
        assert "abort" in out


def test_report_issue_confirmation_prompt_shows_the_title(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    report_path = _make_report(tmp_path)
    alert_id = _insert_alert(conn, report_path=str(report_path), title="a very specific title xyz")
    conn.close()

    fake = FakeGh(stdout="https://github.com/anthropics/claude-code/issues/1\n")
    monkeypatch.setattr(cli_mod, "run_gh", fake)
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "yes")

    main(["report", "issue", str(alert_id), "--yes-post"])

    out = capsys.readouterr().out
    assert "a very specific title xyz" in out


def test_report_issue_refuses_when_report_path_is_empty(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id = _insert_alert(conn, report_path=None)
    conn.close()

    fake = FakeGh()
    monkeypatch.setattr(cli_mod, "run_gh", fake)

    rc = main(["report", "issue", str(alert_id)])

    assert rc == 1
    assert fake.calls == []
    out = capsys.readouterr().out.lower()
    assert "report" in out
    assert "traceback" not in out


def test_report_issue_never_reads_detail_path_even_when_report_path_is_empty(
    tmp_path, monkeypatch, capsys
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    detail_path = tmp_path / "alert-1.json"
    detail_path.write_text(json.dumps({"secret": "sk-ant-should-never-be-read"}), encoding="utf-8")
    alert_id = _insert_alert(conn, report_path=None, detail_path=str(detail_path))
    conn.close()

    fake = FakeGh()
    monkeypatch.setattr(cli_mod, "run_gh", fake)

    rc = main(["report", "issue", str(alert_id)])

    assert rc == 1
    assert fake.calls == []
    out = capsys.readouterr().out
    assert str(detail_path) not in out
    assert "sk-ant" not in out


def test_report_issue_refuses_when_report_path_file_was_deleted(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    report_path = _make_report(tmp_path)
    alert_id = _insert_alert(conn, report_path=str(report_path))
    conn.close()
    report_path.unlink()

    fake = FakeGh()
    monkeypatch.setattr(cli_mod, "run_gh", fake)

    rc = main(["report", "issue", str(alert_id)])

    assert rc == 1
    assert fake.calls == []
    out = capsys.readouterr().out.lower()
    assert "traceback" not in out


def test_report_issue_reports_a_clear_message_for_an_unknown_alert_id(
    tmp_path, monkeypatch, capsys
):
    cfg = _cfg(tmp_path, monkeypatch)
    _conn(cfg).close()

    fake = FakeGh()
    monkeypatch.setattr(cli_mod, "run_gh", fake)

    rc = main(["report", "issue", "999999"])

    assert rc == 1
    assert fake.calls == []
    out = capsys.readouterr().out.lower()
    assert "traceback" not in out
    assert "999999" in out


def test_report_issue_records_url_without_clobbering_existing_evidence(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    report_path = _make_report(tmp_path)
    evidence = {"cls": "B", "matched_rule": 2, "matched_rule_name": "version_change_point"}
    alert_id = _insert_alert(conn, report_path=str(report_path), evidence=evidence)
    conn.close()

    fake = FakeGh(stdout="https://github.com/anthropics/claude-code/issues/77\n")
    monkeypatch.setattr(cli_mod, "run_gh", fake)
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "yes")

    rc = main(["report", "issue", str(alert_id), "--yes-post"])
    assert rc == 0

    check_conn = get_conn(cfg.db_path)
    row = check_conn.execute(
        "SELECT evidence_json FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    stored = json.loads(row["evidence_json"])
    assert stored["gh_issue_url"] == "https://github.com/anthropics/claude-code/issues/77"
    assert stored["cls"] == "B"
    assert stored["matched_rule"] == 2
    assert stored["matched_rule_name"] == "version_change_point"


def test_report_issue_no_flag_leaves_evidence_json_untouched(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    report_path = _make_report(tmp_path)
    evidence = {"cls": "B", "matched_rule": 2}
    alert_id = _insert_alert(conn, report_path=str(report_path), evidence=evidence)
    conn.close()

    fake = FakeGh()
    monkeypatch.setattr(cli_mod, "run_gh", fake)

    main(["report", "issue", str(alert_id)])

    check_conn = get_conn(cfg.db_path)
    row = check_conn.execute(
        "SELECT evidence_json FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    stored = json.loads(row["evidence_json"])
    assert "gh_issue_url" not in stored
    assert stored == evidence


def test_report_issue_gh_failure_does_not_record_a_url(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    report_path = _make_report(tmp_path)
    alert_id = _insert_alert(conn, report_path=str(report_path))
    conn.close()

    fake = FakeGh(returncode=1, stderr="HTTP 401: bad credentials")
    monkeypatch.setattr(cli_mod, "run_gh", fake)
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "yes")

    rc = main(["report", "issue", str(alert_id), "--yes-post"])

    assert rc == 1
    assert len(fake.calls) == 1
    check_conn = get_conn(cfg.db_path)
    row = check_conn.execute(
        "SELECT evidence_json FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    stored = json.loads(row["evidence_json"])
    assert "gh_issue_url" not in stored


def test_report_open_prints_path_and_opens_it(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    report_path = _make_report(tmp_path)
    alert_id = _insert_alert(conn, report_path=str(report_path))
    conn.close()

    opened = []
    monkeypatch.setattr(cli_mod.os, "startfile", lambda p: opened.append(p), raising=False)

    rc = main(["report", "open", str(alert_id)])

    assert rc == 0
    assert opened == [report_path] or [str(p) for p in opened] == [str(report_path)]
    out = capsys.readouterr().out
    assert str(report_path) in out


def test_report_open_guards_startfile_on_non_windows(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    report_path = _make_report(tmp_path)
    alert_id = _insert_alert(conn, report_path=str(report_path))
    conn.close()

    monkeypatch.delattr(cli_mod.os, "startfile", raising=False)

    rc = main(["report", "open", str(alert_id)])

    assert rc == 0
    out = capsys.readouterr().out
    assert str(report_path) in out


def test_report_open_refuses_when_report_path_is_empty(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id = _insert_alert(conn, report_path=None)
    conn.close()

    rc = main(["report", "open", str(alert_id)])

    assert rc == 1
    out = capsys.readouterr().out.lower()
    assert "traceback" not in out


def test_report_open_refuses_when_file_was_deleted(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    report_path = _make_report(tmp_path)
    alert_id = _insert_alert(conn, report_path=str(report_path))
    conn.close()
    report_path.unlink()

    rc = main(["report", "open", str(alert_id)])

    assert rc == 1
    out = capsys.readouterr().out.lower()
    assert "traceback" not in out


def test_report_open_reports_a_clear_message_for_an_unknown_alert_id(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    _conn(cfg).close()

    rc = main(["report", "open", "424242"])

    assert rc == 1
    out = capsys.readouterr().out.lower()
    assert "traceback" not in out
    assert "424242" in out


def _seed_alert_with_anomaly(conn, tmp_path, *, severity: str, secret_text: str) -> int:
    transcript = tmp_path / "t.jsonl"
    transcript.write_text(
        json.dumps(
            {
                "uuid": "turn-x",
                "sessionId": "sess-x",
                "parentUuid": None,
                "timestamp": "2026-08-01T00:30:00+00:00",
                "type": "assistant",
                "message": {
                    "model": "claude-sonnet-5",
                    "content": [{"type": "text", "text": secret_text}],
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    conn.execute(
        "INSERT INTO sessions(session_id, started_at, cwd, cc_version, transcript_path)"
        " VALUES ('sess-x', '2026-08-01T00:00:00+00:00', 'C:/w', '2.1.237', ?)",
        (str(transcript),),
    )
    conn.execute(
        "INSERT INTO transcript_turns(uuid, session_id, ts, role, self_corr_hits, text_len)"
        " VALUES ('turn-x', 'sess-x', '2026-08-01T00:30:00+00:00', 'assistant', 1, 50)"
    )
    cur = conn.execute(
        "INSERT INTO anomalies(signal, model, context_bucket, cc_version, started_at, ended_at,"
        " direction, peak_stat, peak_z, status) VALUES"
        " ('api_latency_p95','claude-sonnet-5','gt180k','2.1.237','2026-08-01T00:00:00+00:00',"
        " '2026-08-01T03:00:00+00:00','up',7.0,12.0,'open')"
    )
    anomaly_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO alerts(ts, severity, attribution, title, evidence_json, anomaly_ids)"
        " VALUES (?,?,?,?,?,?)",
        (
            "2026-08-01T03:00:00+00:00",
            severity,
            "E",
            "latency drift",
            json.dumps(
                {
                    "cls": "E",
                    "matched_rule": 6,
                    "matched_rule_name": "inconclusive",
                    "window": {
                        "start": "2026-08-01T00:00:00+00:00",
                        "end": "2026-08-01T03:00:00+00:00",
                        "open": False,
                    },
                    "rules": [],
                }
            ),
            json.dumps([anomaly_id]),
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def test_report_build_works_for_a_non_critical_alert_and_stamps_report_path(
    tmp_path, monkeypatch, capsys
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id = _seed_alert_with_anomaly(conn, tmp_path, severity="WARN", secret_text="hello")
    assert (
        conn.execute("SELECT report_path FROM alerts WHERE id = ?", (alert_id,)).fetchone()[
            "report_path"
        ]
        is None
    )

    rc = main(["report", "build", str(alert_id)])
    out = capsys.readouterr().out

    assert rc == 0
    check = get_conn(cfg.db_path)
    stamped = check.execute("SELECT report_path FROM alerts WHERE id = ?", (alert_id,)).fetchone()[
        "report_path"
    ]
    assert stamped and Path(stamped).exists()
    assert stamped in out


def test_report_build_makes_report_open_and_report_issue_reachable(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id = _seed_alert_with_anomaly(conn, tmp_path, severity="INFO", secret_text="hello")

    assert main(["report", "build", str(alert_id)]) == 0
    capsys.readouterr()

    calls = []
    monkeypatch.setattr(cli_mod, "run_gh", lambda cmd: calls.append(cmd))
    assert main(["report", "issue", str(alert_id)]) == 0
    out = capsys.readouterr().out

    assert "--body-file" in out
    assert calls == []


def test_report_build_rejects_an_unknown_alert_id(tmp_path, monkeypatch, capsys):
    _cfg(tmp_path, monkeypatch)
    _conn(cfg := load()).close()

    rc = main(["report", "build", "424242"])
    out = capsys.readouterr().out

    assert rc == 1
    assert "424242" in out
    assert cfg.reports_dir.exists() is False or not list(cfg.reports_dir.glob("*.md"))


def test_report_build_is_idempotent_and_overwrites_the_same_path(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    alert_id = _seed_alert_with_anomaly(conn, tmp_path, severity="WARN", secret_text="hello")

    assert main(["report", "build", str(alert_id)]) == 0
    assert main(["report", "build", str(alert_id)]) == 0
    capsys.readouterr()

    assert len(list(cfg.reports_dir.glob(f"*alert{alert_id}.md"))) == 1


def test_report_build_redacts_an_escaped_quote_json_secret_end_to_end(
    tmp_path, monkeypatch, capsys
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    leaky = 'tool_response: {"token": "s3cr3tvalue", "ok": true}'.replace('"', '\\"')
    alert_id = _seed_alert_with_anomaly(conn, tmp_path, severity="WARN", secret_text=leaky)

    assert main(["report", "build", str(alert_id)]) == 0
    capsys.readouterr()

    stamped = (
        get_conn(cfg.db_path)
        .execute("SELECT report_path FROM alerts WHERE id = ?", (alert_id,))
        .fetchone()["report_path"]
    )
    body = Path(stamped).read_text(encoding="utf-8")

    assert "s3cr3tvalue" not in body
    assert "<REDACTED:assignment>" in body

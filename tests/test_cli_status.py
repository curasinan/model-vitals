import json
import socket
import threading
from pathlib import Path

from vitals.config import load
from vitals.daemon import Daemon, ingest_once, job_aggregate, job_ingest
from vitals.db import get_conn, init_db
from vitals.status import render_status
from vitals.timeutil import days_ago_iso, utcnow_iso

PAST = "2026-08-20T10"


def _cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VITALS_PROJECTS_DIR", str(tmp_path / "projects"))
    return load()


def _conn(cfg):
    conn = get_conn(cfg.db_path)
    init_db(conn)
    return conn


def _section_body(out: str, header_substr: str) -> list[str]:
    lines = out.splitlines()
    start = next(i for i, l in enumerate(lines) if header_substr in l)
    body = []
    for line in lines[start + 1 :]:
        if line == "":
            break
        body.append(line)
    return body


def test_status_renders_counts(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    conn.execute("INSERT INTO sessions(session_id, cc_version) VALUES ('s1', '2.1.226')")
    for i in range(3):
        conn.execute(
            "INSERT INTO api_requests(session_id, request_id, ts, model, duration_ms, "
            "output_tokens, context_bucket, cc_version, source) "
            "VALUES ('s1', ?, ?, 'claude-sonnet-5', 1000, 50, 'lt30k', '2.1.226', 'otel')",
            (f"req{i}", utcnow_iso()),
        )
    conn.execute(
        "INSERT INTO alerts(ts, severity, attribution, title, evidence_json) "
        "VALUES (?, 'WARN', 'E', 'Latency drift', '{}')",
        (utcnow_iso(),),
    )
    conn.commit()
    out = render_status(conn, 24)
    assert "claude-sonnet-5" in out
    assert "3" in out
    assert "WARN" in out
    assert "Latency drift" in out


def test_status_on_empty_database_is_still_useful(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    out = render_status(_conn(cfg), 24)
    assert "model-vitals" in out
    assert "no requests" in out.lower() or "0" in out


def test_status_reports_receiver_state(tmp_path, monkeypatch):
    from vitals.db import kv_set

    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    kv_set(conn, "receiver_state", json.dumps({"state": "down", "detail": "port 4318 in use"}))
    out = render_status(conn, 24)
    assert "DOWN" in out.upper() and "4318" in out


def test_status_flags_insufficient_data_strata(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    conn.execute(
        "INSERT INTO signal_windows(window_start, signal, model, context_bucket, value, n, "
        "cc_version) VALUES (?, 'api_latency_p95', 'claude-sonnet-5', 'lt30k', 7.0, 5, '2.1.226')",
        (f"{PAST}:00:00+00:00",),
    )
    conn.commit()
    out = render_status(conn, 24 * 30)
    assert "signal windows" in out.lower()


def test_status_flags_a_permanently_censored_rate_signal(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    conn.execute(
        "INSERT INTO detector_state(signal, model, context_bucket, cc_version, mu0, sigma0,"
        " windows_evaluated, last_window) VALUES (?,?,?,?,?,?,0,?)",
        (
            "api_error_rate",
            "claude-sonnet-5",
            "lt30k",
            "2.1.230",
            0.01,
            0.05,
            f"{PAST}:00:00+00:00",
        ),
    )
    conn.execute(
        "INSERT INTO signal_windows(window_start, signal, model, context_bucket, value, n,"
        " cc_version) VALUES (?,?,?,?,?,?,?)",
        (f"{PAST}:00:00+00:00", "api_error_rate", "claude-sonnet-5", "lt30k", 0.0, 6, "2.1.230"),
    )
    conn.commit()

    out = render_status(conn, 24 * 30)

    assert "censored" in out.lower()
    body = _section_body(out, "censored signals")
    assert any("api_error_rate" in l for l in body)


def test_status_does_not_flag_a_stratum_that_has_actually_evaluated_windows(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    conn.execute(
        "INSERT INTO detector_state(signal, model, context_bucket, cc_version, mu0, sigma0,"
        " windows_evaluated, last_window) VALUES (?,?,?,?,?,?,5,?)",
        (
            "api_latency_p95",
            "claude-sonnet-5",
            "gt180k",
            "2.1.230",
            7.6,
            0.4,
            f"{PAST}:00:00+00:00",
        ),
    )
    conn.commit()

    out = render_status(conn, 24 * 30)

    body = _section_body(out, "censored signals")
    assert not any("api_latency_p95" in l for l in body)
    assert any("(none)" in l for l in body)


def test_status_shows_the_oldest_frozen_stratum_and_its_age(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    old_start = days_ago_iso(30)
    conn.execute(
        "INSERT INTO anomalies(signal, model, context_bucket, cc_version, started_at, status)"
        " VALUES (?,?,?,?,?,'open')",
        ("api_latency_p95", "claude-sonnet-5", "gt180k", "2.1.230", old_start),
    )
    conn.execute(
        "INSERT INTO detector_state(signal, model, context_bucket, cc_version, frozen)"
        " VALUES (?,?,?,?,1)",
        ("api_latency_p95", "claude-sonnet-5", "gt180k", "2.1.230"),
    )
    conn.commit()

    out = render_status(conn, 24)

    assert "frozen" in out.lower()
    assert "api_latency_p95" in out
    assert "29." in out or "30." in out


def test_status_shows_no_frozen_strata_when_none_are_frozen(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)

    out = render_status(conn, 24)

    body = _section_body(out, "frozen strata")
    assert any("(none)" in l for l in body)


def test_ingest_once_pipeline(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    hooks = cfg.spool_dir / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "hooks-20260820.jsonl").write_text(
        json.dumps(
            {
                "hook_event_name": "PostToolUse",
                "session_id": "s1",
                "prompt_id": "p1",
                "tool_name": "Edit",
                "tool_use_id": "t1",
                "tool_input": {"file_path": "a.py"},
                "_recv_ts": 1_787_000_000.0,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    otel = cfg.spool_dir / "otel"
    otel.mkdir(parents=True)
    fixture = Path(__file__).parent / "fixtures" / "otlp_logs_synthetic.json"
    body = json.loads(fixture.read_text(encoding="utf-8"))
    (otel / "otel-20260820.jsonl").write_text(
        json.dumps({"path": "/v1/logs", "recv_ts": 1.0, "body": body}) + "\n", encoding="utf-8"
    )

    ingest_once(cfg)
    conn = get_conn(cfg.db_path)
    assert conn.execute("SELECT COUNT(*) FROM tool_results WHERE source='hook'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM api_requests").fetchone()[0] == 2


def test_two_workers_share_one_database_file(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    _conn(cfg)
    errors: list[Exception] = []

    def worker(job):
        try:
            for _ in range(5):
                conn = get_conn(cfg.db_path)
                job(conn, cfg)
                conn.close()
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(job_ingest,)),
        threading.Thread(target=worker, args=(job_aggregate,)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert errors == []


def test_daemon_survives_a_taken_port(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    _conn(cfg)
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    cfg.otlp_port = blocker.getsockname()[1]
    try:
        daemon = Daemon(cfg)
        daemon.start_receiver()
        conn = get_conn(cfg.db_path)
        row = conn.execute(
            "SELECT * FROM ingest_log WHERE kind='receiver' ORDER BY id DESC"
        ).fetchone()
        assert row is not None and row["err_count"] == 1
        assert "in use" in row["detail"].lower() or "10048" in row["detail"]
        assert "DOWN" in render_status(conn, 24).upper()
    finally:
        blocker.close()


def test_daemon_run_once_does_not_raise_on_empty_state(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    _conn(cfg)
    daemon = Daemon(cfg)
    daemon.run_once(skip_network=True)


def test_a_failing_job_is_logged_and_does_not_stop_the_others(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    daemon = Daemon(cfg)

    def boom(conn, cfg):
        raise RuntimeError("job exploded")

    daemon.safe_run("exploder", boom)
    row = conn.execute("SELECT * FROM ingest_log WHERE kind='job_error'").fetchone()
    assert row is not None and "exploded" in row["detail"]


def test_job_error_is_recorded_even_when_the_job_left_its_connection_unusable(
    tmp_path, monkeypatch
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    daemon = Daemon(cfg)

    def boom(job_conn, cfg):
        job_conn.close()
        raise RuntimeError("job exploded after losing its connection")

    daemon.safe_run("exploder", boom)

    row = conn.execute("SELECT * FROM ingest_log WHERE kind='job_error'").fetchone()
    assert row is not None, "the daemon must be able to record its own failure"
    assert "exploded" in row["detail"]


def test_archiver_gzips_old_spool_days(tmp_path, monkeypatch):
    import gzip

    cfg = _cfg(tmp_path, monkeypatch)
    _conn(cfg)
    hooks = cfg.spool_dir / "hooks"
    hooks.mkdir(parents=True)
    old = hooks / "hooks-20200101.jsonl"
    old.write_text('{"hook_event_name":"Stop","session_id":"s"}\n', encoding="utf-8")
    recent = hooks / f"hooks-{utcnow_iso()[:10].replace('-', '')}.jsonl"
    recent.write_text("{}\n", encoding="utf-8")

    from vitals.daemon import job_archive

    conn = get_conn(cfg.db_path)
    job_archive(conn, cfg)
    assert not old.exists()
    archived = hooks / "hooks-20200101.jsonl.gz"
    assert archived.exists()
    assert "Stop" in gzip.decompress(archived.read_bytes()).decode()
    assert recent.exists()


def test_cli_main_returns_nonzero_without_a_subcommand():
    from vitals.cli import main

    assert main([]) == 1


def test_python_dash_m_vitals_works(tmp_path, monkeypatch):
    import subprocess
    import sys

    env = dict(
        __import__("os").environ,
        VITALS_DATA_DIR=str(tmp_path),
        VITALS_PROJECTS_DIR=str(tmp_path / "projects"),
    )
    proc = subprocess.run(
        [sys.executable, "-m", "vitals", "status"],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "model-vitals" in proc.stdout


def test_cli_status_subcommand_runs(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, monkeypatch)
    _conn(cfg)
    from vitals.cli import main

    assert main(["status"]) == 0
    assert "model-vitals" in capsys.readouterr().out


def test_days_ago_helper_is_sane():
    assert days_ago_iso(1) < utcnow_iso()


def test_status_reports_how_long_since_the_last_hook_fed_row(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    conn.execute("INSERT INTO sessions(session_id) VALUES ('s-hook')")
    conn.execute(
        "INSERT INTO tool_results(session_id, ts, tool_name, success, source)"
        " VALUES ('s-hook', ?, 'Edit', 1, 'hook')",
        (days_ago_iso(0.25),),
    )
    conn.commit()

    out = render_status(conn, 24)

    assert "hook collection:" in out
    line = next(l for l in out.splitlines() if l.startswith("hook collection:"))
    assert "6.0h ago" in line
    assert days_ago_iso(0.25)[:13] in line


def test_status_says_plainly_when_no_hook_row_has_ever_arrived(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    conn.execute("INSERT INTO sessions(session_id) VALUES ('s-otel')")
    conn.execute(
        "INSERT INTO tool_results(session_id, ts, tool_name, success, source)"
        " VALUES ('s-otel', ?, 'Edit', 1, 'otel')",
        (utcnow_iso(),),
    )
    conn.commit()

    out = render_status(conn, 24)

    line = next(l for l in out.splitlines() if l.startswith("hook collection:"))
    assert "no hook-fed record" in line
    assert "install-hooks" in line


def test_status_hook_line_also_counts_compactions_written_by_the_hook(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    conn.execute("INSERT INTO sessions(session_id) VALUES ('s-hook')")
    conn.execute(
        "INSERT INTO compactions(session_id, ts, source, trigger)"
        " VALUES ('s-hook', ?, 'hook', 'auto')",
        (days_ago_iso(0.5),),
    )
    conn.commit()

    line = next(l for l in render_status(conn, 24).splitlines() if l.startswith("hook collection:"))
    assert "12.0h ago" in line


def test_status_hook_line_flags_a_long_silence(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    conn.execute("INSERT INTO sessions(session_id) VALUES ('s-hook')")
    conn.execute(
        "INSERT INTO tool_results(session_id, ts, tool_name, success, source)"
        " VALUES ('s-hook', ?, 'Edit', 1, 'hook')",
        (days_ago_iso(9),),
    )
    conn.commit()

    line = next(l for l in render_status(conn, 24).splitlines() if l.startswith("hook collection:"))
    assert "216.0h ago" in line
    assert "silent" in line.lower()


def _seed_alert(cfg):
    conn = get_conn(cfg.db_path)
    init_db(conn)
    cur = conn.execute(
        "INSERT INTO anomalies(signal, model, context_bucket, cc_version, started_at, direction,"
        " status) VALUES ('api_latency_p95', 'm', 'gt180k', '2.1.1', ?, 'up', 'open')",
        (utcnow_iso(),),
    )
    alert = conn.execute(
        "INSERT INTO alerts(ts, severity, attribution, title, evidence_json, anomaly_ids)"
        " VALUES (?, 'WARN', 'C', 't', '{}', ?)",
        (utcnow_iso(), json.dumps([cur.lastrowid])),
    )
    conn.commit()
    conn.close()
    return alert.lastrowid


def test_label_command_records_a_label(tmp_path, monkeypatch, capsys):
    from vitals.cli import main

    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VITALS_PROJECTS_DIR", str(tmp_path / "projects"))
    alert_id = _seed_alert(load())

    assert main(["label", str(alert_id), "false-alarm"]) == 0
    assert main(["label", "999", "real"]) == 1

    conn = get_conn(load().db_path)
    rows = conn.execute("SELECT alert_id, label, source FROM alert_labels").fetchall()
    assert [tuple(r) for r in rows] == [(alert_id, "false_alarm", "cli")]


def test_resolve_also_records_a_label(tmp_path, monkeypatch):
    from vitals.cli import main

    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VITALS_PROJECTS_DIR", str(tmp_path / "projects"))
    alert_id = _seed_alert(load())

    assert main(["resolve", str(alert_id), "--as", "confirmed"]) == 0

    conn = get_conn(load().db_path)
    rows = conn.execute("SELECT label, source FROM alert_labels").fetchall()
    assert [tuple(r) for r in rows] == [("real", "cli")]


def test_status_reports_label_counts_and_the_false_alarm_rate(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VITALS_PROJECTS_DIR", str(tmp_path / "projects"))
    from vitals.alert.labels import record_label

    cfg = load()
    a1, a2 = _seed_alert(cfg), _seed_alert(cfg)
    conn = get_conn(cfg.db_path)
    record_label(conn, a1, "real", "toast")
    record_label(conn, a2, "false_alarm", "toast")

    out = render_status(conn)

    assert "labels (30d)" in out
    assert "WARN: 1 real / 1 false alarm / 0 unsure" in out
    assert "false-alarm rate 50%" in out

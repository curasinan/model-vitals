from __future__ import annotations

import time
from datetime import timedelta
from pathlib import Path

from vitals import failopen
from vitals.config import CanaryCfg, Config, DetectCfg
from vitals.db import get_conn, init_db, log_ingest
from vitals.timeutil import parse_iso, utcnow_iso
from vitals.watch import deadman


def _cfg(tmp_path: Path) -> Config:
    return Config(
        data_dir=tmp_path,
        db_path=tmp_path / "vitals.db",
        spool_dir=tmp_path / "spool",
        reports_dir=tmp_path / "reports",
        projects_dir=tmp_path / "projects",
        canary=CanaryCfg(enabled=False),
        detect=DetectCfg(),
        channels={},
    )


def _conn(tmp_path: Path):
    conn = get_conn(tmp_path / "vitals.db")
    init_db(conn)
    return conn


def _ago(minutes: float) -> str:
    return (parse_iso(utcnow_iso()) - timedelta(minutes=minutes)).isoformat(timespec="seconds")


def _touch_transcript(cfg: Config, minutes_ago: float = 0.0) -> Path:
    proj = cfg.projects_dir / "proj"
    proj.mkdir(parents=True, exist_ok=True)
    path = proj / "session.jsonl"
    path.write_text("{}\n", encoding="utf-8")
    when = time.time() - minutes_ago * 60
    import os

    os.utime(path, (when, when))
    return path


def test_a_swallowed_failure_leaves_a_mark(tmp_path):
    assert failopen.totals(tmp_path) == {}

    failopen.record("hook.spool", tmp_path)
    failopen.record("hook.spool", tmp_path)
    failopen.record("db.log_ingest", tmp_path)

    assert failopen.totals(tmp_path) == {"hook.spool": 2, "db.log_ingest": 1}


def test_recording_never_raises_even_when_the_data_dir_is_unusable(tmp_path):
    blocked = tmp_path / "a-file-not-a-directory"
    blocked.write_text("x", encoding="utf-8")

    failopen.record("hook.spool", blocked / "nested")
    failopen.record("hook.spool", None)

    assert failopen.totals(blocked / "nested") == {}


def test_counts_survive_a_separate_process(tmp_path):
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: failopen.record("otlp.record", tmp_path), range(50)))

    assert failopen.totals(tmp_path)["otlp.record"] == 50


def test_the_hooks_inlined_counter_matches_failopens_format(tmp_path, monkeypatch):
    from vitals import hook

    monkeypatch.setattr(hook, "_data_dir", lambda: str(tmp_path))
    monkeypatch.setattr(hook, "append_line", lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
    monkeypatch.setattr(hook.sys, "stdin", __import__("io").StringIO('{"hook_event_name":"Stop"}'))

    try:
        hook.main()
    except SystemExit:
        pass

    assert failopen.totals(tmp_path) == {"hook.spool": 1}, (
        "the hook's inlined counter must be readable by failopen.totals -- if this "
        "fails the two formats have drifted and the production counter is dead"
    )


def test_silence_while_claude_is_working_is_an_alert(tmp_path):
    cfg = _cfg(tmp_path)
    conn = _conn(tmp_path)
    log_ingest(conn, "hook_spool", 1, 0)
    conn.execute("UPDATE ingest_log SET ts = ?", (_ago(90),))
    conn.commit()
    _touch_transcript(cfg, minutes_ago=1)

    result = deadman.check_no_data(conn, cfg, utcnow_iso())

    assert result is not None, "90 minutes of silence during active work is not health"
    draft, attribution = result
    assert draft.severity == "WARN"
    assert attribution.cls == "E"
    assert attribution.evidence["reason"] == "no_data"


def test_silence_while_nothing_is_happening_is_not_an_alert(tmp_path):
    cfg = _cfg(tmp_path)
    conn = _conn(tmp_path)
    log_ingest(conn, "hook_spool", 1, 0)
    conn.execute("UPDATE ingest_log SET ts = ?", (_ago(90),))
    conn.commit()
    _touch_transcript(cfg, minutes_ago=240)

    assert deadman.check_no_data(conn, cfg, utcnow_iso()) is None


def test_fresh_data_is_not_an_alert(tmp_path):
    cfg = _cfg(tmp_path)
    conn = _conn(tmp_path)
    log_ingest(conn, "hook_spool", 1, 0)
    _touch_transcript(cfg, minutes_ago=1)

    assert deadman.check_no_data(conn, cfg, utcnow_iso()) is None


def test_the_window_is_configurable(tmp_path):
    cfg = _cfg(tmp_path)
    conn = _conn(tmp_path)
    log_ingest(conn, "hook_spool", 1, 0)
    conn.execute("UPDATE ingest_log SET ts = ?", (_ago(45),))
    conn.commit()
    _touch_transcript(cfg, minutes_ago=1)

    assert deadman.check_no_data(conn, cfg, utcnow_iso()) is not None

    cfg.detect.no_data_window_minutes = 60
    assert deadman.check_no_data(conn, cfg, utcnow_iso()) is None


def test_the_dedup_key_is_stable_so_the_alert_does_not_renotify_every_tick(tmp_path):
    cfg = _cfg(tmp_path)
    conn = _conn(tmp_path)
    log_ingest(conn, "hook_spool", 1, 0)
    conn.execute("UPDATE ingest_log SET ts = ?", (_ago(90),))
    conn.commit()
    _touch_transcript(cfg, minutes_ago=1)

    first, _ = deadman.check_no_data(conn, cfg, utcnow_iso())
    second, _ = deadman.check_no_data(conn, cfg, utcnow_iso())

    assert first.dedup_key == second.dedup_key
    assert "no_data" in first.dedup_key


def test_swallowed_failures_are_reported_alongside_the_silence(tmp_path):
    cfg = _cfg(tmp_path)
    conn = _conn(tmp_path)
    log_ingest(conn, "hook_spool", 1, 0)
    conn.execute("UPDATE ingest_log SET ts = ?", (_ago(90),))
    conn.commit()
    _touch_transcript(cfg, minutes_ago=1)
    failopen.record("hook.spool", tmp_path)
    failopen.record("hook.spool", tmp_path)

    _, attribution = deadman.check_no_data(conn, cfg, utcnow_iso())

    assert attribution.evidence["failopen_totals"]["hook.spool"] == 2

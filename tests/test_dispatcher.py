from __future__ import annotations

import http.client
import json
from datetime import timedelta
from pathlib import Path

import vitals.alert.channels as channels_mod
import vitals.alert.dispatcher as dispatcher_mod
from vitals.alert.channels import AlertPayload
from vitals.alert.dispatcher import dispatch
from vitals.alert.rules import AlertDraft
from vitals.config import load
from vitals.db import get_conn, init_db
from vitals.detect.attribution import Attribution
from vitals.timeutil import hour_add, parse_iso

START = "2026-08-01T00:00:00+00:00"


def _minutes_after(iso: str, minutes: float) -> str:
    return (parse_iso(iso) + timedelta(minutes=minutes)).isoformat(timespec="seconds")


def _cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VITALS_PROJECTS_DIR", str(tmp_path / "projects"))
    return load()


def _conn(cfg):
    conn = get_conn(cfg.db_path)
    init_db(conn)
    return conn


def _draft(**overrides) -> AlertDraft:
    fields = dict(
        severity="WARN",
        title="Multiple families degrading together: errors, latency",
        anomaly_ids=[1, 2],
        families=["errors", "latency"],
        suppressed_by_incident=None,
        dedup_key="api_error_rate::claude-sonnet-5::gt180k|api_latency_p95::claude-sonnet-5::gt180k",
        first_seen=START,
    )
    fields.update(overrides)
    return AlertDraft(**fields)


def _attribution(**evidence_overrides) -> Attribution:
    evidence = {
        "cls": "B",
        "matched_rule": 2,
        "matched_rule_name": "harness_change",
        "generated_at": START,
        "strata": {
            "signals": ["api_error_rate", "api_latency_p95"],
            "models": ["claude-sonnet-5"],
            "context_buckets": ["gt180k"],
            "cc_versions": ["2.1.237"],
        },
        "rules": [],
    }
    evidence.update(evidence_overrides)
    return Attribution(cls=evidence.get("cls", "B"), evidence=evidence)


class _FakeChannel:
    def __init__(self, name, fail: bool = False):
        self.name = name
        self.fail = fail
        self.payloads: list[AlertPayload] = []

    def send(self, payload: AlertPayload) -> None:
        self.payloads.append(payload)
        if self.fail:
            raise RuntimeError(f"{self.name} channel exploded")


def test_dispatch_writes_one_alerts_row_and_calls_every_channel(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    a, b = _FakeChannel("a"), _FakeChannel("b")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [a, b])

    alert_id = dispatch(conn, cfg, _draft(), _attribution(), now_iso=START)

    assert alert_id != 0
    rows = conn.execute("SELECT * FROM alerts").fetchall()
    assert len(rows) == 1
    assert rows[0]["severity"] == "WARN"
    assert rows[0]["attribution"] == "B"
    assert len(a.payloads) == 1
    assert len(b.payloads) == 1


def test_a_raising_channel_does_not_stop_the_next_and_row_written_once(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    boom = _FakeChannel("webhook", fail=True)
    toast = _FakeChannel("desktop", fail=False)
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [boom, toast])

    alert_id = dispatch(conn, cfg, _draft(), _attribution(), now_iso=START)

    assert alert_id != 0
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    assert len(boom.payloads) == 1
    assert len(toast.payloads) == 1

    failures = conn.execute(
        "SELECT * FROM ingest_log WHERE kind = 'alert_dispatch' AND err_count > 0"
    ).fetchall()
    assert len(failures) == 1
    assert "webhook" in failures[0]["detail"]
    assert "exploded" in failures[0]["detail"]


def test_dispatch_does_not_raise_when_every_channel_fails(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    monkeypatch.setattr(
        dispatcher_mod,
        "load_channels",
        lambda cfg: [_FakeChannel("a", fail=True), _FakeChannel("b", fail=True)],
    )
    alert_id = dispatch(conn, cfg, _draft(), _attribution(), now_iso=START)
    assert alert_id != 0
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1


def test_disabled_channel_is_never_constructed_or_called(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    cfg.channels = {
        "desktop": {"enabled": True},
        "telegram": {"enabled": False},
    }
    calls = {"telegram": 0}

    class SpyTelegram:
        name = "telegram"

        def __init__(self, **kwargs):
            calls["telegram"] += 1

        def send(self, payload):  # pragma: no cover
            raise AssertionError("disabled channel must never send")

    import vitals.alert.channels as channels_mod

    monkeypatch.setattr(channels_mod, "Telegram", SpyTelegram)
    notified = []
    monkeypatch.setattr(
        channels_mod,
        "DesktopToast",
        lambda **kwargs: type(
            "D", (), {"name": "desktop", "send": lambda self, p: notified.append(p)}
        )(),
    )

    dispatch(conn, cfg, _draft(), _attribution(), now_iso=START)

    assert calls["telegram"] == 0
    assert len(notified) == 1


def test_unchanged_condition_within_cooldown_is_suppressed(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    cfg.alert.dedup_cooldown_minutes = 60
    conn = _conn(cfg)
    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    first = dispatch(conn, cfg, _draft(), _attribution(), now_iso=START)
    later = _minutes_after(START, 5)
    second_id = dispatch(conn, cfg, _draft(), _attribution(), now_iso=later)

    assert first != 0
    assert second_id == 0
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    assert len(fake.payloads) == 1


def test_condition_renotifies_after_cooldown_expires(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    cfg.alert.dedup_cooldown_minutes = 30
    conn = _conn(cfg)
    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    dispatch(conn, cfg, _draft(), _attribution(), now_iso=START)
    much_later = hour_add(START, 2)
    second_id = dispatch(conn, cfg, _draft(), _attribution(), now_iso=much_later)

    assert second_id != 0
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 2
    assert len(fake.payloads) == 2


def test_severity_escalation_notifies_even_inside_cooldown(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    cfg.alert.dedup_cooldown_minutes = 120
    conn = _conn(cfg)
    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    warn_draft = _draft(severity="WARN")
    dispatch(conn, cfg, warn_draft, _attribution(), now_iso=START)

    soon = _minutes_after(START, 5)
    critical_draft = _draft(severity="CRITICAL")
    second_id = dispatch(conn, cfg, critical_draft, _attribution(), now_iso=soon)

    assert second_id != 0
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 2
    assert len(fake.payloads) == 2


def test_same_or_lower_severity_inside_cooldown_stays_suppressed(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    cfg.alert.dedup_cooldown_minutes = 120
    conn = _conn(cfg)
    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    dispatch(conn, cfg, _draft(severity="WARN"), _attribution(), now_iso=START)
    dispatch(conn, cfg, _draft(severity="CRITICAL"), _attribution(), now_iso=START)
    third_id = dispatch(conn, cfg, _draft(severity="CRITICAL"), _attribution(), now_iso=START)

    assert third_id == 0
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 2
    assert len(fake.payloads) == 2


def test_different_dedup_key_is_never_suppressed_by_an_unrelated_conditions_cooldown(
    tmp_path, monkeypatch
):
    cfg = _cfg(tmp_path, monkeypatch)
    cfg.alert.dedup_cooldown_minutes = 120
    conn = _conn(cfg)
    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    dispatch(conn, cfg, _draft(dedup_key="signal_a::m::b"), _attribution(), now_iso=START)
    other_id = dispatch(
        conn, cfg, _draft(dedup_key="signal_b::m::b"), _attribution(), now_iso=START
    )

    assert other_id != 0
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 2


def test_dedup_identity_is_dedup_key_alone_not_anomaly_ids(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    cfg.alert.dedup_cooldown_minutes = 120
    conn = _conn(cfg)
    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    key = "api_error_rate::claude-sonnet-5::gt180k"
    tick_1, tick_2, tick_3 = START, _minutes_after(START, 5), _minutes_after(START, 10)

    first_id = dispatch(
        conn,
        cfg,
        _draft(dedup_key=key, anomaly_ids=[1], severity="WARN"),
        _attribution(),
        now_iso=tick_1,
    )
    second_id = dispatch(
        conn,
        cfg,
        _draft(dedup_key=key, anomaly_ids=[1, 2], severity="WARN"),
        _attribution(),
        now_iso=tick_2,
    )
    third_id = dispatch(
        conn,
        cfg,
        _draft(dedup_key=key, anomaly_ids=[1, 2, 3], severity="WARN"),
        _attribution(),
        now_iso=tick_3,
    )

    assert first_id != 0
    assert second_id == 0
    assert third_id == 0
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    assert len(fake.payloads) == 1


def test_summary_text_carries_no_identifiers_from_evidence(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    poisoned = _attribution(
        leaked_session_id="sess-abc123",
        leaked_path="C:/Users/asus/project/secret_file.py",
    )

    dispatch(conn, cfg, _draft(), poisoned, now_iso=START)

    payload = fake.payloads[0]
    assert "sess-abc123" not in payload.summary_text
    assert "secret_file.py" not in payload.summary_text
    assert "sess-abc123" not in payload.title
    assert payload.severity == "WARN"
    assert payload.attribution == "B"
    assert "claude-sonnet-5" in payload.summary_text
    assert "gt180k" in payload.summary_text


def test_local_detail_path_is_written_locally_and_attached_to_payload(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    alert_id = dispatch(conn, cfg, _draft(), _attribution(), now_iso=START)

    payload = fake.payloads[0]
    assert payload.local_detail_path is not None
    detail_path = Path(payload.local_detail_path)
    assert detail_path.exists()
    assert str(cfg.reports_dir) in str(detail_path)

    detail = json.loads(detail_path.read_text(encoding="utf-8"))
    assert detail["anomaly_ids"] == [1, 2]
    assert detail["attribution"]["matched_rule_name"] == "harness_change"

    row = conn.execute(
        "SELECT detail_path, report_path FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    assert row["detail_path"] == str(detail_path)
    assert row["report_path"] is None


def test_evidence_json_is_persisted_in_full_on_the_alerts_row(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [])

    alert_id = dispatch(conn, cfg, _draft(), _attribution(), now_iso=START)
    row = conn.execute(
        "SELECT evidence_json, anomaly_ids FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    evidence = json.loads(row["evidence_json"])
    assert evidence["matched_rule_name"] == "harness_change"
    assert json.loads(row["anomaly_ids"]) == [1, 2]


def test_dispatch_with_no_channels_still_writes_the_alerts_row(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    cfg.channels = {}

    alert_id = dispatch(conn, cfg, _draft(), _attribution(), now_iso=START)
    assert alert_id != 0
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1


def test_local_detail_write_failure_does_not_abort_dispatch(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    def boom(cfg, alert_id, draft, attribution, now_iso):
        raise OSError("disk full")

    monkeypatch.setattr(dispatcher_mod, "_write_local_detail", boom)

    alert_id = dispatch(conn, cfg, _draft(), _attribution(), now_iso=START)

    assert alert_id != 0
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    row = conn.execute(
        "SELECT detail_path, report_path FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    assert row["detail_path"] is None
    assert row["report_path"] is None

    assert len(fake.payloads) == 1
    assert fake.payloads[0].local_detail_path is None

    second_id = dispatch(conn, cfg, _draft(), _attribution(), now_iso=_minutes_after(START, 5))
    assert second_id == 0
    assert len(fake.payloads) == 1

    failures = conn.execute(
        "SELECT * FROM ingest_log WHERE kind = 'alert_dispatch' AND detail LIKE 'local_detail_write:%'"
    ).fetchall()
    assert len(failures) == 1
    assert "disk full" in failures[0]["detail"]


def test_critical_alert_gets_a_redacted_report_and_report_path_stamped(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    alert_id = dispatch(
        conn, cfg, _draft(severity="CRITICAL"), _attribution(cls="C"), now_iso=START
    )

    row = conn.execute(
        "SELECT report_path, detail_path FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    assert row["report_path"] is not None
    report_path = Path(row["report_path"])
    assert report_path.exists()
    assert report_path.suffix == ".md"
    assert "Attribution: C" in report_path.read_text(encoding="utf-8")
    assert row["report_path"] != row["detail_path"]


def test_warn_and_info_alerts_never_get_a_report_path(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [])

    alert_id = dispatch(conn, cfg, _draft(severity="WARN"), _attribution(), now_iso=START)

    row = conn.execute("SELECT report_path FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    assert row["report_path"] is None


def test_report_build_failure_does_not_abort_dispatch(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    def boom(conn, cfg, alert_id):
        raise OSError("disk full")

    monkeypatch.setattr(dispatcher_mod, "build_report", boom)

    alert_id = dispatch(conn, cfg, _draft(severity="CRITICAL"), _attribution(), now_iso=START)

    assert alert_id != 0
    row = conn.execute("SELECT report_path FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    assert row["report_path"] is None
    assert len(fake.payloads) == 1

    failures = conn.execute(
        "SELECT * FROM ingest_log WHERE kind = 'alert_dispatch' AND detail LIKE 'report_build:%'"
    ).fetchall()
    assert len(failures) == 1
    assert "disk full" in failures[0]["detail"]


def test_ingest_log_never_persists_a_secret_that_leaks_through_invalidurl(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    token = "1234567:AAF-REALTOKEN-xyz\n"
    monkeypatch.setenv("VITALS_TELEGRAM_TOKEN", token)
    monkeypatch.setenv("VITALS_TELEGRAM_CHAT_ID", "chat-1")
    cfg.channels = {"telegram": {"enabled": True}}

    def raise_invalid_url(request):
        path = f"/bot{token}/sendMessage"
        raise http.client.InvalidURL(
            f"URL can't contain control characters. {path!r} (found at least {chr(10)!r})"
        )

    monkeypatch.setattr(channels_mod, "_urlopen", raise_invalid_url)

    alert_id = dispatch(conn, cfg, _draft(), _attribution(), now_iso=START)

    assert alert_id != 0
    rows = conn.execute(
        "SELECT detail FROM ingest_log WHERE kind = 'alert_dispatch' AND err_count > 0"
    ).fetchall()
    assert len(rows) == 1
    assert token not in rows[0]["detail"]
    assert "REALTOKEN" not in rows[0]["detail"]
    assert "bot***" in rows[0]["detail"]


def test_alert_test_cli_dispatches_synthetic_warn_through_every_enabled_channel(
    tmp_path, monkeypatch
):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    conn.close()

    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    from vitals.cli import main

    rc = main(["alert-test"])
    assert rc == 0

    assert len(fake.payloads) == 1
    payload = fake.payloads[0]
    assert payload.severity == "WARN"
    assert payload.attribution == "E"

    check_conn = get_conn(cfg.db_path)
    rows = check_conn.execute("SELECT severity, attribution FROM alerts").fetchall()
    assert len(rows) == 1
    assert rows[0]["severity"] == "WARN"
    assert rows[0]["attribution"] == "E"


def test_alert_test_cli_is_never_suppressed_by_a_prior_cooldown(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    _conn(cfg).close()

    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    from vitals.cli import main

    assert main(["alert-test"]) == 0
    assert main(["alert-test"]) == 0
    assert len(fake.payloads) == 2


def test_dispatch_marks_the_info_dedup_slot_only_after_it_actually_delivers(tmp_path, monkeypatch):
    from vitals.alert.rules import _info_kv_key
    from vitals.db import kv_get

    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    draft = _draft(
        severity="INFO",
        title="api_latency_p95 alarm (latency)",
        families=["latency"],
        dedup_key="api_latency_p95::claude-sonnet-5::gt180k",
        info_dedup_signals=["api_latency_p95"],
    )
    assert kv_get(conn, _info_kv_key("api_latency_p95")) is None

    alert_id = dispatch(conn, cfg, draft, _attribution(), now_iso=START)

    assert alert_id != 0
    assert kv_get(conn, _info_kv_key("api_latency_p95")) == START


def test_a_dispatch_suppressed_by_cooldown_does_not_consume_the_info_dedup_slot(
    tmp_path, monkeypatch
):
    from vitals.alert.rules import _info_kv_key
    from vitals.db import kv_get, kv_set

    cfg = _cfg(tmp_path, monkeypatch)
    cfg.alert.dedup_cooldown_minutes = 60
    conn = _conn(cfg)
    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    draft = _draft(
        severity="INFO",
        title="api_error_rate alarm (errors)",
        families=["errors"],
        dedup_key="api_error_rate::claude-sonnet-5::gt180k",
        info_dedup_signals=["api_error_rate"],
    )
    dispatch(conn, cfg, _draft(dedup_key=draft.dedup_key), _attribution(), now_iso=START)
    kv_set(conn, _info_kv_key("api_error_rate"), "")
    conn.execute("DELETE FROM vitals_kv WHERE key = ?", (_info_kv_key("api_error_rate"),))
    conn.commit()

    suppressed = dispatch(conn, cfg, draft, _attribution(), now_iso=_minutes_after(START, 5))

    assert suppressed == 0
    assert kv_get(conn, _info_kv_key("api_error_rate")) is None


def test_non_info_dispatch_marks_no_info_slot(tmp_path, monkeypatch):
    from vitals.db import kv_get

    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [])

    dispatch(conn, cfg, _draft(), _attribution(), now_iso=START)

    rows = conn.execute(
        "SELECT COUNT(*) FROM vitals_kv WHERE key LIKE 'alert_info_last:%'"
    ).fetchone()[0]
    assert rows == 0
    assert kv_get(conn, "alert_info_last:api_latency_p95") is None


def test_dispatch_marks_detector_alerts_as_labelable(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, monkeypatch)
    conn = _conn(cfg)
    fake = _FakeChannel("desktop")
    monkeypatch.setattr(dispatcher_mod, "load_channels", lambda cfg: [fake])

    alert_id = dispatch(conn, cfg, _draft(), _attribution(), now_iso=START)
    collection = dispatch(
        conn,
        cfg,
        _draft(anomaly_ids=[], dedup_key="no_data::collection"),
        _attribution(),
        now_iso=START,
    )

    first, second = fake.payloads
    assert (first.alert_id, first.labelable) == (alert_id, True)
    assert (second.alert_id, second.labelable) == (collection, False)


def test_the_desktop_channel_gets_links_only_when_the_handler_is_registered(tmp_path, monkeypatch):
    from vitals.alert import protocol

    cfg = _cfg(tmp_path, monkeypatch)
    cfg.channels = {"desktop": {"enabled": True}}

    monkeypatch.setattr(protocol, "is_registered", lambda: False)
    (unregistered,) = channels_mod.load_channels(cfg)
    monkeypatch.setattr(protocol, "is_registered", lambda: True)
    (registered,) = channels_mod.load_channels(cfg)

    assert unregistered._links is None
    links = registered._links(9)
    assert protocol.parse_uri(links.open, protocol._key(cfg.data_dir, create=False)).alert_id == 9

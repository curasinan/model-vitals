import json
import secrets
import stat
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from vitals import failopen
from vitals.alert import protocol
from vitals.alert.labels import LABELS
from vitals.cli import main
from vitals.config import load
from vitals.db import get_conn, init_db

START = "2026-08-01T00:00:00+00:00"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VITALS_PROJECTS_DIR", str(tmp_path / "projects"))
    return load()


@pytest.fixture
def conn(cfg):
    c = get_conn(cfg.db_path)
    init_db(c)
    yield c
    c.close()


def _key(cfg):
    return protocol._key(cfg.data_dir, create=True)


def _alert(conn):
    cur = conn.execute(
        "INSERT INTO anomalies(signal, model, context_bucket, cc_version, started_at, direction,"
        " status) VALUES ('api_latency_p95', 'm', 'gt180k', '2.1.1', ?, 'up', 'open')",
        (START,),
    )
    cur = conn.execute(
        "INSERT INTO alerts(ts, severity, attribution, title, evidence_json, anomaly_ids)"
        " VALUES (?, 'WARN', 'C', 't', '{}', ?)",
        (START, json.dumps([cur.lastrowid])),
    )
    conn.commit()
    return cur.lastrowid


def _with_query(uri, **changes):
    parts = urlsplit(uri)
    fields = {name: values[0] for name, values in parse_qs(parts.query).items()}
    fields.update(changes)
    query = "&".join(f"{name}={value}" for name, value in fields.items())
    return f"{parts.scheme}://{parts.netloc}?{query}"


def test_signed_links_round_trip(cfg):
    key = _key(cfg)
    for label in LABELS:
        uri = protocol.label_uri(cfg.data_dir, 42, label)
        assert uri.startswith("model-vitals://label?")
        assert protocol.parse_uri(uri, key) == protocol.Action("label", alert_id=42, label=label)
    assert protocol.parse_uri(protocol.open_uri(cfg.data_dir, 7), key) == protocol.Action(
        "open", alert_id=7
    )
    nonce = secrets.token_hex(16)
    assert protocol.parse_uri(protocol.ping_uri(cfg.data_dir, nonce), key) == protocol.Action(
        "ping", nonce=nonce
    )


def test_a_trailing_slash_after_the_action_is_accepted(cfg):
    uri = protocol.label_uri(cfg.data_dir, 3, "real").replace("://label?", "://label/?")
    assert protocol.parse_uri(uri, _key(cfg)).label == "real"


@pytest.mark.parametrize(
    "tamper",
    [
        lambda uri: _with_query(uri, label="false_alarm"),
        lambda uri: _with_query(uri, alert="8"),
        lambda uri: _with_query(uri, sig="0" * 32),
        lambda uri: _with_query(uri, sig=""),
        lambda uri: _with_query(uri, alert="\u00b2"),
        lambda uri: uri + "&label=unsure",
        lambda uri: uri + "#x",
        lambda uri: uri.replace("model-vitals://", "https://"),
        lambda uri: uri.replace("://label?", "://delete?"),
        lambda uri: uri.replace("://label?", "://label/x?"),
        lambda uri: uri + "&pad=" + "a" * 600,
        lambda uri: "",
    ],
)
def test_a_tampered_or_foreign_link_is_rejected(cfg, tamper):
    uri = protocol.label_uri(cfg.data_dir, 7, "real")
    with pytest.raises(protocol.UriError):
        protocol.parse_uri(tamper(uri), _key(cfg))


def test_a_link_signed_by_another_install_is_rejected(cfg, tmp_path):
    other = tmp_path / "other"
    uri = protocol.label_uri(other, 7, "real")
    with pytest.raises(protocol.UriError):
        protocol.parse_uri(uri, _key(cfg))


def test_a_label_link_labels_the_alert(cfg, conn):
    alert_id = _alert(conn)

    assert protocol.handle_uri(cfg, protocol.label_uri(cfg.data_dir, alert_id, "real")) == 0

    row = conn.execute("SELECT resolution FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    assert row[0] == "confirmed"
    labels = conn.execute("SELECT label, source FROM alert_labels").fetchall()
    assert [tuple(r) for r in labels] == [("real", "toast")]


def test_an_open_link_opens_only_that_alerts_detail_file(cfg):
    opened = []
    detail = Path(cfg.reports_dir) / "alert-7.json"
    detail.parent.mkdir(parents=True, exist_ok=True)
    detail.write_text("{}", encoding="utf-8")

    assert protocol.handle_uri(cfg, protocol.open_uri(cfg.data_dir, 7), opened.append) == 0
    assert protocol.handle_uri(cfg, protocol.open_uri(cfg.data_dir, 8), opened.append) == 1
    assert opened == [detail]


def test_bad_links_never_raise_and_leave_a_mark(cfg, conn):
    assert protocol.handle_uri(cfg, "garbage") == 1
    assert protocol.handle_uri(cfg, protocol.label_uri(cfg.data_dir, 999, "real")) == 1

    assert failopen.totals(cfg.data_dir).get("toast.uri", 0) == 2
    assert conn.execute("SELECT COUNT(*) FROM alert_labels").fetchone()[0] == 0


def test_the_handler_never_creates_a_key(cfg):
    uri = protocol.label_uri(Path(cfg.data_dir) / "elsewhere", 1, "real")

    assert protocol.handle_uri(cfg, uri) == 1
    assert not (Path(cfg.data_dir) / "uri.key").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_the_key_file_is_private(cfg):
    _key(cfg)
    mode = (Path(cfg.data_dir) / "uri.key").stat().st_mode
    assert mode & (stat.S_IRWXG | stat.S_IRWXO) == 0


def test_toast_links_cover_the_body_and_three_buttons(cfg):
    links = protocol.toast_links(cfg.data_dir, 5)
    key = _key(cfg)

    assert protocol.parse_uri(links.open, key) == protocol.Action("open", alert_id=5)
    assert [caption for caption, _ in links.buttons] == ["Real", "False alarm", "Not sure"]
    assert [protocol.parse_uri(uri, key).label for _, uri in links.buttons] == list(LABELS)


def test_the_smoke_check_passes_when_the_handler_answers(cfg):
    assert protocol.smoke_check(cfg, launch=lambda uri: protocol.handle_uri(cfg, uri))
    assert not (Path(cfg.data_dir) / "uri-ping").exists()


def test_the_smoke_check_fails_when_nothing_answers(cfg):
    assert not protocol.smoke_check(cfg, launch=lambda uri: None, timeout_s=0.3)


def test_the_registered_command_quotes_the_interpreter_and_the_link():
    pythonw = Path("C:/Users/a b/.model-vitals/venv/Scripts/pythonw.exe")
    assert protocol.handler_command(pythonw) == f'"{pythonw}" -m vitals handle-uri -- "%1"'


def test_the_cli_handles_a_link_passed_after_a_double_dash(cfg, conn):
    alert_id = _alert(conn)
    uri = protocol.label_uri(cfg.data_dir, alert_id, "unsure")

    assert main(["handle-uri", "--", uri]) == 0
    assert main(["handle-uri", "--", "model-vitals://label?alert=1"]) == 1

    labels = conn.execute("SELECT alert_id, label FROM alert_labels").fetchall()
    assert [tuple(r) for r in labels] == [(alert_id, "unsure")]


def _delete_registration(winreg, root):
    for suffix in (r"\shell\open\command", r"\shell\open", r"\shell", ""):
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, root + suffix)
        except FileNotFoundError:
            pass


@pytest.mark.skipif(sys.platform != "win32", reason="registry and shell launch are Windows-only")
def test_a_registered_handler_answers_a_link_launched_through_the_shell(cfg, monkeypatch):
    import winreg

    monkeypatch.setenv("VITALS_URI_SCHEME", f"model-vitals-test-{secrets.token_hex(4)}")
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.exists():
        pythonw = Path(sys.executable)
    root = protocol._reg_path()
    try:
        assert not protocol.is_registered()
        protocol.register(pythonw)
        assert protocol.is_registered()
        assert protocol.smoke_check(cfg, timeout_s=60.0)
    finally:
        _delete_registration(winreg, root)
    assert not protocol.is_registered()

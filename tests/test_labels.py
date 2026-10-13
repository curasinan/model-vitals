import json
import threading

import pytest

from vitals.alert import labels
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


def _alert(conn, severity="WARN", ts=START):
    cur = conn.execute(
        "INSERT INTO anomalies(signal, model, context_bucket, cc_version, started_at, direction,"
        " status) VALUES ('api_latency_p95', 'm', 'gt180k', '2.1.1', ?, 'up', 'open')",
        (ts,),
    )
    anomaly_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO alerts(ts, severity, attribution, title, evidence_json, anomaly_ids)"
        " VALUES (?, ?, 'C', 't', '{}', ?)",
        (ts, severity, json.dumps([anomaly_id])),
    )
    conn.commit()
    return cur.lastrowid, anomaly_id


def _labels(conn, alert_id):
    return [
        (r["label"], r["source"])
        for r in conn.execute(
            "SELECT label, source FROM alert_labels WHERE alert_id = ? ORDER BY id", (alert_id,)
        )
    ]


def test_action_arguments_round_trip():
    for label in labels.LABELS:
        assert labels.parse_action(labels.encode_action(42, label)) == (42, label)


@pytest.mark.parametrize(
    "raw", ["", "garbage", "alert=x&label=real", "alert=3&label=maybe", "label=real", None]
)
def test_parse_rejects_anything_that_is_not_a_label_action(raw):
    assert labels.parse_action(raw) is None


def test_real_confirms_the_alert_and_records_the_label(cfg, conn):
    alert_id, anomaly_id = _alert(conn)

    labels.apply_label(conn, alert_id, "real", "toast", cfg.detect, now_iso=START)

    assert conn.execute("SELECT resolution FROM alerts WHERE id=?", (alert_id,)).fetchone()[0] == (
        "confirmed"
    )
    assert _labels(conn, alert_id) == [("real", "toast")]


def test_false_alarm_folds_the_alert_back(cfg, conn):
    alert_id, anomaly_id = _alert(conn)

    labels.apply_label(conn, alert_id, "false_alarm", "toast", cfg.detect, now_iso=START)

    assert conn.execute("SELECT resolution FROM alerts WHERE id=?", (alert_id,)).fetchone()[0] == (
        "false_positive"
    )
    status = conn.execute("SELECT status FROM anomalies WHERE id=?", (anomaly_id,)).fetchone()[0]
    assert status == "false_positive"


def test_unsure_records_the_label_and_leaves_the_alert_open(cfg, conn):
    alert_id, anomaly_id = _alert(conn)

    labels.apply_label(conn, alert_id, "unsure", "toast", cfg.detect, now_iso=START)

    assert (
        conn.execute("SELECT resolution FROM alerts WHERE id=?", (alert_id,)).fetchone()[0] is None
    )
    assert conn.execute("SELECT status FROM anomalies WHERE id=?", (anomaly_id,)).fetchone()[0] == (
        "open"
    )
    assert _labels(conn, alert_id) == [("unsure", "toast")]


def test_an_unknown_alert_is_not_labelled(cfg, conn):
    with pytest.raises(LookupError):
        labels.apply_label(conn, 999, "real", "cli", cfg.detect, now_iso=START)
    assert conn.execute("SELECT COUNT(*) FROM alert_labels").fetchone()[0] == 0


def test_a_toast_click_is_handled_on_its_own_thread_and_connection(cfg, conn):
    alert_id, _ = _alert(conn)

    worker = threading.Thread(
        target=labels.handle_toast_action, args=(cfg, labels.encode_action(alert_id, "unsure"))
    )
    worker.start()
    worker.join(timeout=30)

    assert _labels(conn, alert_id) == [("unsure", "toast")]


def test_a_bad_toast_click_never_raises_and_leaves_a_mark(cfg, conn):
    labels.handle_toast_action(cfg, "garbage")
    labels.handle_toast_action(cfg, labels.encode_action(999, "real"))

    counts = labels.failopen_totals(cfg)
    assert counts.get("toast.label", 0) == 2


def test_summary_uses_the_latest_label_per_alert(cfg, conn):
    a1, _ = _alert(conn, severity="WARN")
    a2, _ = _alert(conn, severity="WARN")
    a3, _ = _alert(conn, severity="INFO")
    labels.record_label(conn, a1, "unsure", "toast", now_iso=START)
    labels.record_label(conn, a1, "false_alarm", "cli", now_iso=START)
    labels.record_label(conn, a2, "real", "toast", now_iso=START)
    labels.record_label(conn, a3, "false_alarm", "toast", now_iso=START)

    summary = labels.summarize(conn, since_iso=START)

    assert summary["WARN"] == {"real": 1, "false_alarm": 1, "unsure": 0}
    assert summary["INFO"] == {"real": 0, "false_alarm": 1, "unsure": 0}
    assert labels.false_alarm_rate(summary["WARN"]) == 0.5
    assert labels.false_alarm_rate({"real": 0, "false_alarm": 0, "unsure": 3}) is None

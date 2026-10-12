import json
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from vitals.ingest.otlp_receiver import OtlpReceiver

FIXTURES = Path(__file__).parent / "fixtures"


def post(port, path, data, content_type="application/json"):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers={"Content-Type": content_type},
        method="POST",
    )
    return urllib.request.urlopen(req, timeout=10)


def spool_lines(tmp_path):
    files = list((tmp_path / "spool" / "otel").glob("otel-*.jsonl"))
    assert files, "no otel spool file"
    return [json.loads(line) for line in files[0].read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def rx(tmp_path):
    receiver = OtlpReceiver(spool_dir=tmp_path / "spool", port=0)
    receiver.start()
    yield receiver
    receiver.stop()


def test_receiver_spools_logs_and_returns_200(rx, tmp_path):
    body = (FIXTURES / "otlp_logs_sample.json").read_bytes()
    assert post(rx.actual_port, "/v1/logs", body).status == 200
    rec = spool_lines(tmp_path)[0]
    assert rec["path"] == "/v1/logs"
    assert "resourceLogs" in rec["body"]
    assert rec["recv_ts"] > 0


def test_receiver_spools_metrics(rx, tmp_path):
    body = (FIXTURES / "otlp_metrics_sample.json").read_bytes()
    assert post(rx.actual_port, "/v1/metrics", body).status == 200
    assert "resourceMetrics" in spool_lines(tmp_path)[0]["body"]


def test_receiver_tolerates_garbage(rx, tmp_path):
    assert post(rx.actual_port, "/v1/logs", b"\x00garbage").status == 200
    rec = spool_lines(tmp_path)[0]
    assert rec["parse_error"]


def test_protobuf_is_recorded_as_misconfiguration_not_a_crash(rx, tmp_path):
    resp = post(rx.actual_port, "/v1/logs", b"\x0a\x0b", content_type="application/x-protobuf")
    assert resp.status == 200
    assert spool_lines(tmp_path)[0]["parse_error"] == "protobuf-not-supported"


def test_response_body_is_valid_otlp_partial_success(rx):
    body = (FIXTURES / "otlp_logs_sample.json").read_bytes()
    resp = post(rx.actual_port, "/v1/logs", body)
    assert json.loads(resp.read()) == {"partialSuccess": {}}


def test_unknown_path_still_200_and_spooled(rx, tmp_path):
    assert post(rx.actual_port, "/v1/traces", b'{"resourceSpans":[]}').status == 200
    assert spool_lines(tmp_path)[0]["path"] == "/v1/traces"


def test_get_health_endpoint(rx):
    with urllib.request.urlopen(f"http://127.0.0.1:{rx.actual_port}/health", timeout=10) as resp:
        assert resp.status == 200
        assert json.loads(resp.read())["ok"] is True


def test_concurrent_posts_produce_intact_lines(rx, tmp_path):
    import threading

    body = json.dumps({"resourceLogs": [{"x": "y" * 500}]}).encode()
    errors: list[Exception] = []

    def go():
        try:
            post(rx.actual_port, "/v1/logs", body).read()
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=go) for _ in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    lines = spool_lines(tmp_path)
    assert len(lines) == 24


def test_port_in_use_raises_so_the_daemon_can_report_it(tmp_path):
    first = OtlpReceiver(spool_dir=tmp_path / "spool", port=0)
    first.start()
    try:
        second = OtlpReceiver(spool_dir=tmp_path / "spool2", port=first.actual_port)
        with pytest.raises(OSError):
            second.start()
    finally:
        first.stop()


def test_stop_is_idempotent(tmp_path):
    receiver = OtlpReceiver(spool_dir=tmp_path / "spool", port=0)
    receiver.start()
    receiver.stop()
    receiver.stop()


def test_large_body_is_accepted(rx, tmp_path):
    big = json.dumps({"resourceLogs": [{"pad": "z" * 3_000_000}]}).encode()
    assert post(rx.actual_port, "/v1/logs", big).status == 200
    assert len(spool_lines(tmp_path)) == 1


def test_slow_client_does_not_block_others(rx, tmp_path):
    body = (FIXTURES / "otlp_logs_sample.json").read_bytes()
    start = time.time()
    for _ in range(3):
        post(rx.actual_port, "/v1/logs", body)
    assert time.time() - start < 10
    assert len(spool_lines(tmp_path)) == 3

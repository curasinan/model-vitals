from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from vitals import failopen

MAX_BODY_BYTES = 64 * 1024 * 1024
OK_BODY = b'{"partialSuccess":{}}'

_WRITE_LOCK = threading.Lock()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "model-vitals/0.1"

    @property
    def _spool_dir(self) -> Path:
        return self.server.spool_dir  # type: ignore[attr-defined]

    def _respond(self, payload: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._respond(json.dumps({"ok": True, "service": "model-vitals"}).encode())

    def do_POST(self):
        try:
            length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY_BYTES)
            raw = self.rfile.read(length) if length else b""
            content_type = (self.headers.get("Content-Type") or "").lower()

            if "protobuf" in content_type:
                record = {"parse_error": "protobuf-not-supported", "bytes": len(raw)}
            else:
                try:
                    record = {"body": json.loads(raw)}
                except Exception as exc:
                    record = {"parse_error": f"json: {exc}"[:300], "bytes": len(raw)}

            record["path"] = self.path
            record["recv_ts"] = time.time()
            self._write_line(record)
        except Exception:  # pragma: no cover
            failopen.record("otlp.record", self._spool_dir.parent)
        self._respond(OK_BODY)

    def _write_line(self, record: dict) -> None:
        spool = self._spool_dir / "otel"
        spool.mkdir(parents=True, exist_ok=True)
        path = spool / f"otel-{time.strftime('%Y%m%d')}.jsonl"
        line = (json.dumps(record, ensure_ascii=False, default=str) + "\n").encode("utf-8")
        with _WRITE_LOCK:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)

    def log_message(self, *args):
        pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 128

    def __init__(self, addr, handler, spool_dir: Path):
        self.spool_dir = spool_dir
        super().__init__(addr, handler)


class OtlpReceiver:
    def __init__(self, spool_dir: Path, port: int = 4318, host: str = "127.0.0.1"):
        self.spool_dir = Path(spool_dir)
        self.port = port
        self.host = host
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None

    @property
    def actual_port(self) -> int:
        if self._server is None:
            return self.port
        return self._server.server_address[1]

    def start(self) -> None:
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self._server = _Server((self.host, self.port), _Handler, self.spool_dir)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="otlp-receiver", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

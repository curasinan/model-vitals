from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RECEIVED: list[dict] = []


class DumpHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        RECEIVED.append(
            {
                "path": self.path,
                "content_type": self.headers.get("Content-Type"),
                "recv_ts": time.time(),
                "raw": raw,
            }
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"partialSuccess":{}}')

    def log_message(self, *args):
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="tests/fixtures")
    ap.add_argument("--port", type=int, default=4318)
    ap.add_argument("--model", default=None)
    ap.add_argument("--wait", type=float, default=12.0, help="seconds to keep collecting")
    args = ap.parse_args()

    claude = shutil.which("claude")
    if not claude:
        print("claude not found on PATH", file=sys.stderr)
        return 2

    server = ThreadingHTTPServer(("127.0.0.1", args.port), DumpHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    print(f"dump server on 127.0.0.1:{port}")

    env = dict(os.environ)
    env.update(
        {
            "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
            "OTEL_METRICS_EXPORTER": "otlp",
            "OTEL_LOGS_EXPORTER": "otlp",
            "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
            "OTEL_EXPORTER_OTLP_ENDPOINT": f"http://127.0.0.1:{port}",
            "OTEL_LOGS_EXPORT_INTERVAL": "1000",
            "OTEL_METRIC_EXPORT_INTERVAL": "1000",
            "OTEL_METRICS_INCLUDE_SESSION_ID": "true",
            "OTEL_METRICS_INCLUDE_VERSION": "true",
        }
    )
    cmd = [claude, "-p", "Reply with exactly: ok", "--output-format", "json", "--max-turns", "1"]
    if args.model:
        cmd += ["--model", args.model]
    print("running:", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=180)
    print("exit", proc.returncode)
    print("stdout:", proc.stdout[:2000])
    if proc.stderr.strip():
        print("stderr:", proc.stderr[:1000], file=sys.stderr)

    deadline = time.time() + args.wait
    while time.time() < deadline:
        time.sleep(0.5)
    server.shutdown()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    print(f"\n{len(RECEIVED)} POST bodies received")
    by_path: dict[str, list[dict]] = {}
    for item in RECEIVED:
        by_path.setdefault(item["path"], []).append(item)
    for path, items in by_path.items():
        name = path.strip("/").replace("/", "_")
        print(f"  {path}: {len(items)} bodies, content-type={items[0]['content_type']}")
        raw_dump = outdir / f"otlp_{name}_raw.jsonl"
        with raw_dump.open("w", encoding="utf-8") as fh:
            for item in items:
                try:
                    body = json.loads(item["raw"])
                except Exception:
                    body = {"_undecodable": item["raw"][:200].decode("latin-1")}
                fh.write(json.dumps({"path": path, "body": body}, ensure_ascii=False) + "\n")
        print(f"    wrote {raw_dump}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

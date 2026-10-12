from __future__ import annotations

import gzip
import json
import logging
import shutil
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vitals import failopen
from vitals.alert.dispatcher import dispatch
from vitals.alert.rules import evaluate
from vitals.canary.checkers import default_tasks_dir, load_tasks
from vitals.canary.runner import run_cycle
from vitals.config import Config, load
from vitals.db import get_conn, init_db, kv_get, kv_set, log_ingest
from vitals.detect.attribution import classify
from vitals.detect.engine import tick
from vitals.detect.signals import aggregate_hours
from vitals.ingest.normalize import ingest_otel_spool
from vitals.ingest.otlp_receiver import OtlpReceiver
from vitals.ingest.spool import ingest_hook_spool
from vitals.ingest.transcripts import scan_all
from vitals.timeutil import local_day, parse_iso, utcnow_iso
from vitals.watch.change_points import check_and_record, snapshot
from vitals.watch.status_poller import poll

log = logging.getLogger("vitals.daemon")

Job = Callable[[sqlite3.Connection, Config], None]

INGEST_INTERVAL_S = 5
TRANSCRIPT_INTERVAL_S = 60
CHANGE_POINT_INTERVAL_S = 60
STATUS_INTERVAL_S = 300
AGGREGATE_INTERVAL_S = 600
ARCHIVE_INTERVAL_S = 6 * 3600
HEARTBEAT_INTERVAL_S = 3600
ARCHIVE_AFTER_DAYS = 2

CANARY_CHECK_INTERVAL_S = 300

DEADMAN_INTERVAL_S = 300

_KV_CANARY_LAST_RUN = "canary_scheduler_last_run"
_KV_CANARY_LONG_CONTEXT_DAY = "canary_scheduler_long_context_day"


def job_ingest(conn: sqlite3.Connection, cfg: Config) -> None:
    state = cfg.data_dir / "state"
    ingest_otel_spool(conn, cfg.spool_dir, state / "otel_offsets.json")
    ingest_hook_spool(conn, cfg.spool_dir, state / "hook_offsets.json")


def job_transcripts(conn: sqlite3.Connection, cfg: Config) -> None:
    last_full = kv_get(conn, "last_full_transcript_scan")
    wide = not last_full or (time.time() - float(last_full)) > 86400
    scanned = scan_all(conn, cfg.projects_dir, since_days=3 if wide else 0.01)
    if wide:
        kv_set(conn, "last_full_transcript_scan", str(time.time()))
    if scanned:
        log_ingest(conn, "transcripts", scanned, 0)


def job_detect(conn: sqlite3.Connection, cfg: Config, now_iso: str | None = None) -> None:
    now_iso = now_iso or utcnow_iso()
    tick(conn, cfg.detect, now_iso)
    for draft in evaluate(conn, cfg.detect, now_iso):
        attribution = classify(conn, draft, now_iso)
        dispatch(conn, cfg, draft, attribution, now_iso=now_iso)


def job_aggregate(conn: sqlite3.Connection, cfg: Config) -> None:
    inserted = aggregate_hours(conn, cfg.detect)
    if inserted:
        log_ingest(conn, "aggregate", inserted, 0)
    job_detect(conn, cfg)


def job_change_points(conn: sqlite3.Connection, cfg: Config) -> None:
    home = Path.home() / ".claude"
    snap = snapshot(
        home / "settings.json",
        home / "plugins" / "installed_plugins.json",
        cfg.data_dir / "config.toml",
        conn=conn,
    )
    changed = check_and_record(conn, snap)
    if changed:
        log_ingest(conn, "change_points", len(changed), 0, ",".join(changed))


def job_status_poll(conn: sqlite3.Connection, cfg: Config) -> None:
    poll(conn)


def _spool_day(path: Path) -> str | None:
    stem = path.name.split("-", 1)[-1].split(".", 1)[0]
    return stem if len(stem) == 8 and stem.isdigit() else None


def job_archive(conn: sqlite3.Connection, cfg: Config) -> None:
    cutoff = (datetime.now(UTC) - timedelta(days=ARCHIVE_AFTER_DAYS)).strftime("%Y%m%d")
    archived = 0
    for sub in ("hooks", "otel"):
        directory = cfg.spool_dir / sub
        if not directory.exists():
            continue
        for path in directory.glob("*.jsonl"):
            day = _spool_day(path)
            if day is None or day >= cutoff:
                continue
            try:
                with path.open("rb") as src, gzip.open(str(path) + ".gz", "wb") as dst:
                    shutil.copyfileobj(src, dst)
                path.unlink()
                archived += 1
            except OSError:
                continue
    if archived:
        log_ingest(conn, "archive", archived, 0)


def next_due(last_run_iso: str | None, schedule_hours: float, now_iso: str) -> bool:
    if not last_run_iso:
        return True
    try:
        last = parse_iso(last_run_iso)
        now = parse_iso(now_iso)
    except ValueError:
        log.warning(
            "next_due: unparseable timestamp (last_run=%r now=%r); treating as due",
            last_run_iso,
            now_iso,
        )
        return True
    elapsed_s = (now - last).total_seconds()
    if elapsed_s < 0:
        log.warning(
            "next_due: clock skew detected -- now (%s) precedes the last recorded run (%s) by"
            " %.0fs; treating as due rather than waiting out a potentially bogus interval",
            now_iso,
            last_run_iso,
            -elapsed_s,
        )
        return True
    return elapsed_s >= schedule_hours * 3600.0


def job_canary_schedule(conn: sqlite3.Connection, cfg: Config, now_iso: str | None = None) -> None:
    now_iso = now_iso or utcnow_iso()
    last_run = kv_get(conn, _KV_CANARY_LAST_RUN)
    if not next_due(last_run, cfg.canary.schedule_hours, now_iso):
        return

    today = local_day(now_iso)
    long_today = (
        cfg.canary.long_context_daily and kv_get(conn, _KV_CANARY_LONG_CONTEXT_DAY) != today
    )
    canary_cfg = cfg.canary if long_today else replace(cfg.canary, long_context_daily=False)

    tasks = load_tasks(default_tasks_dir())

    kv_set(conn, _KV_CANARY_LAST_RUN, now_iso)
    if long_today:
        kv_set(conn, _KV_CANARY_LONG_CONTEXT_DAY, today)

    run_cycle(conn, canary_cfg, tasks)


def ingest_once(cfg: Config | None = None) -> None:
    cfg = cfg or load()
    conn = get_conn(cfg.db_path)
    init_db(conn)
    try:
        job_ingest(conn, cfg)
        job_transcripts(conn, cfg)
        job_aggregate(conn, cfg)
    finally:
        conn.close()


class Daemon:
    def __init__(self, cfg: Config | None = None):
        self.cfg = cfg or load()
        self.stop_event = threading.Event()
        self.receiver: OtlpReceiver | None = None
        self._threads: list[threading.Thread] = []
        conn = get_conn(self.cfg.db_path)
        try:
            init_db(conn)
        finally:
            conn.close()

    def safe_run(self, name: str, job: Job) -> None:
        conn = None
        try:
            conn = get_conn(self.cfg.db_path)
            job(conn, self.cfg)
        except Exception as exc:
            log.exception("job %s failed", name)
            try:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:  # pragma: no cover
                        failopen.record("daemon.conn_close", self.cfg.data_dir)
                    conn = None
                conn = get_conn(self.cfg.db_path)
                log_ingest(conn, "job_error", 0, 1, f"{name}: {type(exc).__name__}: {exc}"[:500])
            except Exception:  # pragma: no cover
                failopen.record("daemon.recovery", self.cfg.data_dir)
        finally:
            if conn is not None:
                conn.close()

    def _set_receiver_state(self, **state) -> None:
        conn = get_conn(self.cfg.db_path)
        try:
            kv_set(conn, "receiver_state", json.dumps({"ts": utcnow_iso(), **state}))
        finally:
            conn.close()

    def start_receiver(self) -> bool:
        receiver = OtlpReceiver(spool_dir=self.cfg.spool_dir, port=self.cfg.otlp_port)
        try:
            receiver.start()
        except OSError as exc:
            detail = f"port {self.cfg.otlp_port} in use ({exc})"
            conn = get_conn(self.cfg.db_path)
            try:
                log_ingest(conn, "receiver", 0, 1, detail)
            finally:
                conn.close()
            self._set_receiver_state(state="down", detail=detail, port=self.cfg.otlp_port)
            log.error("OTLP receiver not started: %s", detail)
            return False
        self.receiver = receiver
        self._set_receiver_state(state="up", port=receiver.actual_port)
        return True

    def heartbeat(self) -> bool:
        if self.receiver is None:
            return False
        marker = f"vitals-heartbeat-{time.time()}"
        body = json.dumps({"vitals_heartbeat": marker}).encode()
        url = f"http://127.0.0.1:{self.receiver.actual_port}/v1/logs"
        try:
            request = urllib.request.Request(
                url, data=body, headers={"Content-Type": "application/json"}, method="POST"
            )
            urllib.request.urlopen(request, timeout=5).read()
        except (OSError, urllib.error.URLError) as exc:
            self._set_receiver_state(
                state="down", detail=f"heartbeat failed: {exc}", port=self.cfg.otlp_port
            )
            return False
        time.sleep(0.2)
        spool = self.cfg.spool_dir / "otel"
        found = any(
            marker in path.read_text(encoding="utf-8", errors="replace")
            for path in spool.glob("otel-*.jsonl")
        )
        if not found:
            self._set_receiver_state(
                state="down",
                detail="another process answered on the OTLP port; exports are going elsewhere",
                port=self.cfg.otlp_port,
            )
            return False
        self._set_receiver_state(state="up", port=self.receiver.actual_port)
        return True

    def _deadman(self, conn: sqlite3.Connection, cfg: Config) -> None:
        from vitals.alert.dispatcher import dispatch
        from vitals.watch.deadman import check_no_data

        now_iso = utcnow_iso()
        found = check_no_data(conn, cfg, now_iso)
        if found is None:
            return
        draft, attribution = found
        dispatch(conn, cfg, draft, attribution, now_iso=now_iso)

    def _loop(self, name: str, job: Job, interval: float) -> None:
        while not self.stop_event.is_set():
            self.safe_run(name, job)
            self.stop_event.wait(interval)

    def run_once(self, skip_network: bool = False) -> None:
        self.safe_run("ingest", job_ingest)
        self.safe_run("transcripts", job_transcripts)
        self.safe_run("aggregate", job_aggregate)
        self.safe_run("change_points", job_change_points)
        self.safe_run("archive", job_archive)
        self.safe_run("deadman", self._deadman)
        if not skip_network:
            self.safe_run("status_poll", job_status_poll)

    def _job_specs(self) -> list[tuple[str, Job, float]]:
        return [
            ("ingest", job_ingest, INGEST_INTERVAL_S),
            ("transcripts", job_transcripts, TRANSCRIPT_INTERVAL_S),
            ("aggregate", job_aggregate, AGGREGATE_INTERVAL_S),
            ("change_points", job_change_points, CHANGE_POINT_INTERVAL_S),
            ("status_poll", job_status_poll, STATUS_INTERVAL_S),
            ("archive", job_archive, ARCHIVE_INTERVAL_S),
            ("canary", job_canary_schedule, CANARY_CHECK_INTERVAL_S),
            ("deadman", self._deadman, DEADMAN_INTERVAL_S),
        ]

    def run(self) -> int:
        self._setup_logging()
        log.info("model-vitals daemon starting; data dir %s", self.cfg.data_dir)
        self.start_receiver()

        jobs = self._job_specs()
        for name, job, interval in jobs:
            thread = threading.Thread(
                target=self._loop, args=(name, job, interval), name=f"vitals-{name}", daemon=True
            )
            thread.start()
            self._threads.append(thread)

        heartbeat = threading.Thread(target=self._heartbeat_loop, name="vitals-hb", daemon=True)
        heartbeat.start()
        self._threads.append(heartbeat)

        try:
            while not self.stop_event.wait(1.0):
                pass
        except KeyboardInterrupt:
            log.info("interrupted")
        finally:
            self.shutdown()
        return 0

    def _heartbeat_loop(self) -> None:
        while not self.stop_event.is_set():
            if self.receiver is None:
                self.start_receiver()
            else:
                try:
                    self.heartbeat()
                except Exception:
                    log.exception("heartbeat failed")
            self.stop_event.wait(HEARTBEAT_INTERVAL_S)

    def shutdown(self) -> None:
        self.stop_event.set()
        if self.receiver is not None:
            self.receiver.stop()
            self.receiver = None
        for thread in self._threads:
            thread.join(timeout=5)
        self._threads.clear()
        log.info("daemon stopped")

    def _setup_logging(self) -> None:
        log_dir = self.cfg.data_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_dir / "daemon.log", encoding="utf-8")
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(threadName)s %(message)s")
        )
        root = logging.getLogger("vitals")
        root.setLevel(logging.INFO)
        root.handlers = [handler]

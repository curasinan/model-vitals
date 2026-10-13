from __future__ import annotations

import os
import threading
from pathlib import Path

__all__ = ["SITES", "counter_dir", "record", "totals"]

SITES: tuple[str, ...] = (
    "daemon.recovery",
    "daemon.conn_close",
    "db.log_ingest",
    "hook.spool",
    "otlp.record",
    "toast.label",
)

_DIRNAME = "failopen"


def counter_dir(data_dir: Path | str | None) -> Path | None:
    if data_dir is None:
        return None
    try:
        return Path(data_dir) / _DIRNAME
    except (TypeError, ValueError):  # pragma: no cover
        return None


_WRITE_LOCK = threading.Lock()


def record(site: str, data_dir: Path | str | None) -> None:
    try:
        directory = counter_dir(data_dir)
        if directory is None:
            return
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{site}.{os.getpid()}.count"
        with _WRITE_LOCK:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, b"\x01")
            finally:
                os.close(fd)
    except Exception:
        pass


def totals(data_dir: Path | str | None) -> dict[str, int]:
    out: dict[str, int] = {}
    try:
        directory = counter_dir(data_dir)
        if directory is None or not directory.is_dir():
            return out
        for entry in directory.iterdir():
            parts = entry.name.rsplit(".", 2)
            if len(parts) != 3 or parts[2] != "count":
                continue
            try:
                out[parts[0]] = out.get(parts[0], 0) + entry.stat().st_size
            except OSError:  # pragma: no cover
                continue
    except Exception:
        return out
    return out

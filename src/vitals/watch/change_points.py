from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
from collections.abc import Callable
from pathlib import Path

from vitals.db import kv_get, kv_set, log_ingest
from vitals.timeutil import utcnow_iso

KINDS = ("cc_version", "settings", "plugins", "vitals_config")


def _read_text(path: Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return ""


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def default_version() -> str:
    exe = shutil.which("claude")
    if not exe:
        raise OSError("claude not found on PATH")
    proc = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise OSError(f"claude --version exited {proc.returncode}")
    return proc.stdout.strip()


def _plugin_entries(plugins_path: Path) -> list[tuple[str, str, str]]:
    raw = _read_text(plugins_path)
    if not raw:
        return []
    try:
        registry = json.loads(raw)
    except ValueError:
        return []
    entries = []
    for name, installs in (registry.get("plugins") or {}).items():
        for install in installs if isinstance(installs, list) else [installs]:
            if not isinstance(install, dict):
                continue
            entries.append(
                (
                    str(name),
                    str(install.get("version") or "unknown"),
                    str(install.get("gitCommitSha") or ""),
                )
            )
    return sorted(entries)


def snapshot(
    settings_path: Path,
    plugins_path: Path,
    vitals_config_path: Path,
    version_cmd: Callable[[], str] = default_version,
    conn: sqlite3.Connection | None = None,
) -> dict:
    try:
        version = version_cmd()
    except Exception:
        version = (kv_get(conn, "last_cc_version") if conn is not None else None) or "unknown"
        if conn is not None:
            log_ingest(conn, "cc_version_lookup", 0, 1, "falling back to last known version")

    settings_raw = _read_text(settings_path)
    try:
        settings = json.loads(settings_raw) if settings_raw.strip() else {}
    except ValueError:
        settings = {}
    enabled = settings.pop("enabledPlugins", {}) if isinstance(settings, dict) else {}

    entries = _plugin_entries(plugins_path)
    plugins_blob = json.dumps(
        {"installed": entries, "enabled": sorted((enabled or {}).items())}, sort_keys=True
    )

    return {
        "cc_version": version,
        "settings_hash": _sha(json.dumps(settings, sort_keys=True)),
        "plugins_hash": _sha(plugins_blob),
        "vitals_config_hash": _sha(_read_text(vitals_config_path)),
        "plugins_list": plugins_blob,
    }


def _detail(kind: str, old: dict, new: dict) -> str | None:
    if kind != "plugins":
        return None
    try:
        before = {(n, v) for n, v, _ in json.loads(old.get("plugins_list", "{}"))["installed"]}
        after = {(n, v) for n, v, _ in json.loads(new.get("plugins_list", "{}"))["installed"]}
    except (ValueError, KeyError, TypeError):
        return None
    added = sorted(after - before)
    removed = sorted(before - after)
    if not added and not removed:
        return json.dumps({"enabled_toggled": True})
    return json.dumps({"added": added, "removed": removed})


def check_and_record(conn: sqlite3.Connection, snap: dict) -> list[str]:
    previous_raw = kv_get(conn, "snapshot")
    kv_set(conn, "snapshot", json.dumps(snap))
    if snap.get("cc_version") and snap["cc_version"] != "unknown":
        kv_set(conn, "last_cc_version", snap["cc_version"])
    if not previous_raw:
        return []
    try:
        previous = json.loads(previous_raw)
    except ValueError:
        return []

    changed: list[str] = []
    for kind in KINDS:
        key = "cc_version" if kind == "cc_version" else f"{kind}_hash"
        if kind == "vitals_config":
            key = "vitals_config_hash"
        old, new = previous.get(key), snap.get(key)
        if old is None or new is None or old == new:
            continue
        changed.append(kind)
        conn.execute(
            "INSERT INTO change_points(ts, kind, old_value, new_value, detail) VALUES (?,?,?,?,?)",
            (utcnow_iso(), kind, str(old), str(new), _detail(kind, previous, snap)),
        )
    conn.commit()
    return changed

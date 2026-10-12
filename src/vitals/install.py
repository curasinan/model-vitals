from __future__ import annotations

import copy
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from vitals import __version__
from vitals.config import home_data_dir

OTEL_ENV: dict[str, str] = {
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_METRICS_EXPORTER": "otlp",
    "OTEL_LOGS_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318",
    "OTEL_LOGS_EXPORT_INTERVAL": "5000",
    "OTEL_METRIC_EXPORT_INTERVAL": "60000",
    "OTEL_METRICS_INCLUDE_SESSION_ID": "true",
    "OTEL_METRICS_INCLUDE_VERSION": "true",
}

HOOK_EVENTS = [
    "SessionStart",
    "PostToolUse",
    "PostToolUseFailure",
    "PreCompact",
    "PostCompact",
    "Stop",
    "SubagentStop",
    "SessionEnd",
    "ConfigChange",
]
HOOK_TIMEOUT_S = 30
MARKERS = ("model-vitals/hook.py", "claude-vitals/hook.py")


def hook_install_dir() -> Path:
    return home_data_dir()


def _quote(p: str) -> str:
    return f'"{p}"' if " " in p else p


def hook_interpreter() -> str:
    base = getattr(sys, "_base_executable", None) or sys.executable
    return base if Path(base).exists() else sys.executable


def default_hook_cmd() -> str:
    src = Path(__file__).resolve().parent / "hook.py"
    dest_dir = hook_install_dir()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "hook.py"
    body = src.read_text(encoding="utf-8")
    stamp = (
        f"# installed by model-vitals {__version__} from {src} "
        f"at {time.strftime('%Y-%m-%dT%H:%M:%S')}\n"
    )
    dest.write_text(stamp + body, encoding="utf-8")
    exe = hook_interpreter().replace("\\", "/")
    script = str(dest).replace("\\", "/")
    return f"{_quote(exe)} -I {_quote(script)}"


def _is_ours(command: str) -> bool:
    normalized = (command or "").replace("\\", "/")
    return any(marker in normalized for marker in MARKERS)


def merge_settings(settings: dict, hook_cmd: str) -> tuple[dict, list[str]]:
    out = copy.deepcopy(settings)
    conflicts: list[str] = []

    env = out.setdefault("env", {})
    for key, value in OTEL_ENV.items():
        if key not in env:
            env[key] = value
        elif env[key] != value:
            conflicts.append(f"env.{key}: yours={env[key]!r} ours={value!r} (left as yours)")

    hooks = out.setdefault("hooks", {})
    for event in HOOK_EVENTS:
        groups = hooks.setdefault(event, [])
        existing = [
            h for grp in groups for h in grp.get("hooks", []) if _is_ours(h.get("command", ""))
        ]
        if existing:
            for entry in existing:
                entry["command"] = hook_cmd
                entry["type"] = "command"
                entry["async"] = True
                entry["timeout"] = HOOK_TIMEOUT_S
            continue
        groups.append(
            {
                "matcher": "",
                "hooks": [
                    {
                        "type": "command",
                        "async": True,
                        "timeout": HOOK_TIMEOUT_S,
                        "command": hook_cmd,
                    }
                ],
            }
        )
    return out, conflicts


def smoke_check(hook_cmd: str, data_dir: Path, timeout: float = 30.0) -> bool:
    data_dir = Path(data_dir)
    marker = f"vitals-smoke-{uuid.uuid4()}"
    payload = json.dumps(
        {"hook_event_name": "SessionStart", "session_id": marker, "source": "startup"}
    )
    env = dict(os.environ, VITALS_DATA_DIR=str(data_dir))
    try:
        proc = subprocess.run(
            shlex.split(hook_cmd),
            input=payload,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"hook command failed to run: {hook_cmd!r} ({exc})") from exc
    if proc.returncode != 0:
        raise RuntimeError(
            f"hook command exited {proc.returncode} (must always be 0): {proc.stderr.strip()[:500]}"
        )
    if proc.stdout:
        raise RuntimeError("hook wrote to stdout; that would be injected as session context")
    spool = data_dir / "spool" / "hooks"
    found = any(
        marker in f.read_text(encoding="utf-8", errors="replace")
        for f in spool.glob("hooks-*.jsonl")
    )
    if not found:
        raise RuntimeError(
            f"hook ran but wrote no spool line under {spool} — collection would be silently dead"
        )
    return True


def backup_settings(settings_path: Path) -> Path | None:
    if not settings_path.exists():
        return None
    backup = settings_path.with_name(
        f"{settings_path.name}.vitals-bak-{time.strftime('%Y%m%d-%H%M%S')}"
    )
    shutil.copy2(settings_path, backup)
    return backup


def load_settings(settings_path: Path) -> dict:
    if not settings_path.exists():
        return {}
    text = settings_path.read_text(encoding="utf-8")
    return json.loads(text) if text.strip() else {}


def default_settings_path() -> Path:
    return Path.home() / ".claude" / "settings.json"

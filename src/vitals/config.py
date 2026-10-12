from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path


@dataclass
class CanaryCfg:
    model: str = "claude-sonnet-5"
    effort: str = "medium"
    runs_per_task: int = 2
    daily_budget_usd: float = 6.0
    daily_token_budget: int = 3_000_000
    schedule_hours: int = 8
    long_context_daily: bool = True
    per_run_budget_usd: float = 0.5
    per_run_timeout_s: int = 300
    enabled: bool = True


CANARY_PRICE_PER_MTOK_USD: dict[str, tuple[float, float]] = {
    "sonnet-5": (2.0, 10.0),
    "haiku-4-5": (1.0, 5.0),
    "opus-5": (5.0, 25.0),
}

CACHE_READ_PRICE_RATIO = 0.1


@dataclass
class DetectCfg:
    k: float = 0.5
    h: float = 5.0
    lam: float = 0.2
    baseline_days: int = 7
    baseline_max_days: int = 21
    min_windows: int = 50
    min_samples: int = 200
    K_cycles: int = 3
    delta: float = 0.15
    warn_window_h: int = 6
    critical_sustain_h: int = 12
    edit_loop_n: int = 3
    auto_resolve_days: int = 7
    canary_min_valid_fraction: float = 0.5

    no_data_window_minutes: int = 30


@dataclass
class AlertCfg:
    dedup_cooldown_minutes: int = 60


@dataclass
class Config:
    data_dir: Path
    db_path: Path
    spool_dir: Path
    reports_dir: Path
    otlp_port: int = 4318
    projects_dir: Path = field(default_factory=lambda: default_projects_dir())
    canary: CanaryCfg = field(default_factory=CanaryCfg)
    detect: DetectCfg = field(default_factory=DetectCfg)
    alert: AlertCfg = field(default_factory=AlertCfg)
    channels: dict = field(default_factory=dict)


DATA_DIR_NAME = ".model-vitals"
LEGACY_DATA_DIR_NAME = ".claude-vitals"


def home_data_dir() -> Path:
    home = Path(os.path.expanduser("~"))
    current = home / DATA_DIR_NAME
    legacy = home / LEGACY_DATA_DIR_NAME
    if not current.exists() and legacy.exists():
        return legacy
    return current


def default_data_dir() -> Path:
    env = os.environ.get("VITALS_DATA_DIR")
    if env:
        return Path(env)
    return home_data_dir()


def default_projects_dir() -> Path:
    env = os.environ.get("VITALS_PROJECTS_DIR")
    return Path(env) if env else Path.home() / ".claude" / "projects"


def _coerce(value: object, default: object, key: str) -> object:
    if isinstance(default, bool):
        if not isinstance(value, bool):
            raise ValueError(f"config key {key!r} must be a boolean")
        return value
    if isinstance(default, float) and isinstance(value, int) and not isinstance(value, bool):
        return float(value)
    if isinstance(default, int) and isinstance(value, bool):
        raise ValueError(f"config key {key!r} must be a number")
    if isinstance(default, Path):
        return Path(str(value))
    if not isinstance(value, type(default)):
        raise ValueError(
            f"config key {key!r} must be {type(default).__name__}, got {type(value).__name__}"
        )
    return value


def _apply(obj: object, table: dict, prefix: str) -> None:
    known = {f.name for f in fields(obj)}  # type: ignore[arg-type]
    for key, value in table.items():
        full = f"{prefix}.{key}" if prefix else key
        if key not in known:
            raise ValueError(f"unknown config key: {full}")
        setattr(obj, key, _coerce(value, getattr(obj, key), full))


def load(path: Path | None = None) -> Config:
    data_dir = default_data_dir()
    cfg = Config(
        data_dir=data_dir,
        db_path=data_dir / "vitals.db",
        spool_dir=data_dir / "spool",
        reports_dir=data_dir / "reports",
    )
    toml_path = Path(path) if path else data_dir / "config.toml"
    if not toml_path.exists():
        return cfg

    raw = tomllib.loads(toml_path.read_text(encoding="utf-8"))
    channels = raw.pop("channels", {})
    if not isinstance(channels, dict):
        raise ValueError("config key 'channels' must be a table")
    for name, entry in channels.items():
        if not isinstance(entry, dict):
            raise ValueError(
                f"config key 'channels.{name}' must be a table (e.g."
                f" `[channels.{name}]` with `enabled = true` under it), got"
                f" {type(entry).__name__}"
            )
    cfg.channels = channels

    nested = {"canary": cfg.canary, "detect": cfg.detect, "alert": cfg.alert}
    scalars = {k: v for k, v in raw.items() if k not in nested}
    if os.environ.get("VITALS_DATA_DIR"):
        scalars.pop("data_dir", None)
    _apply(cfg, scalars, "")
    for name, sub in nested.items():
        table = raw.get(name, {})
        if not isinstance(table, dict):
            raise ValueError(f"config key {name!r} must be a table")
        _apply(sub, table, name)

    if "db_path" not in scalars:
        cfg.db_path = cfg.data_dir / "vitals.db"
    if "spool_dir" not in scalars:
        cfg.spool_dir = cfg.data_dir / "spool"
    if "reports_dir" not in scalars:
        cfg.reports_dir = cfg.data_dir / "reports"
    return cfg

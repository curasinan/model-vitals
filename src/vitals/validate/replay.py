from __future__ import annotations

import sqlite3
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from vitals import config as config_mod
from vitals.alert.dispatcher import dispatch
from vitals.alert.rules import evaluate, signal_counts_toward_threshold
from vitals.config import Config, DetectCfg
from vitals.db import get_conn, init_db, log_ingest
from vitals.detect.attribution import classify
from vitals.detect.engine import tick
from vitals.detect.signal_ids import FAMILY as FAMILIES
from vitals.detect.signals import aggregate_hours
from vitals.ingest.transcripts import scan_all
from vitals.timeutil import hour_add, parse_iso

__all__ = ["ReplayReport", "backfill", "open_replay_db"]


@dataclass
class ReplayReport:
    windows_aggregated: int
    strata: int
    anomalies: list[dict] = field(default_factory=list)
    would_be_alerts: list[dict] = field(default_factory=list)
    weekly_info: list[int] = field(default_factory=list)
    weekly_warn: list[int] = field(default_factory=list)
    suggested_thresholds: dict | None = None
    strata_with_baseline: int = 0
    insufficient_data_strata: int = 0
    families_with_windows: list[str] = field(default_factory=list)
    families_with_live_baseline: list[str] = field(default_factory=list)
    warn_rule_exercised: bool = False


def open_replay_db(base_dir: Path | None = None) -> tuple[sqlite3.Connection, Path]:
    root = Path(base_dir) if base_dir is not None else Path(tempfile.gettempdir())
    root.mkdir(parents=True, exist_ok=True)
    replay_dir = Path(tempfile.mkdtemp(prefix="vitals-replay-", dir=str(root)))
    db_path = replay_dir / "replay.db"
    conn = get_conn(db_path)
    init_db(conn)
    return conn, db_path


def _conn_file_path(conn: sqlite3.Connection) -> Path | None:
    row = conn.execute("PRAGMA database_list").fetchone()
    raw = row["file"] if row is not None else None
    return Path(raw) if raw else None


def _resolved(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:  # pragma: no cover
        return path


def _assert_not_the_real_db(conn: sqlite3.Connection) -> None:
    path = _conn_file_path(conn)
    if path is None:
        return
    real_db = config_mod.default_data_dir() / "vitals.db"
    if _resolved(path) == _resolved(real_db):
        raise RuntimeError(
            f"refusing to replay into the real vitals database ({_resolved(path)}); "
            "vitals.validate.replay must only ever run against a fresh throwaway database -- "
            "use open_replay_db() to obtain one"
        )


def _replay_config(conn: sqlite3.Connection, projects_dir: Path, detect_cfg: DetectCfg) -> Config:
    path = _conn_file_path(conn)
    data_dir = (
        path.parent if path is not None else Path(tempfile.mkdtemp(prefix="vitals-replay-cfg-"))
    )
    return Config(
        data_dir=data_dir,
        db_path=path or (data_dir / "replay.db"),
        spool_dir=data_dir / "spool",
        reports_dir=data_dir / "reports",
        projects_dir=Path(projects_dir),
        detect=detect_cfg,
        channels={},
    )


def _all_window_hours(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT MIN(window_start) AS lo, MAX(window_start) AS hi FROM signal_windows"
    ).fetchone()
    if not rows or rows["lo"] is None:
        return []
    hours = []
    hour = rows["lo"]
    hi = rows["hi"]
    while hour <= hi:
        hours.append(hour)
        hour = hour_add(hour, 1)
    return hours


def _summarize_anomalies(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT signal, model, context_bucket, cc_version, started_at, ended_at, direction,"
        " status FROM anomalies ORDER BY id"
    ).fetchall()
    return [
        {
            "signal": r["signal"],
            "stratum": f"{r['model'] or 'unknown'}|{r['context_bucket'] or 'unknown'}|"
            f"{r['cc_version'] or 'unknown'}",
            "span": [r["started_at"], r["ended_at"]],
            "direction": r["direction"],
            "status": r["status"],
        }
        for r in rows
    ]


def _count_strata(conn: sqlite3.Connection) -> tuple[int, int, int]:
    total = conn.execute(
        "SELECT COUNT(DISTINCT signal || '|' || model || '|' || context_bucket || '|' ||"
        " cc_version) FROM signal_windows"
    ).fetchone()[0]
    with_baseline = conn.execute(
        "SELECT COUNT(*) FROM detector_state WHERE mu0 IS NOT NULL"
    ).fetchone()[0]
    insufficient = conn.execute("SELECT COUNT(*) FROM detector_state WHERE mu0 IS NULL").fetchone()[
        0
    ]
    return int(total), int(with_baseline), int(insufficient)


def _family_coverage(conn: sqlite3.Connection) -> tuple[list[str], list[str], bool]:
    signals = [row["signal"] for row in conn.execute("SELECT DISTINCT signal FROM signal_windows")]
    families = sorted({FAMILIES.get(s, "unknown") for s in signals})
    live = [
        row["signal"]
        for row in conn.execute("SELECT DISTINCT signal FROM detector_state WHERE mu0 IS NOT NULL")
    ]
    with_baseline = sorted({FAMILIES.get(s, "unknown") for s in live})
    countable = {FAMILIES.get(s, "unknown") for s in live if signal_counts_toward_threshold(s)}
    return families, with_baseline, len(countable) >= 2


def _iso_week(iso: str) -> str:
    dt = parse_iso(iso)
    year, week, _ = dt.isocalendar()
    return f"{year}-W{week:02d}"


def _suggest_thresholds(weekly_warn: list[int], cfg: DetectCfg) -> dict | None:
    if not weekly_warn:
        return None
    n_weeks = len(weekly_warn)
    avg = sum(weekly_warn) / n_weeks
    if avg <= 1.0:
        return None
    return {
        "reason": (
            f"observed {avg:.2f} WARN/week averaged over {n_weeks} week(s) of replayed history, "
            f"which exceeds the spec's < 1 WARN/week acceptance criterion"
        ),
        "observed_warn_per_week": round(avg, 3),
        "options": {
            "h": round(cfg.h + 1.0, 3),
            "delta": round(cfg.delta * 1.3, 3),
        },
    }


def backfill(
    conn: sqlite3.Connection,
    projects_dir: Path,
    since_days: int = 90,
    *,
    detect_cfg: DetectCfg | None = None,
) -> ReplayReport:
    _assert_not_the_real_db(conn)
    init_db(conn)
    cfg_detect = detect_cfg or DetectCfg()

    scanned = scan_all(conn, Path(projects_dir), since_days=since_days)
    log_ingest(conn, "replay_transcripts", scanned, 0, f"since_days={since_days}")

    inserted = aggregate_hours(conn, cfg_detect)

    replay_cfg = _replay_config(conn, projects_dir, cfg_detect)

    hours = _all_window_hours(conn)
    weekly_info: dict[str, int] = defaultdict(int)
    weekly_warn: dict[str, int] = defaultdict(int)

    for hour in hours:
        as_of = hour_add(hour, 1)
        tick(conn, cfg_detect, as_of)
        for draft in evaluate(conn, cfg_detect, as_of):
            attribution = classify(conn, draft, as_of)
            alert_id = dispatch(conn, replay_cfg, draft, attribution, now_iso=as_of)
            if not alert_id:
                continue
            week = _iso_week(as_of)
            if draft.severity == "WARN":
                weekly_warn[week] += 1
            elif draft.severity == "INFO":
                weekly_info[week] += 1

    alert_rows = conn.execute(
        "SELECT ts, severity, attribution, title FROM alerts ORDER BY id"
    ).fetchall()
    would_be_alerts = [
        {
            "severity": r["severity"],
            "attribution": r["attribution"],
            "ts": r["ts"],
            "title": r["title"],
        }
        for r in alert_rows
    ]

    anomalies = _summarize_anomalies(conn)
    total_strata, with_baseline, insufficient = _count_strata(conn)
    families, families_with_baseline, warn_exercised = _family_coverage(conn)

    weeks = sorted(set(weekly_info) | set(weekly_warn) | {_iso_week(h) for h in hours})
    weekly_info_list = [weekly_info[w] for w in weeks]
    weekly_warn_list = [weekly_warn[w] for w in weeks]

    return ReplayReport(
        windows_aggregated=inserted,
        strata=total_strata,
        anomalies=anomalies,
        would_be_alerts=would_be_alerts,
        weekly_info=weekly_info_list,
        weekly_warn=weekly_warn_list,
        suggested_thresholds=_suggest_thresholds(weekly_warn_list, cfg_detect),
        strata_with_baseline=with_baseline,
        insufficient_data_strata=insufficient,
        families_with_windows=families,
        families_with_live_baseline=families_with_baseline,
        warn_rule_exercised=warn_exercised,
    )


def render_replay_report(report: ReplayReport, since_days: int) -> str:
    lines = [
        f"replay over the last {since_days} days:",
        f"  windows aggregated:      {report.windows_aggregated}",
        f"  strata observed:         {report.strata}"
        f" ({report.strata_with_baseline} reached a live baseline,"
        f" {report.insufficient_data_strata} insufficient_data)",
        f"  anomalies opened:        {len(report.anomalies)}",
        f"  would-be alerts:         {len(report.would_be_alerts)}",
    ]
    by_sev: dict[str, int] = defaultdict(int)
    for a in report.would_be_alerts:
        by_sev[a["severity"]] += 1
    for sev in ("INFO", "WARN", "CRITICAL"):
        if by_sev.get(sev):
            lines.append(f"    {sev}: {by_sev[sev]}")
    n_weeks = max(len(report.weekly_warn), 1)
    avg_warn = sum(report.weekly_warn) / n_weeks if report.weekly_warn else 0.0
    avg_info = sum(report.weekly_info) / n_weeks if report.weekly_info else 0.0
    lines.append(f"  implied INFO/week:       {avg_info:.3f}")
    lines.append(f"  implied WARN/week:       {avg_warn:.3f}  (acceptance: < 1)")
    lines.append(
        "  families with windows:   " + (", ".join(report.families_with_windows) or "none")
    )
    lines.append(
        "  ...of those, able to alarm (live baseline): "
        + (", ".join(report.families_with_live_baseline) or "none")
    )
    if report.suggested_thresholds is not None:
        s = report.suggested_thresholds
        lines.append(f"  acceptance criterion:    NOT MET -- {s['reason']}")
        lines.append(
            f"    suggested: h -> {s['options']['h']}, or delta -> {s['options']['delta']}"
        )
    elif not report.warn_rule_exercised:
        lines.append(
            "  acceptance criterion:    WARN rule not exercised by this replay -- fewer than 2"
            " threshold-counting families could alarm"
        )
        lines.append(
            "    WARN needs >= 2 distinct non-excluded families in alarm at once ('weak' (S7)"
            " and the canary families never count), so the WARN/week figure above is a"
            " structural zero, not evidence about the thresholds."
        )
    else:
        lines.append("  acceptance criterion:    MET -- no threshold change suggested")
    return "\n".join(lines)

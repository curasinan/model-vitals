from __future__ import annotations

import json
import random
import sqlite3
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from corpus import schema
from corpus.boundary import load_corpus, read_manifest
from corpus.inject import InjectionClass, inject
from corpus.lower import LoweringReport, lower_corpus
from corpus.synthetic import SYNTHETIC_WORLD_VERSION, build_synthetic_world
from vitals.alert.rules import evaluate as evaluate_alerts
from vitals.canary.checkers import default_tasks_dir, load_tasks
from vitals.config import DetectCfg
from vitals.db import get_conn
from vitals.detect import signal_ids as sid
from vitals.detect.attribution import BUCKET_ORDER, classify
from vitals.detect.engine import CANARY_MIN_CYCLES, tick

__all__ = [
    "CLEAR_VARIANTS",
    "GATING_PROFILE",
    "GATING_WORLD",
    "LADDER",
    "MATCH_RATE_FLOOR",
    "PROFILES",
    "WORLDS",
    "cfg_for_profile",
    "dump_metrics",
    "ladder_for",
    "long_context_task_ids",
    "run_eval",
    "total_fired",
]

WORLDS: dict[str, str] = {
    "synthetic": (
        "the deterministic versioned corpus corpus.synthetic builds in code -- reproducible,"
        " and the only world where the A/B/C attribution diagonal is reachable, so it is what"
        " the structural gate binds to"
    ),
    "real": (
        "the committed corpus on disk -- higher fidelity, measured and published in full,"
        " gating nothing; see metrics['limitations'] for what its own history makes unreachable"
    ),
}
GATING_WORLD = "synthetic"
GATING_PROFILE = "default"

_LIMITATION_MECHANISMS: dict[str, str] = {
    "single_tick_clustering": (
        "single-tick clustering artifact: one tick replays the whole corpus, so the anomalies"
        " whose CUSUM never decays before the corpus ends are all still open at now_iso."
        " rules._gap_hours treats an open occurrence as active through now, so EVERY open"
        " occurrence lands in ONE draft. That makes class A unconfinable and anchors rule 2's"
        " 24h lookback at the oldest anomaly in the cluster rather than near the injected"
        " change point. Incremental replay is recorded as a follow-up; until then these"
        " attributions are about the cluster, not about the injection."
    ),
    "class_a_bucket_contrast": (
        "class A needs a bucket contrast the corpus may not contain: attribution rule 3 grants"
        " class A only when a context bucket strictly BELOW the alarming one holds a live"
        " baseline for one of the alert's own signals and stays quiet. edit_loop_rate (S5)"
        " cannot supply it either -- it is written under context_bucket='all' and carries no"
        " intrinsic contrast. Where no lower bucket baselines, class A is unreachable however"
        " the detector behaves, and baseline densification (--augment-baselines) supplies the"
        " baselines without making A's CLEAR fire."
    ),
    "turn_features_join_rate": (
        "turn_features prompts that no requests row anchors: turn_features carries no timestamp"
        " and is placed in time by the (session_hash, prompt_seq) -> requests join, so a prompt"
        " that misses it reaches no store table at all and the S5 mirror never sees it. A"
        " question for the extractor owner, not a detector finding."
    ),
}

REAL_WORLD_LIMITATIONS: tuple[str, ...] = tuple(_LIMITATION_MECHANISMS)

CLASSES: tuple[InjectionClass, ...] = ("A", "B", "C")

FP_SEVERITIES: frozenset[str] = frozenset({"WARN", "CRITICAL"})

_SEVERITY_RANK: dict[str, int] = {"CRITICAL": 0, "WARN": 1, "INFO": 2}

MATCH_RATE_FLOOR = 0.80

AUGMENT_SEED = 0

ROWS_WRITTEN_FLOORS: dict[str, int] = {
    "sessions": 1,
    "api_requests": 1,
    "signal_windows": 1,
    "canary_cycles": 1,
    "canary_runs": 1,
    "change_points": 1,
}


def _default_cfg() -> DetectCfg:
    return DetectCfg()


def _desensitised_cfg() -> DetectCfg:
    return replace(DetectCfg(), h=50.0)


PROFILES: dict[str, str] = {
    "default": "the shipping DetectCfg, unmodified -- the only gating profile",
    "desensitised": "h = 50.0, diagnostic only: never gates, never exits non-zero",
}


def cfg_for_profile(name: str) -> DetectCfg:
    if name == "default":
        return _default_cfg()
    if name == "desensitised":
        return _desensitised_cfg()
    raise ValueError(f"unknown profile {name!r}; must be one of {sorted(PROFILES)}")


_A_SEED = 12
_B_SEED = 7
_C_SEED = 5

_LADDER_A: list[Mapping[str, object]] = [
    {
        "seed": _A_SEED,
        "magnitude": 1.5,
        "magnitude_latency": 1.15,
        "error_frac": 0.0,
        "n_sessions": 2,
        "n_prompts": 10,
    },
    {
        "seed": _A_SEED,
        "magnitude": 2.5,
        "magnitude_latency": 1.4,
        "error_frac": 0.0,
        "n_sessions": 2,
        "n_prompts": 10,
    },
    {
        "seed": _A_SEED,
        "magnitude": 4.0,
        "magnitude_latency": 1.8,
        "error_frac": 0.0,
        "n_sessions": 2,
        "n_prompts": 10,
    },
    {
        "seed": _A_SEED,
        "magnitude": 4.0,
        "magnitude_latency": 1.8,
        "error_frac": 0.5,
        "n_sessions": 2,
        "n_prompts": 10,
    },
]

_LADDER_B: list[Mapping[str, object]] = [
    {
        "seed": _B_SEED,
        "kind": "plugins",
        "at_frac": 0.7,
        "magnitude_tokens": 1.06,
        "magnitude_latency": 1.02,
    },
    {
        "seed": _B_SEED,
        "kind": "plugins",
        "at_frac": 0.7,
        "magnitude_tokens": 1.20,
        "magnitude_latency": 1.10,
    },
    {
        "seed": _B_SEED,
        "kind": "plugins",
        "at_frac": 0.7,
        "magnitude_tokens": 1.40,
        "magnitude_latency": 1.30,
    },
    {
        "seed": _B_SEED,
        "kind": "plugins",
        "at_frac": 0.7,
        "magnitude_tokens": 1.60,
        "magnitude_latency": 1.50,
    },
]

_LADDER_C: list[Mapping[str, object]] = [
    {"seed": _C_SEED, "drop_to": 0.90, "n_cycles": 4},
    {"seed": _C_SEED, "drop_to": 0.70, "n_cycles": 4},
    {"seed": _C_SEED, "drop_to": 0.55, "n_cycles": 4},
    {"seed": _C_SEED, "drop_to": 0.40, "n_cycles": 4},
]

LADDER: dict[str, list[Mapping[str, object]]] = {
    "A": _LADDER_A,
    "B": _LADDER_B,
    "C": _LADDER_C,
}

CLEAR_VARIANTS: dict[str, Mapping[str, object]] = {
    "A": _LADDER_A[2],
    "B": _LADDER_B[3],
    "C": _LADDER_C[3],
}


def ladder_for(cls: str) -> list[Mapping[str, object]]:
    rungs = LADDER.get(cls, [])
    if not rungs:
        raise ValueError(
            f"class {cls!r} has an empty ladder: there is nothing to compute a recall over, and"
            " a recall of 0/0 would be reported as a miss rather than as an unrun experiment"
        )
    return list(rungs)


def long_context_task_ids() -> frozenset[str]:
    return frozenset(task.task_id for task in load_tasks(default_tasks_dir()) if task.long_context)


def _corpus_end(corpus: Mapping[str, Any]) -> datetime:
    import pyarrow.compute as pc

    latest: datetime | None = None
    for name in ("requests", "canary_cycles", "change_points"):
        table = corpus.get(name)
        if table is None or table.num_rows == 0:
            continue
        moment = pc.max(table.column("ts_bucket_utc")).as_py()
        if isinstance(moment, datetime) and (latest is None or moment > latest):
            latest = moment
    if latest is None:
        raise ValueError(
            "this corpus has no timestamped row in requests, canary_cycles or change_points,"
            " so there is no hour a detector tick could be anchored to"
        )
    return latest.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def _hour_iso(moment: datetime) -> str:
    return (
        moment.astimezone(UTC)
        .replace(minute=0, second=0, microsecond=0)
        .isoformat(timespec="seconds")
    )


def _changed_row_mask(clean: Any, injected: Any) -> Any:
    import pyarrow as pa
    import pyarrow.compute as pc

    rows = min(clean.num_rows, injected.num_rows)
    left, right = clean.slice(0, rows), injected.slice(0, rows)
    mask: Any = pa.array([False] * rows, type=pa.bool_())
    for field in left.schema:
        if field.name == "ts_bucket_utc":
            continue
        a, b = left.column(field.name), right.column(field.name)
        differs = pc.fill_null(pc.not_equal(a, b), False)
        null_moved = pc.not_equal(pc.is_null(a), pc.is_null(b))
        mask = pc.or_(mask, pc.or_(differs, null_moved))
    return mask


def _earliest_perturbed_hour(clean: Mapping[str, Any], injected: Mapping[str, Any]) -> str | None:
    import pyarrow.compute as pc

    earliest: datetime | None = None
    for name in ("requests", "canary_cycles", "change_points"):
        before, after = clean.get(name), injected.get(name)
        if before is None or after is None or after.num_rows == 0:
            continue
        stamps = after.column("ts_bucket_utc")
        candidates = []
        shared = min(before.num_rows, after.num_rows)
        if shared:
            changed = pc.filter(stamps.slice(0, shared), _changed_row_mask(before, after))
            if changed.length():
                candidates.append(pc.min(changed).as_py())
        if after.num_rows > shared:
            candidates.append(pc.min(stamps.slice(shared)).as_py())
        for moment in candidates:
            if isinstance(moment, datetime) and (earliest is None or moment < earliest):
                earliest = moment
    return None if earliest is None else _hour_iso(earliest)


def _augment_baselines(
    conn: sqlite3.Connection, cfg: DetectCfg, *, before_iso: str, seed: int
) -> dict[str, int]:
    rng = random.Random(seed)
    since = _hour_iso(datetime.fromisoformat(before_iso) - timedelta(days=cfg.baseline_days))
    inserted: dict[str, int] = {}

    strata = conn.execute(
        "SELECT DISTINCT signal, model, context_bucket, cc_version FROM signal_windows"
        " WHERE window_start < ? ORDER BY signal, model, context_bucket, cc_version",
        (before_iso,),
    ).fetchall()

    for stratum in strata:
        key = (
            stratum["signal"],
            stratum["model"],
            stratum["context_bucket"],
            stratum["cc_version"],
        )
        sources = conn.execute(
            "SELECT window_start, value, n FROM signal_windows WHERE signal=? AND model=?"
            " AND context_bucket=? AND cc_version=? AND window_start < ? ORDER BY window_start",
            (*key, before_iso),
        ).fetchall()
        if not sources:  # pragma: no cover
            continue
        occupied = {row["window_start"] for row in sources}
        inside = [row for row in sources if row["window_start"] >= since]
        windows = len(inside)
        samples = sum(int(row["n"]) for row in inside)
        if windows >= cfg.min_windows and samples >= cfg.min_samples:
            continue
        pool = inside or sources

        added = 0
        hour = datetime.fromisoformat(before_iso) - timedelta(hours=1)
        floor = datetime.fromisoformat(since)
        while hour >= floor and (windows < cfg.min_windows or samples < cfg.min_samples):
            stamp = _hour_iso(hour)
            hour -= timedelta(hours=1)
            if stamp in occupied:
                continue
            source = pool[rng.randrange(len(pool))]
            conn.execute(
                "INSERT OR IGNORE INTO signal_windows(window_start, signal, model,"
                " context_bucket, value, n, cc_version) VALUES (?,?,?,?,?,?,?)",
                (stamp, key[0], key[1], key[2], source["value"], source["n"], key[3]),
            )
            occupied.add(stamp)
            windows += 1
            samples += int(source["n"])
            added += 1
        if added:
            inserted["|".join(str(part) for part in key)] = added

    conn.commit()
    return inserted


_Fingerprint = tuple[str, str, str, str, str]


@dataclass(frozen=True)
class _Prepared:
    letter: InjectionClass
    params: Mapping[str, object]
    injected: Mapping[str, Any] | None
    error: str | None


@dataclass(frozen=True)
class _DraftRecord:
    severity: str
    anomaly_ids: tuple[int, ...]
    cls: str


@dataclass(frozen=True)
class _Run:
    fingerprints: Mapping[int, _Fingerprint]
    drafts: tuple[_DraftRecord, ...]
    windows_processed: int
    canary_cycles_valid: int
    report: LoweringReport
    match_rate: Mapping[str, float]
    match_mapped: Mapping[str, int]
    augmented: Mapping[str, int]
    baseline_buckets: Mapping[str, list[str]]


def _baseline_buckets(conn: sqlite3.Connection) -> dict[str, list[str]]:
    buckets: dict[str, set[str]] = {}
    for row in conn.execute(
        "SELECT DISTINCT signal, context_bucket FROM detector_state WHERE mu0 IS NOT NULL"
    ):
        if row["context_bucket"] in BUCKET_ORDER:
            buckets.setdefault(str(row["signal"]), set()).add(str(row["context_bucket"]))
    return {
        signal: sorted(found, key=BUCKET_ORDER.index) for signal, found in sorted(buckets.items())
    }


def _windows_processed(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COALESCE(SUM(windows_evaluated), 0) FROM detector_state").fetchone()
    return int(row[0])


def _canary_cycles_valid(conn: sqlite3.Connection, cfg: DetectCfg) -> int:
    valid = 0
    for row in conn.execute(
        "SELECT n_runs, n_invalid, pass_rate, aborted_reason FROM canary_cycles"
    ):
        if row["aborted_reason"] or row["pass_rate"] is None:
            continue
        runs = int(row["n_runs"] or 0)
        if runs <= 0 or (runs - int(row["n_invalid"] or 0)) < cfg.canary_min_valid_fraction * runs:
            continue
        valid += 1
    return valid


def _match_rates(
    corpus: Mapping[str, Any], conn: sqlite3.Connection, report: LoweringReport
) -> tuple[dict[str, float], dict[str, int]]:

    def rows(table: str) -> int:
        arrow = corpus.get(table)
        return 0 if arrow is None else int(arrow.num_rows)

    def count(sql: str) -> int:
        return int(conn.execute(sql).fetchone()[0])

    mapped = {
        "requests": count("SELECT COUNT(*) FROM api_requests")
        + count("SELECT COUNT(*) FROM api_errors"),
        "change_points": count("SELECT COUNT(*) FROM change_points"),
        "canary_cycles": count(
            "SELECT COUNT(*) FROM (SELECT DISTINCT cycle_id, task_id FROM canary_runs)"
        ),
        "turn_features": rows("turn_features")
        - report.unmapped.get("turn_features.no_request_hour", 0),
        "tool_results": rows("tool_results")
        - report.unmapped.get("tool_results.no_request_hour", 0),
    }
    rates: dict[str, float] = {}
    for table in schema.TABLES:
        total = rows(table)
        rates[table] = 1.0 if total == 0 else round(mapped.get(table, 0) / total, 4)
    return rates, mapped


def _run_once(
    corpus: Mapping[str, Any],
    *,
    cfg: DetectCfg,
    now_iso: str,
    augment_before: str | None,
) -> _Run:
    with tempfile.TemporaryDirectory(prefix="vitals-gate1-") as tmp:
        conn = get_conn(Path(tmp) / "eval.db")
        try:
            report = lower_corpus(corpus, conn)
            match_rate, match_mapped = _match_rates(corpus, conn, report)
            augmented: dict[str, int] = {}
            if augment_before is not None:
                augmented = _augment_baselines(
                    conn, cfg, before_iso=augment_before, seed=AUGMENT_SEED
                )

            tick(conn, cfg, now_iso)

            fingerprints: dict[int, _Fingerprint] = {
                int(row["id"]): (
                    str(row["signal"]),
                    str(row["model"] or ""),
                    str(row["context_bucket"] or ""),
                    str(row["cc_version"] or ""),
                    str(row["started_at"] or ""),
                )
                for row in conn.execute(
                    "SELECT id, signal, model, context_bucket, cc_version, started_at"
                    " FROM anomalies ORDER BY id"
                )
            }
            drafts: list[_DraftRecord] = []
            for draft in evaluate_alerts(conn, cfg, now_iso):
                drafts.append(
                    _DraftRecord(
                        severity=str(draft.severity),
                        anomaly_ids=tuple(sorted(int(i) for i in draft.anomaly_ids)),
                        cls=str(classify(conn, draft, now_iso).cls),
                    )
                )
            drafts.sort(key=lambda d: (_SEVERITY_RANK.get(d.severity, 9), d.anomaly_ids))
            return _Run(
                fingerprints=fingerprints,
                drafts=tuple(drafts),
                windows_processed=_windows_processed(conn),
                canary_cycles_valid=_canary_cycles_valid(conn, cfg),
                report=report,
                match_rate=match_rate,
                match_mapped=match_mapped,
                augmented=augmented,
                baseline_buckets=_baseline_buckets(conn),
            )
        finally:
            conn.close()


def _new_anomaly_ids(run: _Run, clean: frozenset[_Fingerprint]) -> set[int]:
    return {
        anomaly_id
        for anomaly_id, fingerprint in run.fingerprints.items()
        if fingerprint not in clean
    }


def _attributed_class(run: _Run, new_ids: set[int]) -> str | None:
    carriers = [(len(set(draft.anomaly_ids) & new_ids), draft) for draft in run.drafts]
    live = [(count, draft) for count, draft in carriers if count > 0]
    if not live:
        return None
    best = min(
        live,
        key=lambda item: (
            -item[0],
            _SEVERITY_RANK.get(item[1].severity, 9),
            item[1].anomaly_ids,
        ),
    )
    return best[1].cls


def dump_metrics(metrics: Mapping[str, object]) -> str:
    return json.dumps(metrics, sort_keys=True, allow_nan=False, indent=2)


def total_fired(metrics: Mapping[str, Any]) -> int:
    return sum(
        1
        for block in metrics["classes"].values()
        for variant in block["variants"]
        if variant["fired"]
    )


def run_eval(
    corpus_dir: Path | str | None = None,
    *,
    world: str = GATING_WORLD,
    cfg: DetectCfg | None = None,
    profile_name: str = GATING_PROFILE,
    augment_baselines: bool = False,
) -> dict[str, object]:
    if world not in WORLDS:
        raise ValueError(f"unknown world {world!r}; must be one of {sorted(WORLDS)}")
    cfg = cfg if cfg is not None else cfg_for_profile(profile_name)

    if world == "synthetic":
        corpus = build_synthetic_world()
        manifest: dict[str, Any] = {}
        world_version: str | None = SYNTHETIC_WORLD_VERSION
    else:
        if corpus_dir is None:
            raise ValueError(
                "world='real' evaluates the COMMITTED corpus, so --corpus / corpus_dir is"
                " required; the synthetic world is the one that needs no directory"
            )
        directory = Path(corpus_dir)
        corpus = load_corpus(directory)
        manifest = read_manifest(directory)
        world_version = None

    now_iso = _hour_iso(_corpus_end(corpus) + timedelta(hours=1))
    long_context = long_context_task_ids()

    prepared: list[_Prepared] = []
    for letter in CLASSES:
        for params in ladder_for(letter):
            try:
                prepared.append(_Prepared(letter, params, inject(corpus, letter, params), None))
            except (ValueError, NotImplementedError) as exc:
                prepared.append(_Prepared(letter, params, None, str(exc)))

    augment_before: str | None = None
    if augment_baselines:
        hours = [
            hour
            for entry in prepared
            if entry.injected is not None
            and (hour := _earliest_perturbed_hour(corpus, entry.injected)) is not None
        ]
        augment_before = min(hours) if hours else now_iso

    clean = _run_once(corpus, cfg=cfg, now_iso=now_iso, augment_before=augment_before)
    clean_fingerprints = frozenset(clean.fingerprints.values())

    classes: dict[str, object] = {}
    for letter in CLASSES:
        variants: list[dict[str, object]] = []
        for entry in prepared:
            if entry.letter != letter:
                continue
            if entry.injected is None:
                variants.append(
                    {
                        "params": dict(entry.params),
                        "fired": False,
                        "attributed": None,
                        "anomalies": 0,
                        "injection_error": entry.error,
                    }
                )
                continue
            run = _run_once(entry.injected, cfg=cfg, now_iso=now_iso, augment_before=augment_before)
            new_ids = _new_anomaly_ids(run, clean_fingerprints)
            variants.append(
                {
                    "params": dict(entry.params),
                    "fired": bool(new_ids),
                    "attributed": _attributed_class(run, new_ids) if new_ids else None,
                    "anomalies": len(new_ids),
                    "injection_error": None,
                }
            )
        clear = dict(CLEAR_VARIANTS[letter])
        matched = next((v for v in variants if v["params"] == clear), None)
        classes[letter] = {
            "variants": variants,
            "recall": round(sum(1 for v in variants if v["fired"]) / len(variants), 4),
            "clear_fired": bool(matched and matched["fired"]),
            "clear_attributed": matched["attributed"] if matched else None,
        }

    metrics: dict[str, object] = {
        "world": world,
        "profile": profile_name,
        "cfg": {"k": cfg.k, "h": cfg.h, "lam": cfg.lam, "K_cycles": cfg.K_cycles},
        "limitations": [],
        "corpus": {
            "span_hours": clean.report.span_hours,
            "row_counts": {name: int(table.num_rows) for name, table in sorted(corpus.items())},
            "hmac_key_id": manifest.get("hmac_key_id"),
            "long_context_task_ids": len(long_context),
            "synthetic_world_version": world_version,
        },
        "lowering": {
            "rows_written": dict(sorted(clean.report.rows_written.items())),
            "signals_written": dict(sorted(clean.report.signals_written.items())),
            "unmapped": dict(sorted(clean.report.unmapped.items())),
            "match_rate": dict(sorted(clean.match_rate.items())),
            "augmented": dict(sorted(clean.augmented.items())),
        },
        "clean": {
            "anomalies": len(clean.fingerprints),
            "drafts": len(clean.drafts),
            "fp_count": sum(1 for d in clean.drafts if d.severity in FP_SEVERITIES),
            "attributions": _attribution_counts(clean.drafts),
            "windows_processed": clean.windows_processed,
            "canary_cycles_valid": clean.canary_cycles_valid,
            "baseline_buckets": {
                signal: list(buckets) for signal, buckets in sorted(clean.baseline_buckets.items())
            },
        },
        "classes": classes,
    }
    violations = _structural_failures(metrics, clean, corpus, long_context)
    gating = world == GATING_WORLD and profile_name == GATING_PROFILE
    metrics["gate1"] = {
        "gating": gating,
        "structural_pass": not violations,
        "failures": violations if gating else [],
        "observations": [] if gating else violations,
    }
    if world == "real":
        metrics["limitations"] = _limitation_notes(metrics, clean)
    return metrics


_CONTRAST_SIGNALS: tuple[str, ...] = (sid.S1_LATENCY_P95, sid.S1B_LATENCY_P50)


def _limitation_notes(metrics: Mapping[str, Any], clean: _Run) -> list[str]:
    row_counts: Mapping[str, int] = metrics["corpus"]["row_counts"]
    unmapped: Mapping[str, int] = metrics["lowering"]["unmapped"]
    match_rate: Mapping[str, float] = metrics["lowering"]["match_rate"]
    span_hours = int(metrics["corpus"]["span_hours"])
    clean_block: Mapping[str, Any] = metrics["clean"]

    notes: list[str] = []

    days = span_hours // 24
    notes.append(
        f"{_LIMITATION_MECHANISMS['single_tick_clustering']} Observed here: {span_hours} hours"
        f" ({days} days) replayed in a single tick, {clean_block['anomalies']} clean"
        f" anomalies collapsing into {clean_block['drafts']} draft(s)."
    )

    contrast = sorted(
        {
            bucket
            for signal in _CONTRAST_SIGNALS
            for bucket in clean.baseline_buckets.get(signal, [])
        },
        key=BUCKET_ORDER.index,
    )
    if not contrast:
        observed = (
            f"Observed here: no context bucket holds a live baseline for"
            f" {'/'.join(_CONTRAST_SIGNALS)} at all, so the contrast is not measurable in this"
            " corpus."
        )
    elif len(contrast) == 1:
        observed = (
            f"Observed here: {'/'.join(_CONTRAST_SIGNALS)} baseline in {contrast[0]} and"
            " nowhere else, so no strictly lower bucket exists to contrast against."
        )
    else:
        observed = (
            f"Observed here: {'/'.join(_CONTRAST_SIGNALS)} baseline in"
            f" {', '.join(contrast)}, so {contrast[0]} is available as a contrast below"
            f" {contrast[-1]}."
        )
    notes.append(f"{_LIMITATION_MECHANISMS['class_a_bucket_contrast']} {observed}")

    total = int(row_counts.get("turn_features", 0))
    unanchored = int(unmapped.get("turn_features.no_request_hour", 0))
    if total == 0:
        observed = "Observed here: this corpus carries no turn_features rows, so nothing joins."
    else:
        observed = (
            f"Observed here: {unanchored} of {total} prompts are unanchored, a join rate of"
            f" {match_rate['turn_features']:.4f}."
        )
    notes.append(f"{_LIMITATION_MECHANISMS['turn_features_join_rate']} {observed}")
    return notes


def _attribution_counts(drafts: Sequence[_DraftRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for draft in drafts:
        counts[draft.cls] = counts.get(draft.cls, 0) + 1
    return dict(sorted(counts.items()))


def _structural_failures(
    metrics: Mapping[str, Any],
    clean: _Run,
    corpus: Mapping[str, Any],
    long_context: frozenset[str],
) -> list[str]:
    failures: list[str] = []

    for letter in CLASSES:
        block = metrics["classes"][letter]
        if not block["clear_fired"]:
            failures.append(f"clear:{letter} the CLEAR variant opened no new anomaly")
        elif block["clear_attributed"] != letter:
            failures.append(
                f"clear:{letter} attributed to {block['clear_attributed']!r}, not {letter!r}"
            )

    written = clean.report.rows_written
    for table, floor in sorted(ROWS_WRITTEN_FLOORS.items()):
        if written.get(table, 0) < floor:
            failures.append(
                f"rows_written:{table} lowered {written.get(table, 0)} rows, floor is {floor}"
            )

    if clean.windows_processed <= 0:
        failures.append(
            "windows_processed the tick standardised no window at all, so nothing was measured"
        )

    canary_rows = corpus.get("canary_cycles")
    if canary_rows is not None and canary_rows.num_rows > 0:
        if clean.canary_cycles_valid < CANARY_MIN_CYCLES:
            failures.append(
                f"canary_cycles_valid {clean.canary_cycles_valid} valid cycles lowered,"
                f" floor is CANARY_MIN_CYCLES={CANARY_MIN_CYCLES}"
            )
        if not long_context:
            failures.append(
                "long_context_task_ids resolved EMPTY while the corpus has canary rows -- the"
                " cheap-suite filter in corpus.lower._lower_canaries stops filtering and signal"
                " C2 gets no series, both silently"
            )

    def _table_rows(table: str) -> int:
        arrow = corpus.get(table)
        return 0 if arrow is None else int(arrow.num_rows)

    for table, rate in sorted(clean.match_rate.items()):
        if rate < MATCH_RATE_FLOOR:
            failures.append(
                f"match_rate:{table} {rate:.4f} of its rows reached the store, floor is"
                f" {MATCH_RATE_FLOOR:.2f}"
            )
        mapped_n = clean.match_mapped.get(table, 0)
        total_n = _table_rows(table)
        if mapped_n > total_n:
            failures.append(
                f"match_rate:{table} mapped {mapped_n} > total {total_n} (double-routing)"
            )
    return failures

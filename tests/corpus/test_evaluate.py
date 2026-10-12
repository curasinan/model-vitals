from __future__ import annotations

import json
import re
import tempfile
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pyarrow.parquet as pq
import pytest

from corpus import evaluate as ev
from corpus import schema
from corpus.inject import inject
from corpus.lower import LoweringReport, lower_corpus
from corpus.synthetic import (
    HIGH_BUCKET,
    LOW_BUCKET,
    REQUESTS_PER_BUCKET,
    SESSIONS,
    SYNTHETIC_WORLD_VERSION,
    WORLD_HOURS,
    build_synthetic_world,
)
from vitals.config import DetectCfg
from vitals.db import get_conn, init_db
from vitals.detect import signal_ids as sid
from vitals.detect.baseline import compute_for

TEST_CFG = DetectCfg(min_windows=30, min_samples=50)

SMALL_HOURS = 24

_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def write_corpus(corpus: dict[str, Any], directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, table in corpus.items():
        pq.write_table(table, directory / f"{name}.parquet")
    (directory / "manifest.json").write_text(
        json.dumps(
            {
                "corpus_schema_version": schema.SCHEMA_VERSION,
                "hmac_key_id": "test-fixture-key:0000",
                "row_counts": {name: table.num_rows for name, table in corpus.items()},
            }
        ),
        encoding="utf-8",
    )
    return directory


@pytest.fixture(scope="module")
def small_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return write_corpus(
        build_synthetic_world(hours=SMALL_HOURS), tmp_path_factory.mktemp("small-corpus")
    )


@pytest.fixture(scope="module")
def default_metrics() -> dict[str, Any]:
    return ev.run_eval(cfg=TEST_CFG)


@pytest.fixture(scope="module")
def measured_metrics(small_dir: Path) -> dict[str, Any]:
    return ev.run_eval(small_dir, world="real", cfg=TEST_CFG)


def test_clean_run_produces_metrics_shape(default_metrics: dict[str, Any]) -> None:
    assert set(default_metrics) == {
        "world",
        "profile",
        "cfg",
        "limitations",
        "corpus",
        "lowering",
        "clean",
        "classes",
        "gate1",
    }
    assert default_metrics["world"] == "synthetic"
    assert default_metrics["profile"] == "default"
    assert default_metrics["cfg"] == {"k": 0.5, "h": 5.0, "lam": 0.2, "K_cycles": 3}
    assert set(default_metrics["corpus"]) == {
        "span_hours",
        "row_counts",
        "hmac_key_id",
        "long_context_task_ids",
        "synthetic_world_version",
    }
    assert set(default_metrics["lowering"]) == {
        "rows_written",
        "signals_written",
        "unmapped",
        "match_rate",
        "augmented",
    }
    assert set(default_metrics["clean"]) == {
        "anomalies",
        "drafts",
        "fp_count",
        "attributions",
        "windows_processed",
        "canary_cycles_valid",
        "baseline_buckets",
    }
    assert set(default_metrics["classes"]) == {"A", "B", "C"}
    assert set(default_metrics["gate1"]) == {
        "gating",
        "structural_pass",
        "failures",
        "observations",
    }

    corpus = default_metrics["corpus"]
    assert corpus["synthetic_world_version"] == SYNTHETIC_WORLD_VERSION
    assert corpus["hmac_key_id"] is None
    assert corpus["row_counts"]["requests"] == (
        WORLD_HOURS * len(SESSIONS) * 2 * REQUESTS_PER_BUCKET
    )
    assert corpus["span_hours"] >= WORLD_HOURS

    for letter, block in default_metrics["classes"].items():
        assert set(block) == {"variants", "recall", "clear_fired", "clear_attributed"}
        assert block["variants"], f"class {letter} produced no variants"
        for variant in block["variants"]:
            assert set(variant) == {"params", "fired", "attributed", "anomalies", "injection_error"}


def test_the_clean_synthetic_world_is_quiet(default_metrics: dict[str, Any]) -> None:
    clean = default_metrics["clean"]
    assert clean["anomalies"] == 0
    assert clean["drafts"] == 0
    assert clean["fp_count"] == 0
    assert clean["windows_processed"] > 0
    assert clean["canary_cycles_valid"] >= 5


def test_clear_class_b_fires_and_attributes_b(default_metrics: dict[str, Any]) -> None:
    block = default_metrics["classes"]["B"]
    assert block["clear_fired"] is True
    assert block["clear_attributed"] == "B"
    assert 0.0 < block["recall"] <= 1.0


def test_every_class_reaches_its_own_letter_in_the_synthetic_world(
    default_metrics: dict[str, Any],
) -> None:
    for letter in ("A", "B", "C"):
        block = default_metrics["classes"][letter]
        assert block["clear_fired"] is True, f"class {letter} CLEAR did not fire"
        assert block["clear_attributed"] == letter, f"class {letter} -> {block['clear_attributed']}"
    assert default_metrics["gate1"]["gating"] is True
    assert default_metrics["gate1"]["failures"] == []
    assert default_metrics["gate1"]["structural_pass"] is True


def test_match_rate_is_reported_for_every_corpus_table(
    default_metrics: dict[str, Any],
) -> None:
    rates = default_metrics["lowering"]["match_rate"]
    assert set(rates) == set(schema.TABLES)
    assert all(rate >= ev.MATCH_RATE_FLOOR for rate in rates.values()), rates


def test_metrics_are_deterministic(default_metrics: dict[str, Any]) -> None:
    again = ev.run_eval(cfg=TEST_CFG)
    assert ev.dump_metrics(again) == ev.dump_metrics(default_metrics)


def test_no_wall_clock_in_metrics(default_metrics: dict[str, Any]) -> None:
    dumped = ev.dump_metrics(default_metrics)
    assert _DATE_RE.search(dumped) is None, _DATE_RE.search(dumped)


def test_desensitised_profile_lowers_recall(default_metrics: dict[str, Any]) -> None:
    blunt = ev.run_eval(cfg=replace(TEST_CFG, h=50.0), profile_name="desensitised")
    assert blunt["profile"] == "desensitised"
    assert blunt["cfg"]["h"] == 50.0
    assert blunt["gate1"]["gating"] is False
    assert ev.total_fired(blunt) < ev.total_fired(default_metrics)


def test_empty_ladder_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(ev.LADDER, "B", [])
    with pytest.raises(ValueError, match="ladder"):
        ev.ladder_for("B")


def test_every_clear_variant_is_a_rung_of_its_own_ladder() -> None:
    for letter, clear in ev.CLEAR_VARIANTS.items():
        assert dict(clear) in [dict(rung) for rung in ev.LADDER[letter]]


def test_metrics_dump_rejects_nan() -> None:
    with pytest.raises(ValueError, match="Out of range float"):
        ev.dump_metrics({"classes": {"A": {"recall": float("nan")}}})


def test_structural_pass_fails_when_lowering_is_gutted(monkeypatch: pytest.MonkeyPatch) -> None:

    def gutted(corpus: Any, conn: Any) -> LoweringReport:
        init_db(conn)
        return LoweringReport(rows_written={}, signals_written={}, unmapped={}, span_hours=0)

    monkeypatch.setattr(ev, "lower_corpus", gutted)
    monkeypatch.setattr(ev, "build_synthetic_world", lambda: build_synthetic_world(hours=24))
    metrics = ev.run_eval(cfg=TEST_CFG)

    assert metrics["gate1"]["gating"] is True
    assert metrics["gate1"]["structural_pass"] is False
    failures = metrics["gate1"]["failures"]
    assert any(f.startswith("rows_written:") for f in failures), failures
    assert any("windows_processed" in f for f in failures), failures
    assert any("canary_cycles_valid" in f for f in failures), failures


def test_match_rate_floor_fails_on_a_mostly_unmapped_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ev,
        "build_synthetic_world",
        lambda: build_synthetic_world(hours=24, orphan_turn_features=40),
    )
    metrics = ev.run_eval(cfg=TEST_CFG)

    rate = metrics["lowering"]["match_rate"]["turn_features"]
    assert rate < ev.MATCH_RATE_FLOOR, rate
    assert metrics["gate1"]["structural_pass"] is False
    assert any(f.startswith("match_rate:turn_features") for f in metrics["gate1"]["failures"]), (
        metrics["gate1"]["failures"]
    )


def test_mapped_exceeding_total_is_a_named_double_routing_failure() -> None:
    metrics: dict[str, Any] = {
        "classes": {
            letter: {"clear_fired": True, "clear_attributed": letter} for letter in ev.CLASSES
        },
    }
    corpus: dict[str, Any] = {"requests": SimpleNamespace(num_rows=100)}
    clean = ev._Run(
        fingerprints={},
        drafts=(),
        windows_processed=1,
        canary_cycles_valid=0,
        report=LoweringReport(
            rows_written=dict(ev.ROWS_WRITTEN_FLOORS),
            signals_written={},
            unmapped={},
            span_hours=1,
        ),
        match_rate={"requests": 1.25},
        match_mapped={"requests": 125},
        augmented={},
        baseline_buckets={},
    )

    failures = ev._structural_failures(metrics, clean, corpus, frozenset())

    assert any(f.startswith("match_rate:requests") and "double-routing" in f for f in failures), (
        failures
    )
    assert any("125" in f and "100" in f for f in failures), failures


def test_empty_long_context_task_ids_is_a_named_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ev, "long_context_task_ids", frozenset)
    monkeypatch.setattr(ev, "build_synthetic_world", lambda: build_synthetic_world(hours=24))
    metrics = ev.run_eval(cfg=TEST_CFG)

    assert metrics["corpus"]["long_context_task_ids"] == 0
    assert metrics["gate1"]["structural_pass"] is False
    assert any("long_context_task_ids" in f for f in metrics["gate1"]["failures"]), metrics[
        "gate1"
    ]["failures"]


def test_densification_fills_a_sparse_stratum_and_never_crosses_the_cutoff(
    tmp_path: Path,
) -> None:
    conn = get_conn(tmp_path / "store" / "eval.db")
    try:
        init_db(conn)
        cutoff = "2026-06-10T00:00:00+00:00"
        for hour in range(6):
            conn.execute(
                "INSERT INTO signal_windows(window_start, signal, model, context_bucket,"
                " value, n, cc_version) VALUES (?,?,?,?,?,?,?)",
                (
                    f"2026-06-09T{hour:02d}:00:00+00:00",
                    sid.S8_OUTPUT_TOKENS,
                    "claude-opus-5",
                    "gt180k",
                    1000.0 + hour,
                    4,
                    "2.1.250",
                ),
            )
        conn.commit()

        cfg = DetectCfg(min_windows=30, min_samples=50)
        added = ev._augment_baselines(conn, cfg, before_iso=cutoff, seed=99)
        assert added, "a stratum six windows deep must have been padded"

        rows = conn.execute(
            "SELECT window_start, value, n FROM signal_windows ORDER BY window_start"
        ).fetchall()
        assert len(rows) >= cfg.min_windows
        assert sum(int(r["n"]) for r in rows) >= cfg.min_samples
        assert all(r["window_start"] < cutoff for r in rows), "wrote at or after the cutoff"
        assert {r["value"] for r in rows} <= {1000.0 + hour for hour in range(6)}
    finally:
        conn.close()


def test_densification_is_deterministic_for_a_seed(tmp_path: Path) -> None:
    def pad(name: str, seed: int) -> list[tuple[str, float]]:
        conn = get_conn(tmp_path / name / "eval.db")
        try:
            init_db(conn)
            for hour in range(6):
                conn.execute(
                    "INSERT INTO signal_windows(window_start, signal, model, context_bucket,"
                    " value, n, cc_version) VALUES (?,?,?,?,?,?,?)",
                    (
                        f"2026-06-09T{hour:02d}:00:00+00:00",
                        sid.S8_OUTPUT_TOKENS,
                        "claude-opus-5",
                        "gt180k",
                        1000.0 + hour,
                        4,
                        "2.1.250",
                    ),
                )
            conn.commit()
            ev._augment_baselines(
                conn,
                DetectCfg(min_windows=30, min_samples=50),
                before_iso="2026-06-10T00:00:00+00:00",
                seed=seed,
            )
            return [
                (str(r["window_start"]), float(r["value"]))
                for r in conn.execute(
                    "SELECT window_start, value FROM signal_windows ORDER BY window_start"
                )
            ]
        finally:
            conn.close()

    assert pad("a", 99) == pad("b", 99)
    assert pad("c", 7) != pad("d", 99)


def test_every_run_in_an_augmented_eval_pads_from_the_same_seed(
    small_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seeds: list[int] = []
    real = ev._augment_baselines

    def spy(conn: Any, cfg: DetectCfg, *, before_iso: str, seed: int) -> dict[str, int]:
        seeds.append(seed)
        return real(conn, cfg, before_iso=before_iso, seed=seed)

    monkeypatch.setattr(ev, "_augment_baselines", spy)
    ev.run_eval(small_dir, world="real", cfg=TEST_CFG, augment_baselines=True)

    assert len(seeds) > 1, "the clean reference and at least one rung must both have been padded"
    assert set(seeds) == {ev.AUGMENT_SEED}, seeds


def test_the_augmentation_cutoff_is_the_hour_the_injection_starts_at() -> None:
    corpus = build_synthetic_world(hours=SMALL_HOURS)
    injected = inject(corpus, "C", dict(ev.CLEAR_VARIANTS["C"]))
    cutoff = ev._earliest_perturbed_hour(corpus, injected)

    cycles = injected["canary_cycles"].to_pylist()
    perturbed = min(
        row["ts_bucket_utc"]
        for row, before in zip(cycles, corpus["canary_cycles"].to_pylist(), strict=True)
        if row["passes"] != before["passes"]
    )
    assert cutoff == perturbed.isoformat(timespec="seconds")


def test_the_synthetic_world_is_byte_stable_across_builds() -> None:
    first, second = build_synthetic_world(), build_synthetic_world()
    assert set(first) == set(second) == set(schema.TABLES)
    for name in schema.TABLES:
        assert first[name].equals(second[name]), name
        assert first[name].to_pylist() == second[name].to_pylist(), name


def test_the_synthetic_world_can_baseline_under_the_SHIPPING_config() -> None:
    cfg = DetectCfg()
    world = build_synthetic_world()
    conn = get_conn(Path(tempfile.mkdtemp(prefix="vitals-gate1-baseline-")) / "eval.db")
    try:
        lower_corpus(world, conn)
        as_of = ev._hour_iso(ev._corpus_end(world) + timedelta(hours=1))
        buckets = {
            row["context_bucket"]
            for row in conn.execute(
                "SELECT DISTINCT signal, model, context_bucket, cc_version FROM signal_windows"
            )
            if compute_for(
                conn,
                cfg,
                row["signal"],
                row["model"],
                row["context_bucket"],
                row["cc_version"],
                as_of,
            )
            is not None
        }
    finally:
        conn.close()

    assert buckets, "no stratum can form a baseline under the shipping DetectCfg"
    assert {HIGH_BUCKET, LOW_BUCKET} <= buckets, buckets


def test_only_the_synthetic_default_combination_gates(
    measured_metrics: dict[str, Any], default_metrics: dict[str, Any]
) -> None:
    assert default_metrics["gate1"]["gating"] is True

    measured = measured_metrics
    assert measured["world"] == "real"
    assert measured["gate1"]["gating"] is False
    assert measured["gate1"]["structural_pass"] is False
    assert measured["gate1"]["failures"] == []
    assert measured["gate1"]["observations"], "a non-gating run must still publish what it found"


def test_only_the_real_world_publishes_limitations(
    measured_metrics: dict[str, Any], default_metrics: dict[str, Any]
) -> None:
    assert default_metrics["limitations"] == []

    measured = measured_metrics
    notes = measured["limitations"]
    assert len(notes) == len(ev.REAL_WORLD_LIMITATIONS)
    joined = " ".join(notes)
    for subject in ("clustering artifact", "class A needs a bucket contrast", "turn_features"):
        assert subject in joined, subject

    assert "class C collides" not in joined

    span_hours = measured["corpus"]["span_hours"]
    total = measured["corpus"]["row_counts"]["turn_features"]
    unanchored = measured["lowering"]["unmapped"].get("turn_features.no_request_hour", 0)
    rate = measured["lowering"]["match_rate"]["turn_features"]

    assert f"{span_hours} hours ({span_hours // 24} days)" in joined
    assert f"{measured['clean']['anomalies']} clean anomalies" in joined
    assert f"{measured['clean']['drafts']} draft(s)" in joined
    assert f"{unanchored} of {total} prompts are unanchored" in joined
    assert f"join rate of {rate:.4f}" in joined

    buckets = {
        bucket
        for signal in (sid.S1_LATENCY_P95, sid.S1B_LATENCY_P50)
        for bucket in measured["clean"]["baseline_buckets"].get(signal, [])
    }
    if buckets:
        assert all(bucket in joined for bucket in buckets), (buckets, joined)
    else:
        assert "not measurable in this corpus" in joined


def test_the_real_world_needs_a_corpus_directory() -> None:
    with pytest.raises(ValueError, match="required"):
        ev.run_eval(None, world="real")


def test_an_unknown_world_is_an_error() -> None:
    with pytest.raises(ValueError, match="unknown world"):
        ev.run_eval(world="imaginary")


def _stub(**gate: Any) -> Any:
    base = {"gating": False, "structural_pass": True, "failures": [], "observations": []}
    return lambda *a, **k: {
        "world": "synthetic",
        "profile": "default",
        "limitations": [],
        "corpus": {"synthetic_world_version": "1.0.0"},
        "gate1": {**base, **gate},
    }


def test_cli_exits_1_only_for_the_gating_combination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import detector_eval

    out = tmp_path / "metrics.json"

    monkeypatch.setattr(detector_eval, "run_eval", _stub(gating=True, structural_pass=True))
    assert detector_eval.main(["--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["gate1"]["structural_pass"] is True

    monkeypatch.setattr(
        detector_eval,
        "run_eval",
        _stub(gating=True, structural_pass=False, failures=["clear:A did not fire"]),
    )
    assert detector_eval.main(["--out", str(out)]) == 1

    monkeypatch.setattr(
        detector_eval,
        "run_eval",
        _stub(gating=False, structural_pass=False, observations=["clear:A did not fire"]),
    )
    assert (
        detector_eval.main(["--world", "real", "--corpus", str(tmp_path), "--out", str(out)]) == 0
    )
    assert detector_eval.main(["--out", str(out), "--profile", "desensitised"]) == 0


def test_cli_headline_names_the_world_and_whether_it_gates() -> None:
    import detector_eval

    gating = detector_eval.headline(_stub(gating=True, structural_pass=True)())
    assert "world=synthetic" in gating and "[GATING]" in gating and "PASS" in gating

    measured = _stub(gating=False, structural_pass=False)()
    measured["world"] = "real"
    measured["corpus"] = {"synthetic_world_version": None}
    line = detector_eval.headline(measured)
    assert "world=real" in line and "non-gating" in line and "FAIL" in line


def _metrics_stub(*, world: str = "synthetic", limitations: list[str] | None = None) -> dict:
    return {
        "world": world,
        "profile": "default",
        "limitations": limitations or [],
        "corpus": {"synthetic_world_version": "1.0.0" if world == "synthetic" else None},
        "gate1": {
            "gating": world == "synthetic",
            "structural_pass": True,
            "failures": [],
            "observations": [],
        },
        "classes": {
            "A": {"variants": [], "recall": 1.0, "clear_fired": True, "clear_attributed": "A"},
            "B": {"variants": [], "recall": 0.75, "clear_fired": True, "clear_attributed": "B"},
            "C": {"variants": [], "recall": 0.0, "clear_fired": False, "clear_attributed": None},
        },
        "clean": {
            "anomalies": 0,
            "drafts": 0,
            "fp_count": 3,
            "attributions": {},
            "windows_processed": 10,
            "canary_cycles_valid": 6,
            "baseline_buckets": {},
        },
    }


def test_summarize_renders_the_headline_class_table_and_fp_count() -> None:
    import detector_eval

    text = detector_eval.summarize(_metrics_stub())

    assert detector_eval.headline(_metrics_stub()) in text
    assert "| A | 1.0000 | True | A |" in text
    assert "| B | 0.7500 | True | B |" in text
    assert "| C | 0.0000 | False | None |" in text
    assert "clean.fp_count: 3" in text
    assert "limitations:" not in text


def test_summarize_is_both_worlds_aware_and_renders_real_world_limitations() -> None:
    import detector_eval

    notes = ["single-tick clustering artifact: ...", "class A needs a bucket contrast: ..."]
    text = detector_eval.summarize(_metrics_stub(world="real", limitations=notes))

    assert "world=real" in text
    assert "limitations:" in text
    for note in notes:
        assert f"- {note}" in text


def test_cli_summarize_reads_a_file_and_needs_no_out(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import detector_eval

    metrics_path = tmp_path / "metrics.json"
    metrics_path.write_text(json.dumps(_metrics_stub()), encoding="utf-8")

    code = detector_eval.main(["--summarize", str(metrics_path)])

    assert code == 0
    printed = capsys.readouterr().out
    assert printed == detector_eval.summarize(_metrics_stub())


def test_cli_requires_out_or_summarize() -> None:
    import detector_eval

    with pytest.raises(SystemExit):
        detector_eval.main([])

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from corpus import boundary, schema
from corpus import evaluate as ev

pytestmark = pytest.mark.slow

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_REAL_CORPUS = _REPO_ROOT / "corpus"

_SKIP_REASON = (
    "NO CORPUS AT ALL -- Task 4's real-world Gate 1 tests did not run against real data. Not "
    f"one of {', '.join(boundary.corpus_file_names())} is present under {_REAL_CORPUS}. "
    "Legitimate only on a checkout made before the first corpus data commit; once that commit "
    "exists these tests always run in CI, so a skip here means the corpus was deleted or never "
    "checked out -- investigate it, do not read it as a pass. A PARTIAL corpus does not skip: "
    "it runs and fails loudly, most likely inside corpus.boundary.load_corpus."
)
_needs_corpus = pytest.mark.skipif(boundary.corpus_is_absent(_REAL_CORPUS), reason=_SKIP_REASON)


@pytest.fixture(scope="module")
def synthetic_metrics() -> dict[str, Any]:
    return ev.run_eval()


@pytest.fixture(scope="module")
def real_metrics() -> dict[str, Any]:
    return ev.run_eval(_REAL_CORPUS, world="real")


def test_gate1_structural_pass_on_the_synthetic_world(
    synthetic_metrics: dict[str, Any],
) -> None:
    gate1 = synthetic_metrics["gate1"]
    assert gate1["gating"] is True
    assert gate1["structural_pass"] is True, gate1["failures"]
    assert gate1["failures"] == []


@pytest.mark.parametrize("letter", ["A", "B", "C"])
def test_each_clear_class_attributes_to_its_own_letter_on_the_synthetic_world(
    synthetic_metrics: dict[str, Any], letter: str
) -> None:
    block = synthetic_metrics["classes"][letter]
    assert block["clear_fired"] is True, f"class {letter} CLEAR did not fire"
    assert block["clear_attributed"] == letter, (
        f"class {letter} attributed to {block['clear_attributed']!r}, not {letter!r}"
    )


def test_desensitised_h50_drops_recall_on_the_synthetic_world(
    synthetic_metrics: dict[str, Any],
) -> None:
    blunt = ev.run_eval(profile_name="desensitised")
    assert blunt["profile"] == "desensitised"
    assert blunt["gate1"]["gating"] is False
    assert ev.total_fired(blunt) < ev.total_fired(synthetic_metrics)


def test_two_synthetic_runs_are_byte_identical(synthetic_metrics: dict[str, Any]) -> None:
    again = ev.run_eval()
    assert ev.dump_metrics(again) == ev.dump_metrics(synthetic_metrics)


@_needs_corpus
def test_real_world_run_publishes_observations_and_limitations(
    real_metrics: dict[str, Any],
) -> None:
    metrics = real_metrics
    gate1 = metrics["gate1"]

    assert isinstance(gate1["observations"], list)
    assert all(isinstance(item, str) and item for item in gate1["observations"])

    for letter in ("A", "B", "C"):
        block = metrics["classes"][letter]
        assert isinstance(block["clear_fired"], bool)
        assert "clear_attributed" in block
        assert block["variants"], f"class {letter} produced no variants"
        for variant in block["variants"]:
            assert "fired" in variant and isinstance(variant["fired"], bool)
            assert "attributed" in variant

    fp_count = metrics["clean"]["fp_count"]
    assert isinstance(fp_count, int) and not isinstance(fp_count, bool)
    assert fp_count >= 0

    rates = metrics["lowering"]["match_rate"]
    assert set(rates) == set(schema.TABLES)
    assert all(isinstance(rate, float) for rate in rates.values())

    limitations = metrics["limitations"]
    assert limitations, "the real world must publish its limitations, not just its numbers"
    assert all(isinstance(note, str) and note for note in limitations)


@_needs_corpus
def test_real_world_never_gates(
    real_metrics: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate1 = real_metrics["gate1"]
    assert gate1["gating"] is False
    failed = gate1["gating"] and not gate1["structural_pass"]
    assert failed is False
    assert gate1["failures"] == []

    import detector_eval

    monkeypatch.setattr(detector_eval, "run_eval", lambda *a, **k: real_metrics)
    out = tmp_path / "metrics-real.json"
    code = detector_eval.main(["--world", "real", "--corpus", str(_REAL_CORPUS), "--out", str(out)])
    assert code == 0
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["gate1"]["gating"] is False


@_needs_corpus
def test_two_real_runs_are_byte_identical(real_metrics: dict[str, Any]) -> None:
    again = ev.run_eval(_REAL_CORPUS, world="real")
    assert ev.dump_metrics(again) == ev.dump_metrics(real_metrics)

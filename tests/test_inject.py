from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from vitals.canary.checkers import TaskSpec
from vitals.canary.runner import run_cycle
from vitals.config import CanaryCfg, Config, DetectCfg
from vitals.db import get_conn, init_db
from vitals.detect import signal_ids as sid
from vitals.detect.engine import tick
from vitals.timeutil import hour_add, utcnow_iso
from vitals.validate import inject
from vitals.validate.inject import (
    DEFAULT_INJECT_MODEL,
    KINDS,
    SHIFT_HOURS,
    insert_fake_version_change_point,
    model_swap_drill,
    synthetic_stream,
)

FIXED_NOW = "2026-06-01T00:00:00+00:00"


def _conn(tmp_path: Path):
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)
    return conn


def test_synthetic_stream_rejects_an_unknown_kind(tmp_path):
    conn = _conn(tmp_path)
    with pytest.raises(ValueError, match="unknown injection kind"):
        synthetic_stream("not-a-real-kind", conn)


def test_synthetic_latency_shift_fires_with_direction_up(tmp_path):
    conn = _conn(tmp_path)
    synthetic_stream("latency_x1.5", conn, now_iso=FIXED_NOW)

    opened = tick(conn, DetectCfg(), FIXED_NOW)
    assert opened

    anomaly = conn.execute(
        "SELECT * FROM anomalies WHERE signal = ? AND cc_version = '1.0.0'", (sid.S1_LATENCY_P95,)
    ).fetchone()
    assert anomaly is not None
    assert anomaly["direction"] == "up"
    assert anomaly["id"] in opened

    last_healthy_hour = hour_add(FIXED_NOW, -(SHIFT_HOURS + 1))
    assert anomaly["started_at"] > last_healthy_hour

    collapsed = conn.execute(
        "SELECT * FROM anomalies WHERE signal = ? AND cc_version = 'any'", (sid.S1_LATENCY_P95,)
    ).fetchone()
    assert collapsed is not None
    assert collapsed["direction"] == "up"


@pytest.mark.parametrize(
    "kind,signal,expected_direction",
    [
        ("error_rate_x4", sid.S2_ERROR_RATE, "up"),
        ("tokens_drop_40pct", sid.S8_OUTPUT_TOKENS, "down"),
        ("post_compaction_2x", sid.S9_POST_COMPACTION_FAIL, "up"),
    ],
)
def test_synthetic_shift_opens_the_named_signal_in_the_right_direction(
    tmp_path, kind, signal, expected_direction
):
    conn = _conn(tmp_path)
    synthetic_stream(kind, conn, now_iso=FIXED_NOW)

    opened = tick(conn, DetectCfg(), FIXED_NOW)
    assert opened

    anomaly = conn.execute(
        "SELECT * FROM anomalies WHERE signal = ? AND cc_version = '1.0.0'", (signal,)
    ).fetchone()
    assert anomaly is not None, f"{kind} never opened an anomaly on {signal}"
    assert anomaly["direction"] == expected_direction


def test_all_four_kinds_are_exercised_by_the_parametrized_and_dedicated_tests():
    assert set(KINDS) == {
        "latency_x1.5",
        "error_rate_x4",
        "tokens_drop_40pct",
        "post_compaction_2x",
    }


_STUB_SOURCE = """\
import json
import os
import sys


def _read_stdin():
    try:
        if not sys.stdin.isatty():
            return sys.stdin.read()
    except Exception:
        pass
    return ""


stdin_data = _read_stdin().strip()
answer_map = json.loads(os.environ.get("VITALS_STUB_ANSWER_MAP", "{}"))
result_json = answer_map.get(
    stdin_data, json.dumps({"is_error": False, "subtype": "success", "result": "NO_MATCH"})
)
sys.stdout.write(result_json)
"""


def _write_stub(tmp_path: Path) -> Path:
    stub_path = tmp_path / "answer_stub.py"
    stub_path.write_text(_STUB_SOURCE, encoding="utf-8")
    return stub_path


def _make_task(tmp_path: Path, task_id: str, prompt: str, golden: str) -> TaskSpec:
    golden_dir = tmp_path / "tasks" / task_id / "golden"
    golden_dir.mkdir(parents=True)
    (golden_dir / "answer.txt").write_text(golden + "\n", encoding="utf-8")
    return TaskSpec(
        task_id=task_id,
        checker="exact",
        prompt=prompt,
        allowed_tools=[],
        max_turns=1,
        golden_dir=golden_dir,
    )


def _make_tasks(tmp_path: Path) -> list[TaskSpec]:
    return [
        _make_task(tmp_path, f"drill-{i}", f"drill prompt {i}", f"golden-{i}") for i in range(5)
    ]


def _cfg(tmp_path: Path) -> Config:
    return Config(
        data_dir=tmp_path,
        db_path=tmp_path / "vitals.db",
        spool_dir=tmp_path / "spool",
        reports_dir=tmp_path / "reports",
        canary=CanaryCfg(
            model="claude-sonnet-5",
            runs_per_task=1,
            long_context_daily=False,
            enabled=True,
            daily_budget_usd=1000.0,
            per_run_timeout_s=30,
        ),
        detect=DetectCfg(),
        channels={},
    )


def _correct_answer_map(tasks: list[TaskSpec]) -> dict:
    return {
        t.prompt: json.dumps({"is_error": False, "subtype": "success", "result": f"golden-{i}"})
        for i, t in enumerate(tasks)
    }


def test_the_drill_runs_more_cycles_than_the_rule_it_is_testing_needs(tmp_path):
    cfg = _cfg(tmp_path)
    assert inject.default_drill_cycles(cfg) > cfg.detect.K_cycles, (
        "the drill must have margin over K_cycles; equal means one lost cycle "
        "turns a detectable degradation into a silent one"
    )

    cfg.detect.K_cycles = 7
    assert inject.default_drill_cycles(cfg) > 7


def _canary_state(conn) -> str:
    cycles = conn.execute(
        "SELECT cycle_id, n_runs, n_pass, n_invalid, pass_rate, aborted_reason"
        " FROM canary_cycles ORDER BY cycle_id"
    ).fetchall()
    reasons = conn.execute(
        "SELECT terminal_reason, COUNT(*) AS n FROM canary_runs WHERE invalid = 1"
        " GROUP BY terminal_reason"
    ).fetchall()
    lines = [
        "cycles:",
        *[
            f"  #{r['cycle_id']} runs={r['n_runs']} pass={r['n_pass']}"
            f" invalid={r['n_invalid']} rate={r['pass_rate']} abort={r['aborted_reason']}"
            for r in cycles
        ],
        "invalid-run reasons: "
        + (", ".join(f"{r['terminal_reason']} x{r['n']}" for r in reasons) or "none"),
    ]
    return "\n" + "\n".join(lines)


def _seed_healthy_canary_history(conn, cfg, tasks, stub, monkeypatch, cycles=6):
    monkeypatch.setenv("VITALS_STUB_ANSWER_MAP", json.dumps(_correct_answer_map(tasks)))
    for _ in range(cycles):
        run_cycle(conn, cfg.canary, tasks, claude_cmd=[sys.executable, str(stub)])


@pytest.mark.slow
def test_model_swap_drill_offline_fires_critical_attributed_to_c_without_naming_haiku(
    tmp_path, monkeypatch
):
    conn = _conn(tmp_path)
    cfg = _cfg(tmp_path)
    init_db(conn)
    tasks = _make_tasks(tmp_path)
    stub = _write_stub(tmp_path)

    _seed_healthy_canary_history(conn, cfg, tasks, stub, monkeypatch)

    drill_map = _correct_answer_map(tasks)
    drill_map[tasks[0].prompt] = json.dumps(
        {"is_error": False, "subtype": "success", "result": "WRONG-0"}
    )
    drill_map[tasks[1].prompt] = json.dumps(
        {"is_error": False, "subtype": "success", "result": "WRONG-1"}
    )
    monkeypatch.setenv("VITALS_STUB_ANSWER_MAP", json.dumps(drill_map))

    results = model_swap_drill(
        conn, cfg, tasks, inject_model=DEFAULT_INJECT_MODEL, claude_cmd=[sys.executable, str(stub)]
    )

    critical = [(d, a) for d, a in results if d.severity == "CRITICAL"]
    assert critical, (
        f"expected a CRITICAL draft; got severities "
        f"{[d.severity for d, _ in results]}" + _canary_state(conn)
    )
    draft, attribution = critical[0]

    assert attribution.cls == "C"
    assert attribution.evidence["matched_rule"] == 4
    assert attribution.evidence["matched_rule_name"] == "provider_no_incident"
    rule4 = attribution.evidence["rules"][3]
    assert rule4["facts"]["branches_matched"] == ["a"]

    blob = json.dumps(attribution.evidence).lower() + draft.title.lower()
    assert "haiku" not in blob

    recorded_models = {r["model"] for r in conn.execute("SELECT DISTINCT model FROM canary_runs")}
    assert recorded_models == {cfg.canary.model}


@pytest.mark.slow
def test_model_swap_drill_with_version_cp_attributes_b_via_the_canary_aware_arm(
    tmp_path, monkeypatch
):
    conn = _conn(tmp_path)
    cfg = _cfg(tmp_path)
    init_db(conn)
    tasks = _make_tasks(tmp_path)
    stub = _write_stub(tmp_path)

    _seed_healthy_canary_history(conn, cfg, tasks, stub, monkeypatch)
    insert_fake_version_change_point(conn)

    drill_map = _correct_answer_map(tasks)
    drill_map[tasks[0].prompt] = json.dumps(
        {"is_error": False, "subtype": "success", "result": "WRONG-0"}
    )
    drill_map[tasks[1].prompt] = json.dumps(
        {"is_error": False, "subtype": "success", "result": "WRONG-1"}
    )
    monkeypatch.setenv("VITALS_STUB_ANSWER_MAP", json.dumps(drill_map))

    results = model_swap_drill(
        conn, cfg, tasks, inject_model=DEFAULT_INJECT_MODEL, claude_cmd=[sys.executable, str(stub)]
    )

    critical = [(d, a) for d, a in results if d.severity == "CRITICAL"]
    assert critical, (
        f"expected a CRITICAL draft; got severities "
        f"{[d.severity for d, _ in results]}" + _canary_state(conn)
    )
    draft, attribution = critical[0]

    assert attribution.cls != "C"
    assert attribution.cls == "B"
    assert attribution.evidence["matched_rule"] == 2
    assert attribution.evidence["matched_rule_name"] == "harness_change"

    rule2 = attribution.evidence["rules"][1]
    assert rule2["matched"] is True
    assert rule2["facts"]["postdates_test"] == "canary_temporal_contrast"

    rule4 = attribution.evidence["rules"][3]
    assert rule4["matched"] is False
    assert "a" not in rule4["facts"]["branches_matched"]
    assert "change point" in rule4["facts"]["branches"]["a"]["reason"]

    blob = json.dumps(attribution.evidence).lower() + draft.title.lower()
    assert "haiku" not in blob


@pytest.mark.slow
def test_model_swap_drill_does_not_mute_a_real_signals_info_alert_for_a_day(tmp_path, monkeypatch):
    from vitals.alert.rules import _info_kv_key, evaluate
    from vitals.db import kv_get

    conn = _conn(tmp_path)
    cfg = _cfg(tmp_path)
    init_db(conn)
    tasks = _make_tasks(tmp_path)
    stub = _write_stub(tmp_path)
    _seed_healthy_canary_history(conn, cfg, tasks, stub, monkeypatch)

    now = utcnow_iso()
    conn.execute(
        "INSERT INTO anomalies(signal, model, context_bucket, cc_version, started_at,"
        " direction, peak_stat, status) VALUES (?,?,?,?,?,?,?, 'open')",
        (sid.S1_LATENCY_P95, "claude-sonnet-5", "gt180k", "2.1.230", hour_add(now, -2), "up", 6.1),
    )
    conn.commit()

    drill_map = _correct_answer_map(tasks)
    drill_map[tasks[0].prompt] = json.dumps(
        {"is_error": False, "subtype": "success", "result": "WRONG-0"}
    )
    monkeypatch.setenv("VITALS_STUB_ANSWER_MAP", json.dumps(drill_map))
    model_swap_drill(
        conn, cfg, tasks, inject_model=DEFAULT_INJECT_MODEL, claude_cmd=[sys.executable, str(stub)]
    )

    assert kv_get(conn, _info_kv_key(sid.S1_LATENCY_P95)) is None
    drafts = evaluate(conn, cfg.detect, utcnow_iso())
    info = [d for d in drafts if d.severity == "INFO" and sid.S1_LATENCY_P95 in d.title]
    assert info, f"the latency INFO was muted by the drill; got {[d.title for d in drafts]}"
    assert info[0].info_dedup_signals == [sid.S1_LATENCY_P95]


def test_insert_fake_version_change_point_records_a_cc_version_row(tmp_path):
    conn = _conn(tmp_path)
    row_id = insert_fake_version_change_point(conn)
    row = conn.execute("SELECT * FROM change_points WHERE id = ?", (row_id,)).fetchone()
    assert row["kind"] == "cc_version"
    assert row["old_value"] != row["new_value"]


def test_inject_cli_without_model_swap_flag_does_nothing(tmp_path, monkeypatch, capsys):
    from vitals.cli import main

    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VITALS_PROJECTS_DIR", str(tmp_path / "projects"))

    rc = main(["inject"])

    assert rc == 1
    assert "nothing to do" in capsys.readouterr().out.lower()


def test_inject_cli_model_swap_prints_severity_attribution_and_never_the_word_haiku(
    tmp_path, monkeypatch, capsys
):
    import vitals.validate.inject as inject_module
    from vitals.alert.rules import AlertDraft
    from vitals.cli import main
    from vitals.detect.attribution import Attribution

    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("VITALS_PROJECTS_DIR", str(tmp_path / "projects"))

    captured = {}

    def fake_drill(
        conn, cfg, tasks, *, inject_model=None, claude_cmd=None, cycles=None, now_iso=None
    ):
        captured["inject_model"] = inject_model
        captured["with_version_cp_called_first"] = conn.execute(
            "SELECT COUNT(*) FROM change_points"
        ).fetchone()[0]
        draft = AlertDraft(
            severity="CRITICAL",
            title="Canary regression: pass rate below baseline for K consecutive cycles",
            anomaly_ids=[1],
            families=["canary"],
        )
        attribution = Attribution(
            cls="C",
            evidence={"matched_rule": 4, "matched_rule_name": "provider_no_incident"},
        )
        return [(draft, attribution)]

    monkeypatch.setattr(inject_module, "model_swap_drill", fake_drill)

    rc = main(["inject", "--model-swap", "--with-version-cp"])
    out = capsys.readouterr().out.lower()

    assert rc == 0
    assert captured["with_version_cp_called_first"] == 1
    assert "critical" in out
    assert "attribution=c" in out
    assert "haiku" not in out

import json
from pathlib import Path

from vitals.alert.rules import AlertDraft, evaluate, mark_info_sent, reconcile_stale_alerts
from vitals.config import DetectCfg
from vitals.db import get_conn, init_db
from vitals.detect import signal_ids as sid
from vitals.detect.baseline import ANY_VERSION, AUTO_FALSE_POSITIVE
from vitals.detect.engine import tick
from vitals.timeutil import hour_add

MODEL = "claude-sonnet-5"
BUCKET = "gt180k"
VER = "2.1.230"
START = "2026-08-01T00:00:00+00:00"


def _conn(tmp_path: Path):
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)
    return conn


def _seed_anomaly(
    conn,
    signal,
    started_at,
    ended_at=None,
    model=MODEL,
    bucket=BUCKET,
    version=VER,
    direction="up",
    status="open",
    peak_stat=6.0,
):
    cur = conn.execute(
        "INSERT INTO anomalies(signal, model, context_bucket, cc_version, started_at, ended_at,"
        " direction, peak_stat, status) VALUES (?,?,?,?,?,?,?,?,?)",
        (signal, model, bucket, version, started_at, ended_at, direction, peak_stat, status),
    )
    conn.commit()
    return cur.lastrowid


def _seed_incident(
    conn, incident_id, created_at, resolved_at=None, components="Claude API (api.anthropic.com)"
):
    conn.execute(
        "INSERT INTO incidents(incident_id, name, status, impact, created_at, resolved_at,"
        " components) VALUES (?,?,?,?,?,?,?)",
        (
            incident_id,
            "Elevated errors",
            "investigating",
            "major",
            created_at,
            resolved_at,
            components,
        ),
    )
    conn.commit()


def _seed_alert(conn, anomaly_ids, resolution=None):
    cur = conn.execute(
        "INSERT INTO alerts(ts, severity, attribution, title, evidence_json, anomaly_ids,"
        " resolution) VALUES (?,?,?,?,?,?,?)",
        (START, "WARN", "E", "test alert", "{}", json.dumps(list(anomaly_ids)), resolution),
    )
    conn.commit()
    return cur.lastrowid


def _cycle(conn, started_at, pass_rate, model=MODEL):
    cur = conn.execute(
        "INSERT INTO canary_cycles(started_at, finished_at, model, effort, suite_hash, n_runs,"
        " n_pass, n_invalid, pass_rate, aborted_reason) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            started_at,
            started_at,
            model,
            "medium",
            "suite1",
            20,
            int(round(pass_rate * 20)),
            0,
            pass_rate,
            None,
        ),
    )
    conn.commit()
    return cur.lastrowid


def _cycle_times(count, start=START, every=8):
    return [hour_add(start, every * i) for i in range(count)]


def test_single_open_anomaly_produces_one_info_draft(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _seed_anomaly(conn, sid.S1_LATENCY_P95, START)

    drafts = evaluate(conn, DetectCfg(), hour_add(START, 1))

    assert len(drafts) == 1
    d = drafts[0]
    assert isinstance(d, AlertDraft)
    assert d.severity == "INFO"
    assert d.anomaly_ids == [aid]
    assert d.families == ["latency"]
    assert d.suppressed_by_incident is None


def test_evaluate_alone_does_not_consume_the_info_dedup_slot(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _seed_anomaly(conn, sid.S1_LATENCY_P95, START)
    cfg = DetectCfg()

    first = evaluate(conn, cfg, hour_add(START, 1))
    second = evaluate(conn, cfg, hour_add(START, 2))

    assert len(first) == 1 and len(second) == 1
    assert first[0].anomaly_ids == second[0].anomaly_ids == [aid]
    assert first[0].info_dedup_signals == [sid.S1_LATENCY_P95]


def test_info_deduped_within_24h_then_fires_again_next_day(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _seed_anomaly(conn, sid.S1_LATENCY_P95, START)
    cfg = DetectCfg()

    first = evaluate(conn, cfg, hour_add(START, 1))
    assert len(first) == 1
    mark_info_sent(conn, sid.S1_LATENCY_P95, hour_add(START, 1))

    same_day = evaluate(conn, cfg, hour_add(START, 5))
    assert same_day == []

    next_day = evaluate(conn, cfg, hour_add(START, 1 + 24))
    assert len(next_day) == 1
    assert next_day[0].anomaly_ids == [aid]


def test_non_info_drafts_carry_no_info_dedup_signals(tmp_path: Path):
    conn = _conn(tmp_path)
    _seed_anomaly(conn, sid.S1_LATENCY_P95, START)
    _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 1))

    drafts = evaluate(conn, DetectCfg(), hour_add(START, 2))

    assert len(drafts) == 1 and drafts[0].severity == "WARN"
    assert drafts[0].info_dedup_signals == []


def test_info_dedup_key_is_scoped_to_one_signal_not_shared_across_signals(tmp_path: Path):
    conn = _conn(tmp_path)
    cfg = DetectCfg()
    _seed_anomaly(conn, sid.S1_LATENCY_P95, START, ended_at=hour_add(START, 1))
    first = evaluate(conn, cfg, hour_add(START, 2))
    assert len(first) == 1 and first[0].families == ["latency"]
    mark_info_sent(conn, sid.S1_LATENCY_P95, hour_add(START, 2))

    b_id = _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 2 + cfg.warn_window_h + 1))
    second = evaluate(conn, cfg, hour_add(START, 3 + cfg.warn_window_h + 1))

    assert len(second) == 1
    assert second[0].families == ["errors"]
    assert second[0].anomaly_ids == [b_id]


def test_evaluate_returns_nothing_when_no_open_anomalies(tmp_path: Path):
    conn = _conn(tmp_path)
    assert evaluate(conn, DetectCfg(), START) == []


def test_two_families_overlapping_produce_warn(tmp_path: Path):
    conn = _conn(tmp_path)
    a1 = _seed_anomaly(conn, sid.S1_LATENCY_P95, START)
    a2 = _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 1))

    drafts = evaluate(conn, DetectCfg(), hour_add(START, 2))

    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "WARN"
    assert d.families == ["errors", "latency"]
    assert d.anomaly_ids == sorted([a1, a2])
    assert d.suppressed_by_incident is None


def test_dedup_by_signal_model_bucket_prevents_phantom_warn_from_one_signal_two_strata(
    tmp_path: Path,
):
    conn = _conn(tmp_path)
    a1 = _seed_anomaly(conn, sid.S1_LATENCY_P95, START, version=VER)
    a2 = _seed_anomaly(conn, sid.S1_LATENCY_P95, START, version=ANY_VERSION)

    drafts = evaluate(conn, DetectCfg(), hour_add(START, 1))

    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "INFO"
    assert d.families == ["latency"]
    assert d.anomaly_ids == sorted([a1, a2])


def test_warn_still_fires_and_keeps_all_evidence_when_one_family_has_two_strata(tmp_path: Path):
    conn = _conn(tmp_path)
    a1 = _seed_anomaly(conn, sid.S1_LATENCY_P95, START, version=VER)
    a2 = _seed_anomaly(conn, sid.S1_LATENCY_P95, START, version=ANY_VERSION)
    a3 = _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 1))

    drafts = evaluate(conn, DetectCfg(), hour_add(START, 2))

    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "WARN"
    assert d.families == ["errors", "latency"]
    assert d.anomaly_ids == sorted([a1, a2, a3])


def test_warn_window_boundary_gap_at_limit_still_correlates(tmp_path: Path):
    conn = _conn(tmp_path)
    cfg = DetectCfg()
    _seed_anomaly(conn, sid.S1_LATENCY_P95, START, ended_at=hour_add(START, 1))
    _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 1 + cfg.warn_window_h))

    now = hour_add(START, 1 + cfg.warn_window_h + 1)
    drafts = evaluate(conn, cfg, now)

    assert len(drafts) == 1
    assert drafts[0].severity == "WARN"


def test_warn_window_boundary_gap_over_limit_stays_separate_info(tmp_path: Path):
    conn = _conn(tmp_path)
    cfg = DetectCfg()
    _seed_anomaly(conn, sid.S1_LATENCY_P95, START, ended_at=hour_add(START, 1))
    _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 1 + cfg.warn_window_h + 1))

    now = hour_add(START, 1 + cfg.warn_window_h + 2)
    drafts = evaluate(conn, cfg, now)

    assert len(drafts) == 1
    assert drafts[0].severity == "INFO"
    assert drafts[0].title.startswith(sid.S2_ERROR_RATE)


def test_active_incident_suppresses_warn_but_keeps_full_evidence(tmp_path: Path):
    conn = _conn(tmp_path)
    a1 = _seed_anomaly(conn, sid.S1_LATENCY_P95, START)
    a2 = _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 1))
    _seed_incident(conn, "inc1", START)

    drafts = evaluate(conn, DetectCfg(), hour_add(START, 2))

    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "INFO"
    assert d.suppressed_by_incident == "inc1"
    assert d.families == ["errors", "latency"]
    assert d.anomaly_ids == sorted([a1, a2])


def test_weak_family_never_counts_toward_warn_threshold(tmp_path: Path):
    conn = _conn(tmp_path)
    _seed_anomaly(conn, sid.S7_SELF_CORR_RATE, START)
    _seed_anomaly(conn, sid.S1_LATENCY_P95, hour_add(START, 1))

    drafts = evaluate(conn, DetectCfg(), hour_add(START, 2))

    assert len(drafts) == 2
    assert {d.severity for d in drafts} == {"INFO"}


def test_weak_family_rides_along_as_evidence_in_a_real_warn_but_never_justifies_it(
    tmp_path: Path,
):
    conn = _conn(tmp_path)
    a1 = _seed_anomaly(conn, sid.S1_LATENCY_P95, START)
    a2 = _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 1))
    a3 = _seed_anomaly(conn, sid.S7_SELF_CORR_RATE, hour_add(START, 1))

    drafts = evaluate(conn, DetectCfg(), hour_add(START, 2))

    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "WARN"
    assert d.families == ["errors", "latency", "weak"]
    assert d.anomaly_ids == sorted([a1, a2, a3])


def test_canary_aux_family_excluded_from_warn_threshold(tmp_path: Path):
    conn = _conn(tmp_path)
    _seed_anomaly(conn, sid.C3_CANARY_LATENCY, START, bucket="all", version=ANY_VERSION)
    _seed_anomaly(conn, sid.S1_LATENCY_P95, hour_add(START, 1))

    drafts = evaluate(conn, DetectCfg(), hour_add(START, 2))

    assert {d.severity for d in drafts} == {"INFO"}


def test_warn_sustained_exactly_at_threshold_stays_warn(tmp_path: Path):
    conn = _conn(tmp_path)
    cfg = DetectCfg()
    _seed_anomaly(conn, sid.S1_LATENCY_P95, START)
    _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 1))

    now = hour_add(START, 1 + cfg.critical_sustain_h)
    drafts = evaluate(conn, cfg, now)

    assert len(drafts) == 1
    assert drafts[0].severity == "WARN"


def test_warn_sustained_over_threshold_becomes_critical(tmp_path: Path):
    conn = _conn(tmp_path)
    cfg = DetectCfg()
    _seed_anomaly(conn, sid.S1_LATENCY_P95, START)
    _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 1))

    now = hour_add(START, 1 + cfg.critical_sustain_h + 1)
    drafts = evaluate(conn, cfg, now)

    assert len(drafts) == 1
    assert drafts[0].severity == "CRITICAL"


def test_canary_k_rule_fires_critical(tmp_path: Path):
    conn = _conn(tmp_path)
    times = _cycle_times(11)
    for ts in times[:8]:
        _cycle(conn, ts, 0.95)
    for ts in times[8:]:
        _cycle(conn, ts, 0.75)

    tick(conn, DetectCfg(), hour_add(times[-1], 1))
    drafts = evaluate(conn, DetectCfg(), hour_add(times[-1], 2))

    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "CRITICAL"
    assert d.families == ["canary"]
    assert d.suppressed_by_incident is None


def test_canary_critical_suppressed_by_incident(tmp_path: Path):
    conn = _conn(tmp_path)
    times = _cycle_times(11)
    for ts in times[:8]:
        _cycle(conn, ts, 0.95)
    for ts in times[8:]:
        _cycle(conn, ts, 0.75)
    tick(conn, DetectCfg(), hour_add(times[-1], 1))
    _seed_incident(conn, "inc-canary", START)

    drafts = evaluate(conn, DetectCfg(), hour_add(times[-1], 2))

    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "INFO"
    assert d.suppressed_by_incident == "inc-canary"
    assert d.families == ["canary"]


def test_evaluate_reconciles_alerts_pointing_at_auto_resolved_anomalies(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _seed_anomaly(conn, sid.S1_LATENCY_P95, START, status="open")
    alert_id = _seed_alert(conn, [aid])

    conn.execute("UPDATE anomalies SET status = ? WHERE id = ?", (AUTO_FALSE_POSITIVE, aid))
    conn.commit()

    drafts = evaluate(conn, DetectCfg(), hour_add(START, 1))

    alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    assert alert["resolution"] == AUTO_FALSE_POSITIVE
    assert alert["resolved_at"] is not None
    assert drafts == []


def test_reconcile_stale_alerts_ignores_already_resolved_alerts(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _seed_anomaly(conn, sid.S1_LATENCY_P95, START, status=AUTO_FALSE_POSITIVE)
    alert_id = _seed_alert(conn, [aid], resolution="confirmed")

    updated = reconcile_stale_alerts(conn, hour_add(START, 1))

    assert updated == []
    alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    assert alert["resolution"] == "confirmed"


def test_reconcile_stale_alerts_is_a_noop_when_nothing_is_stale(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _seed_anomaly(conn, sid.S1_LATENCY_P95, START, status="open")
    _seed_alert(conn, [aid])

    assert reconcile_stale_alerts(conn, hour_add(START, 1)) == []


def test_evaluate_is_idempotent_for_unchanged_warn_state(tmp_path: Path):
    conn = _conn(tmp_path)
    _seed_anomaly(conn, sid.S1_LATENCY_P95, START)
    _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 1))
    cfg = DetectCfg()
    now = hour_add(START, 2)

    first = evaluate(conn, cfg, now)
    second = evaluate(conn, cfg, now)

    assert len(first) == len(second) == 1
    assert (first[0].severity, first[0].families, first[0].anomaly_ids) == (
        second[0].severity,
        second[0].families,
        second[0].anomaly_ids,
    )


def test_info_dedup_boundary_at_age_zero_once_the_slot_is_marked(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _seed_anomaly(conn, sid.S1_LATENCY_P95, START)
    cfg = DetectCfg()
    now = hour_add(START, 1)

    first = evaluate(conn, cfg, now)
    mark_info_sent(conn, sid.S1_LATENCY_P95, now)
    second = evaluate(conn, cfg, now)

    assert len(first) == 1 and first[0].anomaly_ids == [aid]
    assert second == []


def test_dedup_key_is_stable_across_ticks_for_an_unchanged_condition(tmp_path: Path):
    conn = _conn(tmp_path)
    _seed_anomaly(conn, sid.S1_LATENCY_P95, START)
    _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 1))
    cfg = DetectCfg()

    first = evaluate(conn, cfg, hour_add(START, 2))
    second = evaluate(conn, cfg, hour_add(START, 3))

    assert len(first) == len(second) == 1
    assert first[0].severity == second[0].severity == "WARN"
    assert first[0].dedup_key == second[0].dedup_key
    assert first[0].dedup_key != ""


def test_dedup_key_unchanged_when_a_corroborating_any_stratum_anomaly_arrives_a_tick_later(
    tmp_path: Path,
):
    conn = _conn(tmp_path)
    a1 = _seed_anomaly(conn, sid.S1_LATENCY_P95, START, version=VER)
    a2 = _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 1))
    cfg = DetectCfg()

    first = evaluate(conn, cfg, hour_add(START, 2))
    assert len(first) == 1 and first[0].severity == "WARN"
    key1 = first[0].dedup_key
    assert sorted(first[0].anomaly_ids) == sorted([a1, a2])

    a3 = _seed_anomaly(conn, sid.S1_LATENCY_P95, START, version=ANY_VERSION)
    second = evaluate(conn, cfg, hour_add(START, 3))

    assert len(second) == 1
    assert second[0].dedup_key == key1
    assert sorted(second[0].anomaly_ids) == sorted([a1, a2, a3])


def test_dedup_keys_differ_for_two_genuinely_distinct_conditions(tmp_path: Path):
    conn_a = _conn(tmp_path / "a")
    _seed_anomaly(conn_a, sid.S1_LATENCY_P95, START)
    draft_a = evaluate(conn_a, DetectCfg(), hour_add(START, 1))[0]

    conn_b = _conn(tmp_path / "b")
    _seed_anomaly(conn_b, sid.S2_ERROR_RATE, START, model="claude-opus-5")
    draft_b = evaluate(conn_b, DetectCfg(), hour_add(START, 1))[0]

    assert draft_a.dedup_key != draft_b.dedup_key


def test_dedup_key_changes_when_a_new_family_joins(tmp_path: Path):
    conn = _conn(tmp_path)
    _seed_anomaly(conn, sid.S1_LATENCY_P95, START)
    _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 1))
    cfg = DetectCfg()

    first = evaluate(conn, cfg, hour_add(START, 2))
    key1 = first[0].dedup_key

    _seed_anomaly(conn, sid.S4_TOOL_FAIL_ALL, hour_add(START, 1), bucket="all")
    second = evaluate(conn, cfg, hour_add(START, 3))

    assert len(second) == 1
    assert second[0].families == ["errors", "latency", "tooling"]
    assert second[0].dedup_key != key1


def test_dedup_key_reflects_triples_not_anomaly_ids_for_a_solo_info_draft(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _seed_anomaly(conn, sid.S1_LATENCY_P95, START)

    draft = evaluate(conn, DetectCfg(), hour_add(START, 1))[0]

    assert draft.dedup_key == f"{sid.S1_LATENCY_P95}::{MODEL}::{BUCKET}"
    assert draft.first_seen == START
    assert draft.anomaly_ids == [aid]


def test_an_episode_that_ended_long_ago_stops_drafting(tmp_path: Path):
    conn = _conn(tmp_path)
    _seed_anomaly(conn, sid.S1_LATENCY_P95, START, ended_at=hour_add(START, 14))
    _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 1), ended_at=hour_add(START, 14))

    assert evaluate(conn, DetectCfg(), hour_add(START, 14 + 72)) == []


def test_a_recovered_canary_regression_stops_paging(tmp_path: Path):
    conn = _conn(tmp_path)
    _seed_anomaly(conn, sid.C1_CANARY_PASS, START, ended_at=hour_add(START, 24), bucket="all")

    assert evaluate(conn, DetectCfg(), hour_add(START, 24 + 6 * 24)) == []


def test_a_recently_ended_episode_still_correlates_with_a_live_one(tmp_path: Path):
    conn = _conn(tmp_path)
    _seed_anomaly(conn, sid.S1_LATENCY_P95, START, ended_at=hour_add(START, 3))
    _seed_anomaly(conn, sid.S2_ERROR_RATE, hour_add(START, 2))

    drafts = evaluate(conn, DetectCfg(), hour_add(START, 5))

    assert [d.severity for d in drafts] == ["WARN"]

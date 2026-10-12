import json
from pathlib import Path

from vitals.alert.rules import AlertDraft
from vitals.db import get_conn, init_db, kv_set
from vitals.detect import signal_ids as sid
from vitals.detect.attribution import Attribution, classify
from vitals.detect.baseline import ANY_VERSION
from vitals.timeutil import hour_add

MODEL = "claude-sonnet-5"
VER_OLD = "2.1.230"
VER_NEW = "2.1.237"
START = "2026-08-01T12:00:00+00:00"
NOW = hour_add(START, 6)


def _conn(tmp_path: Path):
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)
    return conn


def _anomaly(
    conn,
    signal=sid.S1_LATENCY_P95,
    started_at=START,
    ended_at=None,
    model=MODEL,
    bucket="gt180k",
    version=VER_OLD,
    status="open",
):
    cur = conn.execute(
        "INSERT INTO anomalies(signal, model, context_bucket, cc_version, started_at, ended_at,"
        " direction, peak_stat, peak_z, status) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (signal, model, bucket, version, started_at, ended_at, "up", 6.2, 4.1, status),
    )
    conn.commit()
    return cur.lastrowid


def _incident(
    conn,
    incident_id="inc-1",
    created_at=None,
    resolved_at=None,
    components="Claude API (api.anthropic.com)",
):
    conn.execute(
        "INSERT INTO incidents(incident_id, name, status, impact, created_at, resolved_at,"
        " components) VALUES (?,?,?,?,?,?,?)",
        (
            incident_id,
            "Elevated errors",
            "resolved" if resolved_at else "investigating",
            "major",
            created_at or hour_add(START, -1),
            resolved_at,
            components,
        ),
    )
    conn.commit()
    return incident_id


def _change_point(conn, ts, kind="cc_version", old=VER_OLD, new=VER_NEW, detail=None):
    cur = conn.execute(
        "INSERT INTO change_points(ts, kind, old_value, new_value, detail) VALUES (?,?,?,?,?)",
        (ts, kind, old, new, detail),
    )
    conn.commit()
    return cur.lastrowid


def _baseline(conn, signal, model=MODEL, bucket="gt180k", version=ANY_VERSION, mu0=1.0):
    conn.execute(
        "INSERT OR REPLACE INTO detector_state(signal, model, context_bucket, cc_version, mu0,"
        " sigma0, baseline_n, baseline_samples, baseline_end) VALUES (?,?,?,?,?,?,?,?,?)",
        (signal, model, bucket, version, mu0, 0.25, 60, 900, hour_add(START, -24)),
    )
    conn.commit()


def _cycles(conn, count=6, pass_rate=0.95, first=None, every=8):
    first = first or hour_add(START, -72)
    for i in range(count):
        conn.execute(
            "INSERT INTO canary_cycles(started_at, finished_at, model, effort, suite_hash,"
            " n_runs, n_pass, n_invalid, pass_rate) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                hour_add(first, every * i),
                hour_add(first, every * i),
                MODEL,
                "medium",
                "suite1",
                20,
                int(round(pass_rate * 20)),
                0,
                pass_rate,
            ),
        )
    conn.commit()


def _session(conn, session_id, cwd, is_canary=0):
    conn.execute(
        "INSERT INTO sessions(session_id, started_at, cwd, is_canary, cc_version)"
        " VALUES (?,?,?,?,?)",
        (session_id, START, cwd, is_canary, VER_OLD),
    )
    conn.commit()


def _request(conn, session_id, ts=None, model=MODEL, bucket="lt30k", version=VER_OLD):
    conn.execute(
        "INSERT INTO api_requests(session_id, ts, model, effort, context_bucket, cc_version,"
        " duration_ms) VALUES (?,?,?,?,?,?,?)",
        (session_id, ts or hour_add(START, 1), model, "medium", bucket, version, 1200.0),
    )
    conn.commit()


def _drift_sessions(conn, count=2, bucket="lt30k", version=VER_OLD):
    for i in range(count):
        _session(conn, f"sess-{i}", f"C:/work/project-{i}")
        _request(conn, f"sess-{i}", bucket=bucket, version=version)


def _draft(anomaly_ids, families=("latency",), severity="WARN", first_seen=START):
    return AlertDraft(
        severity=severity,
        title="test draft",
        anomaly_ids=list(anomaly_ids),
        families=list(families),
        dedup_key="k",
        first_seen=first_seen,
    )


def _rule(attribution: Attribution, number: int) -> dict:
    (entry,) = [e for e in attribution.evidence["rules"] if e["rule"] == number]
    return entry


def test_rule1_incident_wins(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn)
    _incident(conn, "inc-42", created_at=hour_add(START, -1))

    result = classify(conn, _draft([aid]), NOW)

    assert result.cls == "C"
    assert result.evidence["matched_rule"] == 1
    facts = _rule(result, 1)["facts"]
    assert _rule(result, 1)["matched"] is True
    assert facts["incident_id"] == "inc-42"
    assert facts["matched_prefix"] == "Claude API"
    assert facts["unresolved"] is True
    assert facts["overlap_hours"] > 0


def test_rule1_matches_an_incident_that_overlapped_and_has_since_resolved(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn)
    _incident(conn, "inc-old", created_at=hour_add(START, -1), resolved_at=hour_add(START, 2))

    result = classify(conn, _draft([aid]), NOW)

    assert result.cls == "C"
    facts = _rule(result, 1)["facts"]
    assert facts["incident_id"] == "inc-old"
    assert facts["unresolved"] is False


def test_rule1_ignores_an_incident_that_closed_before_the_anomaly_started(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn)
    _incident(conn, "inc-stale", created_at=hour_add(START, -20), resolved_at=hour_add(START, -6))

    result = classify(conn, _draft([aid]), NOW)

    assert _rule(result, 1)["matched"] is False
    assert _rule(result, 1)["facts"]["overlapping"] == []
    assert result.cls != "C" or result.evidence["matched_rule"] != 1


def test_rule1_ignores_an_incident_on_an_unrelated_component(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn)
    _incident(conn, "inc-cowork", created_at=hour_add(START, -1), components="Claude Cowork")

    result = classify(conn, _draft([aid]), NOW)

    assert _rule(result, 1)["matched"] is False
    assert "Claude Cowork" not in json.dumps(_rule(result, 1)["facts"]["overlapping"])


def test_rule2_version_change(tmp_path: Path):
    conn = _conn(tmp_path)
    cp = _change_point(conn, hour_add(START, -6))
    new_id = _anomaly(conn, version=VER_NEW)
    any_id = _anomaly(conn, version=ANY_VERSION)

    result = classify(conn, _draft([new_id, any_id]), NOW)

    assert result.cls == "B"
    assert result.evidence["matched_rule"] == 2
    facts = _rule(result, 2)["facts"]
    assert facts["change_point"]["id"] == cp
    assert facts["change_point"]["kind"] == "cc_version"
    assert facts["new_version_alarmed"] == [VER_NEW]
    assert facts["prior_version_quiet"] is True
    assert facts["prior_version_alarm_ids"] == []
    assert facts["collapsed_stratum_alarmed"] is True
    assert sorted(facts["version_alarm_map"]) == sorted([VER_NEW, ANY_VERSION])


def test_rule2_misses_when_the_prior_version_stratum_also_alarmed(tmp_path: Path):
    conn = _conn(tmp_path)
    _change_point(conn, hour_add(START, -6))
    new_id = _anomaly(conn, version=VER_NEW)
    old_id = _anomaly(conn, version=VER_OLD)

    result = classify(conn, _draft([new_id, old_id]), NOW)

    entry = _rule(result, 2)
    assert entry["matched"] is False
    assert entry["facts"]["prior_version_alarm_ids"] == [old_id]
    assert "prior version" in entry["facts"]["reason"]
    assert result.cls != "B"


def test_rule2_misses_when_the_change_point_is_older_than_24h(tmp_path: Path):
    conn = _conn(tmp_path)
    _change_point(conn, hour_add(START, -30))
    new_id = _anomaly(conn, version=VER_NEW)

    result = classify(conn, _draft([new_id]), NOW)

    entry = _rule(result, 2)
    assert entry["matched"] is False
    assert entry["facts"]["candidates"] == []
    assert result.cls != "B"


def test_rule2_misses_when_no_stratum_lives_on_the_new_version(tmp_path: Path):
    conn = _conn(tmp_path)
    _change_point(conn, hour_add(START, -6))
    old_id = _anomaly(conn, version=VER_OLD)

    result = classify(conn, _draft([old_id]), NOW)

    entry = _rule(result, 2)
    assert entry["matched"] is False
    assert entry["facts"]["new_version_alarmed"] == []
    assert VER_NEW in entry["facts"]["reason"]
    assert result.cls != "B"


def test_rule2_records_every_rejected_candidate_not_just_the_newest(tmp_path: Path):
    conn = _conn(tmp_path)
    older = _change_point(conn, hour_add(START, -20), old="2.1.220", new="2.1.225")
    newer = _change_point(conn, hour_add(START, -2))
    aid = _anomaly(conn, version=VER_OLD)

    result = classify(conn, _draft([aid]), NOW)

    facts = _rule(result, 2)["facts"]
    assert [c["id"] for c in facts["candidates"]] == [newer, older]
    assert [r["change_point"]["id"] for r in facts["rejected"]] == [newer, older]
    assert facts["change_point"] is None
    assert all(r["reason"] for r in facts["rejected"])


def test_rule2_falls_back_to_an_older_candidate_when_the_newest_is_rejected(tmp_path: Path):
    conn = _conn(tmp_path)
    older = _change_point(conn, hour_add(START, -20), old=VER_OLD, new=VER_NEW)
    newer = _change_point(conn, hour_add(START, -2), old="2.1.240", new="2.1.245")
    aid = _anomaly(conn, version=VER_NEW)

    result = classify(conn, _draft([aid]), NOW)

    assert result.cls == "B"
    facts = _rule(result, 2)["facts"]
    assert [c["id"] for c in facts["candidates"]] == [newer, older]
    assert facts["change_point"]["id"] == older
    assert facts["change_point"]["new_value"] == VER_NEW
    assert [r["change_point"]["id"] for r in facts["rejected"]] == [newer]
    assert "2.1.245" in facts["rejected"][0]["reason"]
    assert facts["new_version_alarmed"] == [VER_NEW]
    assert facts["prior_version_quiet"] is True


def test_rule2_matches_a_settings_change_when_the_alarm_begins_after_it(tmp_path: Path):
    conn = _conn(tmp_path)
    cp = _change_point(conn, hour_add(START, -2), kind="settings", old="aaa", new="bbb")
    aid = _anomaly(conn)

    result = classify(conn, _draft([aid]), NOW)

    assert result.cls == "B"
    facts = _rule(result, 2)["facts"]
    assert facts["change_point"]["id"] == cp
    assert facts["change_point"]["kind"] == "settings"
    assert facts["postdates_test"] == "alarm_starts_after_change"


def test_rule2_settings_arm_rejects_a_change_point_that_did_not_precede_the_alarm(
    tmp_path: Path,
):
    conn = _conn(tmp_path)
    cp = _change_point(conn, START, kind="settings", old="aaa", new="bbb")
    aid = _anomaly(conn, started_at=START)

    result = classify(conn, _draft([aid]), NOW)

    entry = _rule(result, 2)
    assert entry["matched"] is False, "a simultaneous change point must not explain the alarm"
    assert result.cls != "B"
    reason = entry["facts"]["reason"]
    assert str(cp) in reason and "settings" in reason
    assert "strictly after" in reason


def test_rule2_settings_arm_records_that_no_cross_stratum_contrast_is_possible(tmp_path: Path):
    conn = _conn(tmp_path)
    _change_point(conn, hour_add(START, -2), kind="plugins", old="aaa", new="bbb")
    aid = _anomaly(conn)

    result = classify(conn, _draft([aid]), NOW)

    assert result.cls == "B"
    facts = _rule(result, 2)["facts"]
    assert facts["postdates_test"] == "alarm_starts_after_change"
    assert facts["contrast"] == "none_possible_for_this_kind"
    assert facts["prior_version_quiet"] is None
    assert "version" in facts["why_no_cross_stratum_contrast"].lower()


def test_rule2_version_arm_records_that_the_cross_stratum_contrast_did_run(tmp_path: Path):
    conn = _conn(tmp_path)
    _change_point(conn, hour_add(START, -6))
    new_id = _anomaly(conn, version=VER_NEW)

    result = classify(conn, _draft([new_id]), NOW)

    facts = _rule(result, 2)["facts"]
    assert facts["postdates_test"] == "stratum_cc_version_is_the_new_value"
    assert facts["contrast"] == "cross_stratum_version"
    assert facts["prior_version_quiet"] is True


def test_rule2_records_the_effort_distribution_as_supporting_evidence(tmp_path: Path):
    conn = _conn(tmp_path)
    _change_point(conn, hour_add(START, -6))
    _session(conn, "sess-e", "C:/work/e")
    conn.execute(
        "INSERT INTO api_requests(session_id, ts, model, effort, context_bucket, cc_version)"
        " VALUES (?,?,?,?,?,?)",
        ("sess-e", hour_add(START, -12), MODEL, "medium", "gt180k", VER_OLD),
    )
    conn.execute(
        "INSERT INTO api_requests(session_id, ts, model, effort, context_bucket, cc_version)"
        " VALUES (?,?,?,?,?,?)",
        ("sess-e", hour_add(START, 1), MODEL, "high", "gt180k", VER_NEW),
    )
    conn.commit()
    new_id = _anomaly(conn, version=VER_NEW)

    result = classify(conn, _draft([new_id]), NOW)

    shift = _rule(result, 2)["facts"]["effort_shift"]
    assert shift["modal_before"] == "medium"
    assert shift["modal_after"] == "high"
    assert shift["changed"] is True


def test_rule2_canary_aware_arm_attributes_b_when_version_change_precedes_canary_regression(
    tmp_path: Path,
):
    conn = _conn(tmp_path)
    cp = _change_point(conn, hour_add(START, -6))
    cid = _anomaly(conn, sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)

    result = classify(conn, _draft([cid], families=("canary",), severity="CRITICAL"), NOW)

    assert result.cls == "B"
    assert result.evidence["matched_rule"] == 2
    facts = _rule(result, 2)["facts"]
    assert facts["change_point"]["id"] == cp
    assert facts["postdates_test"] == "canary_temporal_contrast"
    assert facts["canary_anomaly_ids"] == [cid]
    reason = facts["why_no_cross_stratum_contrast"].lower()
    assert "any" in reason and "cc_version" in reason

    branch_a = _rule(result, 4)["facts"]["branches"]["a"]
    assert branch_a["matched"] is False
    assert "change point" in branch_a["reason"]


def test_rule2_will_not_blame_a_bare_canary_regression_on_settings_or_plugins(tmp_path: Path):
    conn = _conn(tmp_path)
    _cycles(conn)
    _change_point(conn, hour_add(START, -18), kind="plugins", old="p1", new="p2")
    cid = _anomaly(conn, sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)

    result = classify(conn, _draft([cid], families=("canary",), severity="CRITICAL"), NOW)

    entry = _rule(result, 2)
    assert entry["matched"] is False
    assert entry["facts"]["canary_only_draft"] is True
    assert "--bare" in entry["facts"]["reason"]
    assert result.cls == "C"
    assert result.evidence["matched_rule"] == 4


def test_rule2_vitals_config_still_explains_a_canary_only_draft(tmp_path: Path):
    conn = _conn(tmp_path)
    _cycles(conn)
    _change_point(conn, hour_add(START, -2), kind="vitals_config", old="v1", new="v2")
    cid = _anomaly(conn, sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)

    result = classify(conn, _draft([cid], families=("canary",)), NOW)

    assert result.cls == "B"
    entry = _rule(result, 2)
    assert entry["matched"] is True
    assert entry["facts"]["change_point"]["kind"] == "vitals_config"


def test_rule2_still_blames_settings_for_a_draft_with_passive_anomalies(tmp_path: Path):
    conn = _conn(tmp_path)
    _cycles(conn)
    _change_point(conn, hour_add(START, -2), kind="settings", old="aaa", new="bbb")
    cid = _anomaly(conn, sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)
    aid = _anomaly(conn)

    result = classify(conn, _draft([cid, aid], families=("canary", "latency")), NOW)

    assert result.cls == "B"
    entry = _rule(result, 2)
    assert entry["matched"] is True
    assert entry["facts"]["canary_only_draft"] is False


def test_order_incident_beats_canary_version_arm(tmp_path: Path):
    conn = _conn(tmp_path)
    _change_point(conn, hour_add(START, -6))
    cid = _anomaly(conn, sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)
    _incident(conn, "inc-88", created_at=hour_add(START, -1))

    result = classify(conn, _draft([cid], families=("canary",)), NOW)

    assert result.cls == "C"
    assert result.evidence["matched_rule"] == 1
    assert _rule(result, 2)["matched"] is True
    assert _rule(result, 2)["facts"]["postdates_test"] == "canary_temporal_contrast"


def test_rule3_long_context_only(tmp_path: Path):
    conn = _conn(tmp_path)
    high = _anomaly(conn, sid.S1_LATENCY_P95, bucket="gt180k")
    post = _anomaly(conn, sid.S9_POST_COMPACTION_FAIL, bucket="all")
    _baseline(conn, sid.S1_LATENCY_P95, bucket="b30_100k")
    _baseline(conn, sid.S1_LATENCY_P95, bucket="gt180k")
    _cycles(conn)

    result = classify(conn, _draft([high, post], families=("latency", "context")), NOW)

    assert result.cls == "A"
    assert result.evidence["matched_rule"] == 3
    facts = _rule(result, 3)["facts"]
    assert facts["confined"] is True
    assert facts["contrast_bucket"] == "b30_100k"
    assert facts["contrast_bucket_scope"] == "draft_signals"
    assert facts["contrast_bucket_quiet"] is True
    assert facts["buckets_with_live_baseline"] == ["b30_100k", "gt180k"]
    assert facts["canary"]["state"] == "green"


def test_rule3_matches_a_post_compaction_alarm_on_its_intrinsic_contrast(tmp_path: Path):
    conn = _conn(tmp_path)
    post = _anomaly(conn, sid.S9_POST_COMPACTION_FAIL, model="all", bucket="all")

    result = classify(conn, _draft([post], families=("context",)), NOW)

    assert result.cls == "A"
    assert result.evidence["matched_rule"] == 3
    facts = _rule(result, 3)["facts"]
    assert facts["confined"] is True
    assert facts["contrast"] == "intrinsic_to_signal"
    assert facts["intrinsic_contrast_signals"] == [sid.S9_POST_COMPACTION_FAIL]
    note = facts["intrinsic_contrast_note"].lower()
    assert "ratio" in note and "compaction" in note
    assert facts["contrast_bucket"] is None


def test_rule3_will_not_reach_class_a_on_edit_loop_rate_alone(tmp_path: Path):
    conn = _conn(tmp_path)
    loop = _anomaly(conn, sid.S5_EDIT_LOOP_RATE, model="all", bucket="all")

    result = classify(conn, _draft([loop], families=("tooling-loops",)), NOW)

    assert result.cls != "A"
    entry = _rule(result, 3)
    assert entry["matched"] is False
    assert entry["facts"]["confined"] is True
    assert entry["facts"]["contrast"] is None
    reason = entry["facts"]["reason"]
    assert sid.S5_EDIT_LOOP_RATE in reason
    assert "intrinsic" in reason
    assert sid.S9_POST_COMPACTION_FAIL in reason


def test_rule3_intrinsic_arm_still_defers_to_a_regressed_canary(tmp_path: Path):
    conn = _conn(tmp_path)
    post = _anomaly(conn, sid.S9_POST_COMPACTION_FAIL, model="all", bucket="all")
    _cycles(conn)
    _anomaly(conn, sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)

    result = classify(conn, _draft([post], families=("context",)), NOW)

    entry = _rule(result, 3)
    assert entry["matched"] is False
    assert entry["facts"]["canary"]["state"] == "regressed"
    assert result.cls != "A"


def test_rule3_misses_when_no_lower_bucket_has_a_live_baseline(tmp_path: Path):
    conn = _conn(tmp_path)
    high = _anomaly(conn, sid.S1_LATENCY_P95, bucket="gt180k")
    _baseline(conn, sid.S1_LATENCY_P95, bucket="gt180k")
    _cycles(conn)

    result = classify(conn, _draft([high]), NOW)

    entry = _rule(result, 3)
    assert entry["matched"] is False
    assert entry["facts"]["contrast_bucket"] is None
    assert "live baseline" in entry["facts"]["reason"]
    assert result.cls != "A"


def test_rule3_refuses_a_contrast_bucket_measured_only_by_unrelated_signals(tmp_path: Path):
    conn = _conn(tmp_path)
    high = _anomaly(conn, sid.S1_LATENCY_P95, bucket="gt180k")
    _baseline(conn, sid.S1_LATENCY_P95, bucket="gt180k")
    _baseline(conn, sid.S2_ERROR_RATE, bucket="b30_100k")
    _cycles(conn)

    result = classify(conn, _draft([high]), NOW)

    assert result.cls == "E"
    entry = _rule(result, 3)
    assert entry["matched"] is False
    assert entry["facts"]["confined"] is True
    assert entry["facts"]["contrast_bucket"] is None
    assert entry["facts"]["contrast_bucket_scope"] == "any_signal"
    assert entry["facts"]["contrast_bucket_candidate"] == "b30_100k"
    reason = entry["facts"]["reason"]
    assert "no live baseline" in reason
    assert sid.S1_LATENCY_P95 in reason
    assert "absence of data" in reason


def test_rule3_misses_when_the_contrast_bucket_is_itself_alarming(tmp_path: Path):
    conn = _conn(tmp_path)
    high = _anomaly(conn, sid.S1_LATENCY_P95, bucket="gt180k")
    low = _anomaly(conn, sid.S2_ERROR_RATE, bucket="b30_100k")
    _baseline(conn, sid.S1_LATENCY_P95, bucket="b30_100k")
    _cycles(conn)

    result = classify(conn, _draft([high]), NOW)

    entry = _rule(result, 3)
    assert entry["matched"] is False
    assert entry["facts"]["confined"] is True
    assert entry["facts"]["contrast_bucket"] == "b30_100k"
    assert entry["facts"]["contrast_bucket_alarm_ids"] == [low]
    assert result.cls != "A"


def test_rule3_misses_when_the_short_context_canary_suite_regressed(tmp_path: Path):
    conn = _conn(tmp_path)
    high = _anomaly(conn, sid.S1_LATENCY_P95, bucket="gt180k")
    _baseline(conn, sid.S1_LATENCY_P95, bucket="b30_100k")
    _cycles(conn)
    _anomaly(conn, sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)

    result = classify(conn, _draft([high]), NOW)

    entry = _rule(result, 3)
    assert entry["matched"] is False
    assert entry["facts"]["canary"]["state"] == "regressed"
    assert result.cls != "A"


def test_rule3_misses_when_a_short_context_signal_is_also_alarming(tmp_path: Path):
    conn = _conn(tmp_path)
    high = _anomaly(conn, sid.S1_LATENCY_P95, bucket="gt180k")
    tool = _anomaly(conn, sid.S4_TOOL_FAIL_ALL, bucket="all")
    _baseline(conn, sid.S1_LATENCY_P95, bucket="b30_100k")
    _cycles(conn)

    result = classify(conn, _draft([high, tool], families=("latency", "tooling")), NOW)

    entry = _rule(result, 3)
    assert entry["matched"] is False
    assert entry["facts"]["confined"] is False
    assert entry["facts"]["unconfined_anomaly_ids"] == [tool]


def test_rule4a_canary_only(tmp_path: Path):
    conn = _conn(tmp_path)
    _cycles(conn)
    cid = _anomaly(conn, sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)

    result = classify(conn, _draft([cid], families=("canary",), severity="CRITICAL"), NOW)

    assert result.cls == "C"
    assert result.evidence["matched_rule"] == 4
    facts = _rule(result, 4)["facts"]
    assert facts["branches_matched"] == ["a"]
    assert facts["branches"]["a"]["matched"] is True
    assert facts["branches"]["a"]["canary_anomaly_ids"] == [cid]
    assert facts["branches"]["a"]["change_points_72h"] == []
    assert facts["branches"]["b"]["matched"] is False
    assert facts["confidence"] == "moderate"


def test_rule4a_misses_when_a_canary_capable_change_point_landed_within_72h(tmp_path: Path):
    for kind in ("cc_version", "vitals_config", "canary_suite"):
        conn = _conn(tmp_path / kind)
        _cycles(conn)
        _change_point(conn, hour_add(START, -30), kind=kind, old="v1", new="v2")
        cid = _anomaly(conn, sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)

        result = classify(conn, _draft([cid], families=("canary",)), NOW)

        branch = _rule(result, 4)["facts"]["branches"]["a"]
        assert branch["matched"] is False, kind
        assert [c["kind"] for c in branch["disqualifying_change_points"]] == [kind]
        assert "72h" in branch["reason"]


def test_rule4a_survives_change_points_that_cannot_reach_a_bare_canary(tmp_path: Path):
    conn = _conn(tmp_path)
    _cycles(conn)
    _change_point(conn, hour_add(START, -30), kind="plugins", old="p1", new="p2")
    _change_point(conn, hour_add(START, -48), kind="settings", old="s1", new="s2")
    cid = _anomaly(conn, sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)

    result = classify(conn, _draft([cid], families=("canary",), severity="CRITICAL"), NOW)

    assert result.cls == "C"
    assert result.evidence["matched_rule"] == 4
    branch = _rule(result, 4)["facts"]["branches"]["a"]
    assert branch["matched"] is True
    assert branch["disqualifying_change_points"] == []
    assert sorted(c["kind"] for c in branch["excluded_change_points"]) == ["plugins", "settings"]
    for excluded in branch["excluded_change_points"]:
        assert "--bare" in excluded["reason"]
    assert len(branch["change_points_72h"]) == 2


def test_rule4a_ignores_a_canary_suite_change_the_detector_already_applied(tmp_path: Path):
    conn = _conn(tmp_path)
    _cycles(conn)
    cp = _change_point(conn, hour_add(START, -30), kind="canary_suite", old="h1", new="h2")
    kv_set(conn, "detector_canary_suite_cp", str(cp))
    cid = _anomaly(conn, sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)

    result = classify(conn, _draft([cid], families=("canary",), severity="CRITICAL"), NOW)

    assert result.cls == "C"
    branch = _rule(result, 4)["facts"]["branches"]["a"]
    assert branch["matched"] is True
    (excluded,) = branch["excluded_change_points"]
    assert excluded["kind"] == "canary_suite"
    assert "reset" in excluded["reason"]


def test_rule4b_passive_drift(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn, sid.S1_LATENCY_P95, bucket="lt30k")
    _drift_sessions(conn, count=2)

    result = classify(conn, _draft([aid]), NOW)

    assert result.cls == "C"
    assert result.evidence["matched_rule"] == 4
    facts = _rule(result, 4)["facts"]
    assert facts["branches_matched"] == ["b"]
    branch = facts["branches"]["b"]
    assert branch["matched"] is True
    assert branch["qualifying_anomaly_ids"] == [aid]
    assert branch["distinct_sessions"] == 2
    assert branch["distinct_projects"] == 2
    assert branch["version_changed"] is False


def test_rule4b_misses_with_only_one_session(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn, sid.S1_LATENCY_P95, bucket="lt30k")
    _drift_sessions(conn, count=1)

    result = classify(conn, _draft([aid]), NOW)

    branch = _rule(result, 4)["facts"]["branches"]["b"]
    assert branch["matched"] is False
    assert branch["distinct_sessions"] == 1
    assert result.cls == "E"


def test_rule4b_ignores_canary_sessions_when_counting_real_sessions(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn, sid.S1_LATENCY_P95, bucket="lt30k")
    _session(conn, "sess-real", "C:/work/real")
    _request(conn, "sess-real")
    _session(conn, "sess-canary", "C:/work/canary", is_canary=1)
    _request(conn, "sess-canary")

    result = classify(conn, _draft([aid]), NOW)

    branch = _rule(result, 4)["facts"]["branches"]["b"]
    assert branch["matched"] is False
    assert branch["distinct_sessions"] == 1


def test_rule4b_never_treats_a_long_context_stratum_as_short_context(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn, sid.S1_LATENCY_P95, bucket="gt180k")
    _drift_sessions(conn, count=3, bucket="gt180k")

    result = classify(conn, _draft([aid]), NOW)

    branch = _rule(result, 4)["facts"]["branches"]["b"]
    assert branch["matched"] is False
    assert branch["qualifying_anomaly_ids"] == []
    assert branch["short_context_buckets"] == ["lt30k", "b30_100k"]
    assert result.cls == "E"


def test_rule4_both_branches(tmp_path: Path):
    conn = _conn(tmp_path)
    _cycles(conn)
    cid = _anomaly(conn, sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)
    pid = _anomaly(conn, sid.S1_LATENCY_P95, bucket="lt30k")
    _drift_sessions(conn, count=2)

    result = classify(conn, _draft([cid, pid], families=("canary", "latency")), NOW)

    assert result.cls == "C"
    facts = _rule(result, 4)["facts"]
    assert facts["branches_matched"] == ["a", "b"]
    assert facts["branches"]["a"]["matched"] is True
    assert facts["branches"]["b"]["matched"] is True
    assert facts["confidence"] == "high"


def test_rule5_is_structurally_present_and_always_misses_today(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn)

    result = classify(conn, _draft([aid]), NOW)

    entry = _rule(result, 5)
    assert entry["rule"] == 5
    assert entry["cls"] == "D"
    assert entry["matched"] is False
    assert entry["facts"]["local_backend"] is False
    assert "Phase 4" in entry["facts"]["reason"]


def test_rule5_still_misses_even_with_a_local_backend_configured(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn)
    kv_set(conn, "active_backend", "ollama")

    result = classify(conn, _draft([aid]), NOW)

    entry = _rule(result, 5)
    assert entry["matched"] is False
    assert entry["facts"]["local_backend"] is True
    assert entry["facts"]["active_backend"] == "ollama"
    assert entry["facts"]["hw_covariates"] == "not_collected"


def test_rule6_inconclusive(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn, sid.S4_TOOL_FAIL_ALL, model="all", bucket="all")

    result = classify(conn, _draft([aid], families=("tooling",)), NOW)

    assert result.cls == "E"
    assert result.evidence["matched_rule"] == 6
    numbers = [e["rule"] for e in result.evidence["rules"]]
    assert numbers == [1, 2, 3, 4, 5, 6]
    for entry in result.evidence["rules"][:5]:
        assert entry["matched"] is False, entry
        assert entry["facts"]["reason"], entry
    assert _rule(result, 6)["matched"] is True
    assert _rule(result, 6)["facts"]["rules_missed"] == [1, 2, 3, 4, 5]


def test_rule6_checklist_names_a_distinct_reason_for_every_rule(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn, sid.S4_TOOL_FAIL_ALL, model="all", bucket="all")

    result = classify(conn, _draft([aid], families=("tooling",)), NOW)

    reasons = {e["rule"]: e["facts"]["reason"] for e in result.evidence["rules"][:5]}
    assert set(reasons) == {1, 2, 3, 4, 5}
    assert len(set(reasons.values())) == 5


def test_order_incident_beats_version(tmp_path: Path):
    conn = _conn(tmp_path)
    _change_point(conn, hour_add(START, -6))
    new_id = _anomaly(conn, version=VER_NEW)
    _incident(conn, "inc-99", created_at=hour_add(START, -1))

    result = classify(conn, _draft([new_id]), NOW)

    assert result.cls == "C"
    assert result.evidence["matched_rule"] == 1
    assert _rule(result, 2)["matched"] is True


def test_order_version_beats_long_context(tmp_path: Path):
    conn = _conn(tmp_path)
    _change_point(conn, hour_add(START, -6))
    high = _anomaly(conn, sid.S1_LATENCY_P95, bucket="gt180k", version=VER_NEW)
    _baseline(conn, sid.S1_LATENCY_P95, bucket="b30_100k")
    _cycles(conn)

    result = classify(conn, _draft([high]), NOW)

    assert result.cls == "B"
    assert result.evidence["matched_rule"] == 2
    assert _rule(result, 3)["matched"] is True


def test_order_incident_beats_canary_branch_a(tmp_path: Path):
    conn = _conn(tmp_path)
    _cycles(conn)
    cid = _anomaly(conn, sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)
    _incident(conn, "inc-7", created_at=hour_add(START, -1))

    result = classify(conn, _draft([cid], families=("canary",)), NOW)

    assert result.cls == "C"
    assert result.evidence["matched_rule"] == 1
    assert _rule(result, 4)["facts"]["branches_matched"] == ["a"]


def test_order_settings_change_beats_passive_drift(tmp_path: Path):
    conn = _conn(tmp_path)
    _change_point(conn, hour_add(START, -2), kind="settings", old="aaa", new="bbb")
    aid = _anomaly(conn, sid.S1_LATENCY_P95, bucket="lt30k")
    _drift_sessions(conn, count=2)

    result = classify(conn, _draft([aid]), NOW)

    assert result.cls == "B"
    assert result.evidence["matched_rule"] == 2
    assert _rule(result, 4)["facts"]["branches_matched"] == ["b"]


def test_order_long_context_beats_the_provider_fallback(tmp_path: Path):
    conn = _conn(tmp_path)
    high = _anomaly(conn, sid.S1_LATENCY_P95, bucket="gt180k")
    low = _anomaly(conn, sid.S1_LATENCY_P95, bucket="lt30k", started_at=hour_add(START, -96))
    conn.execute(
        "UPDATE anomalies SET ended_at = ?, status = 'false_positive' WHERE id = ?",
        (hour_add(START, -90), low),
    )
    conn.commit()
    _baseline(conn, sid.S1_LATENCY_P95, bucket="b30_100k")
    _cycles(conn)
    _drift_sessions(conn, count=2)

    result = classify(conn, _draft([high]), NOW)

    assert result.cls == "A"
    assert result.evidence["matched_rule"] == 3


def test_evidence_is_json_serialisable_and_carries_the_whole_checklist(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn)
    _incident(conn, "inc-1", created_at=hour_add(START, -1))

    result = classify(conn, _draft([aid]), NOW)
    blob = json.dumps(result.evidence)

    assert json.loads(blob)["cls"] == "C"
    assert [e["rule"] for e in json.loads(blob)["rules"]] == [1, 2, 3, 4, 5, 6]
    for entry in result.evidence["rules"]:
        assert set(entry) >= {"rule", "matched", "facts"}
        assert isinstance(entry["matched"], bool)
        assert isinstance(entry["facts"], dict)


def test_evidence_never_carries_session_ids_or_project_paths(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn, sid.S1_LATENCY_P95, bucket="lt30k")
    _drift_sessions(conn, count=2)

    blob = json.dumps(classify(conn, _draft([aid]), NOW).evidence)

    assert "sess-0" not in blob and "sess-1" not in blob
    assert "project-0" not in blob and "C:/work" not in blob
    assert '"distinct_sessions": 2' in blob


def test_classify_is_pure_and_writes_nothing(tmp_path: Path):
    conn = _conn(tmp_path)
    aid = _anomaly(conn)
    _incident(conn, "inc-1", created_at=hour_add(START, -1))

    def snapshot():
        return {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608
            for table in ("alerts", "anomalies", "incidents", "vitals_kv", "ingest_log")
        }

    before = snapshot()
    first = classify(conn, _draft([aid]), NOW)
    second = classify(conn, _draft([aid]), NOW)

    assert snapshot() == before
    assert first.cls == second.cls
    assert first.evidence == second.evidence


def test_classify_survives_a_draft_whose_anomaly_rows_are_missing(tmp_path: Path):
    conn = _conn(tmp_path)

    result = classify(conn, _draft([9999]), NOW)

    assert result.cls == "E"
    assert result.evidence["anomaly_ids_missing"] == [9999]

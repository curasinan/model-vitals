import json
import math
import random
from pathlib import Path

from vitals.config import DetectCfg
from vitals.db import get_conn, init_db
from vitals.detect import engine
from vitals.detect import signal_ids as sid
from vitals.detect.baseline import ANY_VERSION, window_series
from vitals.detect.cusum import update
from vitals.detect.engine import _standardize, resolve, tick
from vitals.timeutil import hour_add

S1 = sid.S1_LATENCY_P95
S2 = sid.S2_ERROR_RATE
MODEL = "claude-sonnet-5"
BUCKET = "gt180k"
VER = "2.1.230"
START = "2026-08-01T00:00:00+00:00"
CFG = DetectCfg(baseline_days=14, baseline_max_days=21)
REAL = DetectCfg()


def _conn(tmp_path: Path):
    conn = get_conn(tmp_path / "v.db")
    init_db(conn)
    return conn


def _seed(conn, signal, version, start, count, value, n=8, model=MODEL, bucket=BUCKET):
    ts = start
    for i in range(count):
        conn.execute(
            "INSERT OR IGNORE INTO signal_windows(window_start, signal, model, context_bucket,"
            " value, n, cc_version) VALUES (?,?,?,?,?,?,?)",
            (ts, signal, model, bucket, value(i) if callable(value) else value, n, version),
        )
        ts = hour_add(ts, 1)
    conn.commit()
    return ts


def _state(conn, signal=S1, version=VER, model=MODEL, bucket=BUCKET):
    return conn.execute(
        "SELECT * FROM detector_state WHERE signal=? AND model=? AND context_bucket=?"
        " AND cc_version=?",
        (signal, model, bucket, version),
    ).fetchone()


def _anomalies(conn):
    return conn.execute("SELECT * FROM anomalies ORDER BY id").fetchall()


def _anomaly(conn, version):
    return conn.execute(
        "SELECT * FROM anomalies WHERE cc_version = ? ORDER BY id", (version,)
    ).fetchone()


def _healthy_then_shift(conn, healthy=192, shifted=12, tail=0):
    rng = random.Random(11)
    ts = _seed(conn, S1, VER, START, healthy, lambda i: 7.60 + rng.gauss(0, 0.02))
    ts = _seed(conn, S1, VER, ts, shifted, lambda i: 8.80 + rng.gauss(0, 0.02))
    if tail:
        ts = _seed(conn, S1, VER, ts, tail, lambda i: 7.60 + rng.gauss(0, 0.02))
    return ts


def test_tick_establishes_baseline_and_opens_an_up_anomaly(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _healthy_then_shift(conn)

    opened = tick(conn, CFG, now)
    assert len(opened) == 2
    assert {a["cc_version"] for a in _anomalies(conn)} == {VER, ANY_VERSION}

    anomaly = _anomaly(conn, VER)
    assert anomaly["id"] in opened
    assert anomaly["signal"] == S1
    assert anomaly["model"] == MODEL and anomaly["context_bucket"] == BUCKET
    assert anomaly["direction"] == "up"
    assert anomaly["status"] == "open"
    assert anomaly["ended_at"] is None
    assert anomaly["peak_stat"] > CFG.h
    assert 3.0 < anomaly["peak_z"] < 3.5
    assert anomaly["started_at"] == hour_add(now, -11)

    state = _state(conn)
    assert state["frozen"] == 1 and state["in_alarm"] == 1
    assert state["baseline_inherited_from"] is None
    assert state["baseline_n"] == CFG.min_windows
    assert abs(state["mu0"] - 7.60) < 0.02
    assert math.isclose(state["sigma0"], 0.05 * state["mu0"])
    assert state["last_window"] == hour_add(now, -1)
    assert state["ewma"] is not None


def test_tick_is_idempotent(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _healthy_then_shift(conn)
    first = tick(conn, CFG, now)
    before = dict(_state(conn))

    second = tick(conn, CFG, now)

    assert first and second == []
    after = dict(_state(conn))
    for column in ("cusum_pos", "cusum_neg", "last_window", "baseline_n", "mu0", "ewma"):
        assert after[column] == before[column], column
    assert len(_anomalies(conn)) == 2


def test_windows_are_never_replayed_after_a_partial_tick(tmp_path: Path):
    conn_a = _conn(tmp_path / "a")
    now = _healthy_then_shift(conn_a)
    tick(conn_a, CFG, now)

    conn_b = _conn(tmp_path / "b")
    _healthy_then_shift(conn_b)
    at = hour_add(START, 100)
    while at < now:
        tick(conn_b, CFG, at)
        at = hour_add(at, 24)
    tick(conn_b, CFG, now)

    for version in (VER, ANY_VERSION):
        a = dict(_state(conn_a, version=version))
        b = dict(_state(conn_b, version=version))
        for column in ("cusum_pos", "cusum_neg", "last_window", "baseline_n", "mu0", "sigma0"):
            assert a[column] == b[column], (version, column)
    assert len(_anomalies(conn_b)) == 2


def _alert_for(conn, anomaly_ids):
    cur = conn.execute(
        "INSERT INTO alerts(ts, severity, attribution, title, evidence_json, anomaly_ids)"
        " VALUES (?,?,?,?,?,?)",
        (START, "INFO", "E", "latency up", "{}", json.dumps(list(anomaly_ids))),
    )
    conn.commit()
    return cur.lastrowid


def test_resolve_false_positive_unfreezes_and_folds_the_window_back(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _healthy_then_shift(conn)
    opened = tick(conn, CFG, now)
    before = _state(conn)["baseline_n"]
    alert_id = _alert_for(conn, opened)

    resolve(conn, alert_id, "false_positive", cfg=CFG, now_iso=now)

    state = _state(conn)
    assert state["frozen"] == 0 and state["in_alarm"] == 0
    assert state["cusum_pos"] == 0 and state["cusum_neg"] == 0
    assert state["baseline_n"] > before
    assert state["baseline_n"] == 204
    assert state["healthy_from"] is None
    assert {a["status"] for a in _anomalies(conn)} == {"false_positive"}
    alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    assert alert["resolution"] == "false_positive" and alert["resolved_at"] is not None


def test_resolve_confirmed_excludes_the_window_and_restarts_the_healthy_counter(tmp_path):
    conn = _conn(tmp_path)
    now = _healthy_then_shift(conn)
    opened = tick(conn, CFG, now)
    alert_id = _alert_for(conn, opened)

    resolve(conn, alert_id, "confirmed", cfg=CFG, now_iso=now)

    state = _state(conn)
    assert state["frozen"] == 0 and state["in_alarm"] == 0
    assert state["cusum_pos"] == 0 and state["cusum_neg"] == 0
    assert state["healthy_from"] == now
    assert state["mu0"] is None
    assert {a["status"] for a in _anomalies(conn)} == {"resolved"}


def test_resolve_accepts_an_anomaly_id_when_no_alert_row_exists(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _healthy_then_shift(conn)
    opened = tick(conn, CFG, now)

    target = _anomaly(conn, VER)["id"]
    assert resolve(conn, target, "false_positive", cfg=CFG, now_iso=now) == [target]

    assert _anomaly(conn, VER)["status"] == "false_positive"
    assert _state(conn)["frozen"] == 0


def test_baseline_is_frozen_while_an_anomaly_is_open(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _healthy_then_shift(conn)
    tick(conn, CFG, now)
    frozen_mu, frozen_n = _state(conn)["mu0"], _state(conn)["baseline_n"]

    later = _seed(conn, S1, VER, now, 24, 8.80)
    tick(conn, CFG, later)

    state = _state(conn)
    assert state["mu0"] == frozen_mu and state["baseline_n"] == frozen_n
    assert state["frozen"] == 1
    assert len(_anomalies(conn)) == 2
    assert _state(conn, version=ANY_VERSION)["frozen"] == 1


def test_anomaly_closes_after_six_quiet_windows(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _healthy_then_shift(conn, shifted=3, tail=40)
    tick(conn, CFG, now)

    anomaly = _anomaly(conn, VER)
    assert anomaly["ended_at"] is not None
    assert anomaly["status"] == "open"
    state = _state(conn)
    assert state["in_alarm"] == 0
    assert state["frozen"] == 1
    assert state["cusum_pos"] < CFG.h / 2


def test_windows_failing_the_sample_gate_are_skipped_not_zero_filled(tmp_path: Path):
    conn = _conn(tmp_path)
    ts = _seed(conn, S2, VER, START, 60, 0.2, n=50, bucket="all")
    now = _seed(conn, S2, VER, ts, 5, 0.0, n=5, bucket="all")

    tick(conn, CFG, now)

    state = _state(conn, signal=S2, bucket="all")
    assert state["mu0"] is not None
    assert state["cusum_neg"] == 0 and state["cusum_pos"] == 0
    assert state["last_window"] == hour_add(now, -1)
    assert _anomalies(conn) == []


def test_a_window_that_passes_the_gate_does_move_the_cusum(tmp_path: Path):
    conn = _conn(tmp_path)
    ts = _seed(conn, S2, VER, START, 60, 0.2, n=50, bucket="all")
    now = _seed(conn, S2, VER, ts, 5, 0.0, n=50, bucket="all")

    tick(conn, CFG, now)

    assert _state(conn, signal=S2, bucket="all")["cusum_neg"] > 0


def test_zero_rate_baseline_still_alarms_on_a_ten_percent_shift(tmp_path: Path):
    conn = _conn(tmp_path)
    ts = _seed(conn, S2, VER, START, 60, 0.0, n=50, bucket="all")
    now = _seed(conn, S2, VER, ts, 4, 0.10, n=50, bucket="all")

    opened = tick(conn, CFG, now)

    assert len(opened) == 2
    anomaly = _anomaly(conn, VER)
    assert anomaly["signal"] == S2 and anomaly["direction"] == "up"
    assert anomaly["started_at"] == hour_add(ts, 1)
    assert anomaly["peak_z"] > 40
    state = _state(conn, signal=S2, bucket="all")
    assert state["baseline_samples"] == 2500
    assert math.isclose(state["mu0"], 0.5 / 2500)


def _in_control_arl0(p0, n, windows=100_000, seed=1234, cfg=REAL, signal=S2):
    rng = random.Random(seed)
    state = {"mu0": p0, "sigma0": math.sqrt(p0 * (1 - p0))}
    pos = neg = 0.0
    alarms = evaluated = 0
    for _ in range(windows):
        raw = _standardize(cfg, signal, state, rng.binomialvariate(n, p0) / n, n)
        if raw is None:
            continue
        evaluated += 1
        pos, neg, alarm = update(pos, neg, max(-cfg.h, min(cfg.h, raw)), cfg.k, cfg.h)
        if alarm:
            alarms += 1
            pos = neg = 0.0
    return (windows / alarms if alarms else math.inf), alarms, evaluated


def test_the_observed_events_arm_no_longer_reaches_the_middle_band():
    arl0, alarms, evaluated = _in_control_arl0(0.05, 50)
    assert evaluated == 0 and alarms == 0
    assert arl0 > 400


def test_in_control_arl_matches_the_spec_where_windows_are_actually_evaluated():
    arl0, alarms, evaluated = _in_control_arl0(0.05, 150)
    assert evaluated == 100_000
    assert arl0 > 400
    assert alarms > 0


def test_the_regime_the_observed_arm_keeps_is_not_itself_degraded():
    _, deep_alarms, deep_evaluated = _in_control_arl0(0.0025, 50)
    assert deep_alarms == 0 and deep_evaluated == 0

    edge_arl0, _, edge_evaluated = _in_control_arl0(0.02, 49)
    assert edge_evaluated > 0
    assert edge_arl0 > 465


def test_version_churn_keeps_a_baseline_available_and_can_still_alarm(tmp_path: Path):
    conn = _conn(tmp_path)
    rng = random.Random(3)
    versions = ["2.1.181", "2.1.196", "2.1.203", "2.1.219", "2.1.230"]
    ts = START
    for version in versions:
        ts = _seed(conn, S1, version, ts, 30, lambda i: 7.60 + rng.gauss(0, 0.02))
    now = _seed(conn, S1, "2.1.237", ts, 8, lambda i: 8.80 + rng.gauss(0, 0.02))

    opened = tick(conn, CFG, now)

    for version in versions + ["2.1.237"]:
        row = _state(conn, version=version)
        assert row["baseline_n"] is None or row["baseline_inherited_from"] is not None

    collapsed = _state(conn, version=ANY_VERSION)
    assert collapsed is not None and collapsed["mu0"] is not None
    assert collapsed["baseline_inherited_from"] is None
    assert collapsed["baseline_n"] >= CFG.min_windows

    newest = _state(conn, version="2.1.237")
    assert newest["mu0"] is not None
    assert newest["baseline_inherited_from"] == ANY_VERSION

    assert len(opened) == 2
    assert {a["cc_version"] for a in _anomalies(conn)} == {"2.1.237", ANY_VERSION}


def test_an_inherited_baseline_is_promoted_once_the_stratum_stands_alone(tmp_path: Path):
    conn = _conn(tmp_path)
    rng = random.Random(5)
    ts = _seed(conn, S1, "2.1.230", START, 200, lambda i: 7.60 + rng.gauss(0, 0.02))
    tick(conn, CFG, ts)
    assert _state(conn, version="2.1.230")["baseline_inherited_from"] is None

    ts = _seed(conn, S1, "2.1.237", ts, 10, lambda i: 7.60 + rng.gauss(0, 0.02))
    tick(conn, CFG, ts)
    borrowed = _state(conn, version="2.1.237")
    assert borrowed["baseline_inherited_from"] == "2.1.230"

    now = _seed(conn, S1, "2.1.237", ts, 70, lambda i: 7.61 + rng.gauss(0, 0.02))
    tick(conn, CFG, now)

    grown = _state(conn, version="2.1.237")
    assert grown["baseline_inherited_from"] is None
    assert grown["baseline_n"] >= CFG.min_windows
    assert grown["mu0"] != borrowed["mu0"]


def test_the_collapsed_stratum_alarms_in_its_own_right(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _healthy_then_shift(conn)
    tick(conn, CFG, now)

    collapsed = _state(conn, version=ANY_VERSION)
    assert collapsed["in_alarm"] == 1 and collapsed["frozen"] == 1
    assert collapsed["cusum_pos"] > CFG.h
    assert collapsed["last_window"] == hour_add(now, -1)
    anomaly = _anomaly(conn, ANY_VERSION)
    assert anomaly["direction"] == "up" and anomaly["status"] == "open"


def test_the_collapsed_baseline_is_held_not_recomputed_under_an_anomaly(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _healthy_then_shift(conn)
    tick(conn, CFG, now)
    held = dict(_state(conn, version=ANY_VERSION))

    later = _seed(conn, S1, VER, now, 48, 8.80)
    tick(conn, CFG, later)

    after = _state(conn, version=ANY_VERSION)
    assert after["mu0"] == held["mu0"] and after["baseline_n"] == held["baseline_n"]
    assert after["baseline_end"] == held["baseline_end"]
    assert len(_anomalies(conn)) == 2


def test_collapsed_windows_pool_versions_that_share_an_hour(tmp_path: Path):
    conn = _conn(tmp_path)
    hour = hour_add(START, 0)
    _seed(conn, S1, "2.1.230", hour, 1, 8.0, n=30)
    _seed(conn, S1, "2.1.237", hour, 1, 6.0, n=10)
    rows = window_series(conn, S1, MODEL, BUCKET, ANY_VERSION, hour_add(hour, 1))
    assert len(rows) == 1
    assert rows[0]["n"] == 40
    assert math.isclose(rows[0]["value"], (8.0 * 30 + 6.0 * 10) / 40)


def test_a_stale_closed_episode_auto_resolves_and_unfreezes(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _healthy_then_shift(conn, shifted=3, tail=40)
    tick(conn, CFG, now)
    assert _anomaly(conn, VER)["ended_at"] is not None
    frozen_n = _state(conn)["baseline_n"]
    assert _state(conn)["frozen"] == 1

    tick(conn, CFG, hour_add(now, 24 * 3))
    assert _anomaly(conn, VER)["status"] == "open"
    assert _state(conn)["frozen"] == 1

    tick(conn, CFG, hour_add(now, 24 * (CFG.auto_resolve_days + 1)))

    assert _anomaly(conn, VER)["status"] == "auto_false_positive"
    assert _anomaly(conn, ANY_VERSION)["status"] == "auto_false_positive"
    state = _state(conn)
    assert state["frozen"] == 0 and state["in_alarm"] == 0
    assert state["cusum_pos"] == 0 and state["cusum_neg"] == 0
    assert state["healthy_from"] is None
    assert state["baseline_n"] > frozen_n
    logged = conn.execute(
        "SELECT COUNT(*) FROM ingest_log WHERE kind = 'anomaly_auto_resolved'"
    ).fetchone()[0]
    assert logged == 1


def test_an_open_episode_is_never_auto_resolved(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _healthy_then_shift(conn)
    tick(conn, CFG, now)
    assert _anomaly(conn, VER)["ended_at"] is None

    tick(conn, CFG, hour_add(now, 24 * 30))

    assert _anomaly(conn, VER)["status"] == "open"
    assert _state(conn)["frozen"] == 1


def test_auto_resolve_days_is_tunable(tmp_path: Path):
    cfg = DetectCfg(baseline_days=14, baseline_max_days=21, auto_resolve_days=1)
    conn = _conn(tmp_path)
    now = _healthy_then_shift(conn, shifted=3, tail=40)
    tick(conn, cfg, now)

    tick(conn, cfg, hour_add(now, 24 * 2))

    assert _anomaly(conn, VER)["status"] == "auto_false_positive"
    assert _state(conn)["frozen"] == 0


WEEK_VERSIONS = [
    "2.1.181",
    "2.1.196",
    "2.1.203",
    "2.1.211",
    "2.1.219",
    "2.1.226",
    "2.1.230",
    "2.1.237",
]
NEW_VERSION = "2.1.245"


def _put(conn, signal, version, ts, value, n=8, model=MODEL, bucket=BUCKET):
    conn.execute(
        "INSERT OR IGNORE INTO signal_windows(window_start, signal, model, context_bucket,"
        " value, n, cc_version) VALUES (?,?,?,?,?,?,?)",
        (ts, signal, model, bucket, value, n, version),
    )


def _week_of_churn(conn, shifted=8):
    rng = random.Random(21)
    hours = [hour_add(START, day * 24 + hour) for day in range(7) for hour in range(9, 23)]
    for index, ts in enumerate(hours):
        slot = min(index * len(WEEK_VERSIONS) // len(hours), len(WEEK_VERSIONS) - 1)
        _put(conn, S1, WEEK_VERSIONS[slot], ts, 7.60 + rng.gauss(0, 0.02))

    first_shift = hour_add(START, 7 * 24 + 9)
    shifted_hours = [hour_add(first_shift, i) for i in range(shifted)]
    for ts in shifted_hours:
        _put(conn, S1, NEW_VERSION, ts, 8.80 + rng.gauss(0, 0.02))
    conn.commit()
    return hour_add(first_shift, shifted), first_shift, shifted_hours


def test_a_week_of_version_churn_still_opens_an_anomaly(tmp_path: Path):
    conn = _conn(tmp_path)
    now, first_shift, shifted_hours = _week_of_churn(conn)

    per_version = conn.execute(
        "SELECT cc_version, COUNT(*) AS c FROM signal_windows GROUP BY cc_version"
    ).fetchall()
    assert len(per_version) == len(WEEK_VERSIONS) + 1
    assert max(row["c"] for row in per_version) < REAL.min_windows

    opened = tick(conn, REAL, now)

    assert len(opened) == 2
    assert {a["cc_version"] for a in _anomalies(conn)} == {NEW_VERSION, ANY_VERSION}
    for version in WEEK_VERSIONS:
        assert _anomaly(conn, version) is None

    fresh = _anomaly(conn, NEW_VERSION)
    assert fresh["direction"] == "up" and fresh["status"] == "open"
    assert fresh["started_at"] == shifted_hours[1]
    assert shifted_hours.index(fresh["started_at"]) + 1 == 2

    collapsed = _anomaly(conn, ANY_VERSION)
    assert collapsed["direction"] == "up"
    assert shifted_hours.index(collapsed["started_at"]) + 1 == 2

    any_state = _state(conn, version=ANY_VERSION)
    assert any_state["baseline_inherited_from"] is None
    assert any_state["baseline_n"] == REAL.min_windows
    assert _state(conn, version=NEW_VERSION)["baseline_inherited_from"] == ANY_VERSION
    for version in WEEK_VERSIONS:
        row = _state(conn, version=version)
        assert row["mu0"] is None or row["baseline_inherited_from"] == ANY_VERSION


def test_a_long_degradation_does_not_drift_the_collapsed_baseline_at_defaults(tmp_path: Path):
    conn = _conn(tmp_path)
    now, first_shift, _ = _week_of_churn(conn, shifted=144)

    opened = tick(conn, REAL, now)

    assert len(opened) == 2
    collapsed = _anomaly(conn, ANY_VERSION)
    assert collapsed["ended_at"] is None
    assert collapsed["status"] == "open"

    state = _state(conn, version=ANY_VERSION)
    assert state["cusum_pos"] > 100
    assert state["baseline_n"] == REAL.min_windows
    assert state["baseline_end"] < first_shift
    assert abs(state["mu0"] - 7.60) < 0.05

    fresh = _state(conn, version=NEW_VERSION)
    assert fresh["frozen"] == 1
    assert fresh["baseline_inherited_from"] == ANY_VERSION
    assert abs(fresh["mu0"] - 7.60) < 0.05


def test_churn_resolve_false_positive_folds_the_window_back_through_inheritance(tmp_path):
    conn = _conn(tmp_path)
    now, _, _ = _week_of_churn(conn)
    opened = tick(conn, REAL, now)
    alert_id = _alert_for(conn, opened)
    before = _state(conn, version=ANY_VERSION)["baseline_n"]

    resolve(conn, alert_id, "false_positive", cfg=REAL, now_iso=now)

    collapsed = _state(conn, version=ANY_VERSION)
    assert collapsed["frozen"] == 0 and collapsed["in_alarm"] == 0
    assert collapsed["cusum_pos"] == 0 and collapsed["cusum_neg"] == 0
    assert collapsed["baseline_n"] > before

    fresh = _state(conn, version=NEW_VERSION)
    assert fresh["frozen"] == 0 and fresh["in_alarm"] == 0
    assert fresh["cusum_pos"] == 0 and fresh["cusum_neg"] == 0
    assert fresh["baseline_inherited_from"] == ANY_VERSION
    assert fresh["baseline_n"] == collapsed["baseline_n"]
    assert {a["status"] for a in _anomalies(conn)} == {"false_positive"}


def test_churn_resolve_confirmed_restarts_the_healthy_counter_everywhere(tmp_path: Path):
    conn = _conn(tmp_path)
    now, _, _ = _week_of_churn(conn)
    opened = tick(conn, REAL, now)
    alert_id = _alert_for(conn, opened)

    resolve(conn, alert_id, "confirmed", cfg=REAL, now_iso=now)

    for version in (ANY_VERSION, NEW_VERSION):
        state = _state(conn, version=version)
        assert state["frozen"] == 0 and state["in_alarm"] == 0, version
        assert state["cusum_pos"] == 0 and state["cusum_neg"] == 0, version
        assert state["healthy_from"] == now, version
        assert state["mu0"] is None, version
    assert {a["status"] for a in _anomalies(conn)} == {"resolved"}


def _cycle(conn, started_at, pass_rate, aborted=None, model=MODEL, n_invalid=0, n_runs=20):
    valid = n_runs - n_invalid
    cur = conn.execute(
        "INSERT INTO canary_cycles(started_at, finished_at, model, effort, suite_hash, n_runs,"
        " n_pass, n_invalid, pass_rate, aborted_reason) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            started_at,
            started_at,
            model,
            "medium",
            "suite1",
            n_runs,
            int(round((pass_rate or 0) * valid)),
            n_invalid,
            pass_rate,
            aborted,
        ),
    )
    conn.commit()
    return cur.lastrowid


def _long_runs(conn, cycle_id, ts, passes, total):
    for i in range(total):
        conn.execute(
            "INSERT INTO canary_runs(cycle_id, task_id, attempt, ts, model, passed, invalid,"
            " long_context) VALUES (?,?,?,?,?,?,0,1)",
            (cycle_id, f"longctx-{i}", 1, ts, MODEL, 1 if i < passes else 0),
        )
    conn.commit()


def _cycle_times(count, start=START, every=8):
    return [hour_add(start, every * i) for i in range(count)]


def test_canary_c1_fires_after_k_consecutive_cycles_below_the_delta(tmp_path: Path):
    conn = _conn(tmp_path)
    times = _cycle_times(11)
    for ts in times[:8]:
        _cycle(conn, ts, 0.95)
    for ts in times[8:]:
        _cycle(conn, ts, 0.75)

    opened = tick(conn, CFG, hour_add(times[-1], 1))

    assert len(opened) == 1
    anomaly = _anomalies(conn)[0]
    assert anomaly["signal"] == sid.C1_CANARY_PASS
    assert anomaly["direction"] == "down"
    assert anomaly["started_at"] == times[-1]
    assert anomaly["peak_z"] is None
    state = _state(conn, signal=sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)
    assert state["k_count"] == CFG.K_cycles
    assert math.isclose(state["mu0"], 0.95)


def test_canary_c1_ignores_invalid_cycles_without_resetting_k(tmp_path: Path):
    conn = _conn(tmp_path)
    times = _cycle_times(12)
    for ts in times[:8]:
        _cycle(conn, ts, 0.95)
    _cycle(conn, times[8], 0.75)
    _cycle(conn, times[9], None, aborted="budget")
    _cycle(conn, times[10], 0.75)
    _cycle(conn, times[11], 0.75)

    opened = tick(conn, CFG, hour_add(times[-1], 1))

    assert len(opened) == 1
    assert _anomalies(conn)[0]["signal"] == sid.C1_CANARY_PASS
    infra = conn.execute("SELECT COUNT(*) FROM ingest_log WHERE kind = 'canary_infra'").fetchone()[
        0
    ]
    assert infra == 1


def test_canary_c1_k_counter_resets_on_a_healthy_cycle(tmp_path: Path):
    conn = _conn(tmp_path)
    times = _cycle_times(12)
    for ts in times[:8]:
        _cycle(conn, ts, 0.95)
    _cycle(conn, times[8], 0.75)
    _cycle(conn, times[9], 0.75)
    _cycle(conn, times[10], 0.95)
    _cycle(conn, times[11], 0.75)

    assert tick(conn, CFG, hour_add(times[-1], 1)) == []
    state = _state(conn, signal=sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)
    assert state["k_count"] == 1


def test_canary_c2_long_context_carries_its_own_baseline_and_counter(tmp_path: Path):
    conn = _conn(tmp_path)
    times = _cycle_times(11)
    for i, ts in enumerate(times):
        cycle_id = _cycle(conn, ts, 0.95)
        _long_runs(conn, cycle_id, ts, passes=2 if i < 8 else 1, total=2)

    opened = tick(conn, CFG, hour_add(times[-1], 1))

    assert len(opened) == 1
    anomaly = _anomalies(conn)[0]
    assert anomaly["signal"] == sid.C2_CANARY_LONGCTX and anomaly["direction"] == "down"
    c1 = _state(conn, signal=sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)
    c2 = _state(conn, signal=sid.C2_CANARY_LONGCTX, bucket="all", version=ANY_VERSION)
    assert c1["k_count"] == 0 and c1["mu0"] is not None
    assert c2["k_count"] == CFG.K_cycles
    assert math.isclose(c2["mu0"], 1.0)


def test_canary_suite_change_point_resets_both_baselines_and_counters(tmp_path: Path):
    conn = _conn(tmp_path)
    times = _cycle_times(12)
    for i, ts in enumerate(times[:10]):
        cycle_id = _cycle(conn, ts, 0.95 if i < 8 else 0.75)
        _long_runs(conn, cycle_id, ts, passes=2 if i < 8 else 1, total=2)
    tick(conn, CFG, hour_add(times[9], 1))
    assert _anomalies(conn) == []
    c1 = _state(conn, signal=sid.C1_CANARY_PASS, bucket="all", version=ANY_VERSION)
    assert c1["k_count"] == 2

    conn.execute(
        "INSERT INTO change_points(ts, kind, old_value, new_value) VALUES (?,?,?,?)",
        (hour_add(times[9], 1), "canary_suite", "suite1", "suite2"),
    )
    conn.commit()
    cycle_id = _cycle(conn, times[10], 0.75)
    _long_runs(conn, cycle_id, times[10], passes=1, total=2)

    assert tick(conn, CFG, hour_add(times[10], 1)) == []

    for signal in (sid.C1_CANARY_PASS, sid.C2_CANARY_LONGCTX):
        state = _state(conn, signal=signal, bucket="all", version=ANY_VERSION)
        assert state["k_count"] == 0, signal
        assert state["mu0"] is None, signal
        assert state["healthy_from"] == hour_add(times[9], 1), signal


def test_the_reclassified_proportion_signals_inherit_s2s_measured_arl0():
    for signal in (sid.S3_RETRY_RATE, sid.S7_SELF_CORR_RATE):
        for p0, n in ((0.05, 150), (0.05, 50), (0.02, 49)):
            assert _in_control_arl0(p0, n, windows=20_000, signal=signal) == _in_control_arl0(
                p0, n, windows=20_000, signal=S2
            ), f"{signal} diverged from {S2} at p0={p0} n={n}"


def test_a_decimated_cycle_cannot_report_a_clean_bill_of_health(tmp_path: Path):
    conn = _conn(tmp_path)
    times = _cycle_times(12)
    for ts in times[:8]:
        _cycle(conn, ts, 0.95)
    _cycle(conn, times[8], 0.75)
    _cycle(conn, times[9], 1.0, n_invalid=11)
    _cycle(conn, times[10], 0.75)
    _cycle(conn, times[11], 0.75)

    opened = tick(conn, CFG, hour_add(times[-1], 1))

    assert len(opened) == 1, "the decimated 1.0 must not break a real degradation streak"
    assert _anomalies(conn)[0]["signal"] == sid.C1_CANARY_PASS
    infra = conn.execute("SELECT COUNT(*) FROM ingest_log WHERE kind = 'canary_infra'").fetchone()[
        0
    ]
    assert infra == 1, "the harness failure must be recorded, not silently dropped"


def test_a_cycle_that_lost_a_minority_of_runs_still_counts_as_evidence(tmp_path: Path):
    conn = _conn(tmp_path)
    times = _cycle_times(12)
    for ts in times[:8]:
        _cycle(conn, ts, 0.95)
    _cycle(conn, times[8], 0.75)
    _cycle(conn, times[9], 0.95, n_invalid=4)
    _cycle(conn, times[10], 0.75)
    _cycle(conn, times[11], 0.75)

    assert tick(conn, CFG, hour_add(times[-1], 1)) == []
    infra = conn.execute("SELECT COUNT(*) FROM ingest_log WHERE kind = 'canary_infra'").fetchone()[
        0
    ]
    assert infra == 0, "a cycle that covered 80% of the suite is evidence, not infra news"


def test_cycles_landing_in_the_same_second_still_form_a_baseline(tmp_path):
    healthy_then_degraded = [1.0] * 6 + [0.6] * 3

    def opened_with(label, timestamps):
        conn = _conn(tmp_path / f"{label}.db")
        for ts, rate in zip(timestamps, healthy_then_degraded, strict=True):
            _cycle(conn, ts, rate, n_runs=5)
        return engine._canary_series(
            conn, DetectCfg(), sid.C1_CANARY_PASS, engine._c1_cycles(conn, DetectCfg())
        )

    spread = [f"2026-08-30T10:{i:02d}:00+00:00" for i in range(9)]
    tied = ["2026-08-30T10:00:00+00:00"] * 9

    assert opened_with("spread", spread), "sanity: a 1.0 -> 0.6 drop must open an anomaly"
    assert opened_with("tied", tied), (
        "the same nine cycles, distinguishable only by cycle_id, must still be "
        "detectable -- a clock that cannot separate them is not evidence of health"
    )

import math
from pathlib import Path

import pytest

from vitals.config import DetectCfg
from vitals.db import get_conn, init_db
from vitals.detect import signal_ids as sid
from vitals.detect.baseline import ANY_VERSION, compute_for, robust
from vitals.timeutil import hour_add

S1 = sid.S1_LATENCY_P95
S2 = sid.S2_ERROR_RATE
MODEL = "claude-sonnet-5"
BUCKET = "gt180k"
START = "2026-08-01T00:00:00+00:00"
CFG = DetectCfg(baseline_days=14, baseline_max_days=21)


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


def test_robust_baseline_ignores_outliers():
    vals = [10.0] * 50 + [500.0]
    mu, sigma = robust(vals)
    assert mu == 10.0 and sigma < 1.0


def test_robust_uses_iqr_when_mad_is_zero():
    vals = [1.0] * 5 + [2.0] * 4
    mu, sigma = robust(vals)
    assert mu == 1.0
    assert math.isclose(sigma, 1.0 / 1.349, rel_tol=1e-9)


def test_robust_relative_floor_on_a_constant_series():
    mu, sigma = robust([10.0] * 40)
    assert mu == 10.0 and math.isclose(sigma, 0.5)


def test_robust_absolute_floor_still_applies_to_real_but_tiny_dispersion():
    _, sigma = robust([1e-12] * 20 + [2e-12] * 20)
    assert sigma == 1e-9


def test_robust_on_empty_is_none():
    assert robust([]) == (None, None)


def test_robust_refuses_a_scale_when_every_dispersion_term_collapses():
    mu, sigma = robust([0.0] * 50)

    assert mu == 0.0
    assert sigma is None


def test_proportion_signals_are_classified_as_rates():
    assert sid.S3_RETRY_RATE in sid.RATE_SIGNALS
    assert sid.S7_SELF_CORR_RATE in sid.RATE_SIGNALS


def test_an_all_zero_retry_rate_baseline_keeps_a_usable_scale(tmp_path: Path):
    conn = _conn(tmp_path)
    end = _seed(conn, sid.S3_RETRY_RATE, "2.1.237", START, 60, 0.0, n=8)

    base = compute_for(conn, CFG, sid.S3_RETRY_RATE, MODEL, BUCKET, "2.1.237", end)

    assert base is not None
    assert base["mu0"] > 0.0, "Jeffreys floor must lift p0 off zero"
    assert base["sigma0"] > 0.01, f"expected a binomial sd, got {base['sigma0']}"


def test_compute_for_uses_own_windows_when_sufficient(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _seed(conn, S1, "2.1.230", START, 60, lambda i: 7.60 + (i % 5) * 0.01)
    base = compute_for(conn, CFG, S1, MODEL, BUCKET, "2.1.230", now)
    assert base is not None
    assert base["inherited_from"] is None
    assert base["n_windows"] == 60 and base["n_samples"] == 480
    assert math.isclose(base["mu0"], 7.62)
    assert math.isclose(base["sigma0"], 0.05 * 7.62)


def test_compute_for_returns_none_with_no_history_anywhere(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _seed(conn, S1, "2.1.230", START, 10, 7.6)
    assert compute_for(conn, CFG, S1, MODEL, BUCKET, "2.1.230", now) is None


def test_compute_for_extends_lookback_before_giving_up(tmp_path: Path):
    conn = _conn(tmp_path)
    end = _seed(conn, S1, "2.1.230", START, 60, 7.6)
    now = hour_add(end, 24 * 10)
    cfg = DetectCfg(baseline_days=7, baseline_max_days=21)
    base = compute_for(conn, cfg, S1, MODEL, BUCKET, "2.1.230", now)
    assert base is not None and base["n_windows"] == 60 and base["inherited_from"] is None
    tight = DetectCfg(baseline_days=7, baseline_max_days=7)
    assert compute_for(conn, tight, S1, MODEL, BUCKET, "2.1.230", now) is None


def test_compute_for_inherits_from_the_most_recent_prior_version(tmp_path: Path):
    conn = _conn(tmp_path)
    end_old = _seed(conn, S1, "2.1.230", START, 60, 7.60)
    conn.execute(
        "INSERT INTO detector_state(signal, model, context_bucket, cc_version, mu0, sigma0,"
        " baseline_n, baseline_samples, baseline_end) VALUES (?,?,?,?,?,?,?,?,?)",
        (S1, MODEL, BUCKET, "2.1.230", 7.60, 0.38, 60, 480, end_old),
    )
    conn.commit()
    now = _seed(conn, S1, "2.1.237", end_old, 10, 9.0)

    base = compute_for(conn, CFG, S1, MODEL, BUCKET, "2.1.237", now)
    assert base is not None
    assert base["inherited_from"] == "2.1.230"
    assert base["mu0"] == 7.60 and base["sigma0"] == 0.38


def test_inheritance_beats_the_version_collapsed_fallback(tmp_path: Path):
    conn = _conn(tmp_path)
    end_old = _seed(conn, S1, "2.1.230", START, 60, 7.60)
    conn.execute(
        "INSERT INTO detector_state(signal, model, context_bucket, cc_version, mu0, sigma0,"
        " baseline_n, baseline_samples, baseline_end) VALUES (?,?,?,?,?,?,?,?,?)",
        (S1, MODEL, BUCKET, "2.1.230", 1.0, 0.5, 60, 480, end_old),
    )
    conn.commit()
    now = _seed(conn, S1, "2.1.237", end_old, 10, 7.60)
    base = compute_for(conn, CFG, S1, MODEL, BUCKET, "2.1.237", now)
    assert base["inherited_from"] == "2.1.230" and base["mu0"] == 1.0


def test_compute_for_falls_back_to_version_collapsed_any(tmp_path: Path):
    conn = _conn(tmp_path)
    ts = START
    for version in ("2.1.181", "2.1.203", "2.1.230"):
        ts = _seed(conn, S1, version, ts, 20, 7.60)
    now = _seed(conn, S1, "2.1.237", ts, 4, 7.60)

    base = compute_for(conn, CFG, S1, MODEL, BUCKET, "2.1.237", now)
    assert base is not None
    assert base["inherited_from"] == ANY_VERSION
    assert base["n_windows"] == 64
    assert math.isclose(base["mu0"], 7.60)


def test_any_stratum_pools_every_version(tmp_path: Path):
    conn = _conn(tmp_path)
    ts = START
    for version in ("2.1.181", "2.1.203", "2.1.230"):
        ts = _seed(conn, S1, version, ts, 20, 7.60)
    base = compute_for(conn, CFG, S1, MODEL, BUCKET, ANY_VERSION, ts)
    assert base is not None and base["n_windows"] == 60 and base["inherited_from"] is None


def test_compute_for_excludes_hours_inside_an_open_anomaly(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _seed(conn, S1, "2.1.230", START, 60, 7.60)
    conn.execute(
        "INSERT INTO anomalies(signal, model, context_bucket, cc_version, started_at, ended_at,"
        " direction, status) VALUES (?,?,?,?,?,?,'up','open')",
        (S1, MODEL, BUCKET, "2.1.230", hour_add(START, 10), hour_add(START, 19)),
    )
    conn.commit()
    base = compute_for(conn, CFG, S1, MODEL, BUCKET, "2.1.230", now)
    assert base["n_windows"] == 50

    conn.execute("UPDATE anomalies SET status = 'false_positive'")
    conn.commit()
    folded = compute_for(conn, CFG, S1, MODEL, BUCKET, "2.1.230", now)
    assert folded["n_windows"] == 60

    conn.execute("UPDATE anomalies SET status = 'auto_false_positive'")
    conn.commit()
    auto = compute_for(conn, CFG, S1, MODEL, BUCKET, "2.1.230", now)
    assert auto["n_windows"] == 60


def test_compute_for_excludes_suppressed_incident_hours(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _seed(conn, S1, "2.1.230", START, 60, 7.60)
    conn.execute(
        "INSERT INTO incidents(incident_id, name, status, created_at, resolved_at, components)"
        " VALUES ('inc1','api degraded','resolved',?,?,'Claude API (api.anthropic.com)')",
        (hour_add(START, 5), hour_add(START, 9)),
    )
    conn.commit()
    base = compute_for(conn, CFG, S1, MODEL, BUCKET, "2.1.230", now)
    assert base["n_windows"] == 55


def test_compute_for_honours_healthy_from(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _seed(conn, S1, "2.1.230", START, 120, 7.60)
    conn.execute(
        "INSERT INTO detector_state(signal, model, context_bucket, cc_version, healthy_from)"
        " VALUES (?,?,?,?,?)",
        (S1, MODEL, BUCKET, "2.1.230", hour_add(START, 60)),
    )
    conn.commit()
    base = compute_for(conn, CFG, S1, MODEL, BUCKET, "2.1.230", now)
    assert base["n_windows"] == 60 and base["inherited_from"] is None


def test_rate_baseline_pools_the_proportion(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _seed(conn, S2, "2.1.230", START, 60, lambda i: 0.0 if i % 2 else 0.2, n=50, bucket="all")
    base = compute_for(conn, CFG, S2, MODEL, "all", "2.1.230", now)
    assert base["is_rate"] is True
    assert math.isclose(base["mu0"], 0.1)
    assert math.isclose(base["sigma0"], math.sqrt(0.1 * 0.9))


def test_rate_baseline_floors_a_zero_proportion(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _seed(conn, S2, "2.1.230", START, 60, 0.0, n=50, bucket="all")
    base = compute_for(conn, CFG, S2, MODEL, "all", "2.1.230", now)
    assert base["n_samples"] == 3000
    assert math.isclose(base["mu0"], 0.5 / 3000)
    assert base["sigma0"] > 0
    assert math.isclose(base["sigma0"], math.sqrt(base["mu0"] * (1 - base["mu0"])))


def test_rate_baseline_leaves_a_healthy_proportion_alone(tmp_path: Path):
    conn = _conn(tmp_path)
    now = _seed(conn, S2, "2.1.230", START, 60, 0.05, n=50, bucket="all")
    base = compute_for(conn, CFG, S2, MODEL, "all", "2.1.230", now)
    assert math.isclose(base["mu0"], 0.05)


@pytest.mark.parametrize("signal", sorted(sid.RATE_SIGNALS))
def test_every_registered_rate_signal_is_treated_as_a_rate(tmp_path: Path, signal: str):
    conn = _conn(tmp_path)
    now = _seed(conn, signal, "2.1.230", START, 60, 0.0, n=50, bucket="all")
    base = compute_for(conn, CFG, signal, MODEL, "all", "2.1.230", now)
    assert base["is_rate"] is True and base["mu0"] > 0

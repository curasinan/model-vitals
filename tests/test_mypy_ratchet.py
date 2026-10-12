from __future__ import annotations

import sys

sys.path.insert(0, "scripts")

from mypy_ratchet import parse_count, verdict


def test_a_rising_count_fails():
    code, message = verdict(241, 240)
    assert code == 1
    assert "rose" in message


def test_the_baseline_exactly_passes():
    code, _ = verdict(240, 240)
    assert code == 0


def test_a_falling_count_also_fails_so_the_baseline_cannot_drift_upward():
    code, message = verdict(238, 240)
    assert code == 1
    assert "must come down" in message


def test_unparseable_output_is_a_failure_not_a_clean_run():
    assert parse_count("Traceback (most recent call last): ...") is None
    code, message = verdict(None, 240)
    assert code == 1
    assert "could not parse" in message


def test_a_genuinely_clean_run_is_recognised():
    assert parse_count("Success: no issues found in 42 source files") == 0
    assert verdict(0, 0)[0] == 0


def test_real_mypy_output_is_parsed():
    real = (
        "src\\vitals\\cli.py:409: error: Function is missing a type annotation "
        "for one or more parameters  [no-untyped-def]\n"
        "Found 240 errors in 23 files (checked 42 source files)\n"
    )
    assert parse_count(real) == 240


def test_a_missing_platform_baseline_fails_rather_than_passing_by_default():
    code, message = verdict(240, None)
    assert code == 1
    assert "no baseline" in message

import math

from vitals.detect.cusum import ewma_update, update


def test_cusum_stays_quiet_in_control():
    import random

    rng = random.Random(7)
    pos = neg = 0.0
    alarms = 0
    for _ in range(400):
        pos, neg, alarm = update(pos, neg, rng.gauss(0, 1), 0.5, 5.0)
        alarms += alarm
    assert alarms <= 1


def test_cusum_detects_one_sigma_shift_within_20():
    pos = neg = 0.0
    for t in range(20):
        pos, neg, alarm = update(pos, neg, 1.0, 0.5, 5.0)
        if alarm:
            assert 8 <= t + 1 <= 12
            break
    else:
        raise AssertionError("no alarm within 20 windows")


def test_cusum_two_sided():
    pos = neg = 0.0
    for _ in range(15):
        pos, neg, alarm = update(pos, neg, -1.2, 0.5, 5.0)
    assert alarm and neg > 5.0


def test_cusum_arms_are_independent_and_never_negative():
    pos = neg = 0.0
    for _ in range(5):
        pos, neg, _ = update(pos, neg, 2.0, 0.5, 5.0)
    assert pos == 7.5 and neg == 0.0
    for _ in range(5):
        pos, neg, _ = update(pos, neg, -2.0, 0.5, 5.0)
    assert pos == 0.0 and neg == 7.5


def test_ewma_tracks_the_series():
    value = None
    for _ in range(50):
        value = ewma_update(value, 10.0, 0.2)
    assert math.isclose(value, 10.0, abs_tol=1e-3)
    assert ewma_update(None, 3.0, 0.2) == 3.0
    assert math.isclose(ewma_update(0.0, 10.0, 0.2), 2.0)

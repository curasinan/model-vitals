from vitals.timeutil import epoch_to_iso, hour_floor, utcnow_iso


def test_utcnow_iso_is_utc_seconds():
    s = utcnow_iso()
    assert s.endswith("+00:00")
    assert len(s) == len("2026-08-25T10:00:00+00:00")


def test_hour_floor_truncates():
    assert hour_floor("2026-08-25T10:37:12+00:00") == "2026-08-25T10:00:00+00:00"
    assert hour_floor("2026-08-25T10:00:00+00:00") == "2026-08-25T10:00:00+00:00"


def test_epoch_to_iso_roundtrip():
    assert epoch_to_iso(0) == "1970-01-01T00:00:00+00:00"
    assert epoch_to_iso(1_756_100_000.5).startswith("2025-")

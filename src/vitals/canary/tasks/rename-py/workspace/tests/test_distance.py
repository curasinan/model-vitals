import math

from geo.distance import great_circle_km


def test_great_circle_km_zero_for_same_point():
    assert great_circle_km(51.5074, -0.1278, 51.5074, -0.1278) == 0.0


def test_great_circle_km_quarter_meridian_matches_quarter_circumference():
    # A quarter of a meridian (equator to pole) is exactly a quarter of the great-circle
    # circumference at the radius the function uses -- an exact geometric check, not a
    # memorized real-world distance.
    d = great_circle_km(0.0, 0.0, 90.0, 0.0)
    expected = (math.pi / 2) * 6371.0088
    assert math.isclose(d, expected, rel_tol=1e-9)


def test_great_circle_km_is_symmetric():
    a = great_circle_km(40.7128, -74.0060, 34.0522, -118.2437)
    b = great_circle_km(34.0522, -118.2437, 40.7128, -74.0060)
    assert math.isclose(a, b, rel_tol=1e-9)

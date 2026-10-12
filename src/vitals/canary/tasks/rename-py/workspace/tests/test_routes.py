import math

from geo.distance import great_circle_km
from geo.routes import route_distance_km


def test_route_distance_km_single_leg_matches_direct_distance():
    waypoints = [(51.5074, -0.1278), (48.8566, 2.3522)]
    assert math.isclose(
        route_distance_km(waypoints),
        great_circle_km(51.5074, -0.1278, 48.8566, 2.3522),
        rel_tol=1e-9,
    )


def test_route_distance_km_sums_multiple_legs():
    waypoints = [(51.5074, -0.1278), (48.8566, 2.3522), (52.5200, 13.4050)]
    leg1 = great_circle_km(51.5074, -0.1278, 48.8566, 2.3522)
    leg2 = great_circle_km(48.8566, 2.3522, 52.5200, 13.4050)
    assert math.isclose(route_distance_km(waypoints), leg1 + leg2, rel_tol=1e-9)


def test_route_distance_km_empty_or_single_point_is_zero():
    assert route_distance_km([]) == 0.0
    assert route_distance_km([(0.0, 0.0)]) == 0.0

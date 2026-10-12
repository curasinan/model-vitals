"""Total distance along a route made of (lat, lon) waypoints, using great_circle_km per leg."""

from __future__ import annotations

from geo.distance import great_circle_km


def route_distance_km(waypoints: list[tuple[float, float]]) -> float:
    if len(waypoints) < 2:
        return 0.0
    total = 0.0
    for (lat1, lon1), (lat2, lon2) in zip(waypoints, waypoints[1:]):
        total += great_circle_km(lat1, lon1, lat2, lon2)
    return total

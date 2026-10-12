from __future__ import annotations

import pyarrow as pa

from corpus.synthetic import (
    SYNTHETIC_WORLD_DIGESTS,
    build_synthetic_world,
    world_digests,
)


def test_the_synthetic_world_content_matches_its_pinned_digest() -> None:
    assert world_digests(build_synthetic_world()) == SYNTHETIC_WORLD_DIGESTS


def test_world_digests_is_deterministic() -> None:
    assert world_digests(build_synthetic_world()) == world_digests(build_synthetic_world())


def test_the_digest_catches_a_one_value_perturbation() -> None:
    world = build_synthetic_world(hours=4)
    baseline = world_digests(world)

    requests = world["requests"]
    column_index = requests.schema.get_field_index("latency_ms")
    original = requests.column(column_index)[0].as_py()
    perturbed_values = requests.column(column_index).to_pylist()
    perturbed_values[0] = original + 1
    perturbed_requests = requests.set_column(
        column_index,
        "latency_ms",
        pa.array(perturbed_values, type=requests.schema.field(column_index).type),
    )
    perturbed_world = dict(world)
    perturbed_world["requests"] = perturbed_requests

    assert world_digests(perturbed_world) != baseline
    perturbed_digests = world_digests(perturbed_world)
    for table in baseline:
        if table != "requests":
            assert perturbed_digests[table] == baseline[table], table
    assert perturbed_digests["requests"] != baseline["requests"]

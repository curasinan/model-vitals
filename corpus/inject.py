from __future__ import annotations

import hashlib
import math
import random
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any, Literal

from corpus import schema

if TYPE_CHECKING:  # pragma: no cover
    import pyarrow as pa

CorpusTables = Mapping[str, "pa.Table"]

InjectionClass = Literal["A", "B", "C", "D"]

InjectionParams = Mapping[str, object]

_Handler = Callable[[CorpusTables, InjectionParams], CorpusTables]


def _require_seed(params: InjectionParams) -> int:
    if "seed" not in params:
        raise ValueError(
            'injection params must include "seed" (an int, fed to random.Random(seed)) -- '
            "corpus.inject never falls back to silent, unseeded randomness"
        )
    value = params["seed"]
    if not isinstance(value, int):
        raise ValueError(f'params["seed"] must be an int, got {type(value).__name__}')
    return value


def _float_param(params: InjectionParams, key: str, default: float) -> float:
    value = params.get(key, default)
    if not isinstance(value, (int, float)):
        raise ValueError(f"params[{key!r}] must be a number, got {type(value).__name__}")
    return float(value)


def _int_param(params: InjectionParams, key: str, default: int) -> int:
    value = params.get(key, default)
    if not isinstance(value, int):
        raise ValueError(f"params[{key!r}] must be an int, got {type(value).__name__}")
    return value


def _str_param(params: InjectionParams, key: str, default: str) -> str:
    value = params.get(key, default)
    if not isinstance(value, str):
        raise ValueError(f"params[{key!r}] must be a str, got {type(value).__name__}")
    return value


_CLASS_A_HIGH_CONTEXT_BUCKETS: frozenset[str] = frozenset({"b100_180k", "gt180k"})


def _most_populated_high_bucket(request_rows: list[Any]) -> str:
    counts: Counter[str] = Counter(
        str(row["context_bucket"])
        for row in request_rows
        if row.get("context_bucket") in _CLASS_A_HIGH_CONTEXT_BUCKETS
    )
    if not counts:
        raise ValueError(
            "class A needs a requests row in a HIGH context bucket "
            f"({sorted(_CLASS_A_HIGH_CONTEXT_BUCKETS)}) to target, but this corpus has none -- "
            'pass params["bucket"] explicitly'
        )
    return max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0]


def _high_bucket_param(params: InjectionParams, request_rows: list[Any]) -> str:
    value = params.get("bucket")
    if value is None:
        return _most_populated_high_bucket(request_rows)
    if not isinstance(value, str):
        raise ValueError(f'params["bucket"] must be a str, got {type(value).__name__}')
    if value not in _CLASS_A_HIGH_CONTEXT_BUCKETS:
        raise ValueError(
            f'params["bucket"] {value!r} is not a HIGH context bucket '
            f"({sorted(_CLASS_A_HIGH_CONTEXT_BUCKETS)}) -- attribution rule 3 can only grant "
            "class A on high-bucket confinement, so a low-context target could never be "
            "attributed to it"
        )
    return value


def _prompt_representative_bucket(request_rows: list[Any]) -> dict[tuple[str, int], str | None]:
    hours: dict[tuple[str, int], Any] = {}
    bucket_for: dict[tuple[str, int], str | None] = {}
    for row in request_rows:
        seq = row.get("prompt_seq")
        if seq is None:
            continue
        key = (str(row["session_hash"]), int(seq))
        moment = row["ts_bucket_utc"]
        if key not in hours or moment < hours[key]:
            hours[key] = moment
            context_bucket = row.get("context_bucket")
            bucket_for[key] = None if context_bucket is None else str(context_bucket)
    return bucket_for


def _scaled_up(value: int, magnitude: float) -> int:
    return max(math.ceil(value * magnitude), value + 2)


def _replace_column(table: pa.Table, name: str, values: list[Any]) -> pa.Table:
    import pyarrow as pa

    index = table.schema.get_field_index(name)
    field = table.schema.field(index)
    return table.set_column(index, field, pa.array(values, type=field.type))


def _append_row(table: pa.Table, table_name: str, row: Mapping[str, object]) -> pa.Table:
    import pyarrow as pa

    new_row = pa.Table.from_pylist([dict(row)], schema=schema.arrow_schema(table_name))
    return pa.concat_tables([table, new_row])


def _synthetic_change_hash(*parts: str) -> str:
    label = "\x00".join(("corpus.inject.class-b.synthetic", *parts))
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


_CLASS_B_ALLOWED_KINDS: frozenset[str] = frozenset(schema.CHANGE_POINT_KINDS) - {
    "cc_version",
    "canary_suite",
}


def _inject_class_a(corpus: CorpusTables, params: InjectionParams) -> CorpusTables:
    seed = _require_seed(params)
    rng = random.Random(seed)
    magnitude = _float_param(params, "magnitude", 4.0)
    magnitude_latency = _float_param(params, "magnitude_latency", 1.8)
    error_frac = _float_param(params, "error_frac", 0.0)
    n_sessions = _int_param(params, "n_sessions", 2)
    n_prompts = _int_param(params, "n_prompts", 10)

    turn_features = corpus["turn_features"]
    turn_rows = turn_features.to_pylist()
    requests = corpus["requests"]
    request_rows = requests.to_pylist()

    bucket = _high_bucket_param(params, request_rows)

    sessions = sorted({str(row["session_hash"]) for row in turn_rows})
    chosen_sessions = set(rng.sample(sessions, k=min(max(n_sessions, 0), len(sessions))))

    prompt_bucket = _prompt_representative_bucket(request_rows)

    rows_by_session: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(turn_rows):
        rows_by_session[str(row["session_hash"])].append(index)

    targets: set[int] = set()
    window_prompt_seqs: dict[str, set[int]] = defaultdict(set)
    for session in chosen_sessions:
        ordered = sorted(rows_by_session[session], key=lambda i: int(turn_rows[i]["prompt_seq"]))
        last_n = ordered[-n_prompts:] if n_prompts > 0 else []
        window_prompt_seqs[session] = {int(turn_rows[i]["prompt_seq"]) for i in last_n}
        for index in last_n:
            key = (session, int(turn_rows[index]["prompt_seq"]))
            if prompt_bucket.get(key) == bucket:
                targets.add(index)

    if not targets:
        raise ValueError(
            f"class A selected zero turn_features rows to perturb: sessions="
            f"{sorted(chosen_sessions)!r}, bucket={bucket!r}, n_prompts={n_prompts} -- an "
            "injection that touches nothing must never return quietly"
        )

    tool_failures = [int(row["tool_failures"]) for row in turn_rows]
    edit_retry_max = [int(row["edit_retry_max"]) for row in turn_rows]
    for index in targets:
        tool_failures[index] = _scaled_up(tool_failures[index], magnitude)
        edit_retry_max[index] = _scaled_up(edit_retry_max[index], magnitude)

    perturbed_turn_features = _replace_column(turn_features, "tool_failures", tool_failures)
    perturbed_turn_features = _replace_column(
        perturbed_turn_features, "edit_retry_max", edit_retry_max
    )

    request_targets: list[int] = []
    for index, row in enumerate(request_rows):
        session = str(row["session_hash"])
        if session not in chosen_sessions:
            continue
        seq = row.get("prompt_seq")
        if seq is None or int(seq) not in window_prompt_seqs.get(session, set()):
            continue
        if row.get("context_bucket") != bucket:
            continue
        request_targets.append(index)

    latency_ms = [row.get("latency_ms") for row in request_rows]
    error_class = [row.get("error_class") for row in request_rows]
    request_changed = False
    for index in request_targets:
        if latency_ms[index] is not None:
            new_latency = round(latency_ms[index] * magnitude_latency)
            request_changed = request_changed or new_latency != latency_ms[index]
            latency_ms[index] = new_latency

    flippable = sorted(i for i in request_targets if error_class[i] == "none")
    n_flip = round(error_frac * len(flippable))
    for index in rng.sample(flippable, k=min(max(n_flip, 0), len(flippable))):
        error_class[index] = "server"
        request_changed = True

    if not request_changed:
        raise ValueError(
            f"class A's request-level layer changed no requests values: sessions="
            f"{sorted(chosen_sessions)!r}, bucket={bucket!r}, n_prompts={n_prompts} -- an "
            "injection that touches nothing must never return quietly"
        )

    perturbed_requests = _replace_column(requests, "latency_ms", latency_ms)
    perturbed_requests = _replace_column(perturbed_requests, "error_class", error_class)

    result = dict(corpus)
    result["turn_features"] = perturbed_turn_features
    result["requests"] = perturbed_requests
    return result


def _inject_class_b(corpus: CorpusTables, params: InjectionParams) -> CorpusTables:
    seed = _require_seed(params)
    random.Random(seed)
    kind = _str_param(params, "kind", "plugins")
    if kind == "cc_version":
        raise ValueError(
            "injection class B cannot target kind='cc_version': change_points identities "
            "(from_hash/to_hash) are 64-hex HMAC digests, and the attribution rule that would "
            "credit a cc_version change point needs PLAINTEXT equality against the anomaly's "
            "own cc_version string -- a hash can never equal a plaintext version, so this arm "
            f"is structurally unreachable. Use one of {sorted(_CLASS_B_ALLOWED_KINDS)} instead."
        )
    if kind not in _CLASS_B_ALLOWED_KINDS:
        raise ValueError(
            f"unknown class B kind {kind!r}; must be one of {sorted(_CLASS_B_ALLOWED_KINDS)}"
        )
    at_frac = _float_param(params, "at_frac", 0.7)
    magnitude_tokens = _float_param(params, "magnitude_tokens", 1.6)
    magnitude_latency = _float_param(params, "magnitude_latency", 1.5)

    requests = corpus["requests"]
    request_rows = requests.to_pylist()
    if not request_rows:
        raise ValueError("class B needs at least one requests row to place a change point on")

    hours = sorted({row["ts_bucket_utc"] for row in request_rows})
    index = min(len(hours) - 1, max(0, math.floor(at_frac * len(hours))))
    chosen_hour = hours[index]

    output_tokens = [row.get("output_tokens") for row in request_rows]
    latency_ms = [row.get("latency_ms") for row in request_rows]
    changed = False
    for i, row in enumerate(request_rows):
        if row["ts_bucket_utc"] < chosen_hour:
            continue
        if output_tokens[i] is not None:
            new_value = round(output_tokens[i] * magnitude_tokens)
            changed = changed or new_value != output_tokens[i]
            output_tokens[i] = new_value
        if latency_ms[i] is not None:
            new_value = round(latency_ms[i] * magnitude_latency)
            changed = changed or new_value != latency_ms[i]
            latency_ms[i] = new_value

    if not changed:
        raise ValueError(
            f"class B's step at hour {chosen_hour!r} (kind={kind!r}) changed no requests "
            "values: every row at/after that hour had NULL output_tokens and latency_ms, or "
            "was already at the scaled value -- an injection that touches nothing must never "
            "return quietly"
        )

    perturbed_requests = _replace_column(requests, "output_tokens", output_tokens)
    perturbed_requests = _replace_column(perturbed_requests, "latency_ms", latency_ms)

    new_change_point = {
        "ts_bucket_utc": chosen_hour,
        "kind": kind,
        "from_hash": _synthetic_change_hash("from", str(seed), kind, repr(at_frac)),
        "to_hash": _synthetic_change_hash("to", str(seed), kind, repr(at_frac)),
    }
    perturbed_change_points = _append_row(
        corpus["change_points"], "change_points", new_change_point
    )

    result = dict(corpus)
    result["requests"] = perturbed_requests
    result["change_points"] = perturbed_change_points
    return result


def _inject_class_c(corpus: CorpusTables, params: InjectionParams) -> CorpusTables:
    seed = _require_seed(params)
    random.Random(seed)
    drop_to = _float_param(params, "drop_to", 0.5)
    n_cycles = _int_param(params, "n_cycles", 4)

    canary_cycles = corpus["canary_cycles"]
    rows = canary_cycles.to_pylist()

    cycle_ids = sorted({int(row["cycle_id"]) for row in rows})
    chosen_cycles = set(cycle_ids[-n_cycles:]) if n_cycles > 0 else set()

    passes = [int(row["passes"]) for row in rows]
    changed = False
    for i, row in enumerate(rows):
        if int(row["cycle_id"]) in chosen_cycles:
            new_value = math.floor(passes[i] * drop_to)
            changed = changed or new_value != passes[i]
            passes[i] = new_value

    if not changed:
        raise ValueError(
            f"class C selected zero canary_cycles rows to change: cycles={sorted(chosen_cycles)!r}"
            f", n_cycles={n_cycles}, drop_to={drop_to} -- an injection that touches nothing must "
            "never return quietly"
        )

    perturbed = _replace_column(canary_cycles, "passes", passes)

    result = dict(corpus)
    result["canary_cycles"] = perturbed
    return result


def _inject_class_d(corpus: CorpusTables, params: InjectionParams) -> CorpusTables:
    raise NotImplementedError(
        "injection class D is reserved for the local backend -- it drives Claude Code "
        "directly rather than perturbing corpus rows, and is out of scope for corpus.inject"
    )


def inject(corpus: CorpusTables, cls: InjectionClass, params: InjectionParams) -> CorpusTables:
    handlers: dict[InjectionClass, _Handler] = {
        "A": _inject_class_a,
        "B": _inject_class_b,
        "C": _inject_class_c,
        "D": _inject_class_d,
    }
    try:
        handler = handlers[cls]
    except KeyError:
        raise ValueError(
            f"unknown injection class {cls!r}; must be one of {sorted(handlers)}"
        ) from None
    return handler(corpus, params)

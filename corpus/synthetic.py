from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from corpus import schema

if TYPE_CHECKING:  # pragma: no cover
    import pyarrow as pa

__all__ = [
    "SYNTHETIC_EPOCH",
    "SYNTHETIC_WORLD_DIGESTS",
    "SYNTHETIC_WORLD_VERSION",
    "WORLD_HOURS",
    "build_corpus",
    "build_synthetic_world",
    "column_value",
    "corpus_table",
    "default_cell",
    "synthetic_hash",
    "world_digests",
    "world_hour",
]

SYNTHETIC_WORLD_VERSION = "1.1.0"

SYNTHETIC_EPOCH = datetime(2026, 1, 5, 0, 0, tzinfo=UTC)

SYNTHETIC_WORLD_DIGESTS: dict[str, str] = {
    "canary_cycles": "26fd6905ce0e615494b6c75e7cb37bec7072c1af8f8e5bf580274e2c2f1cd478",
    "change_points": "eadd9076facc17e0290b40db51dcfac2f4bb80a8f7f4e6dd2265996767cab767",
    "requests": "9f5d88fbb58dfd7ba9b23de6ff4c6b9dca9a291a696e9f19753ae7e09ae8f5a1",
    "tool_results": "ccd7f1c90760c35872984c6fd6a0dbbbc8d3242e93f453a871cd4c0230b1cb01",
    "turn_features": "90acf98dbcb78408f2b67d0b4f721e785da98b2f0ee284b4196a6132f4495356",
}

_HASHER = schema.Hasher(b"corpus.synthetic deterministic world -- not a secret, not the corpus key")


def synthetic_hash(domain: str, value: str) -> str:
    return _HASHER.hash(domain, value)


def _table_digest(table: pa.Table) -> str:
    payload = {name: table.column(name).to_pylist() for name in sorted(table.schema.names)}
    blob = json.dumps(payload, sort_keys=True, allow_nan=False, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def world_digests(world: Mapping[str, pa.Table]) -> dict[str, str]:
    return {name: _table_digest(table) for name, table in sorted(world.items())}


def column_value(col: schema.Column) -> Any:
    kind = col.kind
    if kind is schema.ColumnKind.INT:
        return 0
    if kind is schema.ColumnKind.FLOAT:
        return 0.0
    if kind is schema.ColumnKind.BOOL:
        return False
    if kind is schema.ColumnKind.ENUM:
        if col.enum is None:
            raise AssertionError(f"{col.name} is an enum column that names no vocabulary")
        return schema.ENUMS[col.enum][0]
    if kind is schema.ColumnKind.HASH:
        return synthetic_hash(col.name, "default")
    if kind is schema.ColumnKind.TIMESTAMP:
        return SYNTHETIC_EPOCH
    if kind is schema.ColumnKind.VERSION:
        return "2.1.250"
    raise AssertionError(  # pragma: no cover
        f"corpus.synthetic does not know how to build a {kind!r} column"
    )


def default_cell(col: schema.Column) -> Any:
    return None if col.nullable else column_value(col)


def corpus_table(name: str, rows: Sequence[Mapping[str, Any]]) -> pa.Table:
    import pyarrow as pa

    columns = schema.TABLES[name]
    declared = {col.name for col in columns}
    for index, row in enumerate(rows):
        unknown = sorted(set(row) - declared)
        if unknown:
            raise AssertionError(f"{name} row {index}: not a declared column: {unknown}")
    data = {
        col.name: [row[col.name] if col.name in row else default_cell(col) for row in rows]
        for col in columns
    }
    return pa.Table.from_pydict(data, schema=schema.arrow_schema(name))


def build_corpus(**rows_by_table: Sequence[Mapping[str, Any]]) -> dict[str, pa.Table]:
    unknown = sorted(set(rows_by_table) - set(schema.TABLES))
    if unknown:
        raise AssertionError(f"not a declared corpus table: {unknown}")
    return {name: corpus_table(name, rows_by_table.get(name, ())) for name in schema.TABLES}


WORLD_HOURS = 96

REQUESTS_PER_BUCKET = 2

TOOL_EVERY = 6

MODEL = "claude-opus-5"
CANARY_MODEL = "claude-sonnet-5"
VERSION = "2.1.250"

HIGH_BUCKET = "gt180k"
LOW_BUCKET = "b30_100k"

SESSIONS = (
    synthetic_hash("session", "world-1"),
    synthetic_hash("session", "world-2"),
)

CYCLES = 12
CHEAP_TASKS = ("arith-exact", "bugfix-py", "json-extract")
LONG_TASK = "longctx-needle"


def world_hour(index: int, hours: int = WORLD_HOURS) -> datetime:
    return SYNTHETIC_EPOCH + timedelta(hours=index)


def _jitter(index: int, session: int, salt: int) -> int:
    return (index * 7 + session * 13 + salt * 5) % 5


def build_synthetic_world(
    *, hours: int = WORLD_HOURS, orphan_turn_features: int = 0
) -> dict[str, pa.Table]:
    requests: list[dict[str, Any]] = []
    turns: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    for index in range(hours):
        at = world_hour(index, hours)
        for slot, session in enumerate(SESSIONS):
            common: dict[str, Any] = {
                "session_hash": session,
                "prompt_seq": index,
                "ts_bucket_utc": at,
                "model": MODEL,
                "cc_version": VERSION,
                "error_class": "none",
                "retries": 0,
                "post_compaction": False,
            }
            for repeat in range(REQUESTS_PER_BUCKET):
                requests.append(
                    {
                        **common,
                        "request_seq": repeat,
                        "context_bucket": HIGH_BUCKET,
                        "input_tokens": 190_000,
                        "output_tokens": 1000 + _jitter(index, slot, 1 + repeat),
                        "latency_ms": 800 + _jitter(index, slot, 2 + repeat),
                    }
                )
            for repeat in range(REQUESTS_PER_BUCKET):
                requests.append(
                    {
                        **common,
                        "request_seq": REQUESTS_PER_BUCKET + repeat,
                        "context_bucket": LOW_BUCKET,
                        "input_tokens": 50_000,
                        "output_tokens": 900 + _jitter(index, slot, 3 + repeat),
                        "latency_ms": 700 + _jitter(index, slot, 4 + repeat),
                    }
                )
            turns.append(
                {
                    "session_hash": session,
                    "prompt_seq": index,
                    "self_correction": False,
                    "edit_retry_max": 1,
                    "tool_calls": 2,
                    "tool_failures": 0,
                }
            )
            if index % TOOL_EVERY == 0:
                tools.append(
                    {
                        "session_hash": session,
                        "prompt_seq": index,
                        "tool": "Edit",
                        "ok": True,
                        "duration_ms": 120,
                    }
                )

    for extra in range(orphan_turn_features):
        turns.append(
            {
                "session_hash": SESSIONS[0],
                "prompt_seq": hours + extra,
                "self_correction": False,
                "edit_retry_max": 1,
                "tool_calls": 1,
                "tool_failures": 0,
            }
        )

    cycles: list[dict[str, Any]] = []
    stride = max(1, (hours - 1) // CYCLES)
    for cycle in range(CYCLES):
        at = world_hour(hours - 1 - (CYCLES - 1 - cycle) * stride, hours)
        for task in (*CHEAP_TASKS, LONG_TASK):
            cycles.append(
                {
                    "cycle_id": cycle + 1,
                    "ts_bucket_utc": at,
                    "model": CANARY_MODEL,
                    "cc_version": VERSION,
                    "task_id": task,
                    "runs": 2,
                    "passes": 2,
                    "invalid": 0,
                    "cost_usd": 0.01,
                }
            )

    changes = [
        {
            "ts_bucket_utc": world_hour(0, hours),
            "kind": "settings",
            "from_hash": synthetic_hash("settings", "before"),
            "to_hash": synthetic_hash("settings", "after"),
        },
        {
            "ts_bucket_utc": world_hour(1, hours),
            "kind": "vitals_config",
            "from_hash": synthetic_hash("vitals_config", "before"),
            "to_hash": synthetic_hash("vitals_config", "after"),
        },
    ]

    return build_corpus(
        requests=requests,
        turn_features=turns,
        tool_results=tools,
        canary_cycles=cycles,
        change_points=changes,
    )

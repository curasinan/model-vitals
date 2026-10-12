from __future__ import annotations

import hashlib
import hmac
import re
from datetime import UTC, datetime

import pytest

from corpus import schema

KEY = b"unit-test-hmac-key-that-is-not-a-secret"
OTHER_KEY = b"a-different-unit-test-key-also-not-a-secret"


def test_every_enum_named_by_a_column_exists():
    for table, columns in schema.TABLES.items():
        for col in columns:
            if col.kind is schema.ColumnKind.ENUM:
                assert col.enum in schema.ENUMS, f"{table}.{col.name} names an unknown enum"
            else:
                assert col.enum is None, f"{table}.{col.name} is not an enum but names one"


def test_enum_members_are_unique_and_sorted_free_of_blanks():
    for name, members in schema.ENUMS.items():
        assert len(set(members)) == len(members), f"{name} has duplicate members"
        assert all(m and m.strip() == m for m in members), f"{name} has a blank/padded member"


def test_spec_context_buckets_are_the_live_vocabulary():
    assert schema.ENUMS["context_bucket"] == ("lt30k", "b30_100k", "b100_180k", "gt180k")


def test_error_class_covers_the_spec_values():
    for value in ("none", "rate_limit", "server", "client", "timeout"):
        assert value in schema.ENUMS["error_class"]


def test_tool_enum_holds_no_unnormalized_mcp_names():
    for tool in schema.ENUMS["tool"]:
        if tool.startswith("mcp__"):
            assert tool.count("__") == 1, f"{tool} still carries a server segment"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("mcp__33333333-3333-4333-8333-333333333333__list_teams", "mcp__list_teams"),
        ("mcp__Claude_Browser__computer", "mcp__computer"),
        ("mcp__ccd_session__mark_chapter", "mcp__mark_chapter"),
        ("mcp__server__a__b", "mcp__a__b"),
        ("Bash", "Bash"),
        ("mcp_tool", "mcp_tool"),
        ("mcp__onlyone", "mcp__onlyone"),
        ("mcp__server__", "mcp__server__"),
    ],
)
def test_normalize_tool_name(raw, expected):
    assert schema.normalize_tool_name(raw) == expected


def test_normalization_strips_a_server_uuid_completely():
    uuid = "44444444-4444-4444-8444-444444444444"
    out = schema.normalize_tool_name(f"mcp__{uuid}__search_solutions")
    assert uuid not in out
    assert out == "mcp__search_solutions"


def test_hash_is_stable_and_64_hex():
    h = schema.Hasher(KEY)
    a = h.hash("session", "8f14e45f-ceea-467a-9f2b-2a1c0f3d4e5b")
    b = h.hash("session", "8f14e45f-ceea-467a-9f2b-2a1c0f3d4e5b")
    assert a == b
    assert schema.HASH_RE.match(a)


def test_hash_differs_by_value_and_by_domain():
    h = schema.Hasher(KEY)
    assert h.hash("session", "a") != h.hash("session", "b")
    assert h.hash("session", "a") != h.hash("file", "a")


def test_hash_differs_by_key():
    assert schema.Hasher(KEY).hash("session", "a") != schema.Hasher(OTHER_KEY).hash("session", "a")


def test_hash_does_not_contain_the_input():
    h = schema.Hasher(KEY)
    secret = "C:/Users/somebody/secret-project/notes.md"
    out = h.hash("file", secret)
    assert "somebody" not in out
    assert "secret" not in out


def test_key_id_is_derived_from_the_key_but_is_not_the_key():
    h = schema.Hasher(KEY)
    label, _, digest = h.key_id.partition(":")
    assert label == schema.HMAC_KEY_LABEL
    assert re.fullmatch(r"[0-9a-f]{8}", digest)
    assert KEY.decode() not in h.key_id
    assert schema.Hasher(OTHER_KEY).key_id != h.key_id


def test_key_id_is_not_a_plain_digest_of_the_key():
    digest = schema.Hasher(KEY).key_id.partition(":")[2]
    assert digest != hashlib.sha256(KEY).hexdigest()[:8]
    assert (
        digest
        == hmac.new(KEY, schema.HMAC_KEY_LABEL.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
    )


def test_the_key_floor_is_32_bytes():
    assert schema.MIN_KEY_BYTES == 32
    with pytest.raises(schema.MissingKeyError) as exc:
        schema.Hasher(b"x" * 31)
    assert "32" in str(exc.value)
    schema.Hasher(b"x" * 32)


def test_from_env_names_the_variable_when_it_is_missing():
    with pytest.raises(schema.MissingKeyError) as exc:
        schema.Hasher.from_env({})
    assert schema.HMAC_KEY_ENV in str(exc.value)


def test_from_env_rejects_a_short_key():
    with pytest.raises(schema.MissingKeyError):
        schema.Hasher.from_env({schema.HMAC_KEY_ENV: "abc"})


def test_from_env_never_echoes_the_key():
    key = "0123456789abcdef0123456789abcdef"
    h = schema.Hasher.from_env({schema.HMAC_KEY_ENV: key})
    assert key not in h.key_id
    assert key not in repr(h)
    assert key not in str(h)


@pytest.mark.parametrize(
    "iso",
    [
        "2026-08-25T17:31:45+00:00",
        "2026-08-25T17:31:45Z",
        "2026-08-25T17:31:45.123456+00:00",
    ],
)
def test_hour_bucket_floors_to_the_hour_in_utc(iso):
    assert schema.hour_bucket(iso) == datetime(2026, 8, 25, 17, 0, 0, tzinfo=UTC)


def test_hour_bucket_converts_a_non_utc_offset():
    assert schema.hour_bucket("2026-08-25T19:31:45+02:00") == datetime(
        2026, 8, 25, 17, 0, tzinfo=UTC
    )


def test_hour_bucket_refuses_a_non_timestamp_without_echoing_it():
    offender = "C:/Users/somebody/private/notes.md"
    with pytest.raises(schema.UnreadableValue) as exc:
        schema.hour_bucket(offender)
    assert offender not in str(exc.value)
    assert "somebody" not in str(exc.value)
    assert exc.value.__cause__ is None and exc.value.__context__ is None


def test_derive_retries_refuses_a_non_numeric_attempt_without_echoing_it():
    with pytest.raises(schema.UnreadableValue) as exc:
        schema.derive_retries("C:/Users/somebody/x")  # type: ignore[arg-type]
    assert "somebody" not in str(exc.value)


def test_hour_bucket_keeps_no_sub_hour_resolution():
    a = schema.hour_bucket("2026-08-25T17:00:01+00:00")
    b = schema.hour_bucket("2026-08-25T17:59:59+00:00")
    assert a == b


@pytest.mark.parametrize(
    ("status", "text", "expected"),
    [
        (429, None, "rate_limit"),
        (400, None, "client"),
        (404, None, "client"),
        (500, None, "server"),
        (529, None, "server"),
        (408, None, "timeout"),
        (504, None, "timeout"),
        (None, "Request timed out after 600s", "timeout"),
        (None, "Overloaded", "server"),
        (None, "You've hit your session limit", "rate_limit"),
        (None, "something nobody has seen before", "unknown"),
        (None, None, "unknown"),
    ],
)
def test_classify_error(status, text, expected):
    assert schema.classify_error(status, text) == expected


def test_classify_error_only_ever_returns_an_enum_member():
    for status in (None, 200, 400, 418, 429, 500, 599, 999):
        assert schema.classify_error(status, "any text at all") in schema.ENUMS["error_class"]


@pytest.mark.parametrize(
    ("attempt", "exhausted", "expected"),
    [
        (None, 0, 0),
        (0, 0, 0),
        (1, 0, 1),
        (3, 0, 3),
        (4, 1, 3),
        (1, 1, 0),
        (-2, 0, 0),
    ],
)
def test_derive_retries(attempt, exhausted, expected):
    assert schema.derive_retries(attempt, exhausted) == expected


def test_gate_passes_known_values_through():
    gate = schema.SchemaGate(schema.Hasher(KEY))
    assert gate.enum("tool", "Bash", column="tool_results.tool") == "Bash"
    assert gate.enum("tool", None, column="tool_results.tool") is None
    gate.raise_if_violations()


def test_gate_fails_on_an_unknown_tool_and_names_the_enum_class():
    gate = schema.SchemaGate(schema.Hasher(KEY))
    assert gate.enum("tool", "TotallyNewTool", column="tool_results.tool") is None
    with pytest.raises(schema.EnumViolation) as exc:
        gate.raise_if_violations()
    message = str(exc.value)
    assert "tool" in message
    assert "tool_results.tool" in message


def test_gate_message_never_contains_the_offending_value():
    gate = schema.SchemaGate(schema.Hasher(KEY))
    offender = "C:/Users/somebody/private-client-work/tool.py"
    gate.enum("tool", offender, column="tool_results.tool")
    with pytest.raises(schema.EnumViolation) as exc:
        gate.raise_if_violations()
    message = str(exc.value)
    assert offender not in message
    assert "somebody" not in message
    assert "private-client-work" not in message


def test_gate_reports_a_count_not_one_line_per_row():
    gate = schema.SchemaGate(schema.Hasher(KEY))
    for _ in range(7):
        gate.enum("model", "not-a-model", column="requests.model")
    with pytest.raises(schema.EnumViolation) as exc:
        gate.raise_if_violations()
    assert "7" in str(exc.value)
    assert gate.violations["model"].rows == 7
    assert gate.violations["model"].distinct == 1


def test_gate_accumulates_across_enum_classes_before_failing():
    gate = schema.SchemaGate(schema.Hasher(KEY))
    gate.enum("model", "not-a-model", column="requests.model")
    gate.enum("tool", "NotATool", column="tool_results.tool")
    with pytest.raises(schema.EnumViolation) as exc:
        gate.raise_if_violations()
    assert set(gate.violations) == {"model", "tool"}
    assert "model" in str(exc.value) and "tool" in str(exc.value)


def test_gate_version_check_accepts_real_shapes_and_rejects_prose():
    gate = schema.SchemaGate(schema.Hasher(KEY))
    assert gate.version("2.1.250", column="requests.cc_version") == "2.1.250"
    assert gate.version("2.1.92", column="requests.cc_version") == "2.1.92"
    assert gate.version(None, column="requests.cc_version") is None
    gate.raise_if_violations()

    gate.version("2.1.250 (Claude Code) at C:/Users/somebody", column="requests.cc_version")
    with pytest.raises(schema.EnumViolation) as exc:
        gate.raise_if_violations()
    assert "somebody" not in str(exc.value)


def test_unknown_enum_class_is_a_programming_error_not_a_violation():
    gate = schema.SchemaGate(schema.Hasher(KEY))
    with pytest.raises(KeyError):
        gate.enum("no_such_enum", "x", column="requests.model")


def test_the_five_spec_tables_are_declared():
    assert set(schema.TABLES) == {
        "requests",
        "tool_results",
        "turn_features",
        "canary_cycles",
        "change_points",
    }


def test_no_declared_column_is_free_text():
    allowed = set(schema.ColumnKind)
    assert allowed == {
        schema.ColumnKind.INT,
        schema.ColumnKind.FLOAT,
        schema.ColumnKind.BOOL,
        schema.ColumnKind.ENUM,
        schema.ColumnKind.HASH,
        schema.ColumnKind.TIMESTAMP,
        schema.ColumnKind.VERSION,
    }
    for columns in schema.TABLES.values():
        for col in columns:
            assert col.kind in allowed


def test_spec_columns_are_all_present():
    expected = {
        "requests": {
            "session_hash",
            "prompt_seq",
            "request_seq",
            "ts_bucket_utc",
            "model",
            "cc_version",
            "plugins_hash",
            "context_bucket",
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "latency_ms",
            "retries",
            "error_class",
            "post_compaction",
        },
        "tool_results": {
            "session_hash",
            "prompt_seq",
            "tool",
            "ok",
            "duration_ms",
            "file_hash",
            "test_exit_code",
            "test_runner",
        },
        "turn_features": {
            "session_hash",
            "prompt_seq",
            "self_correction",
            "edit_retry_max",
            "tool_calls",
            "tool_failures",
        },
        "canary_cycles": {
            "cycle_id",
            "ts_bucket_utc",
            "model",
            "cc_version",
            "task_id",
            "runs",
            "passes",
            "invalid",
            "latency_ms_p50",
            "tokens_total",
            "cost_usd",
        },
        "change_points": {"ts_bucket_utc", "kind", "from_hash", "to_hash"},
    }
    for table, names in expected.items():
        assert {c.name for c in schema.TABLES[table]} == names


def test_arrow_schema_matches_the_declaration():
    import pyarrow as pa

    for table, columns in schema.TABLES.items():
        arrow = schema.arrow_schema(table)
        assert arrow.names == [c.name for c in columns]
        for col in columns:
            field = arrow.field(col.name)
            assert field.nullable == col.nullable, f"{table}.{col.name}"
            if col.kind is schema.ColumnKind.BOOL:
                assert field.type == pa.bool_()
            elif col.kind is schema.ColumnKind.INT:
                assert field.type == pa.int64()
            elif col.kind is schema.ColumnKind.FLOAT:
                assert field.type == pa.float64()
            elif col.kind is schema.ColumnKind.TIMESTAMP:
                assert field.type == pa.timestamp("ms", tz="UTC")
            else:
                assert field.type == pa.string()


def test_arrow_schema_rejects_an_unknown_table():
    with pytest.raises(KeyError):
        schema.arrow_schema("not_a_table")

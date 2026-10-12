from __future__ import annotations

import json
import tomllib
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from corpus import boundary, schema

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_REAL_CORPUS = _REPO_ROOT / "corpus"


_FIXTURE_HASHER = schema.Hasher(b"privacy-boundary fixture key -- not a secret, not the corpus key")

_FIXTURE_ROWS = 48

_FIXTURE_EPOCH = datetime(2026, 8, 25, tzinfo=UTC)


def _fixture_values(col: schema.Column, rows: int) -> list[Any]:
    kind = col.kind
    values: list[Any]
    if kind is schema.ColumnKind.INT:
        values = [i * 7 for i in range(rows)]
    elif kind is schema.ColumnKind.FLOAT:
        values = [round(i * 0.25, 4) for i in range(rows)]
    elif kind is schema.ColumnKind.BOOL:
        values = [i % 2 == 0 for i in range(rows)]
    elif kind is schema.ColumnKind.ENUM:
        assert col.enum is not None, f"{col.name} is an enum column that names no vocabulary"
        members = schema.ENUMS[col.enum]
        values = [members[i % len(members)] for i in range(rows)]
    elif kind is schema.ColumnKind.HASH:
        values = [_FIXTURE_HASHER.hash(col.name, f"row-{i}") for i in range(rows)]
    elif kind is schema.ColumnKind.TIMESTAMP:
        values = [_FIXTURE_EPOCH + timedelta(hours=i) for i in range(rows)]
    elif kind is schema.ColumnKind.VERSION:
        values = ["2.1.250" if i % 2 else "2.1.246" for i in range(rows)]
    else:  # pragma: no cover
        raise AssertionError(f"the fixture does not know how to build a {kind!r} column")
    if col.nullable:
        values[-1] = None
    return values


def write_synthetic_corpus(
    out_dir: Path,
    *,
    rows: int = _FIXTURE_ROWS,
    extra_columns: Mapping[str, Mapping[str, tuple[Any, Sequence[Any]]]] | None = None,
    replace: Mapping[tuple[str, str], Sequence[Any]] | None = None,
    manifest_mutate: Callable[[dict[str, Any]], None] | None = None,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    observed: dict[str, set[str]] = {name: set() for name in schema.ENUMS}
    row_counts: dict[str, int] = {}
    sizes: dict[str, int] = {}
    session_hashes: set[str] = set()

    for table, columns in schema.TABLES.items():
        data: dict[str, list[Any]] = {c.name: _fixture_values(c, rows) for c in columns}
        for (target_table, target_column), values in (replace or {}).items():
            if target_table == table:
                data[target_column] = list(values)

        fields = list(schema.arrow_schema(table))
        for name, (arrow_type, values) in (extra_columns or {}).get(table, {}).items():
            data[name] = list(values)
            fields.append(pa.field(name, arrow_type, nullable=True))

        path = out_dir / f"{table}.parquet"
        pq.write_table(
            pa.Table.from_pydict(data, schema=pa.schema(fields)), path, compression="zstd"
        )

        row_counts[table] = len(next(iter(data.values())))
        sizes[table] = path.stat().st_size
        for col in columns:
            if col.kind is schema.ColumnKind.ENUM and col.enum is not None:
                observed[col.enum] |= {v for v in data[col.name] if v is not None}
        if "session_hash" in data:
            session_hashes |= {v for v in data["session_hash"] if v is not None}

    span_end = _FIXTURE_EPOCH + timedelta(hours=rows - 1)
    stamps = {"start": _FIXTURE_EPOCH.isoformat(), "end": span_end.isoformat()}
    manifest: dict[str, Any] = {
        "corpus_schema_version": schema.SCHEMA_VERSION,
        "row_counts": row_counts,
        "enums": {
            name: {
                "declared_cardinality": len(members),
                "observed_cardinality": len(observed[name]),
            }
            for name, members in schema.ENUMS.items()
        },
        "size_bytes": {**sizes, "total": sum(sizes.values()), "cap": 52_428_800},
        "time_span_utc": {
            **stamps,
            "days": round((rows - 1) / 24, 2),
            "per_table": {t: dict(stamps) for t in ("requests", "canary_cycles", "change_points")},
            "per_source_table": {t: dict(stamps) for t in ("api_requests", "tool_results")},
        },
        "sessions": {
            "in_store": len(session_hashes),
            "included": len(session_hashes),
            "sampling_rate": 1.0,
            "cap_met": True,
        },
        "excluded": {
            "api_errors_transcript_synthetic": 0,
            "requests_error_rows_deduped": 0,
            "tool_results_sidechain": 0,
            "tool_results_without_prompt_id": 0,
        },
    }
    if manifest_mutate is not None:
        manifest_mutate(manifest)
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    return out_dir


def _planted_uuid() -> str:
    return "-".join(["1" * 8, "2" * 4, "4" * 4, "8" * 4, "3" * 12])


def _planted_posix_transcript_path() -> str:
    return "/" + "/".join(
        ["home", "planted-user", "." + "claude", "projects", _planted_transcript_filename()]
    )


def _planted_windows_home_path() -> str:
    return "\\".join(["C:", "Users", "planted-user", "notes.md"])


def _planted_transcript_filename() -> str:
    return _planted_uuid() + "." + "jsonl"


def _planted_api_key() -> str:
    return "sk" + "-" + "ant" + "-" + "planted" + "0123456789"


PLANTED_TEXT: tuple[Callable[[], str], ...] = (
    _planted_posix_transcript_path,
    _planted_windows_home_path,
    _planted_transcript_filename,
    _planted_api_key,
)


def _planted_column(rows: int) -> list[str]:
    built = [make() for make in PLANTED_TEXT]
    return [built[i % len(built)] for i in range(rows)]


def _toml_rules() -> list[dict[str, Any]]:
    raw = (_REPO_ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
    rules = tomllib.loads(raw).get("rules", [])
    assert isinstance(rules, list)
    return rules


def test_every_gitleaks_rule_in_the_config_is_accounted_for():
    loaded = boundary.load_gitleaks_rules()
    compiled = {rule.id for rule in loaded.rules}
    extends_only = set(loaded.extends_only)
    assert compiled & extends_only == set()
    assert compiled | extends_only == {rule["id"] for rule in _toml_rules()}


def test_the_config_keeps_the_gitleaks_built_in_rules_enabled():
    config = tomllib.loads((_REPO_ROOT / ".gitleaks.toml").read_text(encoding="utf-8"))
    assert config.get("extend", {}).get("useDefault") is True, (
        "gitleaks' built-in rule set is no longer enabled. The privacy boundary applies only "
        "this config's own custom rules, so nothing is now checking corpus-adjacent files for "
        "cloud keys, PEM blocks or JWTs."
    )


def test_the_only_regex_less_rule_is_the_documented_extend_by_id():
    assert set(boundary.load_gitleaks_rules().extends_only) == {"generic-api-key"}


def test_every_compiled_rule_keeps_its_regex_verbatim_from_the_config():
    from_config = {rule["id"]: rule["regex"] for rule in _toml_rules() if "regex" in rule}
    for rule in boundary.load_gitleaks_rules().rules:
        assert rule.regex.pattern == from_config[rule.id]


def test_an_uncompilable_rule_fails_loudly_and_names_the_rule(tmp_path):
    config = tmp_path / "broken.toml"
    config.write_text(
        "\n".join(
            [
                "[[rules]]",
                'id = "model-vitals-not-compilable-in-python"',
                "regex = '''abc(?i)def'''",
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(boundary.GitleaksRuleError) as exc:
        boundary.load_gitleaks_rules(config)
    assert "model-vitals-not-compilable-in-python" in str(exc.value)


@pytest.mark.parametrize("make", PLANTED_TEXT, ids=lambda f: f.__name__)
def test_the_loaded_rules_actually_fire_on_a_planted_shape(make):
    rules = boundary.load_gitleaks_rules()
    assert boundary.matching_rule(rules, make()) is not None


def test_the_loaded_rules_do_not_fire_on_ordinary_corpus_shapes():
    rules = boundary.load_gitleaks_rules()
    ordinary = [
        _FIXTURE_HASHER.hash("session_hash", "row-0"),
        "claude-opus-5[1m]",
        "mcp__search_session_transcripts",
        "2.1.250",
        "b100_180k",
        str(_FIXTURE_EPOCH),
        "0",
        "-1",
        "0.0625",
    ]
    for value in ordinary:
        assert boundary.matching_rule(rules, value) is None, value


@pytest.fixture
def clean_corpus(tmp_path):
    return write_synthetic_corpus(tmp_path / "clean")


def test_a_clean_synthetic_corpus_has_no_violations(clean_corpus):
    violations = boundary.validate_corpus(clean_corpus)
    assert violations == [], boundary.format_violations(violations)


def test_every_column_kind_is_classified_by_the_boundary():
    classified = boundary.NUMERIC_FAMILY_KINDS | boundary.CLOSED_VOCABULARY_KINDS
    assert classified == set(schema.ColumnKind)
    assert not boundary.NUMERIC_FAMILY_KINDS & boundary.CLOSED_VOCABULARY_KINDS


def test_a_missing_table_is_a_violation_not_a_pass(tmp_path):
    corpus = write_synthetic_corpus(tmp_path / "gap")
    (corpus / "change_points.parquet").unlink()
    reasons = {v.reason for v in boundary.validate_corpus(corpus)}
    assert "missing-parquet-file" in reasons


def test_an_undeclared_parquet_file_is_a_violation(tmp_path):
    corpus = write_synthetic_corpus(tmp_path / "stray")
    pq.write_table(pa.table({"n": [1, 2, 3]}), corpus / "scratch.parquet")
    reasons = {v.reason for v in boundary.validate_corpus(corpus)}
    assert "undeclared-parquet-file" in reasons


def test_the_skip_predicate_only_fires_on_a_totally_absent_corpus(tmp_path):
    empty = tmp_path / "never-committed"
    empty.mkdir()
    assert boundary.corpus_is_absent(empty)

    full = write_synthetic_corpus(tmp_path / "full")
    assert not boundary.corpus_is_absent(full)

    for victim in ("manifest.json", "requests.parquet", "change_points.parquet"):
        partial = write_synthetic_corpus(tmp_path / f"without-{victim}")
        (partial / victim).unlink()
        assert not boundary.corpus_is_absent(partial), victim

    stub = tmp_path / "one-file-only"
    stub.mkdir()
    (stub / "manifest.json").write_text("{}", encoding="utf-8")
    assert not boundary.corpus_is_absent(stub)


@pytest.mark.parametrize("victim", ["manifest.json", "requests.parquet"])
def test_a_partial_corpus_runs_and_fails_rather_than_skipping(tmp_path, victim):
    corpus = write_synthetic_corpus(tmp_path / "partial")
    (corpus / victim).unlink()
    assert not boundary.corpus_is_absent(corpus)
    violations = boundary.validate_corpus(corpus)
    assert violations, f"deleting {victim} produced no violation at all"
    expected = "missing-manifest" if victim.endswith(".json") else "missing-parquet-file"
    assert expected in {v.reason for v in violations}, boundary.format_violations(violations)


def test_a_missing_declared_column_is_a_violation(tmp_path):
    corpus = tmp_path / "short"
    write_synthetic_corpus(corpus)
    table = pq.read_table(corpus / "turn_features.parquet")
    pq.write_table(table.drop_columns(["tool_failures"]), corpus / "turn_features.parquet")
    violations = boundary.validate_corpus(corpus)
    assert {"missing-declared-column"} <= {v.reason for v in violations}


def test_a_value_outside_the_enum_vocabulary_fails_the_schema_assertion(tmp_path):
    corpus = write_synthetic_corpus(
        tmp_path / "bad-enum",
        replace={("tool_results", "tool"): ["NotADeclaredTool"] * _FIXTURE_ROWS},
    )
    violations = [v for v in boundary.validate_corpus(corpus) if v.assertion == "schema"]
    assert any(v.reason == "value-outside-enum-vocabulary" for v in violations), violations
    assert any(v.column == "tool" for v in violations)


@pytest.mark.parametrize(
    ("label", "arrow_type", "value"),
    [
        ("int64", pa.int64(), 1_756_700_000_000),
        ("float64", pa.float64(), 0.5),
        ("timestamp[us]", pa.timestamp("us", tz="UTC"), _FIXTURE_EPOCH + timedelta(minutes=37)),
    ],
)
def test_an_undeclared_non_string_column_fails_the_schema_assertion(
    tmp_path, label, arrow_type, value
):
    corpus = write_synthetic_corpus(
        tmp_path / f"extra-{label}",
        extra_columns={"turn_features": {"extra": (arrow_type, [value] * _FIXTURE_ROWS)}},
    )
    violations = boundary.validate_corpus(corpus)
    undeclared = [v for v in violations if v.reason == "undeclared-column"]
    assert undeclared, f"an extra {label} column passed the boundary: {violations}"
    assert {v.column for v in undeclared} == {"extra"}
    assert str(arrow_type) in undeclared[0].detail, undeclared[0].detail


def test_a_malformed_hash_fails_the_schema_assertion(tmp_path):
    corpus = write_synthetic_corpus(
        tmp_path / "bad-hash",
        replace={("change_points", "from_hash"): ["not-a-digest"] * _FIXTURE_ROWS},
    )
    reasons = {v.reason for v in boundary.validate_corpus(corpus) if v.assertion == "schema"}
    assert "value-outside-hash-shape" in reasons


def test_a_prose_version_fails_the_schema_assertion(tmp_path):
    corpus = write_synthetic_corpus(
        tmp_path / "bad-version",
        replace={("requests", "cc_version"): ["2.1.250 (a product name)"] * _FIXTURE_ROWS},
    )
    reasons = {v.reason for v in boundary.validate_corpus(corpus) if v.assertion == "schema"}
    assert "value-outside-version-shape" in reasons


def test_temporal_columns_are_numeric_family_not_string(clean_corpus):
    field = pq.read_schema(clean_corpus / "requests.parquet").field("ts_bucket_utc")
    assert str(field.type) == "timestamp[ms, tz=UTC]"
    assert boundary.type_family(field.type) == "numeric"


def test_a_string_typed_timestamp_would_fail(tmp_path):
    corpus = tmp_path / "text-ts"
    write_synthetic_corpus(corpus)
    table = pq.read_table(corpus / "change_points.parquet")
    formatted = [str(v) for v in table.column("ts_bucket_utc").to_pylist()]
    replaced = table.drop_columns(["ts_bucket_utc"]).append_column(
        pa.field("ts_bucket_utc", pa.string()), pa.array(formatted)
    )
    pq.write_table(replaced, corpus / "change_points.parquet")
    violations = boundary.validate_corpus(corpus)
    assert any(v.assertion == "schema" for v in violations), boundary.format_violations(violations)


def test_an_overlong_categorical_fails_the_content_assertion(tmp_path):
    corpus = write_synthetic_corpus(
        tmp_path / "long",
        extra_columns={"turn_features": {"note": (pa.string(), ["n" * 80] * _FIXTURE_ROWS)}},
    )
    reasons = {v.reason for v in boundary.validate_corpus(corpus) if v.assertion == "content"}
    assert "categorical-too-long" in reasons


def test_a_value_outside_the_content_charset_fails(tmp_path):
    corpus = write_synthetic_corpus(
        tmp_path / "charset",
        extra_columns={
            "turn_features": {"note": (pa.string(), ["a b" + "/" + "c"] * _FIXTURE_ROWS)}
        },
    )
    reasons = {v.reason for v in boundary.validate_corpus(corpus) if v.assertion == "content"}
    assert "categorical-outside-charset" in reasons


def test_the_bracket_exception_is_exactly_one_declared_member():
    needs_exception = [
        member
        for members in schema.ENUMS.values()
        for member in members
        if not boundary.CATEGORICAL_RE.match(member)
    ]
    assert needs_exception == ["claude-opus-5[1m]"]
    for hostile in ("/", "\\", ":", " ", '"', "'", "~", "%", "@", "`"):
        assert not boundary.DECLARED_MEMBER_RE.match("a" + hostile + "b"), hostile


def test_the_bracket_exception_does_not_apply_outside_a_declared_vocabulary(tmp_path):
    corpus = write_synthetic_corpus(
        tmp_path / "brackets",
        extra_columns={"turn_features": {"note": (pa.string(), ["x[1m]"] * _FIXTURE_ROWS)}},
    )
    reasons = {v.reason for v in boundary.validate_corpus(corpus) if v.assertion == "content"}
    assert "categorical-outside-charset" in reasons


def test_hash_columns_are_pinned_to_exactly_64_characters():
    assert boundary.MAX_CATEGORICAL_LEN == 64
    assert schema.HASH_RE.match("0" * 64)
    assert not schema.HASH_RE.match("0" * 63)
    assert not schema.HASH_RE.match("0" * 65)


def test_the_pattern_assertion_fires_on_a_declared_column(tmp_path):
    corpus = write_synthetic_corpus(
        tmp_path / "pattern-declared",
        replace={("requests", "cc_version"): [_planted_posix_transcript_path()] * _FIXTURE_ROWS},
    )
    violations = [v for v in boundary.validate_corpus(corpus) if v.assertion == "pattern"]
    assert violations, "the gitleaks rules did not fire on a planted transcript path"
    assert any(v.rule_id for v in violations), violations


def test_the_pattern_assertion_reports_the_rule_that_fired(tmp_path):
    corpus = write_synthetic_corpus(
        tmp_path / "pattern-rule",
        extra_columns={
            "turn_features": {
                "note": (pa.string(), [_planted_transcript_filename()] * _FIXTURE_ROWS)
            }
        },
    )
    fired = {v.rule_id for v in boundary.validate_corpus(corpus) if v.assertion == "pattern"}
    assert "model-vitals-transcript-filename" in fired


def test_a_violation_never_echoes_the_offending_value(tmp_path):
    corpus = write_synthetic_corpus(
        tmp_path / "quiet",
        extra_columns={"turn_features": {"note": (pa.string(), _planted_column(_FIXTURE_ROWS))}},
    )
    rendered = boundary.format_violations(boundary.validate_corpus(corpus))
    assert rendered
    for make in PLANTED_TEXT:
        assert make() not in rendered
    assert "planted-user" not in rendered


def test_a_manifest_row_count_that_disagrees_fails(tmp_path):
    def bump(manifest: dict[str, Any]) -> None:
        manifest["row_counts"]["requests"] += 1

    corpus = write_synthetic_corpus(tmp_path / "rows", manifest_mutate=bump)
    violations = [v for v in boundary.validate_corpus(corpus) if v.assertion == "manifest"]
    assert any(v.reason == "row-count-disagrees" for v in violations), violations


def test_a_manifest_enum_cardinality_that_disagrees_fails(tmp_path):
    def skew(manifest: dict[str, Any]) -> None:
        manifest["enums"]["tool"]["observed_cardinality"] += 1
        manifest["enums"]["model"]["declared_cardinality"] -= 1

    corpus = write_synthetic_corpus(tmp_path / "enums", manifest_mutate=skew)
    reasons = {v.reason for v in boundary.validate_corpus(corpus) if v.assertion == "manifest"}
    assert reasons >= {"observed-cardinality-disagrees", "declared-cardinality-disagrees"}


@pytest.mark.parametrize(
    ("block", "wrong_value"),
    [
        ("row_counts", []),
        ("enums", "not-an-object"),
        ("size_bytes", 0),
        ("sessions", None),
        ("excluded", []),
        ("time_span_utc", []),
    ],
)
def test_a_wrong_typed_manifest_block_is_a_violation(tmp_path, block, wrong_value):

    def wreck(manifest: dict[str, Any]) -> None:
        manifest[block] = wrong_value

    corpus = write_synthetic_corpus(tmp_path / f"wrong-{block}", manifest_mutate=wreck)
    violations = [v for v in boundary.validate_corpus(corpus) if v.assertion == "manifest"]
    wrong_typed = [v for v in violations if v.reason == "manifest-block-wrong-type"]
    assert wrong_typed, f"a {type(wrong_value).__name__} in `{block}` passed: {violations}"
    assert {v.column for v in wrong_typed} == {block}


def test_a_missing_manifest_is_a_violation(tmp_path):
    corpus = write_synthetic_corpus(tmp_path / "no-manifest")
    (corpus / "manifest.json").unlink()
    reasons = {v.reason for v in boundary.validate_corpus(corpus)}
    assert "missing-manifest" in reasons


def test_a_sub_hour_manifest_timestamp_is_a_violation(tmp_path):

    def unfloor(manifest: dict[str, Any]) -> None:
        manifest["time_span_utc"]["start"] = "2026-08-25T17:31:45+00:00"

    corpus = write_synthetic_corpus(tmp_path / "span", manifest_mutate=unfloor)
    reasons = {v.reason for v in boundary.validate_corpus(corpus) if v.assertion == "manifest"}
    assert "timestamp-not-hour-floored" in reasons


def test_a_manifest_session_count_that_disagrees_fails(tmp_path):
    def shrink(manifest: dict[str, Any]) -> None:
        manifest["sessions"]["included"] -= 1

    corpus = write_synthetic_corpus(tmp_path / "sessions", manifest_mutate=shrink)
    reasons = {v.reason for v in boundary.validate_corpus(corpus) if v.assertion == "manifest"}
    assert "session-count-disagrees" in reasons


def test_a_manifest_size_that_disagrees_fails(tmp_path):
    def resize(manifest: dict[str, Any]) -> None:
        manifest["size_bytes"]["requests"] += 1

    corpus = write_synthetic_corpus(tmp_path / "sizes", manifest_mutate=resize)
    reasons = {v.reason for v in boundary.validate_corpus(corpus) if v.assertion == "manifest"}
    assert "size-disagrees" in reasons


def test_red_proof_one_added_text_column_fails_the_boundary(tmp_path):
    corpus = write_synthetic_corpus(
        tmp_path / "red",
        extra_columns={
            "tool_results": {"tool_input": (pa.string(), _planted_column(_FIXTURE_ROWS))}
        },
    )
    violations = boundary.validate_corpus(corpus)
    assert violations, "a corpus with a text column full of paths passed the boundary"

    by_assertion = {v.assertion for v in violations}
    assert {"schema", "content", "pattern"} <= by_assertion, boundary.format_violations(violations)
    assert {v.column for v in violations} == {"tool_input"}
    assert any(v.reason == "undeclared-column" for v in violations)

    rendered = boundary.format_violations(violations)
    assert "tool_results" in rendered and "tool_input" in rendered
    for make in PLANTED_TEXT:
        assert make() not in rendered


def test_red_proof_the_same_corpus_without_the_text_column_is_clean(tmp_path):
    assert boundary.validate_corpus(write_synthetic_corpus(tmp_path / "green")) == []


_SKIP_REASON = (
    "NO CORPUS AT ALL -- the privacy boundary did not run against real data. Not one of "
    f"{', '.join(boundary.corpus_file_names())} is present. This skip is legitimate ONLY on a "
    "checkout made before the first corpus data commit. Once that commit exists the files are "
    "tracked in git and these tests ALWAYS run in CI, so a skip here means the whole corpus "
    "was deleted or never committed -- investigate it, do not read it as a pass. A PARTIAL "
    "corpus does not skip: it runs and fails."
)
_needs_corpus = pytest.mark.skipif(boundary.corpus_is_absent(_REAL_CORPUS), reason=_SKIP_REASON)


@pytest.fixture(scope="module")
def real_violations() -> list[boundary.Violation]:
    return boundary.validate_corpus(_REAL_CORPUS)


@_needs_corpus
def test_real_corpus_assertion_1_schema(real_violations):
    found = [v for v in real_violations if v.assertion == "schema"]
    assert found == [], boundary.format_violations(found)


@_needs_corpus
def test_real_corpus_assertion_2_content(real_violations):
    found = [v for v in real_violations if v.assertion == "content"]
    assert found == [], boundary.format_violations(found)


@_needs_corpus
def test_real_corpus_assertion_3_pattern(real_violations):
    found = [v for v in real_violations if v.assertion == "pattern"]
    assert found == [], boundary.format_violations(found)


@_needs_corpus
def test_real_corpus_assertion_4_manifest(real_violations):
    found = [v for v in real_violations if v.assertion == "manifest"]
    assert found == [], boundary.format_violations(found)


@_needs_corpus
def test_real_corpus_is_the_declared_five_tables_and_nothing_else():
    present = {p.name for p in _REAL_CORPUS.glob("*.parquet")}
    assert present == {f"{table}.parquet" for table in schema.TABLES}


@_needs_corpus
def test_real_corpus_carries_no_hmac_key_material():
    manifest = json.loads((_REAL_CORPUS / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["hmac_key_env"] == schema.HMAC_KEY_ENV
    key_id = manifest["hmac_key_id"]
    label, _, digest = key_id.partition(":")
    assert label == schema.HMAC_KEY_LABEL
    assert len(digest) == 8
    assert {k for k in manifest if "key" in k.lower()} == {"hmac_key_env", "hmac_key_id"}

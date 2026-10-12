from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from corpus import schema

CORPUS_DIR = Path(__file__).resolve().parent
REPO_ROOT = CORPUS_DIR.parent
GITLEAKS_CONFIG = REPO_ROOT / ".gitleaks.toml"
MANIFEST_NAME = "manifest.json"

ASSERTIONS: tuple[str, ...] = ("schema", "content", "pattern", "manifest")


NUMERIC_FAMILY_KINDS: frozenset[schema.ColumnKind] = frozenset(
    {
        schema.ColumnKind.INT,
        schema.ColumnKind.FLOAT,
        schema.ColumnKind.BOOL,
        schema.ColumnKind.TIMESTAMP,
    }
)

CLOSED_VOCABULARY_KINDS: frozenset[schema.ColumnKind] = frozenset(
    {schema.ColumnKind.ENUM, schema.ColumnKind.HASH, schema.ColumnKind.VERSION}
)

_VOCABULARY_REASON: dict[schema.ColumnKind, str] = {
    schema.ColumnKind.ENUM: "value-outside-enum-vocabulary",
    schema.ColumnKind.HASH: "value-outside-hash-shape",
    schema.ColumnKind.VERSION: "value-outside-version-shape",
}


MAX_CATEGORICAL_LEN = 64

CATEGORICAL_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")

DECLARED_MEMBER_RE = re.compile(r"^[A-Za-z0-9_.\[\]\-]+$")


class GitleaksRuleError(RuntimeError): ...


@dataclass(frozen=True, slots=True)
class GitleaksRule:
    id: str
    regex: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class GitleaksRules:
    rules: tuple[GitleaksRule, ...]
    extends_only: tuple[str, ...]


def load_gitleaks_rules(config_path: Path | str = GITLEAKS_CONFIG) -> GitleaksRules:
    path = Path(config_path)
    config = tomllib.loads(path.read_text(encoding="utf-8"))
    entries = config.get("rules", [])
    if not isinstance(entries, list):
        raise GitleaksRuleError(
            f"{path.name} has no [[rules]] array; assertion 3 has nothing to apply"
        )

    rules: list[GitleaksRule] = []
    extends_only: list[str] = []
    failures: list[str] = []
    for index, entry in enumerate(entries):
        rule_id = str(entry.get("id", f"<unnamed rule #{index}>"))
        pattern = entry.get("regex")
        if pattern is None:
            extends_only.append(rule_id)
            continue
        try:
            compiled = re.compile(str(pattern))
        except re.error as exc:
            failures.append(f"  {rule_id}: {exc}")
            continue
        rules.append(GitleaksRule(id=rule_id, regex=compiled))

    if failures:
        raise GitleaksRuleError(
            "\n".join(
                [
                    f"{len(failures)} gitleaks rule(s) in {path.name} do not compile under "
                    "Python's `re`, so the privacy boundary cannot apply them:",
                    *failures,
                    "  Fix the translation in corpus/boundary.py and document it, or change the"
                    " rule. Skipping a rule here is a silent hole in the pattern assertion.",
                ]
            )
        )
    if not rules:
        raise GitleaksRuleError(
            f"{path.name} yielded zero applicable rules. The pattern assertion would pass"
            " vacuously, which is indistinguishable from a corpus with no leaks in it."
        )
    return GitleaksRules(tuple(rules), tuple(extends_only))


def matching_rule(rules: GitleaksRules, text: str) -> str | None:
    for rule in rules.rules:
        if rule.regex.search(text):
            return rule.id
    return None


@dataclass(frozen=True, slots=True)
class Violation:
    assertion: str
    table: str
    column: str
    reason: str
    rows: int = 0
    distinct: int = 0
    rule_id: str | None = None
    detail: str = ""

    def describe(self) -> str:
        parts = [f"[{self.assertion}] {self.table}.{self.column}: {self.reason}"]
        if self.rule_id is not None:
            parts.append(f"rule={self.rule_id}")
        if self.rows or self.distinct:
            parts.append(f"{self.rows} row(s), {self.distinct} distinct value(s)")
        if self.detail:
            parts.append(self.detail)
        return " -- ".join(parts)


def format_violations(violations: Sequence[Violation]) -> str:
    if not violations:
        return "no privacy-boundary violations"
    lines = [
        f"{len(violations)} privacy-boundary violation(s). This corpus must not be committed.",
        *(f"  {v.describe()}" for v in violations),
        "  Offending values are never printed: a value that should not be in this corpus may be"
        " a path, a project name or a username.",
    ]
    return "\n".join(lines)


def type_family(arrow_type: Any) -> str:
    import pyarrow.types as pat

    if (
        pat.is_boolean(arrow_type)
        or pat.is_integer(arrow_type)
        or pat.is_floating(arrow_type)
        or pat.is_decimal(arrow_type)
        or pat.is_temporal(arrow_type)
    ):
        return "numeric"
    if pat.is_string(arrow_type) or pat.is_large_string(arrow_type):
        return "string"
    if pat.is_dictionary(arrow_type):
        return type_family(arrow_type.value_type)
    return "other"


def corpus_file_names() -> list[str]:
    return [f"{table}.parquet" for table in schema.TABLES] + [MANIFEST_NAME]


def missing_corpus_files(corpus_dir: Path | str = CORPUS_DIR) -> list[str]:
    directory = Path(corpus_dir)
    return [name for name in corpus_file_names() if not (directory / name).is_file()]


def present_corpus_files(corpus_dir: Path | str = CORPUS_DIR) -> list[str]:
    directory = Path(corpus_dir)
    return [name for name in corpus_file_names() if (directory / name).is_file()]


def load_corpus(corpus_dir: Path | str = CORPUS_DIR) -> dict[str, Any]:
    directory = Path(corpus_dir)
    missing = [
        f"{table}.parquet"
        for table in schema.TABLES
        if not (directory / f"{table}.parquet").is_file()
    ]
    if missing:
        raise FileNotFoundError(
            f"{directory}: not a complete corpus -- missing {', '.join(missing)}"
        )

    import pyarrow.parquet as pq

    return {table: pq.read_table(directory / f"{table}.parquet") for table in schema.TABLES}


def read_manifest(corpus_dir: Path | str = CORPUS_DIR) -> dict[str, Any]:
    path = Path(corpus_dir) / MANIFEST_NAME
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def corpus_is_absent(corpus_dir: Path | str = CORPUS_DIR) -> bool:
    return not present_corpus_files(corpus_dir)


@dataclass(slots=True)
class _Scan:
    row_counts: dict[str, int] = field(default_factory=dict)
    observed: dict[str, set[str]] = field(default_factory=dict)
    session_hashes: set[str] = field(default_factory=set)


def _distinct(column: Any) -> tuple[list[str], list[int]]:
    import pyarrow.compute as pc

    tally = pc.value_counts(pc.drop_null(column))
    values = tally.field("values").to_pylist()
    counts = tally.field("counts").to_pylist()
    return [str(value) for value in values], [int(count) for count in counts]


def _charset_ok(text: str, members: frozenset[str]) -> bool:
    if CATEGORICAL_RE.match(text):
        return True
    return text in members and DECLARED_MEMBER_RE.match(text) is not None


def _in_vocabulary(kind: schema.ColumnKind, members: frozenset[str], text: str) -> bool:
    if kind is schema.ColumnKind.ENUM:
        return text in members
    if kind is schema.ColumnKind.HASH:
        return schema.HASH_RE.match(text) is not None
    return schema.CC_VERSION_RE.match(text) is not None


def _tally(marked: Sequence[tuple[str, int]]) -> tuple[int, int]:
    return sum(count for _text, count in marked), len(marked)


def _check_string_column(
    table: str,
    name: str,
    column: schema.Column | None,
    texts: Sequence[str],
    counts: Sequence[int],
) -> list[Violation]:
    violations: list[Violation] = []
    kind: schema.ColumnKind | None = None
    members: frozenset[str] = frozenset()
    pairs = list(zip(texts, counts, strict=True))

    if column is None:
        pass
    elif column.kind not in CLOSED_VOCABULARY_KINDS:
        violations.append(
            Violation(
                "schema",
                table,
                name,
                "string-column-with-non-vocabulary-kind",
                detail=f"declared kind={column.kind.value}",
            )
        )
    else:
        kind = column.kind
        if kind is schema.ColumnKind.ENUM and column.enum is not None:
            members = frozenset(schema.ENUMS[column.enum])
        outside = [pair for pair in pairs if not _in_vocabulary(kind, members, pair[0])]
        if outside:
            rows, distinct = _tally(outside)
            violations.append(
                Violation(
                    "schema", table, name, _VOCABULARY_REASON[kind], rows=rows, distinct=distinct
                )
            )

    bounded = kind is not schema.ColumnKind.HASH
    too_long = [pair for pair in pairs if bounded and len(pair[0]) >= MAX_CATEGORICAL_LEN]
    if too_long:
        rows, distinct = _tally(too_long)
        violations.append(
            Violation(
                "content",
                table,
                name,
                "categorical-too-long",
                rows=rows,
                distinct=distinct,
                detail=f"limit is {MAX_CATEGORICAL_LEN} characters",
            )
        )
    off_charset = [pair for pair in pairs if not _charset_ok(pair[0], members)]
    if off_charset:
        rows, distinct = _tally(off_charset)
        violations.append(
            Violation(
                "content",
                table,
                name,
                "categorical-outside-charset",
                rows=rows,
                distinct=distinct,
                detail=f"charset is {CATEGORICAL_RE.pattern}",
            )
        )
    return violations


def _pattern_scan(
    table: str,
    name: str,
    texts: Sequence[str],
    counts: Sequence[int],
    rules: GitleaksRules,
    memo: dict[str, str | None],
) -> list[Violation]:
    hits: dict[str, list[int]] = {}
    for text, occurrences in zip(texts, counts, strict=True):
        if text in memo:
            rule_id = memo[text]
        else:
            rule_id = matching_rule(rules, text)
            memo[text] = rule_id
        if rule_id is not None:
            tally = hits.setdefault(rule_id, [0, 0])
            tally[0] += occurrences
            tally[1] += 1
    return [
        Violation(
            "pattern",
            table,
            name,
            "matches-gitleaks-rule",
            rows=rows,
            distinct=distinct,
            rule_id=rule_id,
        )
        for rule_id, (rows, distinct) in sorted(hits.items())
    ]


def _check_table(
    path: Path,
    table: str,
    columns: Sequence[schema.Column],
    rules: GitleaksRules,
    memo: dict[str, str | None],
    scan: _Scan,
) -> list[Violation]:
    import pyarrow.parquet as pq

    violations: list[Violation] = []
    arrow_table = pq.read_table(path)
    scan.row_counts[table] = int(arrow_table.num_rows)
    declared = {column.name: column for column in columns}
    declared_types = schema.arrow_schema(table)
    file_names = [str(f.name) for f in arrow_table.schema]

    for column_name in declared:
        if column_name not in file_names:
            violations.append(Violation("schema", table, column_name, "missing-declared-column"))
    in_file = [column.name for column in columns if column.name in file_names]
    if [name for name in file_names if name in declared] != in_file:
        violations.append(Violation("schema", table, "-", "declared-column-order-changed"))

    for name in file_names:
        arrow_field = arrow_table.schema.field(name)
        column = declared.get(name)

        if column is None:
            violations.append(
                Violation(
                    "schema",
                    table,
                    name,
                    "undeclared-column",
                    detail=f"arrow type={arrow_field.type}",
                )
            )
        else:
            declared_field = declared_types.field(name)
            if not bool(arrow_field.type.equals(declared_field.type)):
                violations.append(
                    Violation(
                        "schema",
                        table,
                        name,
                        "declared-type-mismatch",
                        detail=f"file={arrow_field.type}, declared={declared_field.type}",
                    )
                )
            if bool(arrow_field.nullable) != bool(declared_field.nullable):
                violations.append(
                    Violation(
                        "schema",
                        table,
                        name,
                        "declared-nullability-mismatch",
                        detail=f"file nullable={bool(arrow_field.nullable)}",
                    )
                )

        family = type_family(arrow_field.type)
        if family == "other":
            violations.append(
                Violation(
                    "schema", table, name, "unsupported-arrow-type", detail=str(arrow_field.type)
                )
            )
            continue

        texts, counts = _distinct(arrow_table.column(name))
        if family == "string":
            violations += _check_string_column(table, name, column, texts, counts)
        violations += _pattern_scan(table, name, texts, counts, rules, memo)

        if column is not None and column.kind is schema.ColumnKind.ENUM and column.enum:
            scan.observed[column.enum] |= set(texts)
        if name == "session_hash":
            scan.session_hashes |= set(texts)

    return violations


_REQUIRED_MANIFEST_KEYS = (
    "corpus_schema_version",
    "row_counts",
    "enums",
    "size_bytes",
    "time_span_utc",
    "sessions",
    "excluded",
)

_REQUIRED_EXCLUSIONS = ("tool_results_sidechain", "requests_error_rows_deduped")


def _manifest_block(
    manifest: dict[str, Any], key: str, violations: list[Violation]
) -> dict[str, Any] | None:
    block = manifest.get(key, {})
    if isinstance(block, dict):
        return block
    violations.append(
        Violation(
            "manifest",
            "-",
            key,
            "manifest-block-wrong-type",
            detail=f"expected an object, found {type(block).__name__}",
        )
    )
    return None


def _iter_instants(node: Any, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _iter_instants(value, f"{path}.{key}")
    elif isinstance(node, str) and path.rsplit(".", 1)[-1] in ("start", "end"):
        yield path, node


def _check_manifest(directory: Path, scan: _Scan) -> list[Violation]:
    path = directory / MANIFEST_NAME
    if not path.is_file():
        return [Violation("manifest", "-", MANIFEST_NAME, "missing-manifest")]
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [Violation("manifest", "-", MANIFEST_NAME, "unreadable-manifest")]
    if not isinstance(parsed, dict):
        return [Violation("manifest", "-", MANIFEST_NAME, "unreadable-manifest")]
    manifest: dict[str, Any] = parsed

    violations: list[Violation] = []
    for key in _REQUIRED_MANIFEST_KEYS:
        if key not in manifest:
            violations.append(Violation("manifest", "-", key, "manifest-missing-key"))

    if manifest.get("corpus_schema_version") != schema.SCHEMA_VERSION:
        violations.append(
            Violation(
                "manifest",
                "-",
                "corpus_schema_version",
                "schema-version-disagrees",
                detail=f"declared={schema.SCHEMA_VERSION}",
            )
        )

    claimed_rows = _manifest_block(manifest, "row_counts", violations)
    if claimed_rows is not None:
        for table, actual in scan.row_counts.items():
            if claimed_rows.get(table) != actual:
                violations.append(
                    Violation(
                        "manifest",
                        table,
                        "row_counts",
                        "row-count-disagrees",
                        detail=f"manifest={claimed_rows.get(table)!r}, files={actual}",
                    )
                )
        for table in sorted(set(claimed_rows) - set(schema.TABLES)):
            violations.append(
                Violation("manifest", table, "row_counts", "row-count-for-undeclared-table")
            )

    claimed_enums = _manifest_block(manifest, "enums", violations)
    if claimed_enums is not None:
        for name, members in schema.ENUMS.items():
            block = claimed_enums.get(name)
            if not isinstance(block, dict):
                violations.append(Violation("manifest", "-", name, "manifest-missing-enum"))
                continue
            if block.get("declared_cardinality") != len(members):
                violations.append(
                    Violation(
                        "manifest",
                        "-",
                        name,
                        "declared-cardinality-disagrees",
                        detail=f"manifest={block.get('declared_cardinality')!r},"
                        f" schema={len(members)}",
                    )
                )
            observed = len(scan.observed.get(name, set()))
            if block.get("observed_cardinality") != observed:
                violations.append(
                    Violation(
                        "manifest",
                        "-",
                        name,
                        "observed-cardinality-disagrees",
                        detail=f"manifest={block.get('observed_cardinality')!r}, files={observed}",
                    )
                )

    claimed_sizes = _manifest_block(manifest, "size_bytes", violations)
    if claimed_sizes is not None:
        actual_sizes = {
            table: (directory / f"{table}.parquet").stat().st_size for table in scan.row_counts
        }
        for table, actual in actual_sizes.items():
            if claimed_sizes.get(table) != actual:
                violations.append(
                    Violation(
                        "manifest",
                        table,
                        "size_bytes",
                        "size-disagrees",
                        detail=f"manifest={claimed_sizes.get(table)!r}, file={actual}",
                    )
                )
        complete = len(actual_sizes) == len(schema.TABLES) and "total" in claimed_sizes
        if complete and claimed_sizes["total"] != sum(actual_sizes.values()):
            violations.append(
                Violation(
                    "manifest",
                    "-",
                    "size_bytes",
                    "size-total-disagrees",
                    detail=f"manifest={claimed_sizes['total']!r},"
                    f" files={sum(actual_sizes.values())}",
                )
            )

    span = _manifest_block(manifest, "time_span_utc", violations)
    for label, raw in _iter_instants(span or {}, "time_span_utc"):
        try:
            moment = schema.parse_instant(raw)
        except schema.UnreadableValue:
            violations.append(Violation("manifest", "-", label, "manifest-timestamp-unreadable"))
            continue
        if moment.minute or moment.second or moment.microsecond:
            violations.append(Violation("manifest", "-", label, "timestamp-not-hour-floored"))

    sessions = _manifest_block(manifest, "sessions", violations)
    if sessions is not None:
        included = sessions.get("included")
        in_store = sessions.get("in_store")
        rate = sessions.get("sampling_rate")
        if included != len(scan.session_hashes):
            violations.append(
                Violation(
                    "manifest",
                    "-",
                    "sessions",
                    "session-count-disagrees",
                    detail=f"manifest={included!r}, files={len(scan.session_hashes)}",
                )
            )
        if isinstance(included, int) and isinstance(in_store, int) and included > in_store:
            violations.append(Violation("manifest", "-", "sessions", "session-count-exceeds-store"))
        if not isinstance(rate, int | float) or isinstance(rate, bool) or not 0 < rate <= 1:
            violations.append(Violation("manifest", "-", "sessions", "sampling-rate-out-of-range"))

    excluded = _manifest_block(manifest, "excluded", violations)
    if excluded is not None:
        for key in _REQUIRED_EXCLUSIONS:
            value = excluded.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                violations.append(
                    Violation("manifest", "-", f"excluded.{key}", "excluded-count-missing")
                )
    return violations


def validate_corpus(
    corpus_dir: Path | str = CORPUS_DIR, *, rules: GitleaksRules | None = None
) -> list[Violation]:
    directory = Path(corpus_dir)
    rule_set = load_gitleaks_rules() if rules is None else rules
    violations: list[Violation] = []
    scan = _Scan(observed={name: set() for name in schema.ENUMS})
    memo: dict[str, str | None] = {}

    expected = {f"{table}.parquet" for table in schema.TABLES}
    for stray in sorted({p.name for p in directory.glob("*.parquet")} - expected):
        violations.append(Violation("schema", stray, "-", "undeclared-parquet-file"))

    for table, columns in schema.TABLES.items():
        path = directory / f"{table}.parquet"
        if not path.is_file():
            violations.append(Violation("schema", table, "-", "missing-parquet-file"))
            continue
        violations += _check_table(path, table, columns, rule_set, memo, scan)

    violations += _check_manifest(directory, scan)
    return violations

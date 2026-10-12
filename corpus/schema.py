from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    import pyarrow as pa

SCHEMA_VERSION = "1.0.0"


HMAC_KEY_ENV = "VITALS_CORPUS_HMAC_KEY"
HMAC_KEY_LABEL = "vitals-corpus-hmac-v1"

MIN_KEY_BYTES = 32

HASH_RE = re.compile(r"^[0-9a-f]{64}$")

CC_VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,3}$")


class MissingKeyError(RuntimeError): ...


class UnreadableValue(ValueError): ...


def unreadable(what: str) -> UnreadableValue:
    return UnreadableValue(f"{what} could not be read (value withheld by design)")


class Hasher:
    __slots__ = ("_key", "_key_id")

    def __init__(self, key: bytes) -> None:
        if len(key) < MIN_KEY_BYTES:
            raise MissingKeyError(
                f"the corpus HMAC key must be at least {MIN_KEY_BYTES} bytes; "
                f"set {HMAC_KEY_ENV} to a long random value"
            )
        self._key = bytes(key)
        self._key_id = (
            f"{HMAC_KEY_LABEL}:"
            f"{hmac.new(self._key, HMAC_KEY_LABEL.encode('utf-8'), hashlib.sha256).hexdigest()[:8]}"
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Hasher:
        raw = env.get(HMAC_KEY_ENV, "")
        if not raw:
            raise MissingKeyError(
                f"{HMAC_KEY_ENV} is not set. Generate a random key and export it for this "
                "run only; it must never be committed, echoed, or written to the manifest."
            )
        return cls(raw.encode("utf-8"))

    @property
    def key_id(self) -> str:
        return self._key_id

    def hash(self, domain: str, value: str) -> str:
        return hmac.new(self._key, f"{domain}\x00{value}".encode(), hashlib.sha256).hexdigest()

    def digest_label(self, value: str) -> str:
        return self.hash("diagnostic", value)[:12]

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Hasher {self._key_id}>"

    __str__ = __repr__


MODELS: tuple[str, ...] = (
    "claude-fable-5",
    "claude-haiku-4-5-20251001",
    "claude-opus-4-6",
    "claude-opus-4-7",
    "claude-opus-4-8",
    "claude-opus-5",
    "claude-opus-5[1m]",
    "claude-sonnet-5",
    "definitely-not-a-real-model-xyz",
)

CONTEXT_BUCKETS: tuple[str, ...] = ("lt30k", "b30_100k", "b100_180k", "gt180k")

ERROR_CLASSES: tuple[str, ...] = (
    "none",
    "rate_limit",
    "server",
    "client",
    "timeout",
    "unknown",
)

TOOLS: tuple[str, ...] = (
    "Agent",
    "Artifact",
    "AskUserQuestion",
    "Bash",
    "Edit",
    "EnterWorktree",
    "ExitPlanMode",
    "ExitWorktree",
    "Glob",
    "Grep",
    "ListAgents",
    "Monitor",
    "NotebookEdit",
    "PowerShell",
    "Read",
    "ReportFindings",
    "SendMessage",
    "SendUserFile",
    "Skill",
    "StructuredOutput",
    "TaskOutput",
    "TaskStop",
    "ToolSearch",
    "WebFetch",
    "WebSearch",
    "Workflow",
    "Write",
    "mcp_tool",
    "mcp__computer",
    "mcp__get_project",
    "mcp__javascript_tool",
    "mcp__list_projects",
    "mcp__list_teams",
    "mcp__mark_chapter",
    "mcp__navigate",
    "mcp__preview_list",
    "mcp__preview_start",
    "mcp__search_session_transcripts",
    "mcp__spawn_task",
    "mcp__tabs_close",
    "mcp__tabs_create",
    "mcp__tabs_select",
)

TEST_RUNNERS: tuple[str, ...] = (
    "cargo",
    "clippy",
    "eslint",
    "flake8",
    "go",
    "npm",
    "pytest",
    "ruff",
)

CANARY_TASK_IDS: tuple[str, ...] = (
    "arith-exact",
    "bugfix-py",
    "diff-golden",
    "format-follow",
    "json-extract",
    "longctx-edit",
    "longctx-needle",
    "regex-golden",
    "rename-py",
    "sql-golden",
    "test-writing",
    "tool-sequence",
)

CHANGE_POINT_KINDS: tuple[str, ...] = (
    "canary_suite",
    "cc_version",
    "plugins",
    "settings",
    "vitals_config",
)

ENUMS: dict[str, tuple[str, ...]] = {
    "model": MODELS,
    "context_bucket": CONTEXT_BUCKETS,
    "error_class": ERROR_CLASSES,
    "tool": TOOLS,
    "test_runner": TEST_RUNNERS,
    "canary_task_id": CANARY_TASK_IDS,
    "change_point_kind": CHANGE_POINT_KINDS,
}

_ENUM_SETS: dict[str, frozenset[str]] = {k: frozenset(v) for k, v in ENUMS.items()}


class ColumnKind(StrEnum):
    INT = "int"
    FLOAT = "float"
    BOOL = "bool"
    ENUM = "enum"
    HASH = "hash"
    TIMESTAMP = "timestamp"
    VERSION = "version"


@dataclass(frozen=True, slots=True)
class Column:
    name: str
    kind: ColumnKind
    nullable: bool = False
    enum: str | None = None


def _c(name: str, kind: ColumnKind, *, null: bool = False, enum: str | None = None) -> Column:
    return Column(name=name, kind=kind, nullable=null, enum=enum)


_INT, _FLOAT, _BOOL = ColumnKind.INT, ColumnKind.FLOAT, ColumnKind.BOOL
_ENUM, _HASH, _TS, _VER = (
    ColumnKind.ENUM,
    ColumnKind.HASH,
    ColumnKind.TIMESTAMP,
    ColumnKind.VERSION,
)

TABLES: dict[str, tuple[Column, ...]] = {
    "requests": (
        _c("session_hash", _HASH),
        _c("prompt_seq", _INT, null=True),
        _c("request_seq", _INT),
        _c("ts_bucket_utc", _TS),
        _c("model", _ENUM, enum="model"),
        _c("cc_version", _VER, null=True),
        _c("plugins_hash", _HASH, null=True),
        _c("context_bucket", _ENUM, null=True, enum="context_bucket"),
        _c("input_tokens", _INT, null=True),
        _c("output_tokens", _INT, null=True),
        _c("cache_read_tokens", _INT, null=True),
        _c("latency_ms", _INT, null=True),
        _c("retries", _INT),
        _c("error_class", _ENUM, enum="error_class"),
        _c("post_compaction", _BOOL),
    ),
    "tool_results": (
        _c("session_hash", _HASH),
        _c("prompt_seq", _INT),
        _c("tool", _ENUM, enum="tool"),
        _c("ok", _BOOL, null=True),
        _c("duration_ms", _INT, null=True),
        _c("file_hash", _HASH, null=True),
        _c("test_exit_code", _INT, null=True),
        _c("test_runner", _ENUM, null=True, enum="test_runner"),
    ),
    "turn_features": (
        _c("session_hash", _HASH),
        _c("prompt_seq", _INT),
        _c("self_correction", _BOOL),
        _c("edit_retry_max", _INT),
        _c("tool_calls", _INT),
        _c("tool_failures", _INT),
    ),
    "canary_cycles": (
        _c("cycle_id", _INT),
        _c("ts_bucket_utc", _TS),
        _c("model", _ENUM, enum="model"),
        _c("cc_version", _VER, null=True),
        _c("task_id", _ENUM, enum="canary_task_id"),
        _c("runs", _INT),
        _c("passes", _INT),
        _c("invalid", _INT),
        _c("latency_ms_p50", _INT, null=True),
        _c("tokens_total", _INT, null=True),
        _c("cost_usd", _FLOAT, null=True),
    ),
    "change_points": (
        _c("ts_bucket_utc", _TS),
        _c("kind", _ENUM, enum="change_point_kind"),
        _c("from_hash", _HASH, null=True),
        _c("to_hash", _HASH, null=True),
    ),
}


def arrow_schema(table: str) -> pa.Schema:
    import pyarrow as pa

    types = {
        ColumnKind.INT: pa.int64(),
        ColumnKind.FLOAT: pa.float64(),
        ColumnKind.BOOL: pa.bool_(),
        ColumnKind.TIMESTAMP: pa.timestamp("ms", tz="UTC"),
        ColumnKind.ENUM: pa.string(),
        ColumnKind.HASH: pa.string(),
        ColumnKind.VERSION: pa.string(),
    }
    return pa.schema([pa.field(c.name, types[c.kind], nullable=c.nullable) for c in TABLES[table]])


def normalize_tool_name(raw: str) -> str:
    prefix = "mcp__"
    if not raw.startswith(prefix):
        return raw
    _server, sep, suffix = raw[len(prefix) :].partition("__")
    if not sep or not suffix:
        return raw
    return prefix + suffix


def normalize_file_path(raw: str) -> str:
    return raw.replace("\\", "/").rstrip("/").casefold()


def parse_instant(iso: str) -> datetime:
    moment: datetime | None = None
    try:
        text = iso.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        moment = datetime.fromisoformat(text)
    except (AttributeError, TypeError, ValueError):
        moment = None
    if moment is None:
        raise unreadable("a timestamp column")
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def hour_bucket(iso: str) -> datetime:
    return parse_instant(iso).replace(minute=0, second=0, microsecond=0)


_TIMEOUT_MARKERS = re.compile(r"tim(?:ed?\s?out|eout)|deadline exceeded", re.IGNORECASE)
_SERVER_MARKERS = re.compile(
    r"overloaded|connection (?:closed|reset|error)|internal server", re.IGNORECASE
)
_RATE_MARKERS = re.compile(r"(?:rate|session|usage|quota) limit|too many requests", re.IGNORECASE)


def classify_error(status_code: int | None, error_text: str | None) -> str:
    if status_code is None:
        text = error_text or ""
        if _TIMEOUT_MARKERS.search(text):
            return "timeout"
        if _SERVER_MARKERS.search(text):
            return "server"
        if _RATE_MARKERS.search(text):
            return "rate_limit"
        return "unknown"
    if status_code in (408, 504, 524):
        return "timeout"
    if status_code == 429:
        return "rate_limit"
    if 500 <= status_code < 600:
        return "server"
    if 400 <= status_code < 500:
        return "client"
    return "unknown"


def derive_retries(attempt: int | None, retries_exhausted: int | None = 0) -> int:
    if attempt is None:
        return 0
    value: int | None = None
    try:
        value = int(attempt)
    except (TypeError, ValueError):
        value = None
    if value is None:
        raise unreadable("api_errors.attempt")
    if retries_exhausted:
        value -= 1
    return max(value, 0)


class EnumViolation(Exception): ...


@dataclass(slots=True)
class ViolationTally:
    rows: int = 0
    distinct: int = 0
    digests: set[str] = field(default_factory=set)
    columns: set[str] = field(default_factory=set)


class SchemaGate:
    def __init__(self, hasher: Hasher, *, max_digests: int = 10) -> None:
        self._hasher = hasher
        self._max_digests = max_digests
        self.violations: dict[str, ViolationTally] = {}

    def enum(self, enum_name: str, value: str | None, *, column: str) -> str | None:
        members = _ENUM_SETS[enum_name]
        if value is None or value in members:
            return value
        self._record(enum_name, value, column)
        return None

    def version(self, value: str | None, *, column: str) -> str | None:
        if value is None or CC_VERSION_RE.match(value):
            return value
        self._record("cc_version", value, column)
        return None

    def _record(self, enum_name: str, value: str, column: str) -> None:
        tally = self.violations.setdefault(enum_name, ViolationTally())
        tally.rows += 1
        tally.columns.add(column)
        digest = self._hasher.digest_label(value)
        if digest not in tally.digests:
            tally.distinct += 1
            if len(tally.digests) < self._max_digests:
                tally.digests.add(digest)
            else:
                tally.distinct = max(tally.distinct, len(tally.digests) + 1)

    def raise_if_violations(self) -> None:
        if not self.violations:
            return
        lines = [
            f"corpus extraction aborted: {len(self.violations)} vocabulary "
            f"violation class(es). Nothing was written.",
        ]
        for name in sorted(self.violations):
            tally = self.violations[name]
            shown = ", ".join(sorted(tally.digests))
            more = "" if tally.distinct <= len(tally.digests) else " (+more)"
            lines.append(
                f"  {name}: {tally.rows} row(s), {tally.distinct} distinct unknown value(s)"
                f" in {', '.join(sorted(tally.columns))}; digests: {shown}{more}"
            )
        lines.append(
            "  Raw values are never printed: an unknown value may be a path, a project name"
            " or a username."
        )
        lines.append(
            f"  Fix by adding the value to corpus/schema.py deliberately (see {__name__}),"
            " or by correcting the source."
        )
        raise EnumViolation("\n".join(lines))

from __future__ import annotations

import difflib
import hashlib
import json
import re
import sqlite3
import subprocess
import sys
import time
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import jsonschema

__all__ = [
    "CHECKERS",
    "CheckResult",
    "RunArtifacts",
    "TaskSpec",
    "default_tasks_dir",
    "load_tasks",
    "suite_hash",
]


@dataclass
class TaskSpec:
    task_id: str
    checker: str
    prompt: str
    allowed_tools: list[str]
    max_turns: int
    golden_dir: Path
    per_run_budget_usd: float | None = None
    per_run_timeout_s: int | None = None
    long_context: bool = False
    allowed_files: list[str] | None = None
    forbidden_regex: str | None = None
    workspace_template: Path | None = None
    json_schema: dict | None = None
    structured_output: bool = False


@dataclass
class RunArtifacts:
    result_text: str
    structured_output: object | None
    workspace: Path | None


@dataclass
class CheckResult:
    passed: bool
    detail: str = ""


def default_tasks_dir() -> Path:
    return Path(resources.files("vitals.canary") / "tasks")


_REQUIRED_TOML_KEYS = {"task_id", "checker"}


def load_tasks(tasks_dir: Path) -> list[TaskSpec]:
    tasks_dir = Path(tasks_dir)
    tasks: list[TaskSpec] = []
    for task_dir in sorted(p for p in tasks_dir.iterdir() if p.is_dir()):
        toml_path = task_dir / "task.toml"
        if not toml_path.exists():
            continue
        raw = tomllib.loads(toml_path.read_text(encoding="utf-8"))
        missing = _REQUIRED_TOML_KEYS - raw.keys()
        if missing:
            raise ValueError(f"{toml_path}: missing required key(s): {sorted(missing)}")

        prompt_path = task_dir / raw.get("prompt_file", "prompt.md")
        prompt = prompt_path.read_text(encoding="utf-8")

        golden_dir = task_dir / "golden"
        schema_path = golden_dir / "schema.json"
        json_schema = (
            json.loads(schema_path.read_text(encoding="utf-8")) if schema_path.exists() else None
        )

        workspace_template_name = raw.get("workspace_template")
        allowed_files = raw.get("allowed_files")

        tasks.append(
            TaskSpec(
                task_id=raw["task_id"],
                checker=raw["checker"],
                prompt=prompt,
                allowed_tools=list(raw.get("allowed_tools", [])),
                max_turns=int(raw.get("max_turns", 1)),
                golden_dir=golden_dir,
                per_run_budget_usd=raw.get("per_run_budget_usd"),
                per_run_timeout_s=raw.get("per_run_timeout_s"),
                long_context=bool(raw.get("long_context", False)),
                allowed_files=list(allowed_files) if allowed_files is not None else None,
                forbidden_regex=raw.get("forbidden_regex"),
                workspace_template=(
                    task_dir / workspace_template_name if workspace_template_name else None
                ),
                json_schema=json_schema,
                structured_output=bool(raw.get("structured_output", False)),
            )
        )
    tasks.sort(key=lambda t: t.task_id)
    return tasks


def suite_hash(tasks: list[TaskSpec]) -> str:
    h = hashlib.sha256()
    for task in sorted(tasks, key=lambda t: t.task_id):
        task_dir = task.golden_dir.parent
        toml_path = task_dir / "task.toml"
        if toml_path.exists():
            h.update(toml_path.read_bytes())
        h.update(task.prompt.encode("utf-8"))
        if task.golden_dir.exists():
            for p in sorted(task.golden_dir.rglob("*")):
                if p.is_file():
                    h.update(p.read_bytes())
    return h.hexdigest()


_WS_RE = re.compile(r"\s+")


def _normalize(text: str) -> str:
    return _WS_RE.sub(" ", text.strip())


def check_exact(task: TaskSpec, artifacts: RunArtifacts) -> CheckResult:
    golden = _normalize((task.golden_dir / "answer.txt").read_text(encoding="utf-8"))
    actual = _normalize(artifacts.result_text)
    if actual == golden:
        return CheckResult(True, "")
    return CheckResult(False, f"expected {golden!r}, got {actual!r}")


_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def _extract_structured_output(artifacts: RunArtifacts) -> object:
    if artifacts.structured_output is not None:
        return artifacts.structured_output
    blocks = _FENCE_RE.findall(artifacts.result_text)
    candidate = blocks[-1] if blocks else artifacts.result_text
    return json.loads(candidate)


def check_json_schema(task: TaskSpec, artifacts: RunArtifacts) -> CheckResult:
    try:
        data = _extract_structured_output(artifacts)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        return CheckResult(False, f"could not parse JSON output: {exc}")

    schema = task.json_schema
    if schema is None:
        schema_path = task.golden_dir / "schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))

    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as exc:
        return CheckResult(False, f"schema validation failed: {exc.message}")

    golden = json.loads((task.golden_dir / "expected.json").read_text(encoding="utf-8"))
    if data == golden:
        return CheckResult(True, "")
    return CheckResult(False, f"expected {golden!r}, got {data!r}")


_SQL_TIMEOUT_S = 5.0

_FORBIDDEN_SQL_KEYWORDS = re.compile(
    r"\b(insert|update|delete|drop|alter|create|attach|detach|pragma|replace|vacuum|reindex|"
    r"begin|commit|rollback|savepoint)\b",
    re.IGNORECASE,
)

_SQL_FENCE_RE = re.compile(r"^```(?:sql)?\s*(.*?)```$", re.DOTALL)

_SELECT_OR_WITH_RE = re.compile(r"^(with|select)\b", re.IGNORECASE)


def _strip_sql_fence(text: str) -> str:
    stripped = text.strip()
    match = _SQL_FENCE_RE.match(stripped)
    return match.group(1).strip() if match else stripped


def _validate_select_only(body: str) -> str | None:
    if not body:
        return "empty query"
    if ";" in body:
        return "only a single statement is allowed"
    if not _SELECT_OR_WITH_RE.match(body):
        return "only SELECT statements (optionally with a leading WITH clause) are allowed"
    if _FORBIDDEN_SQL_KEYWORDS.search(body):
        return "forbidden keyword in query"
    if not sqlite3.complete_statement(body + ";"):
        return "incomplete SQL statement"
    return None


def check_sql(task: TaskSpec, artifacts: RunArtifacts) -> CheckResult:
    body = _strip_sql_fence(artifacts.result_text).rstrip().rstrip(";").strip()
    error = _validate_select_only(body)
    if error:
        return CheckResult(False, error)

    fixture_sql = (task.golden_dir / "fixture.sql").read_text(encoding="utf-8")
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(fixture_sql)
        start = time.monotonic()

        def _timeout_guard() -> int:
            return 1 if (time.monotonic() - start) > _SQL_TIMEOUT_S else 0

        conn.set_progress_handler(_timeout_guard, 1000)
        try:
            rows = [tuple(r) for r in conn.execute(body).fetchall()]
        except sqlite3.Error as exc:
            return CheckResult(False, f"query failed: {exc}")
    finally:
        conn.close()

    golden_rows = json.loads((task.golden_dir / "rows.json").read_text(encoding="utf-8"))
    golden_tuples = [tuple(r) for r in golden_rows]
    actual_sorted = sorted(rows)
    golden_sorted = sorted(golden_tuples)
    if actual_sorted == golden_sorted:
        return CheckResult(True, "")
    return CheckResult(False, f"expected rows {golden_sorted!r}, got {actual_sorted!r}")


_NOISE_DIR_NAMES = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".git"}
_NOISE_SUFFIXES = {".pyc", ".pyo"}

_PYTEST_TIMEOUT_S = 120.0


def _is_noise(rel_parts: tuple[str, ...], suffix: str) -> bool:
    return any(part in _NOISE_DIR_NAMES for part in rel_parts) or suffix in _NOISE_SUFFIXES


def _snapshot_files(root: Path) -> dict[str, bytes]:
    snapshot: dict[str, bytes] = {}
    if not root.is_dir():
        return snapshot
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if _is_noise(rel.parts, path.suffix):
            continue
        snapshot[rel.as_posix()] = path.read_bytes()
    return snapshot


def _changed_files(template: Path, workspace: Path) -> list[str]:
    before = _snapshot_files(template)
    after = _snapshot_files(workspace)
    changed = {rel for rel, content in after.items() if before.get(rel) != content}
    changed |= before.keys() - after.keys()
    return sorted(changed)


def _enforce_allowed_files(task: TaskSpec, workspace: Path) -> str | None:
    if task.allowed_files is None or task.workspace_template is None:
        return None
    allowed = set(task.allowed_files)
    offenders = [f for f in _changed_files(task.workspace_template, workspace) if f not in allowed]
    if offenders:
        return f"changed file(s) outside allowed_files {sorted(allowed)!r}: {offenders}"
    return None


def _enforce_forbidden_regex(task: TaskSpec, workspace: Path) -> str | None:
    if task.forbidden_regex is None:
        return None
    pattern = re.compile(task.forbidden_regex)
    for path in sorted(workspace.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(workspace)
        if _is_noise(rel.parts, path.suffix):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, ValueError):
            continue
        if pattern.search(text):
            return f"forbidden pattern {task.forbidden_regex!r} found in {rel.as_posix()}"
    return None


def _pytest_import_error(python: str) -> str | None:
    try:
        probe = subprocess.run([python, "-c", "import pytest"], capture_output=True, text=True)
    except OSError as exc:
        return f"INFRA: could not launch interpreter {python!r}: {exc}"
    if probe.returncode == 0:
        return None
    stderr = probe.stderr.strip() or probe.stdout.strip()
    return f"INFRA: pytest is not importable with interpreter {python!r}: {stderr}"


def _run_pytest(workspace: Path) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=_PYTEST_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return None


def _pytest_failure_detail(result: subprocess.CompletedProcess) -> str:
    tail = (result.stdout + "\n" + result.stderr).strip()
    return f"pytest exited {result.returncode}:\n{tail[-2000:]}"


def check_pytest(task: TaskSpec, artifacts: RunArtifacts) -> CheckResult:
    workspace = artifacts.workspace
    if workspace is None:
        return CheckResult(False, "INFRA: no workspace artifact was captured for this run")
    if task.workspace_template is None:
        return CheckResult(False, "INFRA: task has no workspace_template configured")

    import_error = _pytest_import_error(sys.executable)
    if import_error is not None:
        return CheckResult(False, import_error)

    error = _enforce_allowed_files(task, workspace)
    if error:
        return CheckResult(False, error)
    error = _enforce_forbidden_regex(task, workspace)
    if error:
        return CheckResult(False, error)

    baseline = _run_pytest(workspace)
    if baseline is None:
        return CheckResult(False, f"pytest exceeded the {_PYTEST_TIMEOUT_S:.0f}s timeout")
    if baseline.returncode != 0:
        return CheckResult(False, _pytest_failure_detail(baseline))

    mutants_dir = task.golden_dir / "mutants"
    if mutants_dir.is_dir():
        target_rel = (mutants_dir / "target.txt").read_text(encoding="utf-8").strip()
        target_path = workspace / target_rel
        original = target_path.read_bytes()
        try:
            for mutant_path in sorted(mutants_dir.glob("mutant_*.py")):
                target_path.write_bytes(mutant_path.read_bytes())
                result = _run_pytest(workspace)
                if result is None:
                    return CheckResult(
                        False,
                        f"pytest exceeded the {_PYTEST_TIMEOUT_S:.0f}s timeout while checking "
                        f"mutant {mutant_path.name!r}",
                    )
                if result.returncode == 0:
                    return CheckResult(
                        False,
                        f"tests still pass against mutant {mutant_path.name!r} "
                        "(mutation not detected)",
                    )
        finally:
            target_path.write_bytes(original)

    return CheckResult(True, "")


def _strip_trailing_ws(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.splitlines())


def _normalize_newlines_bytes(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def check_diff_golden(task: TaskSpec, artifacts: RunArtifacts) -> CheckResult:
    workspace = artifacts.workspace
    if workspace is None:
        return CheckResult(False, "INFRA: no workspace artifact was captured for this run")
    if task.workspace_template is None:
        return CheckResult(False, "INFRA: task has no workspace_template configured")
    if not task.allowed_files or len(task.allowed_files) != 1:
        return CheckResult(False, "INFRA: diff_golden requires exactly one entry in allowed_files")

    error = _enforce_allowed_files(task, workspace)
    if error:
        return CheckResult(False, error)
    error = _enforce_forbidden_regex(task, workspace)
    if error:
        return CheckResult(False, error)

    target_rel = task.allowed_files[0]
    workspace_target = workspace / target_rel
    if not workspace_target.exists():
        return CheckResult(False, f"expected file not found in workspace: {target_rel}")

    diff_golden_path = task.golden_dir / "expected.diff"
    if diff_golden_path.exists():
        template_target = task.workspace_template / target_rel
        before = template_target.read_text(encoding="utf-8") if template_target.exists() else ""
        after = workspace_target.read_text(encoding="utf-8")
        diff_text = "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile=target_rel,
                tofile=target_rel,
            )
        )
        actual = _strip_trailing_ws(diff_text)
        expected = _strip_trailing_ws(diff_golden_path.read_text(encoding="utf-8"))
        if actual == expected:
            return CheckResult(True, "")
        return CheckResult(
            False, f"diff for {target_rel} did not match golden/expected.diff:\n{actual}"
        )

    stem, suffix = Path(target_rel).stem, Path(target_rel).suffix
    content_golden_path = task.golden_dir / f"{stem}_expected{suffix}"
    if content_golden_path.exists():
        actual_bytes = _normalize_newlines_bytes(workspace_target.read_bytes())
        expected_bytes = _normalize_newlines_bytes(content_golden_path.read_bytes())
        if actual_bytes == expected_bytes:
            return CheckResult(True, "")
        return CheckResult(
            False, f"content of {target_rel} did not match {content_golden_path.name} byte-for-byte"
        )

    return CheckResult(
        False,
        f"INFRA: no golden comparison file found for {target_rel} (expected "
        f"golden/expected.diff or golden/{stem}_expected{suffix})",
    )


CHECKERS: dict[str, Callable[[TaskSpec, RunArtifacts], CheckResult]] = {
    "exact": check_exact,
    "json_schema": check_json_schema,
    "sql": check_sql,
    "pytest": check_pytest,
    "diff_golden": check_diff_golden,
}

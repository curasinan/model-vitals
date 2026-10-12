from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

import jsonschema
import pytest

from vitals.canary.checkers import (
    CHECKERS,
    RunArtifacts,
    TaskSpec,
    default_tasks_dir,
    load_tasks,
    suite_hash,
)

REAL_TASK_IDS = ["arith-exact", "format-follow", "json-extract", "regex-golden", "sql-golden"]

ALL_REAL_TASK_IDS = [
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
]


def _write_task_dir(
    tasks_dir: Path,
    task_id: str,
    checker: str,
    golden_text: str | None = None,
    schema: dict | None = None,
    golden_json: object | None = None,
    fixture_sql: str | None = None,
    rows: list | None = None,
    extra_toml: dict | None = None,
) -> Path:
    task_dir = tasks_dir / task_id
    golden_dir = task_dir / "golden"
    golden_dir.mkdir(parents=True)
    (task_dir / "prompt.md").write_text(f"Prompt for {task_id}.\n", encoding="utf-8")

    toml_lines = [f'task_id = "{task_id}"', f'checker = "{checker}"', "max_turns = 1"]
    for key, value in (extra_toml or {}).items():
        if isinstance(value, str):
            toml_lines.append(f'{key} = "{value}"')
        elif isinstance(value, bool):
            toml_lines.append(f"{key} = {str(value).lower()}")
        elif isinstance(value, list):
            rendered = ", ".join(f'"{v}"' for v in value)
            toml_lines.append(f"{key} = [{rendered}]")
        else:
            toml_lines.append(f"{key} = {value}")
    (task_dir / "task.toml").write_text("\n".join(toml_lines) + "\n", encoding="utf-8")

    if golden_text is not None:
        (golden_dir / "answer.txt").write_text(golden_text, encoding="utf-8")
    if schema is not None:
        (golden_dir / "schema.json").write_text(json.dumps(schema), encoding="utf-8")
    if golden_json is not None:
        (golden_dir / "expected.json").write_text(json.dumps(golden_json), encoding="utf-8")
    if fixture_sql is not None:
        (golden_dir / "fixture.sql").write_text(fixture_sql, encoding="utf-8")
    if rows is not None:
        (golden_dir / "rows.json").write_text(json.dumps(rows), encoding="utf-8")
    return task_dir


def _mk_task(
    tmp_path: Path,
    checker: str,
    golden_text: str | None = None,
    schema: dict | None = None,
    golden_json: object | None = None,
) -> TaskSpec:
    task_dir = _write_task_dir(
        tmp_path,
        "t",
        checker,
        golden_text=golden_text,
        schema=schema,
        golden_json=golden_json,
    )
    return TaskSpec(
        task_id="t",
        checker=checker,
        prompt="p",
        allowed_tools=[],
        max_turns=1,
        golden_dir=task_dir / "golden",
        json_schema=schema,
    )


_SQL_FIXTURE = (
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, name TEXT NOT NULL, total REAL NOT NULL);\n"
    "INSERT INTO orders (id, name, total) VALUES\n"
    "  (1, 'Alice', 150.0), (2, 'Bob', 50.0), (3, 'Carla', 200.0);\n"
)
_SQL_GOLDEN_ROWS = [["Alice", 150.0], ["Carla", 200.0]]


def _mk_task_sql(tmp_path: Path) -> TaskSpec:
    task_dir = _write_task_dir(
        tmp_path,
        "sqlt",
        "sql",
        fixture_sql=_SQL_FIXTURE,
        rows=_SQL_GOLDEN_ROWS,
    )
    return TaskSpec(
        task_id="sqlt",
        checker="sql",
        prompt="p",
        allowed_tools=[],
        max_turns=1,
        golden_dir=task_dir / "golden",
    )


def _fixture_suite(tmp_path: Path) -> Path:
    _write_task_dir(tmp_path, "arith-exact", "exact", golden_text="123\n")
    _write_task_dir(tmp_path, "other-task", "exact", golden_text="456\n")
    return tmp_path


def test_exact_checker_normalizes_whitespace(tmp_path):
    task = _mk_task(tmp_path, checker="exact", golden_text="429981696\n")
    ok = CHECKERS["exact"](task, RunArtifacts("  429981696 ", None, None))
    bad = CHECKERS["exact"](task, RunArtifacts("429981695", None, None))
    assert ok.passed and not bad.passed and "429981695" in bad.detail


def test_exact_checker_collapses_internal_whitespace(tmp_path):
    task = _mk_task(tmp_path, checker="exact", golden_text="hello   world\n")
    ok = CHECKERS["exact"](task, RunArtifacts("hello\nworld", None, None))
    assert ok.passed


def test_json_schema_checker_validates_and_compares(tmp_path):
    task = _mk_task(
        tmp_path,
        checker="json_schema",
        schema={
            "type": "object",
            "required": ["priority"],
            "properties": {"priority": {"type": "string"}},
            "additionalProperties": False,
        },
        golden_json={"priority": "high"},
    )
    ok = CHECKERS["json_schema"](task, RunArtifacts("", {"priority": "high"}, None))
    wrong = CHECKERS["json_schema"](task, RunArtifacts("", {"priority": "low"}, None))
    invalid = CHECKERS["json_schema"](task, RunArtifacts("", {"prio": 1}, None))
    assert ok.passed and not wrong.passed and not invalid.passed


def test_json_schema_checker_falls_back_to_fenced_block_in_result_text(tmp_path):
    task = _mk_task(
        tmp_path,
        checker="json_schema",
        schema={
            "type": "object",
            "required": ["priority"],
            "properties": {"priority": {"type": "string"}},
        },
        golden_json={"priority": "high"},
    )
    text = 'Here is the result:\n```json\n{"priority": "high"}\n```\n'
    ok = CHECKERS["json_schema"](task, RunArtifacts(text, None, None))
    assert ok.passed


def test_json_schema_checker_unparseable_output_fails_cleanly(tmp_path):
    task = _mk_task(
        tmp_path,
        checker="json_schema",
        schema={"type": "object"},
        golden_json={"priority": "high"},
    )
    bad = CHECKERS["json_schema"](task, RunArtifacts("not json at all", None, None))
    assert not bad.passed


def test_sql_checker_rowset_equality(tmp_path):
    task = _mk_task_sql(tmp_path)
    ok = CHECKERS["sql"](
        task,
        RunArtifacts("SELECT name, total FROM orders WHERE total > 100 ORDER BY name", None, None),
    )
    assert ok.passed


def test_sql_checker_wrong_rows_fails(tmp_path):
    task = _mk_task_sql(tmp_path)
    bad = CHECKERS["sql"](
        task,
        RunArtifacts("SELECT name, total FROM orders WHERE total > 40 ORDER BY name", None, None),
    )
    assert not bad.passed


def test_sql_checker_rejects_non_select(tmp_path):
    task = _mk_task_sql(tmp_path)
    bad = CHECKERS["sql"](task, RunArtifacts("DELETE FROM orders", None, None))
    assert not bad.passed


def test_sql_checker_rejects_multiple_statements(tmp_path):
    task = _mk_task_sql(tmp_path)
    bad = CHECKERS["sql"](
        task,
        RunArtifacts("SELECT 1; DROP TABLE orders", None, None),
    )
    assert not bad.passed


def test_sql_checker_strips_markdown_fence(tmp_path):
    task = _mk_task_sql(tmp_path)
    ok = CHECKERS["sql"](
        task,
        RunArtifacts(
            "```sql\nSELECT name, total FROM orders WHERE total > 100 ORDER BY name\n```",
            None,
            None,
        ),
    )
    assert ok.passed


def test_sql_checker_rejects_incomplete_statement(tmp_path):
    task = _mk_task_sql(tmp_path)
    bad = CHECKERS["sql"](
        task, RunArtifacts("SELECT * FROM orders WHERE name = 'unterminated", None, None)
    )
    assert not bad.passed


def test_sql_checker_accepts_leading_with_cte(tmp_path):
    task = _mk_task_sql(tmp_path)
    cte_query = (
        "WITH big AS (SELECT name, total FROM orders WHERE total > 100) "
        "SELECT name, total FROM big ORDER BY name"
    )
    ok = CHECKERS["sql"](task, RunArtifacts(cte_query, None, None))
    assert ok.passed


def test_sql_checker_rejects_drop_table_single_statement(tmp_path):
    task = _mk_task_sql(tmp_path)
    bad = CHECKERS["sql"](task, RunArtifacts("DROP TABLE orders", None, None))
    assert not bad.passed


def test_sql_checker_rejects_pragma(tmp_path):
    task = _mk_task_sql(tmp_path)
    bad = CHECKERS["sql"](task, RunArtifacts("PRAGMA table_info(orders)", None, None))
    assert not bad.passed


def test_sql_checker_rejects_with_clause_hiding_a_write(tmp_path):
    task = _mk_task_sql(tmp_path)
    bad = CHECKERS["sql"](
        task, RunArtifacts("WITH big AS (SELECT 1) DELETE FROM orders", None, None)
    )
    assert not bad.passed


def test_real_sql_golden_task_accepts_cte_form_answer():
    task = _real_task("sql-golden")
    cte_query = (
        "WITH big_orders AS (\n"
        "    SELECT name, total FROM orders WHERE total > 100\n"
        ")\n"
        "SELECT name, total FROM big_orders ORDER BY name"
    )
    ok = CHECKERS["sql"](task, RunArtifacts(cte_query, None, None))
    assert ok.passed


def test_pytest_and_diff_golden_report_infra_failure_without_a_workspace(tmp_path):
    task = _mk_task(tmp_path, checker="pytest")
    pytest_result = CHECKERS["pytest"](task, RunArtifacts("", None, None))
    diff_result = CHECKERS["diff_golden"](task, RunArtifacts("", None, None))
    assert not pytest_result.passed and pytest_result.detail.startswith("INFRA:")
    assert not diff_result.passed and diff_result.detail.startswith("INFRA:")


def test_load_tasks_parses_toml_and_defaults(tmp_path):
    _write_task_dir(tmp_path, "arith-exact", "exact", golden_text="1\n")
    tasks = load_tasks(tmp_path)
    assert len(tasks) == 1
    task = tasks[0]
    assert task.task_id == "arith-exact"
    assert task.checker == "exact"
    assert task.prompt == "Prompt for arith-exact.\n"
    assert task.allowed_tools == []
    assert task.max_turns == 1
    assert task.per_run_budget_usd is None
    assert task.per_run_timeout_s is None
    assert task.long_context is False
    assert task.allowed_files is None
    assert task.forbidden_regex is None
    assert task.workspace_template is None
    assert task.json_schema is None
    assert task.golden_dir == tmp_path / "arith-exact" / "golden"


def test_load_tasks_reads_explicit_overrides(tmp_path):
    _write_task_dir(
        tmp_path,
        "rename-py",
        "diff_golden",
        golden_text="ok\n",
        extra_toml={
            "per_run_budget_usd": 0.25,
            "per_run_timeout_s": 900,
            "long_context": True,
            "allowed_files": ["a.py", "b.py"],
            "forbidden_regex": "old_name",
        },
    )
    tasks = load_tasks(tmp_path)
    task = tasks[0]
    assert task.per_run_budget_usd == 0.25
    assert task.per_run_timeout_s == 900
    assert task.long_context is True
    assert task.allowed_files == ["a.py", "b.py"]
    assert task.forbidden_regex == "old_name"


def test_load_tasks_sorted_by_task_id(tmp_path):
    _write_task_dir(tmp_path, "zzz-task", "exact", golden_text="1\n")
    _write_task_dir(tmp_path, "aaa-task", "exact", golden_text="1\n")
    tasks = load_tasks(tmp_path)
    assert [t.task_id for t in tasks] == ["aaa-task", "zzz-task"]


def test_load_tasks_missing_required_key_raises(tmp_path):
    task_dir = tmp_path / "broken"
    (task_dir / "golden").mkdir(parents=True)
    (task_dir / "prompt.md").write_text("hi", encoding="utf-8")
    (task_dir / "task.toml").write_text('checker = "exact"\n', encoding="utf-8")
    with pytest.raises(ValueError):
        load_tasks(tmp_path)


def test_suite_hash_changes_when_golden_changes(tmp_path):
    tasks = load_tasks(_fixture_suite(tmp_path))
    h1 = suite_hash(tasks)
    (tmp_path / "arith-exact" / "golden" / "answer.txt").write_text("different")
    h2 = suite_hash(load_tasks(tmp_path))
    assert h1 != h2


def test_suite_hash_stable_when_nothing_changes(tmp_path):
    tasks_dir = _fixture_suite(tmp_path)
    h1 = suite_hash(load_tasks(tasks_dir))
    h2 = suite_hash(load_tasks(tasks_dir))
    assert h1 == h2


def test_suite_hash_changes_when_prompt_changes(tmp_path):
    tasks_dir = _fixture_suite(tmp_path)
    h1 = suite_hash(load_tasks(tasks_dir))
    (tasks_dir / "arith-exact" / "prompt.md").write_text("a different prompt\n", encoding="utf-8")
    h2 = suite_hash(load_tasks(tasks_dir))
    assert h1 != h2


def test_default_tasks_dir_resolves_and_loads_all_twelve_tasks():
    tasks_dir = default_tasks_dir()
    assert tasks_dir.is_dir()
    tasks = load_tasks(tasks_dir)
    assert [t.task_id for t in tasks] == ALL_REAL_TASK_IDS


def _real_task(task_id: str) -> TaskSpec:
    tasks = {t.task_id: t for t in load_tasks(default_tasks_dir())}
    return tasks[task_id]


def test_real_arith_exact_task_golden_is_the_true_answer():
    task = _real_task("arith-exact")
    assert task.checker == "exact"
    true_answer = 12 * 34 + 56 * 789 - 1011
    golden_text = (task.golden_dir / "answer.txt").read_text(encoding="utf-8").strip()
    assert golden_text == str(true_answer)
    ok = CHECKERS["exact"](task, RunArtifacts(str(true_answer), None, None))
    bad = CHECKERS["exact"](task, RunArtifacts(str(true_answer + 1), None, None))
    assert ok.passed and not bad.passed


def test_real_json_extract_task_golden_matches_schema_and_ticket():
    task = _real_task("json-extract")
    assert task.checker == "json_schema"
    schema = json.loads((task.golden_dir / "schema.json").read_text(encoding="utf-8"))
    golden = json.loads((task.golden_dir / "expected.json").read_text(encoding="utf-8"))
    jsonschema.validate(golden, schema)
    ticket_lines = [line for line in task.prompt.splitlines() if line.startswith("Ticket #")]
    assert ticket_lines
    ok = CHECKERS["json_schema"](task, RunArtifacts("", golden, None))
    assert ok.passed
    wrong = CHECKERS["json_schema"](task, RunArtifacts("", {**golden, "priority": "low"}, None))
    assert not wrong.passed
    assert golden["sla_breach"] is True
    assert golden["priority"] == "high"


def test_real_regex_golden_task_answer_matches_recomputed_pattern():
    task = _real_task("regex-golden")
    assert task.checker == "exact"
    cases = json.loads((task.golden_dir / "cases.json").read_text(encoding="utf-8"))
    pattern = cases["pattern"]
    recomputed = "".join("Y" if re.fullmatch(pattern, c) else "N" for c in cases["inputs"])
    assert len(cases["inputs"]) == 12
    golden_text = (task.golden_dir / "answer.txt").read_text(encoding="utf-8").strip()
    assert recomputed == golden_text
    ok = CHECKERS["exact"](task, RunArtifacts(recomputed, None, None))
    assert ok.passed


def test_real_sql_golden_task_fixture_has_eight_rows_and_correct_golden():
    task = _real_task("sql-golden")
    assert task.checker == "sql"
    fixture_sql = (task.golden_dir / "fixture.sql").read_text(encoding="utf-8")
    conn = sqlite3.connect(":memory:")
    conn.executescript(fixture_sql)
    (count,) = conn.execute("SELECT COUNT(*) FROM orders").fetchone()
    assert count == 8
    conn.close()

    correct_query = "SELECT name, total FROM orders WHERE total > 100 ORDER BY name"
    ok = CHECKERS["sql"](task, RunArtifacts(correct_query, None, None))
    assert ok.passed
    bad = CHECKERS["sql"](
        task, RunArtifacts("SELECT name, total FROM orders WHERE total > 1000000", None, None)
    )
    assert not bad.passed


def test_real_format_follow_task_golden_is_five_lines_and_exact():
    task = _real_task("format-follow")
    assert task.checker == "exact"
    golden_text = (task.golden_dir / "answer.txt").read_text(encoding="utf-8").strip("\n")
    lines = golden_text.split("\n")
    assert len(lines) == 5
    ok = CHECKERS["exact"](task, RunArtifacts(golden_text, None, None))
    assert ok.passed
    mutated = golden_text.replace(lines[-1], "DUE: 1999-01-01")
    bad = CHECKERS["exact"](task, RunArtifacts(mutated, None, None))
    assert not bad.passed


def test_all_five_real_tasks_are_cheap_single_shot():
    for task_id in REAL_TASK_IDS:
        task = _real_task(task_id)
        assert task.long_context is False
        assert task.max_turns == 1


def test_format_follow_omits_budget_override_to_use_canary_default():
    task = _real_task("format-follow")
    assert task.per_run_budget_usd is None
    assert task.per_run_timeout_s is None


def test_arith_exact_golden_satisfies_prompt_structural_rules():
    task = _real_task("arith-exact")
    assert "no thousands separators" in task.prompt
    golden = (task.golden_dir / "answer.txt").read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"-?\d+", golden)


def test_regex_golden_golden_satisfies_prompt_structural_rules():
    task = _real_task("regex-golden")
    assert "exactly 12 characters" in task.prompt
    golden = (task.golden_dir / "answer.txt").read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"[YN]{12}", golden)


def test_format_follow_golden_satisfies_prompt_structural_rules():
    task = _real_task("format-follow")
    prompt = task.prompt
    golden = (task.golden_dir / "answer.txt").read_text(encoding="utf-8").strip("\n")
    lines = golden.split("\n")

    assert len(lines) == 5

    field_prefixes = ["DATE: ", "ATTENDEES: ", "DECISION: ", "ACTION_OWNER: ", "DUE: "]
    for prefix, line in zip(field_prefixes, lines):
        assert prefix.strip() in prompt, f"prompt must actually name the {prefix!r} field"
        assert line.startswith(prefix), f"golden line {line!r} must start with {prefix!r}"

    date_re = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    assert date_re.match(lines[0][len("DATE: ") :]), "DATE must be YYYY-MM-DD per the prompt"
    assert lines[1][len("ATTENDEES: ") :].isdigit(), "ATTENDEES must be a plain integer"

    decision_body = lines[2][len("DECISION: ") :]
    assert decision_body.endswith("."), "DECISION must end with a single period"
    assert decision_body[0].isupper(), "DECISION must be capitalized per the transform rule"
    assert not re.search(r"\bdecided\b|\bwe\b", decision_body, re.IGNORECASE), (
        "the prompt explicitly forbids 'decided'/'we' anywhere in the DECISION line — this is "
        "the exact rule that was missing when the golden and prompt could both independently "
        "satisfy a looser reading and still disagree with each other"
    )

    assert lines[3][len("ACTION_OWNER: ") :].strip(), "ACTION_OWNER must not be empty"
    assert date_re.match(lines[4][len("DUE: ") :]), "DUE must be YYYY-MM-DD per the prompt"

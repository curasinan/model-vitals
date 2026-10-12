from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from vitals.canary.checkers import CHECKERS, RunArtifacts, TaskSpec, default_tasks_dir, load_tasks

REAL_WORKSPACE_TASK_IDS = ["bugfix-py", "diff-golden", "rename-py", "test-writing", "tool-sequence"]

CHECKERS_PYTEST = CHECKERS["pytest"]
CHECKERS_DIFF = CHECKERS["diff_golden"]


pytestmark = pytest.mark.slow


def _real_task(task_id: str) -> TaskSpec:
    tasks = {t.task_id: t for t in load_tasks(default_tasks_dir())}
    return tasks[task_id]


def _make_workspace(task: TaskSpec, tmp_path: Path) -> Path:
    dest = tmp_path / "workspace"
    shutil.copytree(task.workspace_template, dest)
    return dest


def _artifacts(workspace: Path) -> RunArtifacts:
    return RunArtifacts(result_text="", structured_output=None, workspace=workspace)


def test_all_five_workspace_tasks_load_with_expected_shape():
    tasks = {t.task_id: t for t in load_tasks(default_tasks_dir())}
    for task_id in REAL_WORKSPACE_TASK_IDS:
        task = tasks[task_id]
        assert task.workspace_template is not None
        assert task.workspace_template.is_dir()
        assert task.checker in ("pytest", "diff_golden")


def test_bugfix_py_and_rename_py_demonstrate_each_enforcement_mechanism():
    bugfix = _real_task("bugfix-py")
    rename = _real_task("rename-py")
    assert bugfix.allowed_files == ["invoicer/totals.py"]
    assert bugfix.forbidden_regex is None
    assert rename.forbidden_regex == "haversine_km"
    assert rename.allowed_files is None


def test_bugfix_py_unfixed_template_has_exactly_one_failing_test(tmp_path):
    task = _real_task("bugfix-py")
    workspace = _make_workspace(task, tmp_path)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert "1 failed" in result.stdout
    assert "test_tax_cents_rounds_up_at_half_cent_boundary" in result.stdout


def test_bugfix_py_checker_fails_on_unfixed_workspace(tmp_path):
    task = _real_task("bugfix-py")
    workspace = _make_workspace(task, tmp_path)
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert not result.passed


def test_bugfix_py_checker_passes_once_golden_fix_applied(tmp_path):
    task = _real_task("bugfix-py")
    workspace = _make_workspace(task, tmp_path)
    fixed = (task.golden_dir / "solved" / "invoicer" / "totals.py").read_text(encoding="utf-8")
    (workspace / "invoicer" / "totals.py").write_text(fixed, encoding="utf-8")
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert result.passed, result.detail


def test_bugfix_py_checker_fails_when_fix_corrupted_back_to_buggy(tmp_path):
    task = _real_task("bugfix-py")
    workspace = _make_workspace(task, tmp_path)
    fixed = (task.golden_dir / "solved" / "invoicer" / "totals.py").read_text(encoding="utf-8")
    (workspace / "invoicer" / "totals.py").write_text(fixed, encoding="utf-8")
    corrupted = fixed.replace("(numerator + 5000) // 10000", "numerator // 10000")
    (workspace / "invoicer" / "totals.py").write_text(corrupted, encoding="utf-8")
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert not result.passed


def test_bugfix_py_checker_fails_when_edit_touches_a_file_outside_allowed_files(tmp_path):
    task = _real_task("bugfix-py")
    workspace = _make_workspace(task, tmp_path)
    fixed = (task.golden_dir / "solved" / "invoicer" / "totals.py").read_text(encoding="utf-8")
    (workspace / "invoicer" / "totals.py").write_text(fixed, encoding="utf-8")
    (workspace / "invoicer" / "models.py").write_text(
        (workspace / "invoicer" / "models.py").read_text(encoding="utf-8") + "\n# unrelated edit\n",
        encoding="utf-8",
    )
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert not result.passed
    assert "invoicer/models.py" in result.detail


def test_rename_py_checker_fails_on_unrenamed_workspace(tmp_path):
    task = _real_task("rename-py")
    workspace = _make_workspace(task, tmp_path)
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert not result.passed


def test_rename_py_checker_passes_once_golden_rename_applied(tmp_path):
    task = _real_task("rename-py")
    workspace = _make_workspace(task, tmp_path)
    solved = task.golden_dir / "solved" / "geo"
    for name in ("distance.py", "routes.py", "cli.py"):
        shutil.copy(solved / name, workspace / "geo" / name)
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert result.passed, result.detail


def test_rename_py_checker_fails_when_one_file_left_unrenamed(tmp_path):
    task = _real_task("rename-py")
    workspace = _make_workspace(task, tmp_path)
    solved = task.golden_dir / "solved" / "geo"
    shutil.copy(solved / "distance.py", workspace / "geo" / "distance.py")
    shutil.copy(solved / "routes.py", workspace / "geo" / "routes.py")
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert not result.passed
    assert "haversine_km" in result.detail
    assert "cli.py" in result.detail


def test_test_writing_checker_passes_with_golden_solved_test_file(tmp_path):
    task = _real_task("test-writing")
    workspace = _make_workspace(task, tmp_path)
    solved = (task.golden_dir / "solved" / "test_slugify.py").read_text(encoding="utf-8")
    (workspace / "test_slugify.py").write_text(solved, encoding="utf-8")
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert result.passed, result.detail


def test_test_writing_checker_fails_with_no_test_file_at_all(tmp_path):
    task = _real_task("test-writing")
    workspace = _make_workspace(task, tmp_path)
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert not result.passed


def test_test_writing_checker_fails_when_weak_tests_dont_catch_mutants(tmp_path):
    weak = """\
from slugify import slugify


def test_returns_nonempty_string_for_normal_text():
    result = slugify("Hello World")
    assert isinstance(result, str)
    assert result != ""


def test_no_leading_or_trailing_separator():
    result = slugify("--Hello World--")
    assert not result.startswith("-")
    assert not result.endswith("-")
"""
    task = _real_task("test-writing")
    workspace = _make_workspace(task, tmp_path)
    (workspace / "test_slugify.py").write_text(weak, encoding="utf-8")
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert not result.passed
    assert "mutation not detected" in result.detail


def test_test_writing_checker_restores_the_module_after_mutation_testing(tmp_path):
    task = _real_task("test-writing")
    workspace = _make_workspace(task, tmp_path)
    solved = (task.golden_dir / "solved" / "test_slugify.py").read_text(encoding="utf-8")
    (workspace / "test_slugify.py").write_text(solved, encoding="utf-8")
    original = (workspace / "slugify.py").read_text(encoding="utf-8")
    CHECKERS_PYTEST(task, _artifacts(workspace))
    assert (workspace / "slugify.py").read_text(encoding="utf-8") == original


def test_test_writing_checker_fails_when_slugify_itself_is_edited(tmp_path):
    task = _real_task("test-writing")
    workspace = _make_workspace(task, tmp_path)
    solved = (task.golden_dir / "solved" / "test_slugify.py").read_text(encoding="utf-8")
    (workspace / "test_slugify.py").write_text(solved, encoding="utf-8")
    (workspace / "slugify.py").write_text(
        (workspace / "slugify.py").read_text(encoding="utf-8") + "\n# cheating edit\n",
        encoding="utf-8",
    )
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert not result.passed
    assert "slugify.py" in result.detail


def test_tool_sequence_checker_passes_when_gen_output_piped_correctly(tmp_path):
    task = _real_task("tool-sequence")
    workspace = _make_workspace(task, tmp_path)
    out_dir = workspace / "out"
    out_dir.mkdir()
    result = subprocess.run(
        [sys.executable, str(workspace / "gen.py")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    (out_dir / "b.txt").write_text(result.stdout, encoding="utf-8")
    verdict = CHECKERS_DIFF(task, _artifacts(workspace))
    assert verdict.passed, verdict.detail


def test_tool_sequence_checker_fails_on_wrong_content(tmp_path):
    task = _real_task("tool-sequence")
    workspace = _make_workspace(task, tmp_path)
    out_dir = workspace / "out"
    out_dir.mkdir()
    (out_dir / "b.txt").write_text("not the right table\n", encoding="utf-8")
    verdict = CHECKERS_DIFF(task, _artifacts(workspace))
    assert not verdict.passed


def test_tool_sequence_checker_fails_when_gen_py_itself_is_modified(tmp_path):
    task = _real_task("tool-sequence")
    workspace = _make_workspace(task, tmp_path)
    out_dir = workspace / "out"
    out_dir.mkdir()
    (out_dir / "b.txt").write_text(
        (task.golden_dir / "b_expected.txt").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (workspace / "gen.py").write_text(
        (workspace / "gen.py").read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8"
    )
    verdict = CHECKERS_DIFF(task, _artifacts(workspace))
    assert not verdict.passed
    assert "gen.py" in verdict.detail


def test_gen_py_prints_byte_identical_output_across_runs(tmp_path):
    task = _real_task("tool-sequence")
    gen = task.workspace_template / "gen.py"
    runs = [
        subprocess.run([sys.executable, str(gen)], capture_output=True, timeout=30).stdout
        for _ in range(3)
    ]
    assert runs[0] == runs[1] == runs[2]
    assert runs[0]


def test_diff_golden_checker_passes_with_the_expected_conversion(tmp_path):
    task = _real_task("diff-golden")
    workspace = _make_workspace(task, tmp_path)
    solved = (task.golden_dir / "solved" / "report.py").read_text(encoding="utf-8")
    (workspace / "report.py").write_text(solved, encoding="utf-8")
    result = CHECKERS_DIFF(task, _artifacts(workspace))
    assert result.passed, result.detail


def test_diff_golden_checker_fails_when_unconverted(tmp_path):
    task = _real_task("diff-golden")
    workspace = _make_workspace(task, tmp_path)
    result = CHECKERS_DIFF(task, _artifacts(workspace))
    assert not result.passed


def test_diff_golden_checker_fails_with_extra_change_to_a_second_file_named_in_detail(tmp_path):
    task = _real_task("diff-golden")
    workspace = _make_workspace(task, tmp_path)
    solved = (task.golden_dir / "solved" / "report.py").read_text(encoding="utf-8")
    (workspace / "report.py").write_text(solved, encoding="utf-8")
    (workspace / "extra.py").write_text("x = 1\n", encoding="utf-8")
    result = CHECKERS_DIFF(task, _artifacts(workspace))
    assert not result.passed
    assert "extra.py" in result.detail


def test_diff_golden_checker_behavioral_equivalence_of_the_six_conversions(tmp_path):
    import importlib.util

    task = _real_task("diff-golden")

    def _load(path: Path, name: str):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        previous = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            spec.loader.exec_module(module)
        finally:
            sys.dont_write_bytecode = previous
        return module

    old = _load(task.workspace_template / "report.py", "old_report")
    new = _load(task.golden_dir / "solved" / "report.py", "new_report")
    cases = [
        ("render_header", ("proj", 42)),
        ("render_summary", (3, 1, 2)),
        ("render_duration", (12.3456,)),
        ("render_percentage", (3, 6)),
        ("render_percentage", (0, 0)),
        ("render_footer", ("alice",)),
        ("render_failure_line", ("test_x", 17)),
    ]
    for fname, args in cases:
        assert getattr(old, fname)(*args) == getattr(new, fname)(*args)


def test_pytest_checker_reports_infra_when_no_workspace_captured():
    task = _real_task("bugfix-py")
    result = CHECKERS_PYTEST(task, RunArtifacts("", None, None))
    assert not result.passed
    assert result.detail.startswith("INFRA:")


def test_diff_golden_checker_reports_infra_when_no_workspace_captured():
    task = _real_task("diff-golden")
    result = CHECKERS_DIFF(task, RunArtifacts("", None, None))
    assert not result.passed
    assert result.detail.startswith("INFRA:")


def test_pytest_checker_reports_infra_when_interpreter_cannot_import_pytest(tmp_path, monkeypatch):
    import vitals.canary.checkers as checkers_module

    task = _real_task("bugfix-py")
    workspace = _make_workspace(task, tmp_path)
    monkeypatch.setattr(checkers_module.sys, "executable", "definitely-not-a-real-interpreter")
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert not result.passed
    assert result.detail.startswith("INFRA:")
    assert "definitely-not-a-real-interpreter" in result.detail


def _mk_synthetic_pytest_task(tmp_path: Path, allowed_files=None, forbidden_regex=None) -> TaskSpec:
    template = tmp_path / "template"
    (template / "pkg").mkdir(parents=True)
    (template / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (template / "pkg" / "mod.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (template / "test_mod.py").write_text(
        "from pkg.mod import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n",
        encoding="utf-8",
    )
    golden_dir = tmp_path / "golden"
    golden_dir.mkdir()
    return TaskSpec(
        task_id="synthetic-pytest",
        checker="pytest",
        prompt="synthetic",
        allowed_tools=[],
        max_turns=1,
        golden_dir=golden_dir,
        workspace_template=template,
        allowed_files=allowed_files,
        forbidden_regex=forbidden_regex,
    )


def test_synthetic_pytest_task_passes_when_untouched(tmp_path):
    task = _mk_synthetic_pytest_task(tmp_path)
    workspace = _make_workspace(task, tmp_path)
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert result.passed, result.detail


def test_synthetic_allowed_files_blocks_edits_outside_the_list(tmp_path):
    task = _mk_synthetic_pytest_task(tmp_path, allowed_files=["pkg/mod.py"])
    workspace = _make_workspace(task, tmp_path)
    (workspace / "test_mod.py").write_text(
        (workspace / "test_mod.py").read_text(encoding="utf-8") + "\n# edited\n", encoding="utf-8"
    )
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert not result.passed
    assert "test_mod.py" in result.detail


def test_synthetic_forbidden_regex_blocks_a_leftover_reference(tmp_path):
    task = _mk_synthetic_pytest_task(tmp_path, forbidden_regex="TODO_REMOVE_ME")
    workspace = _make_workspace(task, tmp_path)
    (workspace / "pkg" / "mod.py").write_text(
        (workspace / "pkg" / "mod.py").read_text(encoding="utf-8") + "\n# TODO_REMOVE_ME\n",
        encoding="utf-8",
    )
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert not result.passed
    assert "TODO_REMOVE_ME" in result.detail
    assert "mod.py" in result.detail


def test_synthetic_pytest_checker_detects_hanging_test_via_timeout(tmp_path, monkeypatch):
    import vitals.canary.checkers as checkers_module

    task = _mk_synthetic_pytest_task(tmp_path)
    workspace = _make_workspace(task, tmp_path)
    monkeypatch.setattr(checkers_module, "_PYTEST_TIMEOUT_S", 0.01)
    (workspace / "test_mod.py").write_text(
        "import time\n\n\ndef test_slow():\n    time.sleep(5)\n", encoding="utf-8"
    )
    result = CHECKERS_PYTEST(task, _artifacts(workspace))
    assert not result.passed
    assert "timeout" in result.detail
    assert not result.detail.startswith("INFRA:")

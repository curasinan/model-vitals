from __future__ import annotations

import ast
import hashlib
import re

from vitals.canary.checkers import CHECKERS, RunArtifacts, TaskSpec, default_tasks_dir, load_tasks
from vitals.canary.longctx import (
    EDIT_CONST_NAME,
    EDIT_NEW_VALUE,
    EDIT_OLD_VALUE,
    EDIT_SEED,
    EDIT_TARGET_LINES,
    NEEDLE_SEED,
    format_expected_answer,
    generate_log,
    generate_module,
    planted_answers,
    solved_module,
)


def test_generate_log_is_byte_identical_across_calls():
    first = generate_log(1)
    second = generate_log(1)
    assert (
        hashlib.sha256(first.encode("utf-8")).hexdigest()
        == hashlib.sha256(second.encode("utf-8")).hexdigest()
    )

    estimated_tokens = len(first) / 4
    assert 90_000 <= estimated_tokens <= 115_000, estimated_tokens


def test_generate_log_different_seeds_diverge():
    assert generate_log(1, target_tokens=2_000) != generate_log(2, target_tokens=2_000)


def test_generate_log_never_touches_global_random_state():
    import random

    random.seed(12345)
    state_before = random.getstate()
    generate_log(1, target_tokens=2_000)
    assert random.getstate() == state_before


def test_planted_answers_appear_verbatim_in_the_generated_log():
    seed = 1
    target_tokens = 4_000
    log = generate_log(seed, target_tokens=target_tokens)
    answers = planted_answers(seed, target_tokens=target_tokens)

    assert len(answers["orders"]) == 3
    for order in answers["orders"]:
        needle = f"order={order['id']} status={order['status']}"
        assert needle in log

    assert answers["error_count"] >= 0
    assert isinstance(answers["error_class"], str)


def test_planted_answers_derived_from_same_generation_not_hand_copied():
    seed, target_tokens = 7, 3_000
    a1 = planted_answers(seed, target_tokens=target_tokens)
    a2 = planted_answers(seed, target_tokens=target_tokens)
    assert a1 == a2

    log = generate_log(seed, target_tokens=target_tokens)
    for order in a1["orders"]:
        assert log.count(order["id"]) == 1, "target order id must appear exactly once"


def test_target_order_ids_are_unique_needles_no_accidental_duplicate():
    seed, target_tokens = 1, 6_000
    log = generate_log(seed, target_tokens=target_tokens)
    answers = planted_answers(seed, target_tokens=target_tokens)
    ids = [o["id"] for o in answers["orders"]]
    assert len(set(ids)) == 3
    for oid in ids:
        assert log.count(oid) == 1, f"{oid} must be a genuinely unique needle in the log"


def test_error_count_matches_independent_regex_count_of_the_same_text():
    seed, target_tokens = 3, 8_000
    log = generate_log(seed, target_tokens=target_tokens)
    answers = planted_answers(seed, target_tokens=target_tokens)
    pattern = re.compile(r"class=" + re.escape(answers["error_class"]) + r"\b")
    assert len(pattern.findall(log)) == answers["error_count"]


def test_config_rotated_event_planted_exactly_once():
    seed, target_tokens = 1, 5_000
    log = generate_log(seed, target_tokens=target_tokens)
    assert log.count("CONFIG_ROTATED") == 1


def test_planted_fact_depths_within_tolerance():
    seed, target_tokens = 1, 20_000
    log = generate_log(seed, target_tokens=target_tokens)
    answers = planted_answers(seed, target_tokens=target_tokens)
    total_len = len(log)

    targets = [0.10, 0.50, 0.90]
    for order, target_depth in zip(answers["orders"], targets):
        needle = f"order={order['id']} status={order['status']}"
        offset = log.index(needle)
        depth = offset / total_len
        assert abs(depth - target_depth) <= 0.05, (order["id"], depth, target_depth)


def test_format_expected_answer_matches_exact_checker(tmp_path):
    seed, target_tokens = 1, 3_000
    answers = planted_answers(seed, target_tokens=target_tokens)
    text = format_expected_answer(answers)
    lines = text.strip("\n").split("\n")
    assert len(lines) == 4
    for order, line in zip(answers["orders"], lines[:3]):
        assert line == f"{order['id']}: {order['status']}"
    assert lines[3] == f"{answers['error_class']}: {answers['error_count']}"

    golden_dir = tmp_path / "golden"
    golden_dir.mkdir()
    (golden_dir / "answer.txt").write_text(text, encoding="utf-8")
    task = TaskSpec(
        task_id="t",
        checker="exact",
        prompt="p",
        allowed_tools=[],
        max_turns=1,
        golden_dir=golden_dir,
    )
    ok = CHECKERS["exact"](task, RunArtifacts(text, None, None))
    assert ok.passed


def test_generate_module_is_byte_identical_across_calls():
    first = generate_module(EDIT_SEED, target_lines=300)
    second = generate_module(EDIT_SEED, target_lines=300)
    assert first == second


def test_generate_module_is_valid_python():
    text = generate_module(EDIT_SEED, target_lines=300)
    ast.parse(text)


def test_solved_module_is_valid_python():
    text = solved_module(EDIT_SEED, target_lines=300)
    ast.parse(text)


def test_constant_definition_and_exactly_three_marked_usages():
    text = generate_module(EDIT_SEED, target_lines=300)
    assert text.count(f"{EDIT_CONST_NAME} = {EDIT_OLD_VALUE}") == 1
    assert text.count(f"# {EDIT_CONST_NAME}") == 3


def test_generate_and_solved_module_differ_in_exactly_four_lines():
    before = generate_module(EDIT_SEED, target_lines=300).splitlines()
    after = solved_module(EDIT_SEED, target_lines=300).splitlines()
    assert len(before) == len(after)
    diff_indices = [i for i, (b, a) in enumerate(zip(before, after)) if b != a]
    assert len(diff_indices) == 4
    for i in diff_indices:
        assert str(EDIT_OLD_VALUE) in before[i]
        assert str(EDIT_NEW_VALUE) in after[i]
        assert before[i].startswith(f"{EDIT_CONST_NAME} = ") or f"# {EDIT_CONST_NAME}" in before[i]


def test_generate_module_reaches_target_line_count_approximately():
    text = generate_module(EDIT_SEED, target_lines=3_000)
    lines = text.splitlines()
    assert 3_000 <= len(lines) <= 3_100


def _real_task(task_id: str) -> TaskSpec:
    tasks = {t.task_id: t for t in load_tasks(default_tasks_dir())}
    return tasks[task_id]


def test_real_longctx_needle_task_shape():
    task = _real_task("longctx-needle")
    assert task.checker == "exact"
    assert task.long_context is True
    assert task.per_run_timeout_s == 900
    assert task.per_run_budget_usd == 1.50
    assert "{LOG}" in task.prompt


def test_real_longctx_needle_golden_matches_planted_answers_not_hand_transcribed():
    task = _real_task("longctx-needle")
    answers = planted_answers(NEEDLE_SEED)
    expected_text = format_expected_answer(answers)
    golden_text = (task.golden_dir / "answer.txt").read_text(encoding="utf-8")
    assert golden_text.strip("\n") == expected_text.strip("\n")

    filled_prompt = task.prompt.replace("{LOG}", generate_log(NEEDLE_SEED))
    assert "{LOG}" not in filled_prompt
    for order in answers["orders"]:
        assert order["id"] in filled_prompt

    ok = CHECKERS["exact"](task, RunArtifacts(expected_text, None, None))
    assert ok.passed
    bad = CHECKERS["exact"](task, RunArtifacts(expected_text + "\nextra line", None, None))
    assert bad.passed is False


def test_real_longctx_needle_prompt_and_golden_agree_on_structural_rules():
    task = _real_task("longctx-needle")
    prompt = task.prompt
    golden = task.golden_dir.joinpath("answer.txt").read_text(encoding="utf-8").strip("\n")
    lines = golden.split("\n")
    assert len(lines) == 4

    order_lines, error_line = lines[:3], lines[3]
    status_re = re.compile(r"^ORDER-\d{6}: [A-Z]+$")
    for line in order_lines:
        assert status_re.match(line), line
        order_id = line.split(":")[0]
        assert order_id in prompt, f"prompt must literally ask about {order_id}"

    assert re.match(r"^PaymentGatewayTimeout: \d+$", error_line), error_line
    assert "PaymentGatewayTimeout" in prompt


def test_real_longctx_edit_task_shape():
    task = _real_task("longctx-edit")
    assert task.checker == "diff_golden"
    assert task.long_context is True
    assert task.per_run_timeout_s == 900
    assert task.per_run_budget_usd == 1.50
    assert task.allowed_files == ["module.py"]
    assert task.workspace_template is not None


def test_real_longctx_edit_workspace_and_golden_match_generator_not_hand_transcribed():
    task = _real_task("longctx-edit")
    workspace_module = (task.workspace_template / "module.py").read_text(encoding="utf-8")
    golden_module = (task.golden_dir / "module_expected.py").read_text(encoding="utf-8")

    assert workspace_module == generate_module(EDIT_SEED, EDIT_TARGET_LINES)
    assert golden_module == solved_module(EDIT_SEED, EDIT_TARGET_LINES)
    assert str(EDIT_OLD_VALUE) in task.prompt
    assert str(EDIT_NEW_VALUE) in task.prompt
    assert EDIT_CONST_NAME in task.prompt


def test_real_longctx_edit_correct_edit_passes_diff_golden(tmp_path):
    task = _real_task("longctx-edit")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "module.py").write_text(
        solved_module(EDIT_SEED, EDIT_TARGET_LINES), encoding="utf-8"
    )
    result = CHECKERS["diff_golden"](task, RunArtifacts("", None, workspace))
    assert result.passed, result.detail


def test_real_longctx_edit_unedited_workspace_fails_diff_golden(tmp_path):
    task = _real_task("longctx-edit")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "module.py").write_text(
        generate_module(EDIT_SEED, EDIT_TARGET_LINES), encoding="utf-8"
    )
    result = CHECKERS["diff_golden"](task, RunArtifacts("", None, workspace))
    assert not result.passed


def test_real_longctx_edit_overreaching_edit_fails_diff_golden(tmp_path):
    task = _real_task("longctx-edit")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    solved_text = solved_module(EDIT_SEED, EDIT_TARGET_LINES)
    overreached = solved_text.replace(
        '"""Auto-generated synthetic service module (deterministic canary fixture).',
        '"""auto-generated synthetic service module (deterministic canary fixture).',
        1,
    )
    (workspace / "module.py").write_text(overreached, encoding="utf-8")
    result = CHECKERS["diff_golden"](task, RunArtifacts("", None, workspace))
    assert not result.passed

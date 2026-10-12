from vitals.ingest.selfcorr import SELF_CORR_PATTERNS, count_hits
from vitals.ingest.testparse import detect_runner, parse_result


def test_detect_runner():
    assert detect_runner("uv run pytest -x tests/") == "pytest"
    assert detect_runner("python -m pytest") == "pytest"
    assert detect_runner("npm test -- --ci") == "npm"
    assert detect_runner("cargo test --workspace") == "cargo"
    assert detect_runner("go test ./...") == "go"
    assert detect_runner("ruff check src/") == "ruff"
    assert detect_runner("npx eslint .") == "eslint"
    assert detect_runner("flake8 src") == "flake8"
    assert detect_runner("cargo clippy -- -D warnings") == "clippy"
    assert detect_runner("ls -la") is None
    assert detect_runner("") is None


def test_clippy_wins_over_cargo():
    assert detect_runner("cargo clippy --all-targets") == "clippy"


def test_words_inside_other_tokens_do_not_match():
    assert detect_runner("echo 'we should go test this later'") is None
    assert detect_runner("cat pytest.ini") is None
    assert detect_runner('git commit -m "make go test pass"') is None


def test_runner_found_after_a_cd_or_wrapper():
    assert detect_runner("cd frontend && npm test") == "npm"
    assert detect_runner("CI=1 uv run pytest") == "pytest"
    assert detect_runner("C:/py/Scripts/pytest.exe -q") == "pytest"
    assert detect_runner("cargo nextest run") == "cargo"


def test_lint_is_exit_code_only():
    assert parse_result("ruff", "", "Exit code 1\nsrc/a.py:3:1: F401 unused import") == (1, 1)
    assert parse_result("ruff", "All checks passed!", None) == (None, 0)
    assert parse_result("eslint", "", "Exit code 2\n") == (2, 1)


def test_parse_pytest_failures_from_response():
    out = "=== 3 failed, 14 passed in 2.1s ==="
    assert parse_result("pytest", out, None) == (None, 3)


def test_parse_exit_code_from_posttoolusefailure_error():
    assert parse_result("pytest", "", "Exit code 1\nFAILED tests/a.py::t") == (1, 1)


def test_green_run():
    assert parse_result("pytest", "=== 20 passed in 1.0s ===", None) == (None, 0)


def test_npm_cargo_go():
    assert parse_result("npm", "Tests:  2 failing, 8 passing", None) == (None, 2)
    assert parse_result("cargo", "test result: FAILED. 12 passed; 3 failed; 0 ignored", None) == (
        None,
        3,
    )
    assert parse_result("cargo", "test result: ok. 12 passed; 0 failed", None) == (None, 0)
    assert parse_result("go", "FAIL\tgithub.com/x/y\t0.1s\nok\tgithub.com/x/z\t0.2s", None) == (
        None,
        1,
    )


def test_exit_code_wins_when_output_is_unparseable():
    assert parse_result("pytest", "INTERNALERROR crash", "Exit code 3") == (3, 1)


def test_unknown_runner_returns_nothing():
    assert parse_result(None, "whatever", None) == (None, None)


def test_selfcorr_patterns_hit_known_phrases():
    text = "I apologize - let me try again. Actually, the previous edit was wrong; reverting."
    assert count_hits(text) >= 3
    assert len(SELF_CORR_PATTERNS) >= 5


def test_selfcorr_does_not_fire_on_ordinary_prose():
    assert count_hits("Here is the implementation you asked for. It passes all tests.") == 0

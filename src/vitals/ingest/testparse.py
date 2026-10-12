from __future__ import annotations

import re

_WRAPPERS = frozenset(
    {
        "sudo",
        "time",
        "env",
        "nice",
        "uv",
        "uvx",
        "run",
        "npx",
        "bunx",
        "poetry",
        "pipenv",
        "pdm",
        "hatch",
        "rye",
        "python",
        "python3",
        "py",
        "-m",
        "exec",
        "command",
    }
)
_SUBCOMMANDS = {
    "cargo": {"test": "cargo", "clippy": "clippy", "nextest": "cargo"},
    "go": {"test": "go"},
    "npm": {"test": "npm", "t": "npm"},
    "yarn": {"test": "npm"},
    "pnpm": {"test": "npm"},
    "bun": {"test": "npm"},
}
_BARE = {
    "pytest": "pytest",
    "py.test": "pytest",
    "ruff": "ruff",
    "eslint": "eslint",
    "flake8": "flake8",
}
_SEGMENT_SPLIT = re.compile(r"[;&|\n]+")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

LINT_RUNNERS = frozenset({"ruff", "eslint", "flake8", "clippy"})
TEST_RUNNERS = frozenset({"pytest", "npm", "cargo", "go"})

_EXIT_CODE = re.compile(r"^\s*Exit code (\d+)", re.MULTILINE)
_PYTEST_FAILED = re.compile(r"(\d+) failed")
_PYTEST_PASSED = re.compile(r"(\d+) passed")
_NPM_FAILING = re.compile(r"(\d+) failing")
_CARGO_RESULT = re.compile(r"test result:\s*(?:ok|FAILED)\.\s*(\d+) passed;\s*(\d+) failed")
_GO_FAIL_LINE = re.compile(r"^FAIL\s", re.MULTILINE)
_GO_OK_LINE = re.compile(r"^ok\s", re.MULTILINE)


def _basename(token: str) -> str:
    return token.replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".exe")


def detect_runner(command: str | None) -> str | None:
    if not command:
        return None
    for segment in _SEGMENT_SPLIT.split(command):
        tokens = segment.split()
        while tokens and (_basename(tokens[0]) in _WRAPPERS or _ASSIGNMENT.match(tokens[0])):
            tokens.pop(0)
        if not tokens:
            continue
        head = _basename(tokens[0])
        if head in _BARE:
            return _BARE[head]
        subs = _SUBCOMMANDS.get(head)
        if subs:
            for token in tokens[1:]:
                if token in subs:
                    return subs[token]
                if not token.startswith("-"):
                    break
    return None


def _exit_code(error_text: str | None) -> int | None:
    if not error_text:
        return None
    match = _EXIT_CODE.search(error_text)
    return int(match.group(1)) if match else None


def parse_result(
    runner: str | None, tool_response: str | None, error_text: str | None
) -> tuple[int | None, int | None]:
    if runner is None:
        return None, None

    code = _exit_code(error_text)
    if runner in LINT_RUNNERS:
        if code is not None:
            return code, 1 if code != 0 else 0
        return None, 0

    text = tool_response or ""
    parsed: int | None = None
    if runner == "pytest":
        failed = _PYTEST_FAILED.search(text)
        if failed:
            parsed = int(failed.group(1))
        elif _PYTEST_PASSED.search(text):
            parsed = 0
    elif runner == "npm":
        failing = _NPM_FAILING.search(text)
        if failing:
            parsed = int(failing.group(1))
    elif runner == "cargo":
        result = _CARGO_RESULT.search(text)
        if result:
            parsed = int(result.group(2))
    elif runner == "go":
        fails = len(_GO_FAIL_LINE.findall(text))
        if fails or _GO_OK_LINE.search(text):
            parsed = fails

    if parsed is not None:
        return code, parsed
    if code is not None:
        return code, 1 if code != 0 else 0
    return None, None

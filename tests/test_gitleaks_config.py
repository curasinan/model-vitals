from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow

_REPO_ROOT = Path(__file__).resolve().parent.parent
_GITLEAKS_CONFIG = _REPO_ROOT / ".gitleaks.toml"
_GITLEAKS_BIN = shutil.which("gitleaks")

_SKIP_REASON = (
    "gitleaks not on PATH in this test environment -- guard-liveness check cannot run "
    "(this must SKIP loudly, never silently pass: see this module's docstring)"
)


def _run_gitleaks(text: str) -> tuple[int, set[str]]:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        target = tmp_path / "leaked.txt"
        target.write_text(text, encoding="utf-8")
        report_path = tmp_path / "report.json"

        proc = subprocess.run(
            [
                _GITLEAKS_BIN,
                "dir",
                "--config",
                str(_GITLEAKS_CONFIG),
                "--no-banner",
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                str(tmp_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        rule_ids: set[str] = set()
        if report_path.exists():
            report = json.loads(report_path.read_text(encoding="utf-8"))
            rule_ids = {finding["RuleID"] for finding in report}
    return proc.returncode, rule_ids


def _uuid() -> str:
    return "-".join(["0" * 8, "0" * 4, "0" * 4, "0" * 4, "0" * 12])


def _bare_transcript_filename() -> str:
    return "session file: " + _uuid() + "." + "jsonl" + "\n"


def _posix_home_path() -> str:
    return "/" + "home" + "/" + "synthetic-user" + "/project/notes.txt seen in log\n"


def _macos_users_path() -> str:
    return "/" + "Users" + "/" + "synthetic-user" + "/project/notes.txt seen in log\n"


def _windows_home_path_escaped() -> str:
    bs = "\\" + "\\"
    return 'note: "C:' + bs + "Users" + bs + "synthetic-user" + bs + 'notes.txt" seen in log\n'


def _windows_home_path_raw() -> str:
    return "raw path C:" + "\\" + "Users" + "\\" + "synthetic-user" + "\\notes.txt seen\n"


def _claude_projects_path() -> str:
    return (
        "/" + "home" + "/" + "synthetic-user" + "/" + ".claude" + "/" + "projects"
        "/some-session-dir seen in log\n"
    )


def _brief_demo_string() -> str:
    home = "/" + "home" + "/"
    user = "synthetic" + "-" + "user"
    claude_projects = "/" + ".claude" + "/" + "projects" + "/"
    filename = _uuid() + "." + "jsonl"
    return "leaked transcript path: " + home + user + claude_projects + filename + "\n"


def _windows_mangled_cwd_slug() -> str:
    return (
        "project dir: " + "C" + "-" + "-" + "Users" + "-" + "synthetic-user"
        "-Desktop-myproject seen in log\n"
    )


def _posix_mangled_cwd_slug() -> str:
    return (
        "project dir: " + "-" + "home" + "-" + "synthetic-user" + "-Desktop-myproject seen in log\n"
    )


def _populated_tilde_path() -> str:
    return "~" + "/" + ".claude" + "/" + "projects" + "/some-session-dir seen in log\n"


def _bare_tilde_mention() -> str:
    return "see `~/.claude/projects` for details\n"


@pytest.mark.skipif(_GITLEAKS_BIN is None, reason=_SKIP_REASON)
def test_bare_transcript_filename_trips_only_the_filename_rule():
    code, rule_ids = _run_gitleaks(_bare_transcript_filename())
    assert code == 1, f"gitleaks did not flag a bare UUID.jsonl filename. rule_ids={rule_ids}"
    assert "model-vitals-transcript-filename" in rule_ids, sorted(rule_ids)


@pytest.mark.skipif(_GITLEAKS_BIN is None, reason=_SKIP_REASON)
def test_posix_home_path_trips_the_abs_home_path_rule():
    code, rule_ids = _run_gitleaks(_posix_home_path())
    assert code == 1, f"gitleaks did not flag a /home/<user> path. rule_ids={rule_ids}"
    assert "model-vitals-abs-home-path" in rule_ids, sorted(rule_ids)
    assert "model-vitals-claude-projects-path" not in rule_ids, (
        "a bare /home path with no .claude in it should not trip the .claude-specific rule -- "
        f"rule_ids={sorted(rule_ids)}"
    )


@pytest.mark.skipif(_GITLEAKS_BIN is None, reason=_SKIP_REASON)
def test_macos_users_path_trips_the_abs_home_path_rule():
    code, rule_ids = _run_gitleaks(_macos_users_path())
    assert code == 1, f"gitleaks did not flag a /Users/<user> path. rule_ids={rule_ids}"
    assert "model-vitals-abs-home-path" in rule_ids, sorted(rule_ids)


@pytest.mark.skipif(_GITLEAKS_BIN is None, reason=_SKIP_REASON)
def test_windows_home_path_raw_trips_the_abs_home_path_rule():
    code, rule_ids = _run_gitleaks(_windows_home_path_raw())
    assert code == 1, f"gitleaks did not flag a raw C:\\Users\\<user> path. rule_ids={rule_ids}"
    assert "model-vitals-abs-home-path" in rule_ids, sorted(rule_ids)


@pytest.mark.skipif(_GITLEAKS_BIN is None, reason=_SKIP_REASON)
def test_windows_home_path_escaped_trips_the_abs_home_path_rule():
    code, rule_ids = _run_gitleaks(_windows_home_path_escaped())
    assert code == 1, (
        f"gitleaks did not flag an ESCAPED C:\\\\Users\\\\<user> path. rule_ids={rule_ids}"
    )
    assert "model-vitals-abs-home-path" in rule_ids, sorted(rule_ids)


@pytest.mark.skipif(_GITLEAKS_BIN is None, reason=_SKIP_REASON)
def test_claude_projects_path_trips_both_the_projects_and_home_path_rules():
    code, rule_ids = _run_gitleaks(_claude_projects_path())
    assert code == 1, f"gitleaks did not flag a .claude/projects path. rule_ids={rule_ids}"
    expected = {"model-vitals-claude-projects-path", "model-vitals-abs-home-path"}
    assert expected <= rule_ids, f"expected all of {expected}, got {sorted(rule_ids)}"


@pytest.mark.skipif(_GITLEAKS_BIN is None, reason=_SKIP_REASON)
def test_the_brief_demo_string_trips_all_three_rules_it_was_designed_for():
    code, rule_ids = _run_gitleaks(_brief_demo_string())
    assert code == 1, f"gitleaks did not flag the brief's demo string. rule_ids={rule_ids}"
    expected = {
        "model-vitals-claude-projects-path",
        "model-vitals-abs-home-path",
        "model-vitals-transcript-filename",
    }
    assert expected <= rule_ids, f"expected all of {expected}, got {sorted(rule_ids)}"


@pytest.mark.skipif(_GITLEAKS_BIN is None, reason=_SKIP_REASON)
def test_populated_tilde_path_trips_the_envvar_path_rule():
    code, rule_ids = _run_gitleaks(_populated_tilde_path())
    assert code == 1, (
        f"gitleaks did not flag a populated ~/.claude/projects/... path. rule_ids={rule_ids}"
    )
    assert "model-vitals-claude-projects-envvar-path" in rule_ids, sorted(rule_ids)


@pytest.mark.skipif(_GITLEAKS_BIN is None, reason=_SKIP_REASON)
def test_bare_tilde_mention_is_not_flagged_by_any_rule():
    code, rule_ids = _run_gitleaks(_bare_tilde_mention())
    assert code == 0, f"a bare tilde mention was flagged: rule_ids={rule_ids}"


@pytest.mark.skipif(_GITLEAKS_BIN is None, reason=_SKIP_REASON)
def test_windows_mangled_cwd_slug_trips_the_slug_rule():
    code, rule_ids = _run_gitleaks(_windows_mangled_cwd_slug())
    assert code == 1, f"gitleaks did not flag a Windows mangled-cwd slug. rule_ids={rule_ids}"
    assert "model-vitals-claude-projects-slug" in rule_ids, sorted(rule_ids)


@pytest.mark.skipif(_GITLEAKS_BIN is None, reason=_SKIP_REASON)
def test_posix_mangled_cwd_slug_trips_the_slug_rule():
    code, rule_ids = _run_gitleaks(_posix_mangled_cwd_slug())
    assert code == 1, f"gitleaks did not flag a POSIX mangled-cwd slug. rule_ids={rule_ids}"
    assert "model-vitals-claude-projects-slug" in rule_ids, sorted(rule_ids)


@pytest.mark.skipif(_GITLEAKS_BIN is None, reason=_SKIP_REASON)
def test_gitleaks_config_loads_without_error():
    proc = subprocess.run(
        [
            _GITLEAKS_BIN,
            "git",
            "--config",
            str(_GITLEAKS_CONFIG),
            "--no-banner",
            "--log-opts=-1",
            "--exit-code",
            "0",
            str(_REPO_ROOT),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "unable to load gitleaks config" not in proc.stderr.lower(), proc.stderr
    assert proc.returncode == 0, (
        f"gitleaks reported a leak in the current HEAD commit, which the full-history scan "
        f"already reviewed and allowlisted (see task-1-report.md) -- new debt or the "
        f"allowlist drifted. stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )

from __future__ import annotations

from gitleaks_scan import build_command


def test_no_push_range_uses_staged_mode_for_the_interactive_local_commit():
    cmd = build_command("gitleaks", "")
    assert "--pre-commit" in cmd
    assert "--staged" in cmd
    assert not any(arg.startswith("--log-opts") for arg in cmd)


def test_whitespace_only_push_range_is_treated_as_absent():
    cmd = build_command("gitleaks", "")
    assert "--staged" in cmd


def test_a_push_range_uses_log_opts_mode_for_ci_and_never_staged():
    cmd = build_command("gitleaks", "abc123..def456")
    assert "--log-opts=abc123..def456" in cmd
    assert "--pre-commit" not in cmd
    assert "--staged" not in cmd


def test_the_gitleaks_binary_path_is_passed_through_verbatim():
    cmd = build_command("C:/some/where/gitleaks.exe", "")
    assert cmd[0] == "C:/some/where/gitleaks.exe"


def test_both_modes_point_at_the_repo_gitleaks_toml():
    from pathlib import Path

    staged_cmd = build_command("gitleaks", "")
    ci_cmd = build_command("gitleaks", "abc..def")
    for cmd in (staged_cmd, ci_cmd):
        assert "--config" in cmd
        config_arg = cmd[cmd.index("--config") + 1]
        assert Path(config_arg).name == ".gitleaks.toml"

import json
import sys
from pathlib import Path

import pytest

HOOK_CMD = "C:/py/python.exe C:/lad/model-vitals/hook.py"
EVENTS = [
    "SessionStart",
    "PostToolUse",
    "PostToolUseFailure",
    "PreCompact",
    "PostCompact",
    "Stop",
    "SubagentStop",
    "SessionEnd",
    "ConfigChange",
]


def test_merge_preserves_existing_hooks_and_env():
    from vitals.install import merge_settings

    existing = {
        "hooks": {
            "Stop": [
                {
                    "matcher": "",
                    "hooks": [{"type": "command", "command": "python C:/x/token_tracker.py"}],
                }
            ]
        },
        "env": {"FOO": "1"},
        "enabledPlugins": {"a@b": True},
    }
    out, conflicts = merge_settings(existing, HOOK_CMD)
    stop_cmds = [h["command"] for grp in out["hooks"]["Stop"] for h in grp["hooks"]]
    assert any("token_tracker" in c for c in stop_cmds)
    assert HOOK_CMD in stop_cmds
    assert out["env"]["FOO"] == "1"
    assert out["env"]["CLAUDE_CODE_ENABLE_TELEMETRY"] == "1"
    assert out["env"]["OTEL_EXPORTER_OTLP_PROTOCOL"] == "http/json"
    assert out["enabledPlugins"] == {"a@b": True}
    assert conflicts == []
    assert existing["env"] == {"FOO": "1"}


def test_all_nine_events_registered_async_and_fail_open():
    from vitals.install import merge_settings

    out, _ = merge_settings({}, HOOK_CMD)
    for event in EVENTS:
        entries = [h for grp in out["hooks"][event] for h in grp["hooks"]]
        ours = [h for h in entries if h["command"] == HOOK_CMD]
        assert len(ours) == 1, event
        assert ours[0]["async"] is True, event
        assert ours[0]["type"] == "command"
        assert ours[0]["timeout"] == 30


def test_merge_is_idempotent():
    from vitals.install import merge_settings

    once, _ = merge_settings({}, HOOK_CMD)
    twice, _ = merge_settings(once, HOOK_CMD)
    assert once == twice


def test_merge_is_idempotent_when_only_the_interpreter_changed():
    from vitals.install import merge_settings

    once, _ = merge_settings({}, "C:/old/python.exe C:/lad/model-vitals/hook.py")
    twice, _ = merge_settings(once, "C:/new/python.exe C:/lad/model-vitals/hook.py")
    entries = [h for grp in twice["hooks"]["Stop"] for h in grp["hooks"]]
    ours = [h for h in entries if "model-vitals/hook.py" in h["command"]]
    assert len(ours) == 1
    assert ours[0]["command"].startswith("C:/new/python.exe")


def test_conflicting_user_env_value_is_reported_not_overwritten():
    from vitals.install import merge_settings

    out, conflicts = merge_settings({"env": {"OTEL_METRICS_EXPORTER": "prometheus"}}, HOOK_CMD)
    assert out["env"]["OTEL_METRICS_EXPORTER"] == "prometheus"
    assert any("OTEL_METRICS_EXPORTER" in c for c in conflicts)


def test_privacy_gates_are_never_enabled():
    from vitals.install import merge_settings

    out, _ = merge_settings({}, HOOK_CMD)
    for gate in [
        "OTEL_LOG_USER_PROMPTS",
        "OTEL_LOG_ASSISTANT_RESPONSES",
        "OTEL_LOG_TOOL_DETAILS",
        "OTEL_LOG_TOOL_CONTENT",
        "OTEL_LOG_RAW_API_BODIES",
    ]:
        assert gate not in out["env"], gate


def test_default_hook_cmd_copies_out_of_repo(tmp_path, monkeypatch):
    from vitals.install import default_hook_cmd, hook_interpreter

    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("VITALS_DATA_DIR", raising=False)
    cmd = default_hook_cmd()
    interp = hook_interpreter().replace("\\", "/")
    assert Path(interp).is_absolute() and Path(interp).exists()
    assert interp in cmd
    assert (tmp_path / ".model-vitals" / "hook.py").exists()


def test_install_paths_avoid_the_msix_redirected_localappdata(tmp_path, monkeypatch):
    from vitals.config import default_data_dir
    from vitals.install import hook_install_dir

    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    monkeypatch.delenv("VITALS_DATA_DIR", raising=False)
    assert "Local" not in str(hook_install_dir().relative_to(tmp_path))
    assert "Local" not in str(default_data_dir().relative_to(tmp_path))
    assert hook_install_dir() == default_data_dir()


def test_hook_interpreter_is_the_base_not_the_venv_shim():
    from vitals.install import hook_interpreter

    interp = Path(hook_interpreter())
    assert interp.exists()
    if sys.prefix != sys.base_prefix:
        assert sys.base_prefix.lower() in str(interp).lower()


def test_smoke_check_runs_the_exact_installed_command(tmp_path, monkeypatch):
    from vitals.install import default_hook_cmd, smoke_check

    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("VITALS_DATA_DIR", str(tmp_path / "data"))
    cmd = default_hook_cmd()
    assert smoke_check(cmd, tmp_path / "data") is True


def test_smoke_check_fails_loudly_on_a_bad_interpreter(tmp_path):
    from vitals.install import smoke_check

    with pytest.raises(RuntimeError):
        smoke_check("C:/nope/python.exe C:/nope/hook.py", tmp_path / "data")


def test_settings_roundtrip_is_valid_json(tmp_path):
    from vitals.install import merge_settings

    out, _ = merge_settings({"model": "opus"}, HOOK_CMD)
    assert json.loads(json.dumps(out))["model"] == "opus"


def test_merge_replaces_a_legacy_claude_vitals_hook_entry():
    from vitals.install import merge_settings

    legacy, _ = merge_settings({}, "C:/py/python.exe C:/lad/claude-vitals/hook.py")
    merged, _ = merge_settings(legacy, HOOK_CMD)
    commands = [h["command"] for grp in merged["hooks"]["Stop"] for h in grp["hooks"]]
    assert commands == [HOOK_CMD]

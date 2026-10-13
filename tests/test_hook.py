import json
import os
import subprocess
import sys
from pathlib import Path

HOOK = str(Path(__file__).resolve().parents[1] / "src" / "vitals" / "hook.py")


def run_hook(payload, tmp_path, raw=None):
    env = dict(os.environ, VITALS_DATA_DIR=str(tmp_path))
    return subprocess.run(
        [sys.executable, HOOK],
        input=json.dumps(payload) if raw is None else raw,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


def spooled(tmp_path):
    files = sorted((tmp_path / "spool" / "hooks").glob("hooks-*.jsonl"))
    assert files, "no spool file written"
    return [
        json.loads(line)
        for f in files
        for line in f.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_posttooluse_slims_tool_io(tmp_path):
    p = run_hook(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "s1",
            "prompt_id": "p1",
            "tool_name": "Write",
            "tool_use_id": "toolu_1",
            "duration_ms": 12,
            "tool_input": {"file_path": "C:\\proj\\a.py", "content": "SECRET" * 999},
            "tool_response": {"filePath": "C:\\proj\\a.py", "success": True},
            "transcript_path": "x",
            "cwd": "C:\\proj",
        },
        tmp_path,
    )
    assert p.returncode == 0 and p.stdout == ""
    rec = spooled(tmp_path)[0]
    assert rec["tool_input"] == {"file_path": "C:\\proj\\a.py"}
    assert "content" in rec["tool_input_dropped"]
    assert "SECRET" not in json.dumps(rec)
    assert rec["_recv_ts"] > 0


def test_userprompt_text_never_stored(tmp_path):
    run_hook(
        {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "s1",
            "prompt": "my secret prompt",
            "transcript_path": "x",
            "cwd": "c",
        },
        tmp_path,
    )
    recs = spooled(tmp_path)
    assert "my secret prompt" not in json.dumps(recs)
    assert recs[0]["prompt_length"] == len("my secret prompt")


def test_bash_command_is_kept_for_test_runner_detection(tmp_path):
    run_hook(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "s1",
            "tool_name": "Bash",
            "tool_use_id": "t2",
            "tool_input": {"command": "uv run pytest -q", "timeout": 120},
            "tool_response": "1 failed, 9 passed",
        },
        tmp_path,
    )
    rec = spooled(tmp_path)[0]
    assert rec["tool_input"]["command"] == "uv run pytest -q"
    assert rec["tool_response"] == "1 failed, 9 passed"


def test_long_tool_response_is_truncated(tmp_path):
    run_hook(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "s1",
            "tool_name": "Bash",
            "tool_use_id": "t3",
            "tool_input": {"command": "ls"},
            "tool_response": "x" * 200_000,
        },
        tmp_path,
    )
    rec = spooled(tmp_path)[0]
    assert 0 < len(rec["tool_response"]) <= 8192


def test_garbage_stdin_still_exits_zero(tmp_path):
    p = run_hook(None, tmp_path, raw="not json{{{")
    assert p.returncode == 0
    assert p.stdout == ""


def test_empty_stdin_still_exits_zero(tmp_path):
    p = run_hook(None, tmp_path, raw="")
    assert p.returncode == 0


def test_unwritable_data_dir_still_exits_zero(tmp_path):
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    env = dict(os.environ, VITALS_DATA_DIR=str(blocker))
    p = subprocess.run(
        [sys.executable, HOOK],
        input='{"hook_event_name":"Stop","session_id":"s"}',
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert p.returncode == 0
    assert p.stdout == ""


def test_appends_multiple_lines_to_one_day_file(tmp_path):
    for i in range(3):
        run_hook({"hook_event_name": "Stop", "session_id": f"s{i}"}, tmp_path)
    assert len(spooled(tmp_path)) == 3
    files = list((tmp_path / "spool" / "hooks").glob("hooks-*.jsonl"))
    assert len(files) == 1


def test_concurrent_hook_processes_lose_nothing(tmp_path):
    import threading

    n = 16
    results: list[int] = []

    def go(i):
        p = run_hook(
            {"hook_event_name": "PostToolUse", "session_id": "s", "tool_use_id": f"t{i}"},
            tmp_path,
        )
        results.append(p.returncode)

    threads = [threading.Thread(target=go, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results == [0] * n
    recs = spooled(tmp_path)
    assert len(recs) == n, f"lost {n - len(recs)} of {n} concurrent hook records"
    assert {r["tool_use_id"] for r in recs} == {f"t{i}" for i in range(n)}


def test_hook_data_dir_follows_the_same_legacy_rule(tmp_path, monkeypatch):
    from vitals.hook import _data_dir

    monkeypatch.delenv("VITALS_DATA_DIR", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert _data_dir() == str(tmp_path / ".model-vitals")
    (tmp_path / ".claude-vitals").mkdir()
    assert _data_dir() == str(tmp_path / ".claude-vitals")


def test_utf8_payload_survives_an_ansi_console_code_page(tmp_path):
    env = dict(os.environ, VITALS_DATA_DIR=str(tmp_path), PYTHONIOENCODING="cp1254")
    payload = {
        "hook_event_name": "PostToolUse",
        "session_id": "s1",
        "tool_name": "Bash",
        "tool_response": {"stdout": "ŞEKER ━━ çalıştı"},
    }
    p = subprocess.run(
        [sys.executable, HOOK],
        input=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        capture_output=True,
        env=env,
        timeout=30,
    )
    assert p.returncode == 0
    rows = spooled(tmp_path)
    assert len(rows) == 1
    assert "ŞEKER" in json.dumps(rows[0], ensure_ascii=False)

import json
import os
import random
import sys
import time

try:
    import msvcrt
except ImportError:  # pragma: no cover
    msvcrt = None
try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

KEEP_TOOL_INPUT = {
    "file_path",
    "notebook_path",
    "command",
    "description",
    "timeout",
    "run_in_background",
    "subagent_type",
    "pattern",
}
TRUNC = 4096


def _data_dir() -> str:
    d = os.environ.get("VITALS_DATA_DIR")
    if d:
        return d
    home = os.path.expanduser("~")
    current = os.path.join(home, ".model-vitals")
    legacy = os.path.join(home, ".claude-vitals")
    if not os.path.exists(current) and os.path.exists(legacy):
        return legacy
    return current


def slim(p):
    if isinstance(p.get("tool_input"), dict):
        ti = p["tool_input"]
        p["tool_input"] = {k: v for k, v in ti.items() if k in KEEP_TOOL_INPUT}
        p["tool_input_dropped"] = sorted(set(ti) - set(p["tool_input"]))
    if "tool_response" in p:
        tr = p["tool_response"]
        s = tr if isinstance(tr, str) else json.dumps(tr, ensure_ascii=False, default=str)
        p["tool_response"] = s[: TRUNC * 2]
    if "prompt" in p:
        p["prompt_length"] = len(p.pop("prompt") or "")
    if isinstance(p.get("last_assistant_message"), str):
        p["last_assistant_message"] = p["last_assistant_message"][:TRUNC]
    if isinstance(p.get("compact_summary"), str):
        p["compact_summary"] = p["compact_summary"][:TRUNC]
    if isinstance(p.get("error"), str):
        p["error"] = p["error"][:TRUNC]
    p.pop("permission_suggestions", None)
    return p


def _try_lock(fd):
    try:
        if msvcrt is not None:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        elif fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _unlock(fd):
    try:
        if msvcrt is not None:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        elif fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass


def append_line(path, line):
    lock_path = path + ".lock"
    lock_fd = None
    locked = False
    try:
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.time() + 2.0
        while time.time() < deadline:
            if _try_lock(lock_fd):
                locked = True
                break
            time.sleep(0.004 + random.random() * 0.012)
    except OSError:
        lock_fd = None

    if not locked:
        path = "%s.p%d.jsonl" % (path[:-6] if path.endswith(".jsonl") else path, os.getpid())

    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)
    finally:
        if lock_fd is not None:
            if locked:
                _unlock(lock_fd)
            os.close(lock_fd)


def main():
    try:
        raw = sys.stdin.read(2_000_000)
        p = slim(json.loads(raw))
        p["_recv_ts"] = time.time()
        spool = os.path.join(_data_dir(), "spool", "hooks")
        os.makedirs(spool, exist_ok=True)
        path = os.path.join(spool, "hooks-%s.jsonl" % time.strftime("%Y%m%d"))
        line = (json.dumps(p, ensure_ascii=False, default=str) + "\n").encode("utf-8")
        append_line(path, line)
    except Exception:
        try:
            d = os.path.join(_data_dir(), "failopen")
            os.makedirs(d, exist_ok=True)
            fd = os.open(
                os.path.join(d, "hook.spool.%d.count" % os.getpid()),
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            try:
                os.write(fd, b"\x01")
            finally:
                os.close(fd)
        except Exception:
            pass
    sys.exit(0)


if __name__ == "__main__":
    main()

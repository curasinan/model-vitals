from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

BASELINE_PATH = Path(__file__).resolve().parent.parent / "mypy_baseline.json"

_COUNT_RE = re.compile(r"Found (\d+) errors? in \d+ files?")
_CLEAN_RE = re.compile(r"Success: no issues found")


def platform_key() -> str:
    return sys.platform


def parse_count(output: str) -> int | None:
    if _CLEAN_RE.search(output):
        return 0
    match = _COUNT_RE.search(output)
    return int(match.group(1)) if match else None


def verdict(count: int | None, baseline: int | None) -> tuple[int, str]:
    if count is None:
        return 1, "could not parse a mypy error count -- treating as failure, not as clean"
    if baseline is None:
        return 1, (
            f"no baseline recorded for {platform_key()!r}; mypy reports {count}. "
            f"Add it to {BASELINE_PATH.name} in this commit."
        )
    if count > baseline:
        return 1, (
            f"mypy errors rose: {count} > baseline {baseline} for {platform_key()!r}. "
            "Fix the new errors, or -- if they are genuinely pre-existing and newly "
            "surfaced -- say so explicitly by raising the baseline in the same commit."
        )
    if count < baseline:
        return 1, (
            f"mypy errors fell to {count} (baseline {baseline}) -- good, and the "
            f"baseline must come down with it. Set {platform_key()!r} to {count} in "
            f"{BASELINE_PATH.name}. Left as-is, the slack would hide the next regression."
        )
    return 0, f"mypy at baseline: {count} errors on {platform_key()!r}"


def load_baseline(path: Path = BASELINE_PATH) -> dict[str, int]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print-only", action="store_true", help="report the count and always exit 0"
    )
    args = parser.parse_args(argv)

    proc = subprocess.run(
        [sys.executable, "-m", "mypy"],
        capture_output=True,
        text=True,
        cwd=BASELINE_PATH.parent,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    count = parse_count(output)
    code, message = verdict(count, load_baseline().get(platform_key()))

    print(output.rstrip())
    print(f"\nmypy-ratchet: {message}")
    return 0 if args.print_only else code


if __name__ == "__main__":
    raise SystemExit(main())

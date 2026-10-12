from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

_CONFIG_PATH = Path(__file__).resolve().parent.parent / ".gitleaks.toml"


def build_command(
    gitleaks_bin: str, push_range: str, config_path: Path = _CONFIG_PATH
) -> list[str]:
    base = [gitleaks_bin, "git", "--config", str(config_path), "--redact", "--verbose"]
    if push_range:
        return [*base, f"--log-opts={push_range}"]
    return [*base, "--pre-commit", "--staged"]


def main(argv: list[str] | None = None) -> int:
    del argv

    gitleaks_bin = shutil.which("gitleaks")
    if gitleaks_bin is None:
        print(
            "gitleaks_scan.py: 'gitleaks' is not on PATH. Install it (winget install "
            "Gitleaks.Gitleaks, or see .pre-commit-config.yaml) and start a new shell so the "
            "PATH update takes effect.",
            file=sys.stderr,
        )
        return 1

    push_range = os.environ.get("GITLEAKS_PUSH_RANGE", "").strip()
    cmd = build_command(gitleaks_bin, push_range)
    proc = subprocess.run(cmd, check=False)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())

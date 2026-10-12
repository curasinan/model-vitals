"""Render lines of a nightly-build report as plain text."""

from __future__ import annotations


def render_header(project: str, build_number: int) -> str:
    return f"Build report for {project} (build #{build_number})"


def render_summary(passed: int, failed: int, skipped: int) -> str:
    total = passed + failed + skipped
    return f"{passed} passed, {failed} failed, {skipped} skipped (of {total} total)"


def render_duration(seconds: float) -> str:
    return f"Duration: {seconds:.2f} seconds"


def render_percentage(passed: int, total: int) -> str:
    pct = (passed / total) * 100 if total else 0.0
    return f"Pass rate: {pct:.1f}%"


def render_footer(owner: str) -> str:
    return f"Report generated for {owner}"


def render_failure_line(name: str, line_no: int) -> str:
    return f"  FAILED: {name} at line {line_no}"

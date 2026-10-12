"""Render lines of a nightly-build report as plain text."""

from __future__ import annotations


def render_header(project: str, build_number: int) -> str:
    return "Build report for %s (build #%d)" % (project, build_number)


def render_summary(passed: int, failed: int, skipped: int) -> str:
    total = passed + failed + skipped
    return "%d passed, %d failed, %d skipped (of %d total)" % (passed, failed, skipped, total)


def render_duration(seconds: float) -> str:
    return "Duration: %.2f seconds" % seconds


def render_percentage(passed: int, total: int) -> str:
    pct = (passed / total) * 100 if total else 0.0
    return "Pass rate: %.1f%%" % pct


def render_footer(owner: str) -> str:
    return "Report generated for %s" % owner


def render_failure_line(name: str, line_no: int) -> str:
    return "  FAILED: %s at line %d" % (name, line_no)

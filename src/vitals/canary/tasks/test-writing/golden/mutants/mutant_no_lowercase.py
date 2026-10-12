"""Mutant: drops the lowercasing step (mutation-sensitivity fixture for test-writing)."""

from __future__ import annotations

import re
import unicodedata

_STRIP_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    return _STRIP_RE.sub("-", ascii_only).strip("-")

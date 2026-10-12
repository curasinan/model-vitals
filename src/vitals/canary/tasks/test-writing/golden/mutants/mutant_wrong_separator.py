"""Mutant: uses underscore instead of hyphen as the separator (mutation-sensitivity fixture)."""

from __future__ import annotations

import re
import unicodedata

_STRIP_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    lowered = ascii_only.lower()
    return _STRIP_RE.sub("_", lowered).strip("_")

"""Turn arbitrary text into a URL-safe slug."""

from __future__ import annotations

import re
import unicodedata

_STRIP_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    """Convert `text` to a lowercase, hyphen-separated, ASCII slug.

    Steps: Unicode-normalize and strip accents down to plain ASCII, lowercase the result,
    replace any run of non-alphanumeric characters with a single hyphen, and strip any
    leading or trailing hyphen.
    """
    normalized = unicodedata.normalize("NFKD", text)
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    lowered = ascii_only.lower()
    return _STRIP_RE.sub("-", lowered).strip("-")

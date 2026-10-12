from __future__ import annotations

import re

SELF_CORR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bI apolog",
        r"\blet me try again\b",
        r"\blet me fix\b",
        r"\bactually,\s",
        r"\brevert(?:ing|ed)?\b",
        r"\bthat (?:didn't|did not) work\b",
        r"\bmy mistake\b",
    )
]


def count_hits(text: str) -> int:
    if not text:
        return 0
    return sum(1 for pattern in SELF_CORR_PATTERNS if pattern.search(text))

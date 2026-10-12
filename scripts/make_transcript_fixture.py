from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

KEEP_KEYS = frozenset(
    {
        "type",
        "role",
        "model",
        "version",
        "effort",
        "stop_reason",
        "stop_sequence",
        "service_tier",
        "speed",
        "inference_geo",
        "userType",
        "entrypoint",
        "permissionMode",
        "promptSource",
        "timestamp",
        "level",
        "subtype",
        "name",
    }
)
ID_KEYS = frozenset({"sessionId", "uuid", "parentUuid", "promptId", "requestId", "id", "toolUseID"})
PATH_KEYS = {"cwd": "C:/proj/demo", "gitBranch": "main", "transcriptPath": "C:/proj/demo.jsonl"}

PROSE = [
    "Placeholder assistant prose for fixture purposes.",
    "I apologize - let me try again with a different approach.",
    "Placeholder tool output line one.\nPlaceholder tool output line two.",
    "Actually, that edit was wrong; reverting it now.",
    "Placeholder user request text.",
]


def fake_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(f"{prefix}:{value}".encode()).hexdigest()
    if prefix == "requestId":
        return f"req_{digest[:24]}"
    return f"{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-8{digest[17:20]}-{digest[20:32]}"


def scrub(node, key: str | None = None, depth: int = 0):
    if isinstance(node, dict):
        return {k: scrub(v, k, depth + 1) for k, v in node.items()}
    if isinstance(node, list):
        return [scrub(v, key, depth + 1) for v in node]
    if isinstance(node, str):
        if key in KEEP_KEYS:
            return node
        if key in ID_KEYS:
            return fake_id(key, node)
        if key in PATH_KEYS:
            return PATH_KEYS[key]
        if key == "text":
            return "I apologize - let me try again. Actually, that edit was wrong; reverting."
        return PROSE[len(node) % len(PROSE)]
    return node


def main() -> int:
    src = Path(sys.argv[1])
    dest = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "transcript_sample.jsonl"
    out = []
    for line in src.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        out.append(json.dumps(scrub(json.loads(line)), ensure_ascii=False))
    dest.write_text("\n".join(out) + "\n", encoding="utf-8")
    blob = dest.read_text(encoding="utf-8")
    for leak in ("asus", "curasinan", "OneDrive", "@gmail"):
        if leak in blob:
            raise SystemExit(f"scrubber missed {leak!r} — refusing to keep {dest}")
    print(f"wrote {dest} ({len(out)} records)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import json
import sys
from pathlib import Path

PII_REPLACEMENTS = {
    "user.email": "dev@example.invalid",
    "user.id": "0" * 64,
    "user.account_uuid": "00000000-0000-4000-8000-000000000001",
    "user.account_id": "user_000000000000000000000000",
    "organization.id": "00000000-0000-4000-8000-000000000002",
    "session.id": "11111111-1111-4111-8111-111111111111",
    "prompt.id": "22222222-2222-4222-8222-222222222222",
    "message.uuid": "33333333-3333-4333-8333-333333333333",
}


def scrub_attrs(attrs: list[dict]) -> None:
    for attr in attrs:
        replacement = PII_REPLACEMENTS.get(attr.get("key"))
        if replacement is not None:
            attr["value"] = {"stringValue": replacement}


def scrub(node) -> None:
    if isinstance(node, dict):
        if isinstance(node.get("attributes"), list):
            scrub_attrs(node["attributes"])
        for value in node.values():
            scrub(value)
    elif isinstance(node, list):
        for item in node:
            scrub(item)


def main() -> int:
    src, dest = Path(sys.argv[1]), Path(sys.argv[2])
    bodies = [json.loads(line)["body"] for line in src.read_text(encoding="utf-8").splitlines()]
    merged = bodies[0]
    key = "resourceLogs" if "resourceLogs" in merged else "resourceMetrics"
    for extra in bodies[1:]:
        merged[key].extend(extra.get(key, []))
    scrub(merged)
    blob = json.dumps(merged, indent=1, ensure_ascii=False)
    for value in ("curasinan", "@gmail.com", "user_01"):
        if value in blob:
            raise SystemExit(f"sanitizer missed {value!r} — refusing to write {dest}")
    dest.write_text(blob + "\n", encoding="utf-8")
    print(f"wrote {dest} ({len(blob)} bytes, {len(bodies)} bodies merged)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

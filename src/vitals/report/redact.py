"""Reminder: the entropy rule is not a backstop for hex. A hex alphabet tops out at
4.0 bits/char, below the 4.2 threshold, so hex-shaped secrets must be matched by name."""

from __future__ import annotations

import math
import re
from typing import Any

_SK_ANT_RE = re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}")
_GHP_RE = re.compile(r"ghp_[A-Za-z0-9]{20,}")
_GITHUB_PAT_RE = re.compile(r"github_pat_[A-Za-z0-9_]{20,}")
_AKIA_RE = re.compile(r"AKIA[0-9A-Z]{16}")
_SLACK_RE = re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")

_JWT_RE = re.compile(r"eyJ[\w-]{1,8192}+\.[\w-]{1,8192}+\.[\w-]{1,8192}+")

_PEM_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,16384}?"
    r"-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----"
)


_SECRET_NAME_END = re.compile(
    r"(?i)(?:api[_-]?key|apikey|secret|passw(?:or)?d|passwd|pwd|authorization|auth|token"
    r"|cookie|\Asession|session[_-]?id|sessid|csrf(?:[_-]?token)?|credentials?"
    r"|private[_-]?key(?:[_-]?id)?|sig|signature"
    r"|(?:access|signing|encryption|master|hmac|client|ssh)[_-]?key|[_.-]key)\Z"
)

_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{1,80})"
    r"(?:\\)?[\"']?"
    r"(\s*[:=]\s*(?:(?:Bearer|Basic|Token)\s+)?|\s+(?:Bearer|Basic)\s+)"
    r"(?:\\)?[\"']?"
    r"(?:(?:Bearer|Basic)\s+)*+"
    r"(?!<REDACTED:)([^\s;,&\"']+)"
)

_CLI_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9-])(--?[A-Za-z0-9-]{1,40})(\s+)(?!-)(?!<REDACTED:)([^\s;,\"']+)"
)
_CLI_SECRET_NAME_END = re.compile(r"(?i)(?:password|passwd|pwd|token|secret|api-?key)\Z")


def _redact_assignments(text: str) -> str:
    out: list[str] = []
    pos = 0
    while True:
        m = _ASSIGNMENT_RE.search(text, pos)
        if m is None:
            break
        if _SECRET_NAME_END.search(m.group(1)):
            out.append(text[pos : m.start()])
            out.append(f"{m.group(1)}{m.group(2)}<REDACTED:assignment>")
            pos = m.end()
        else:
            out.append(text[pos : m.start(3)])
            pos = m.start(3)
    out.append(text[pos:])
    return "".join(out)


def _cli_repl(m: re.Match[str]) -> str:
    if _CLI_SECRET_NAME_END.search(m.group(1)):
        return f"{m.group(1)}{m.group(2)}<REDACTED:assignment>"
    return m.group(0)


_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._+-]{1,64}+(?:@|%40)(?:[A-Za-z0-9-]{1,63}+\.)+[A-Za-z]{2,24}+\b"
)


_WIN_USERDIR_RE = re.compile(
    r"\b[A-Z]:(?:\\+|/)Users(?:\\+|/)"
    r"(?:[^\\/\s\"'`]+(?: [^\\/\s\"'`]+){0,3}(?=\\|/)|[^\\/\s\"'`]+)",
    re.IGNORECASE,
)
_WIN_USERDIR_ENCODED_RE = re.compile(
    r"\b[A-Z]%3A(?:%5C|%2F)+Users(?:%5C|%2F)+[^%\s\"'`&]+", re.IGNORECASE
)
_POSIX_USERDIR_RE = re.compile(r"(?:/|\\+)(?:home|Users)(?:/|\\+)[^\\/\s\"'`]+", re.IGNORECASE)


_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)


def _is_exempt_ipv4(ip: str) -> bool:
    return ip.startswith("127.") or ip == "0.0.0.0"


def _ipv4_repl(m: re.Match[str]) -> str:
    ip = m.group(0)
    return ip if _is_exempt_ipv4(ip) else "<REDACTED:ip>"


_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_=-]{24,}")
_ENTROPY_THRESHOLD = 4.2


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def _entropy_repl(m: re.Match[str]) -> str:
    token = m.group(0)
    if _shannon_entropy(token) > _ENTROPY_THRESHOLD:
        return "<REDACTED:entropy>"
    return token


def redact_text(s: str) -> str:
    text = s

    text = _SK_ANT_RE.sub("<REDACTED:key>", text)
    text = _GHP_RE.sub("<REDACTED:key>", text)
    text = _GITHUB_PAT_RE.sub("<REDACTED:key>", text)
    text = _AKIA_RE.sub("<REDACTED:key>", text)
    text = _SLACK_RE.sub("<REDACTED:key>", text)
    text = _JWT_RE.sub("<REDACTED:jwt>", text)
    text = _PEM_RE.sub("<REDACTED:privkey>", text)

    text = _redact_assignments(text)
    text = _CLI_SECRET_RE.sub(_cli_repl, text)

    text = _EMAIL_RE.sub("<REDACTED:email>", text)

    text = _WIN_USERDIR_RE.sub("<REDACTED:path>", text)
    text = _WIN_USERDIR_ENCODED_RE.sub("<REDACTED:path>", text)
    text = _POSIX_USERDIR_RE.sub("<REDACTED:path>", text)

    text = _IPV4_RE.sub(_ipv4_repl, text)

    text = _ENTROPY_TOKEN_RE.sub(_entropy_repl, text)

    return text


def redact_report(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact_report(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_report(v) for v in obj]
    return obj

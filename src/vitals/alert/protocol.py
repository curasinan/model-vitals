"""Reminder: any web page can launch a registered URI scheme once the user confirms the
browser prompt, so every link is signed with a per-install key and the handler trusts
nothing in the URI beyond an alert id, a label and a nonce."""

from __future__ import annotations

import hmac
import os
import re
import secrets
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple
from urllib.parse import parse_qs, urlencode, urlsplit

from vitals import failopen
from vitals.alert.labels import BUTTONS, LABELS, apply_label
from vitals.db import get_conn

if TYPE_CHECKING:
    from vitals.config import Config

__all__ = [
    "Action",
    "ToastLinks",
    "UriError",
    "handle_uri",
    "handler_command",
    "is_registered",
    "label_uri",
    "open_uri",
    "parse_uri",
    "ping_uri",
    "register",
    "scheme",
    "smoke_check",
    "toast_links",
]

_KEY_FILE = "uri.key"
_PING_FILE = "uri-ping"
_MAX_URI = 512
_SIG_LEN = 32
_FAILOPEN_SITE = "toast.uri"
_ALERT_RE = re.compile(r"[0-9]{1,12}")
_NONCE_RE = re.compile(r"[0-9a-f]{32}")


class UriError(ValueError): ...


@dataclass(frozen=True)
class Action:
    kind: str
    alert_id: int = 0
    label: str = ""
    nonce: str = ""


class ToastLinks(NamedTuple):
    open: str
    buttons: list[tuple[str, str]]


def scheme() -> str:
    return os.environ.get("VITALS_URI_SCHEME", "model-vitals")


def _reg_path() -> str:
    return rf"Software\Classes\{scheme()}"


def _key(data_dir: Path, create: bool) -> bytes:
    path = Path(data_dir) / _KEY_FILE
    if create and not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            try:
                os.write(fd, secrets.token_hex(32).encode("ascii"))
            finally:
                os.close(fd)
    raw = path.read_text(encoding="ascii").strip()
    if len(raw) != 64:
        raise UriError("uri key missing or truncated")
    return bytes.fromhex(raw)


def _sign(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode("ascii"), sha256).hexdigest()[:_SIG_LEN]


def _uri(data_dir: Path, action: str, fields: dict[str, str], message: str) -> str:
    signed = {**fields, "sig": _sign(_key(data_dir, create=True), message)}
    return f"{scheme()}://{action}?{urlencode(signed)}"


def label_uri(data_dir: Path, alert_id: int, label: str) -> str:
    if label not in LABELS:
        raise ValueError(f"unknown label {label!r}")
    message = f"label:{int(alert_id)}:{label}"
    return _uri(data_dir, "label", {"alert": str(int(alert_id)), "label": label}, message)


def open_uri(data_dir: Path, alert_id: int) -> str:
    return _uri(data_dir, "open", {"alert": str(int(alert_id))}, f"open:{int(alert_id)}")


def ping_uri(data_dir: Path, nonce: str) -> str:
    return _uri(data_dir, "ping", {"nonce": nonce}, f"ping:{nonce}")


def toast_links(data_dir: Path, alert_id: int) -> ToastLinks:
    buttons = [(caption, label_uri(data_dir, alert_id, label)) for caption, label in BUTTONS]
    return ToastLinks(open_uri(data_dir, alert_id), buttons)


def _alert_id(fields: dict[str, str]) -> int:
    alert = fields.get("alert", "")
    if not _ALERT_RE.fullmatch(alert):
        raise UriError("bad alert id")
    return int(alert)


def parse_uri(uri: str, key: bytes) -> Action:
    if not uri or len(uri) > _MAX_URI:
        raise UriError("empty or oversized uri")
    parts = urlsplit(uri)
    if parts.scheme != scheme() or parts.path not in ("", "/") or parts.fragment:
        raise UriError("not a model-vitals uri")
    try:
        query = parse_qs(parts.query, strict_parsing=True)
    except ValueError:
        raise UriError("malformed query") from None
    if any(len(values) != 1 for values in query.values()):
        raise UriError("repeated field")
    fields = {name: values[0] for name, values in query.items()}

    if parts.netloc == "label":
        label = fields.get("label", "")
        if label not in LABELS:
            raise UriError("bad label")
        action = Action("label", alert_id=_alert_id(fields), label=label)
        message = f"label:{action.alert_id}:{label}"
    elif parts.netloc == "open":
        action = Action("open", alert_id=_alert_id(fields))
        message = f"open:{action.alert_id}"
    elif parts.netloc == "ping":
        nonce = fields.get("nonce", "")
        if not _NONCE_RE.fullmatch(nonce):
            raise UriError("bad nonce")
        action = Action("ping", nonce=nonce)
        message = f"ping:{nonce}"
    else:
        raise UriError("unknown action")

    given = fields.get("sig", "").encode("ascii", "replace")
    if not hmac.compare_digest(given, _sign(key, message).encode("ascii")):
        raise UriError("bad signature")
    return action


def _default_open_file(path: Path) -> None:
    if sys.platform != "win32":
        raise UriError("opening files is only wired on Windows")
    os.startfile(path)


def handle_uri(cfg: Config, uri: str, open_file: Callable[[Path], None] | None = None) -> int:
    try:
        action = parse_uri(uri, _key(cfg.data_dir, create=False))
        if action.kind == "ping":
            (Path(cfg.data_dir) / _PING_FILE).write_text(action.nonce, encoding="ascii")
        elif action.kind == "open":
            detail = Path(cfg.reports_dir) / f"alert-{action.alert_id}.json"
            if not detail.is_file():
                raise UriError("no detail file for this alert")
            (open_file or _default_open_file)(detail)
        else:
            conn = get_conn(cfg.db_path)
            try:
                apply_label(conn, action.alert_id, action.label, "toast", cfg.detect)
            finally:
                conn.close()
        return 0
    except Exception:
        failopen.record(_FAILOPEN_SITE, cfg.data_dir)
        return 1


def handler_command(pythonw: Path) -> str:
    return f'"{pythonw}" -m vitals handle-uri -- "%1"'


def register(pythonw: Path) -> None:
    if sys.platform != "win32":
        raise OSError("URI scheme registration is Windows-only")
    import winreg

    root = _reg_path()
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, root) as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, f"URL:{scheme()}")
        winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, root + r"\shell\open\command") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, handler_command(pythonw))


def is_registered() -> bool:
    if sys.platform != "win32":
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _reg_path() + r"\shell\open\command") as key:
            value, _ = winreg.QueryValueEx(key, "")
    except OSError:
        return False
    return bool(value)


def smoke_check(
    cfg: Config,
    launch: Callable[[str], object] | None = None,
    timeout_s: float = 15.0,
) -> bool:
    if launch is None:
        if sys.platform != "win32":
            return False
        launch = os.startfile
    nonce = secrets.token_hex(16)
    ping = Path(cfg.data_dir) / _PING_FILE
    ping.unlink(missing_ok=True)
    launch(ping_uri(cfg.data_dir, nonce))
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            if ping.read_text(encoding="ascii") == nonce:
                ping.unlink(missing_ok=True)
                return True
        except OSError:
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.2)

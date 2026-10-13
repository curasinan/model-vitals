from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

from vitals.report.redact import redact_text

__all__ = [
    "AlertPayload",
    "Channel",
    "ChannelError",
    "DesktopToast",
    "Ntfy",
    "Telegram",
    "Webhook",
    "load_channels",
    "mask_telegram_url",
]


class ChannelError(RuntimeError): ...


@dataclass
class AlertPayload:
    severity: str
    attribution: str
    title: str
    summary_text: str
    local_detail_path: str | None = None
    alert_id: int | None = None
    labelable: bool = False


class Channel(Protocol):
    """Reminder: `_scrub` skips secrets shorter than 8 characters (`_MIN_SCRUB_LEN`).
    A channel must never put a short secret into a URL or error message on its own."""

    name: str

    def send(self, payload: AlertPayload) -> None: ...


def _urlopen(request: urllib.request.Request):
    return urllib.request.urlopen(request, timeout=10)


def _mask_host_only(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}/***"


def _raw_selector(url: str) -> str:
    scheme_end = url.find("://")
    rest = url[scheme_end + 3 :] if scheme_end != -1 else url
    slash = rest.find("/")
    return rest[slash:] if slash != -1 else ""


_MIN_SCRUB_LEN = 8


def _scrub(text: str, secrets: Iterable[str]) -> str:
    for secret in secrets:
        if not secret or len(secret) < _MIN_SCRUB_LEN:
            continue
        text = text.replace(secret, "***")
        escaped = repr(secret)[1:-1]
        if escaped and escaped != secret:
            text = text.replace(escaped, "***")
    return text


def _safe_message(text: str, secrets: Iterable[str] = ()) -> str:
    return redact_text(_scrub(text, secrets))


def _post_and_check(
    opener: Callable[[urllib.request.Request], object],
    request: urllib.request.Request,
    channel_name: str,
    masked_url: str,
    secrets: Iterable[str] = (),
) -> None:
    try:
        with opener(request) as response:  # type: ignore[union-attr]
            status = getattr(response, "status", 200)
            if status >= 400:
                raise ChannelError(
                    _safe_message(f"{channel_name}: HTTP {status} from {masked_url}", secrets)
                )
    except ChannelError:
        raise
    except urllib.error.URLError as exc:
        message = f"{channel_name}: request to {masked_url} failed: {exc.reason}"
        raise ChannelError(_safe_message(message, secrets)) from None
    except Exception as exc:
        message = f"{channel_name}: request to {masked_url} failed: {exc}"
        raise ChannelError(_safe_message(message, secrets)) from None


def _compose_text(payload: AlertPayload) -> str:
    return f"[{payload.severity}] {payload.title}\n{payload.summary_text}"


_LIVE_TOASTS: deque[tuple[Any, Any]] = deque(maxlen=64)


def _build_label_toast(
    title: str,
    body: str,
    buttons: list[tuple[str, str]],
    on_activated: Callable[[str], None],
) -> tuple[Any, Any]:
    from windows_toasts import InteractableWindowsToaster, Toast, ToastButton

    toaster = InteractableWindowsToaster("model-vitals")
    toast = Toast()
    toast.text_fields = [title, body]
    for caption, arguments in buttons:
        toast.AddAction(ToastButton(caption, arguments))
    toast.on_activated = lambda event: on_activated(event.arguments or "")
    return toaster, toast


def _default_toast_notify(
    title: str,
    body: str,
    buttons: list[tuple[str, str]] | None = None,
    on_activated: Callable[[str], None] | None = None,
) -> None:
    if buttons and on_activated is not None:
        toaster, toast = _build_label_toast(title, body, buttons, on_activated)
        _LIVE_TOASTS.append((toaster, toast))
        toaster.show_toast(toast)
        return

    from windows_toasts import Toast, WindowsToaster

    plain_toaster = WindowsToaster("model-vitals")
    plain = Toast()
    plain.text_fields = [title, body]
    plain_toaster.show_toast(plain)


class DesktopToast:
    name = "desktop"

    def __init__(
        self,
        notify: Callable[..., None] | None = None,
        on_label: Callable[[str], None] | None = None,
    ) -> None:
        self._notify = notify or _default_toast_notify
        self._on_label = on_label

    def _activated(self, arguments: str) -> None:
        if self._on_label is None or not arguments:
            return
        try:
            self._on_label(arguments)
        except Exception:
            return

    def send(self, payload: AlertPayload) -> None:
        from vitals.alert.labels import BUTTONS, encode_action

        body = payload.summary_text
        if payload.local_detail_path:
            body = f"{body}\ndetail: {payload.local_detail_path}"
        try:
            if payload.labelable and payload.alert_id is not None and self._on_label is not None:
                buttons = [
                    (caption, encode_action(payload.alert_id, label)) for caption, label in BUTTONS
                ]
                self._notify(payload.title, body, buttons, self._activated)
            else:
                self._notify(payload.title, body)
        except Exception as exc:  # pragma: no cover
            raise ChannelError(_safe_message(f"{self.name}: {exc}")) from None


_TELEGRAM_HOST = "api.telegram.org"
_TELEGRAM_TOKEN_RE = re.compile(r"/bot[^/]+/")


def mask_telegram_url(url: str) -> str:
    return _TELEGRAM_TOKEN_RE.sub("/bot***/", url)


class Telegram:
    name = "telegram"

    def __init__(
        self,
        token_env: str = "VITALS_TELEGRAM_TOKEN",
        chat_id_env: str = "VITALS_TELEGRAM_CHAT_ID",
        opener: Callable[[urllib.request.Request], object] | None = None,
    ) -> None:
        self._token_env = token_env
        self._chat_id_env = chat_id_env
        self._opener = opener or _urlopen

    def send(self, payload: AlertPayload) -> None:
        token = os.environ.get(self._token_env)
        chat_id = os.environ.get(self._chat_id_env)
        if not token or not chat_id:
            raise ChannelError(
                f"{self.name}: set {self._token_env} and {self._chat_id_env} to enable this channel"
            )
        url = f"https://{_TELEGRAM_HOST}/bot{token}/sendMessage"
        masked = mask_telegram_url(url)
        body = json.dumps({"chat_id": chat_id, "text": _compose_text(payload)}).encode("utf-8")
        request = urllib.request.Request(
            url, data=body, method="POST", headers={"Content-Type": "application/json"}
        )
        _post_and_check(self._opener, request, self.name, masked, secrets=[token, chat_id, url])


class Ntfy:
    name = "ntfy"

    def __init__(
        self,
        topic_env: str = "VITALS_NTFY_TOPIC",
        base_url: str = "https://ntfy.sh",
        opener: Callable[[urllib.request.Request], object] | None = None,
    ) -> None:
        self._topic_env = topic_env
        self._base_url = base_url.rstrip("/")
        self._opener = opener or _urlopen

    def send(self, payload: AlertPayload) -> None:
        topic = os.environ.get(self._topic_env)
        if not topic:
            raise ChannelError(f"{self.name}: set {self._topic_env} to enable this channel")
        url = f"{self._base_url}/{topic}"
        masked = f"{self._base_url}/***"
        body = _compose_text(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={"Title": payload.title.encode("ascii", "replace").decode("ascii")},
        )
        _post_and_check(self._opener, request, self.name, masked, secrets=[topic, url])


class Webhook:
    name = "webhook"

    def __init__(
        self,
        url_env: str = "VITALS_WEBHOOK_URL",
        opener: Callable[[urllib.request.Request], object] | None = None,
    ) -> None:
        self._url_env = url_env
        self._opener = opener or _urlopen

    def send(self, payload: AlertPayload) -> None:
        url = os.environ.get(self._url_env)
        if not url:
            raise ChannelError(f"{self.name}: set {self._url_env} to enable this channel")
        masked = _mask_host_only(url)
        selector = _raw_selector(url)
        body = json.dumps(
            {
                "severity": payload.severity,
                "attribution": payload.attribution,
                "title": payload.title,
                "summary_text": payload.summary_text,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            url, data=body, method="POST", headers={"Content-Type": "application/json"}
        )
        _post_and_check(self._opener, request, self.name, masked, secrets=[url, selector])


def load_channels(cfg) -> list[Channel]:
    channels_cfg = cfg.channels or {}
    channels: list[Channel] = []

    desktop_cfg = channels_cfg.get("desktop") or {}
    if desktop_cfg.get("enabled"):
        from vitals.alert.labels import handle_toast_action

        channels.append(
            DesktopToast(on_label=lambda arguments: handle_toast_action(cfg, arguments))
        )

    telegram_cfg = channels_cfg.get("telegram") or {}
    if telegram_cfg.get("enabled"):
        channels.append(
            Telegram(
                token_env=telegram_cfg.get("token_env", "VITALS_TELEGRAM_TOKEN"),
                chat_id_env=telegram_cfg.get("chat_id_env", "VITALS_TELEGRAM_CHAT_ID"),
            )
        )

    ntfy_cfg = channels_cfg.get("ntfy") or {}
    if ntfy_cfg.get("enabled"):
        channels.append(Ntfy(topic_env=ntfy_cfg.get("topic_env", "VITALS_NTFY_TOPIC")))

    webhook_cfg = channels_cfg.get("webhook") or {}
    if webhook_cfg.get("enabled"):
        channels.append(Webhook(url_env=webhook_cfg.get("url_env", "VITALS_WEBHOOK_URL")))

    return channels

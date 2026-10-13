from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlsplit

from vitals.report.redact import redact_text

if TYPE_CHECKING:
    from vitals.alert.protocol import ToastLinks

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


def _build_toast(title: str, body: str, links: ToastLinks | None) -> tuple[Any, Any]:
    from windows_toasts import InteractableWindowsToaster, Toast, ToastButton, WindowsToaster

    toast = Toast()
    toast.text_fields = [title, body]
    if links is None:
        return WindowsToaster("model-vitals"), toast
    toast.launch_action = links.open
    for caption, uri in links.buttons:
        toast.AddAction(ToastButton(caption, launch=uri))
    return InteractableWindowsToaster("model-vitals"), toast


def _default_toast_notify(title: str, body: str, links: ToastLinks | None = None) -> None:
    toaster, toast = _build_toast(title, body, links)
    toaster.show_toast(toast)


class DesktopToast:
    name = "desktop"

    def __init__(
        self,
        notify: Callable[..., None] | None = None,
        links: Callable[[int], ToastLinks] | None = None,
    ) -> None:
        self._notify = notify or _default_toast_notify
        self._links = links

    def _links_for(self, payload: AlertPayload) -> ToastLinks | None:
        if not payload.labelable or payload.alert_id is None or self._links is None:
            return None
        try:
            return self._links(payload.alert_id)
        except Exception:
            return None

    def send(self, payload: AlertPayload) -> None:
        body = payload.summary_text
        if payload.local_detail_path:
            body = f"{body}\ndetail: {payload.local_detail_path}"
        links = self._links_for(payload)
        try:
            if links is None:
                self._notify(payload.title, body)
            else:
                self._notify(payload.title, body, links)
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
        from vitals.alert import protocol

        links = None
        if protocol.is_registered():
            links = partial(protocol.toast_links, cfg.data_dir)
        channels.append(DesktopToast(links=links))

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

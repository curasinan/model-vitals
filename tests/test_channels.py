from __future__ import annotations

import http.client
import json
import sys
import traceback
import urllib.error

import pytest

from vitals.alert.channels import (
    AlertPayload,
    ChannelError,
    DesktopToast,
    Ntfy,
    Telegram,
    Webhook,
    load_channels,
    mask_telegram_url,
)
from vitals.alert.dispatcher import _summary_text
from vitals.alert.protocol import ToastLinks
from vitals.alert.rules import AlertDraft
from vitals.detect.attribution import Attribution


class _FakeResponse:
    def __init__(self, status: int = 200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _payload(**overrides) -> AlertPayload:
    fields = dict(
        severity="WARN",
        attribution="B",
        title="Multiple families degrading together: errors, latency",
        summary_text=(
            "3 anomaly signal(s) across families=[errors, latency]; models=[claude-sonnet-5]"
            " buckets=[gt180k]; attribution reason: harness_change"
        ),
        local_detail_path=None,
    )
    fields.update(overrides)
    return AlertPayload(**fields)


def test_telegram_posts_to_expected_host_and_path(monkeypatch):
    monkeypatch.setenv("VITALS_TELEGRAM_TOKEN", "TOK123")
    monkeypatch.setenv("VITALS_TELEGRAM_CHAT_ID", "chat-42")
    captured = {}

    def fake_opener(request):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["headers"] = request.headers
        return _FakeResponse()

    channel = Telegram(opener=fake_opener)
    channel.send(_payload())

    assert captured["url"] == "https://api.telegram.org/botTOK123/sendMessage"
    assert captured["body"]["chat_id"] == "chat-42"
    assert "WARN" in captured["body"]["text"]
    assert "Multiple families degrading together" in captured["body"]["text"]


def test_telegram_body_never_contains_a_session_id(monkeypatch):
    monkeypatch.setenv("VITALS_TELEGRAM_TOKEN", "TOK123")
    monkeypatch.setenv("VITALS_TELEGRAM_CHAT_ID", "chat-42")

    seeded_session_id = "sess-should-never-leak-abc123"
    draft = AlertDraft(
        severity="WARN",
        title="Multiple families degrading together: errors, latency",
        anomaly_ids=[1, 2],
        families=["errors", "latency"],
        suppressed_by_incident=None,
        dedup_key="k",
        first_seen="2026-08-01T00:00:00+00:00",
    )
    poisoned = Attribution(
        cls="B",
        evidence={
            "matched_rule_name": "harness_change",
            "strata": {"models": ["claude-sonnet-5"], "context_buckets": ["gt180k"]},
            "leaked_session_id": seeded_session_id,
        },
    )
    payload = AlertPayload(
        severity=draft.severity,
        attribution=poisoned.cls,
        title=draft.title,
        summary_text=_summary_text(draft, poisoned),
    )

    captured = {}

    def fake_opener(request):
        captured["url"] = request.full_url
        captured["body"] = request.data.decode("utf-8")
        return _FakeResponse()

    channel = Telegram(opener=fake_opener)
    channel.send(payload)

    assert seeded_session_id not in captured["body"]
    assert seeded_session_id not in captured["url"]
    assert "claude-sonnet-5" in captured["body"]
    assert "harness_change" in captured["body"]


def test_telegram_masks_token_on_send_failure(monkeypatch):
    monkeypatch.setenv("VITALS_TELEGRAM_TOKEN", "SUPERSECRETTOKEN")
    monkeypatch.setenv("VITALS_TELEGRAM_CHAT_ID", "chat-42")

    def boom(request):
        raise urllib.error.URLError("connection refused")

    channel = Telegram(opener=boom)
    with pytest.raises(ChannelError) as excinfo:
        channel.send(_payload())

    message = str(excinfo.value)
    assert "SUPERSECRETTOKEN" not in message
    assert "api.telegram.org/bot***/" in message


def test_telegram_masks_token_on_non_2xx_response(monkeypatch):
    monkeypatch.setenv("VITALS_TELEGRAM_TOKEN", "SUPERSECRETTOKEN")
    monkeypatch.setenv("VITALS_TELEGRAM_CHAT_ID", "chat-42")

    channel = Telegram(opener=lambda request: _FakeResponse(status=401))
    with pytest.raises(ChannelError) as excinfo:
        channel.send(_payload())

    message = str(excinfo.value)
    assert "SUPERSECRETTOKEN" not in message
    assert "api.telegram.org/bot***/" in message


def test_telegram_scrubs_a_token_that_leaks_through_invalidurl(monkeypatch):
    token = "1234567:AAF-REALTOKEN-xyz\n"
    monkeypatch.setenv("VITALS_TELEGRAM_TOKEN", token)
    monkeypatch.setenv("VITALS_TELEGRAM_CHAT_ID", "chat-42")

    def raise_invalid_url(request):
        path = f"/bot{token}/sendMessage"
        raise http.client.InvalidURL(
            f"URL can't contain control characters. {path!r} (found at least {chr(10)!r})"
        )

    channel = Telegram(opener=raise_invalid_url)
    with pytest.raises(ChannelError) as excinfo:
        channel.send(_payload())

    message = str(excinfo.value)
    assert token not in message
    assert "REALTOKEN" not in message
    assert "api.telegram.org/bot***/" in message


def test_short_chat_id_does_not_corrupt_unrelated_diagnostic_text(monkeypatch):
    monkeypatch.setenv("VITALS_TELEGRAM_TOKEN", "SUPERSECRETTOKENLONGENOUGH")
    monkeypatch.setenv("VITALS_TELEGRAM_CHAT_ID", "1")

    channel = Telegram(opener=lambda request: _FakeResponse(status=401))
    with pytest.raises(ChannelError) as excinfo:
        channel.send(_payload())

    message = str(excinfo.value)
    assert "HTTP 401" in message
    assert "SUPERSECRETTOKENLONGENOUGH" not in message


def test_realistic_length_telegram_token_is_still_scrubbed(monkeypatch):
    token = "123456789:AAHk3realisticLookingTelegramBotToken12"
    assert len(token) >= 46
    monkeypatch.setenv("VITALS_TELEGRAM_TOKEN", token)
    monkeypatch.setenv("VITALS_TELEGRAM_CHAT_ID", "chat-42")

    channel = Telegram(opener=lambda request: _FakeResponse(status=401))
    with pytest.raises(ChannelError) as excinfo:
        channel.send(_payload())

    message = str(excinfo.value)
    assert token not in message
    assert "HTTP 401" in message
    assert "api.telegram.org/bot***/" in message


def test_channel_error_hides_the_unscrubbed_cause_from_traceback_formatting(monkeypatch):
    token = "A_REALISTIC_LENGTH_SECRET_TOKEN_1234567890"
    assert len(token) >= 8
    monkeypatch.setenv("VITALS_TELEGRAM_TOKEN", token)
    monkeypatch.setenv("VITALS_TELEGRAM_CHAT_ID", "chat-42")

    def boom(request):
        raise urllib.error.URLError(f"connection refused while talking to secret {token}")

    channel = Telegram(opener=boom)
    with pytest.raises(ChannelError) as excinfo:
        channel.send(_payload())
    err = excinfo.value

    assert err.__cause__ is None
    formatted_1arg = "".join(traceback.format_exception(err))
    formatted_3arg = "".join(traceback.format_exception(type(err), err, err.__traceback__))
    assert token not in formatted_1arg
    assert token not in formatted_3arg


def test_telegram_raises_when_env_vars_missing(monkeypatch):
    monkeypatch.delenv("VITALS_TELEGRAM_TOKEN", raising=False)
    monkeypatch.delenv("VITALS_TELEGRAM_CHAT_ID", raising=False)
    channel = Telegram(opener=lambda request: _FakeResponse())
    with pytest.raises(ChannelError):
        channel.send(_payload())


def test_mask_telegram_url_strips_the_token():
    masked = mask_telegram_url("https://api.telegram.org/bot123456:ABCDEF-ghijk/sendMessage")
    assert masked == "https://api.telegram.org/bot***/sendMessage"
    assert "123456" not in masked
    assert "ABCDEF" not in masked


def test_ntfy_posts_body_to_topic_url(monkeypatch):
    monkeypatch.setenv("VITALS_NTFY_TOPIC", "my-secret-topic")
    captured = {}

    def fake_opener(request):
        captured["url"] = request.full_url
        captured["body"] = request.data.decode("utf-8")
        return _FakeResponse()

    channel = Ntfy(opener=fake_opener)
    channel.send(_payload())

    assert captured["url"] == "https://ntfy.sh/my-secret-topic"
    assert "WARN" in captured["body"]


def test_ntfy_masks_topic_on_failure(monkeypatch):
    monkeypatch.setenv("VITALS_NTFY_TOPIC", "my-secret-topic")

    def boom(request):
        raise urllib.error.URLError("timed out")

    channel = Ntfy(opener=boom)
    with pytest.raises(ChannelError) as excinfo:
        channel.send(_payload())

    message = str(excinfo.value)
    assert "my-secret-topic" not in message
    assert "ntfy.sh/***" in message


def test_ntfy_scrubs_a_topic_that_leaks_through_invalidurl(monkeypatch):
    topic = "my-secret-topic\n"
    monkeypatch.setenv("VITALS_NTFY_TOPIC", topic)

    def raise_invalid_url(request):
        path = f"/{topic}"
        raise http.client.InvalidURL(
            f"URL can't contain control characters. {path!r} (found at least {chr(10)!r})"
        )

    channel = Ntfy(opener=raise_invalid_url)
    with pytest.raises(ChannelError) as excinfo:
        channel.send(_payload())

    message = str(excinfo.value)
    assert topic not in message
    assert "my-secret-topic" not in message
    assert "ntfy.sh/***" in message


def test_short_ntfy_topic_does_not_corrupt_unrelated_diagnostic_text(monkeypatch):
    monkeypatch.setenv("VITALS_NTFY_TOPIC", "test")

    def boom(request):
        raise RuntimeError("self-test probe")

    channel = Ntfy(opener=boom)
    with pytest.raises(ChannelError) as excinfo:
        channel.send(_payload())

    message = str(excinfo.value)
    assert "self-test probe" in message
    assert "ntfy.sh/***" in message


def test_ntfy_raises_when_topic_missing(monkeypatch):
    monkeypatch.delenv("VITALS_NTFY_TOPIC", raising=False)
    channel = Ntfy(opener=lambda request: _FakeResponse())
    with pytest.raises(ChannelError):
        channel.send(_payload())


def test_webhook_posts_json_without_local_detail_path(monkeypatch):
    monkeypatch.setenv("VITALS_WEBHOOK_URL", "https://hooks.example.com/services/T00/B00/xyz")
    captured = {}

    def fake_opener(request):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return _FakeResponse()

    channel = Webhook(opener=fake_opener)
    channel.send(_payload(local_detail_path="C:/Users/someone/.model-vitals/reports/alert-9.json"))

    assert captured["url"] == "https://hooks.example.com/services/T00/B00/xyz"
    assert captured["body"]["severity"] == "WARN"
    assert captured["body"]["title"] == _payload().title
    assert "local_detail_path" not in captured["body"]
    assert "alert-9.json" not in json.dumps(captured["body"])


def test_webhook_masks_url_path_on_failure(monkeypatch):
    monkeypatch.setenv("VITALS_WEBHOOK_URL", "https://hooks.example.com/services/T00/B00/xyz")

    def boom(request):
        raise urllib.error.URLError("refused")

    channel = Webhook(opener=boom)
    with pytest.raises(ChannelError) as excinfo:
        channel.send(_payload())

    message = str(excinfo.value)
    assert "T00/B00/xyz" not in message
    assert "hooks.example.com" in message


def test_webhook_scrubs_the_url_path_that_leaks_through_invalidurl(monkeypatch):
    selector = "/services/T00\nB00/xyz"
    monkeypatch.setenv("VITALS_WEBHOOK_URL", f"https://hooks.example.com{selector}")

    def raise_invalid_url(request):
        raise http.client.InvalidURL(
            f"URL can't contain control characters. {selector!r} (found at least {chr(10)!r})"
        )

    channel = Webhook(opener=raise_invalid_url)
    with pytest.raises(ChannelError) as excinfo:
        channel.send(_payload())

    message = str(excinfo.value)
    assert "T00" not in message
    assert "B00/xyz" not in message
    assert "hooks.example.com" in message


def test_webhook_raises_when_url_missing(monkeypatch):
    monkeypatch.delenv("VITALS_WEBHOOK_URL", raising=False)
    channel = Webhook(opener=lambda request: _FakeResponse())
    with pytest.raises(ChannelError):
        channel.send(_payload())


def test_desktop_toast_uses_injected_notify_and_never_touches_windows_toasts():
    calls = []
    channel = DesktopToast(notify=lambda title, body: calls.append((title, body)))
    channel.send(_payload(local_detail_path="C:/Users/someone/.model-vitals/reports/alert-1.json"))

    assert len(calls) == 1
    title, body = calls[0]
    assert title == _payload().title
    assert "alert-1.json" in body


def test_desktop_toast_without_local_detail_path_does_not_mention_one():
    calls = []
    channel = DesktopToast(notify=lambda title, body: calls.append((title, body)))
    channel.send(_payload(local_detail_path=None))
    _, body = calls[0]
    assert "detail" not in body.lower()


def test_desktop_toast_wraps_notify_failure():
    def boom(title, body):
        raise OSError("no toast backend")

    channel = DesktopToast(notify=boom)
    with pytest.raises(ChannelError):
        channel.send(_payload())


def test_channels_module_imports_without_windows_toasts(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def blocking_import(name, *args, **kwargs):
        if name == "windows_toasts":
            raise ImportError("simulated: windows_toasts not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocking_import)

    import importlib

    import vitals.alert.channels as channels_mod

    original_namespace = dict(channels_mod.__dict__)
    try:
        importlib.reload(channels_mod)
        channel = channels_mod.DesktopToast(notify=lambda title, body: None)
        channel.send(_payload())
    finally:
        channels_mod.__dict__.clear()
        channels_mod.__dict__.update(original_namespace)

    assert channels_mod.ChannelError is ChannelError


class _Cfg:
    def __init__(self, channels: dict):
        self.channels = channels


def test_load_channels_only_constructs_enabled_ones(monkeypatch):
    constructed = {"telegram": 0, "ntfy": 0, "webhook": 0}

    class SpyTelegram:
        name = "telegram"

        def __init__(self, **kwargs):
            constructed["telegram"] += 1

        def send(self, payload):  # pragma: no cover
            raise AssertionError("disabled channel must never send")

    import vitals.alert.channels as channels_mod

    monkeypatch.setattr(channels_mod, "Telegram", SpyTelegram)

    cfg = _Cfg(
        {
            "desktop": {"enabled": True},
            "telegram": {"enabled": False},
            "ntfy": {"enabled": False},
            "webhook": {"enabled": False},
        }
    )
    result = channels_mod.load_channels(cfg)

    assert constructed["telegram"] == 0
    assert [c.name for c in result] == ["desktop"]


def test_load_channels_constructs_every_enabled_channel(monkeypatch):
    monkeypatch.setenv("VITALS_TELEGRAM_TOKEN", "t")
    monkeypatch.setenv("VITALS_TELEGRAM_CHAT_ID", "c")
    monkeypatch.setenv("VITALS_NTFY_TOPIC", "topic")
    monkeypatch.setenv("VITALS_WEBHOOK_URL", "https://example.com/hook")

    cfg = _Cfg(
        {
            "desktop": {"enabled": True},
            "telegram": {"enabled": True},
            "ntfy": {"enabled": True},
            "webhook": {"enabled": True},
        }
    )
    result = load_channels(cfg)
    assert {c.name for c in result} == {"desktop", "telegram", "ntfy", "webhook"}


def test_load_channels_empty_config_returns_nothing():
    assert load_channels(_Cfg({})) == []


def test_load_channels_respects_custom_env_var_names(monkeypatch):
    monkeypatch.setenv("MY_NTFY_TOPIC", "topic2")
    cfg = _Cfg({"ntfy": {"enabled": True, "topic_env": "MY_NTFY_TOPIC"}})
    result = load_channels(cfg)
    assert len(result) == 1
    captured = {}

    def fake_opener(request):
        captured["url"] = request.full_url
        return _FakeResponse()

    result[0]._opener = fake_opener
    result[0].send(_payload())
    assert captured["url"] == "https://ntfy.sh/topic2"


def test_channel_protocol_docstring_states_the_scrub_floor_invariant():
    from vitals.alert.channels import _MIN_SCRUB_LEN, Channel

    doc = Channel.__doc__ or ""
    assert str(_MIN_SCRUB_LEN) in doc
    assert "scrub" in doc.lower()
    assert "url" in doc.lower()


def test_channel_error_redacts_a_secret_the_scrubber_never_knew_about(monkeypatch):
    monkeypatch.setenv("VITALS_WEBHOOK_URL", "https://hooks.example.com/services/ABCDEF123456")

    def boom(request):
        raise RuntimeError('upstream rejected {\\"token\\": \\"s3cr3tvalue\\"} in the body')

    with pytest.raises(ChannelError) as excinfo:
        Webhook(opener=boom).send(_payload())

    message = str(excinfo.value)
    assert "s3cr3tvalue" not in message
    assert "<REDACTED:assignment>" in message


def test_channel_error_redacts_a_local_path_and_an_email(monkeypatch):
    monkeypatch.setenv("VITALS_NTFY_TOPIC", "my-alerts-topic")

    def boom(request):
        raise RuntimeError(r"relay failed; see C:\Users\asus\logs\ntfy.txt or mail ops@example.com")

    with pytest.raises(ChannelError) as excinfo:
        Ntfy(opener=boom).send(_payload())

    message = str(excinfo.value)
    assert "asus" not in message
    assert "ops@example.com" not in message
    assert "<REDACTED:path>" in message and "<REDACTED:email>" in message


def test_desktop_toast_error_is_redacted_too():
    def boom(title, body):
        raise RuntimeError(r"toast backend died writing C:\Users\asus\AppData\x.log")

    with pytest.raises(ChannelError) as excinfo:
        DesktopToast(notify=boom).send(_payload())

    assert "asus" not in str(excinfo.value)


def test_redaction_does_not_mangle_ordinary_diagnostic_text(monkeypatch):
    monkeypatch.setenv("VITALS_TELEGRAM_TOKEN", "123456789:AAHk3realisticLookingBotToken12345")
    monkeypatch.setenv("VITALS_TELEGRAM_CHAT_ID", "chat-42")

    channel = Telegram(opener=lambda request: _FakeResponse(status=503))
    with pytest.raises(ChannelError) as excinfo:
        channel.send(_payload())

    message = str(excinfo.value)
    assert "HTTP 503" in message
    assert "api.telegram.org/bot***/" in message


def _links(alert_id):
    return ToastLinks(
        f"open:{alert_id}",
        [("Real", f"real:{alert_id}"), ("False alarm", f"fa:{alert_id}")],
    )


def test_desktop_toast_carries_links_for_a_labelable_alert():
    calls = []
    channel = DesktopToast(
        notify=lambda title, body, links: calls.append(links),
        links=_links,
    )
    channel.send(_payload(alert_id=7, labelable=True))

    assert calls == [_links(7)]


def test_desktop_toast_has_no_links_without_an_alert_id_or_a_registered_handler():
    calls = []
    plain = DesktopToast(notify=lambda title, body: calls.append(title), links=_links)
    plain.send(_payload(alert_id=None, labelable=True))
    no_handler = DesktopToast(notify=lambda title, body: calls.append(title))
    no_handler.send(_payload(alert_id=3, labelable=True))
    not_labelable = DesktopToast(notify=lambda title, body: calls.append(title), links=_links)
    not_labelable.send(_payload(alert_id=3, labelable=False))
    assert len(calls) == 3


def test_a_failing_link_builder_still_shows_a_plain_toast():
    calls = []

    def boom(alert_id):
        raise OSError("key file unreadable")

    channel = DesktopToast(notify=lambda title, body: calls.append(title), links=boom)
    channel.send(_payload(alert_id=1, labelable=True))
    assert len(calls) == 1


@pytest.mark.skipif(sys.platform != "win32", reason="windows-toasts is only installed on Windows")
def test_the_real_toast_launches_signed_links_through_the_protocol():
    from vitals.alert.channels import _build_toast

    links = ToastLinks(
        "model-vitals://open?alert=1&sig=ab",
        [
            ("Real", "model-vitals://label?alert=1&label=real&sig=cd"),
            ("Not sure", "model-vitals://label?alert=1&label=unsure&sig=ef"),
        ],
    )
    toaster, toast = _build_toast("title", "body", links)

    assert toast.launch_action == links.open
    assert [a.launch for a in toast.actions] == [uri for _, uri in links.buttons]
    assert type(toaster).__name__ == "InteractableWindowsToaster"
    xml = toaster._setup_toast(toast, False).xmlDocument.get_xml()
    assert xml.count('activationType="protocol"') == 3
    assert "label=real&amp;sig=cd" in xml


@pytest.mark.skipif(sys.platform != "win32", reason="windows-toasts is only installed on Windows")
def test_the_real_plain_toast_has_no_actions():
    from vitals.alert.channels import _build_toast

    toaster, toast = _build_toast("title", "body", None)

    assert toast.actions == []
    assert toast.launch_action is None
    assert type(toaster).__name__ == "WindowsToaster"

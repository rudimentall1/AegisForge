from types import SimpleNamespace

from notify import send_telegram_alert


def test_telegram_alert_requires_runtime_credentials(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)

    assert send_telegram_alert("test alert") is False


def test_telegram_alert_uses_runtime_credentials(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "test-chat")
    captured = {}

    def fake_post(url, json, timeout):
        captured.update(url=url, payload=json, timeout=timeout)
        return SimpleNamespace(status_code=200, text="ok")

    monkeypatch.setattr("notify.requests.post", fake_post)

    assert send_telegram_alert("critical finding", severity="CRITICAL") is True
    assert captured["url"] == "https://api.telegram.org/bottest-token/sendMessage"
    assert captured["payload"]["chat_id"] == "test-chat"
    assert "CRITICAL" in captured["payload"]["text"]

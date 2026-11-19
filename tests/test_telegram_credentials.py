from types import SimpleNamespace

import agents.notifier as agent_notifier
import audit_bot
import wallet_watcher


def test_agents_notifier_requires_runtime_credentials(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)

    assert agent_notifier.send_telegram_alert("base", "", "critical", "patch.sol") is False


def test_audit_bot_requires_runtime_token(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)

    assert audit_bot.send("123", "message") is False


def test_wallet_watcher_requires_runtime_credentials(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)

    assert wallet_watcher.send_alert("low balance") is False


def test_alert_modules_use_runtime_credentials(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "test-chat")
    calls = []

    def fake_post(url, json, timeout, **kwargs):
        calls.append((url, json))
        return SimpleNamespace(status_code=200, text="ok", json=lambda: {"ok": True})

    monkeypatch.setattr(agent_notifier.requests, "post", fake_post)
    monkeypatch.setattr(audit_bot.requests, "post", fake_post)
    monkeypatch.setattr(wallet_watcher.requests, "post", fake_post)

    assert agent_notifier.send_telegram_alert("base", "", "critical", "patch.sol") is True
    assert audit_bot.send("test-chat", "audit result") is True
    assert wallet_watcher.send_alert("low balance") is True
    assert len(calls) == 3
    assert all("bottest-token/" in url for url, _ in calls)

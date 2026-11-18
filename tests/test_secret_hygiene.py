import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_FILES = (
    "notify.py",
    "agents/notifier.py",
    "audit_bot.py",
    "wallet_watcher.py",
    "agents/rpc_monitor.py",
    "rescue.py",
    "agents/config.py",
)

TELEGRAM_TOKEN_PATTERN = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b")
PRIVATE_KEY_LITERAL_PATTERN = re.compile(
    r"""(?:PRIVATE_KEY|RESCUE_PRIVATE_KEY)\s*=\s*["']0x[0-9a-fA-F]{64}["']"""
)


def test_runtime_credentials_are_not_hardcoded_in_production_modules():
    for relative_path in PRODUCTION_FILES:
        source = (ROOT / relative_path).read_text(encoding="utf-8")
        assert TELEGRAM_TOKEN_PATTERN.search(source) is None, relative_path
        assert PRIVATE_KEY_LITERAL_PATTERN.search(source) is None, relative_path

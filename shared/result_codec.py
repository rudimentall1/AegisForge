"""Compact JSON encoding for persistent AegisForge task results."""

import json
import zlib


MAGIC = b"AFZ1"


def encode(value):
    """Return UTF-8 JSON or compressed bytes, whichever is smaller."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    raw = text.encode("utf-8")
    compressed = MAGIC + zlib.compress(raw, level=6)
    return compressed if len(compressed) < len(raw) else text


def decode(value):
    """Decode legacy JSON text and current compressed result values."""
    if value is None:
        return None
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytes):
        if value.startswith(MAGIC):
            return json.loads(zlib.decompress(value[len(MAGIC):]).decode("utf-8"))
        value = value.decode("utf-8")
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return value

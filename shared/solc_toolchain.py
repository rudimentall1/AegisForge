"""Shared resolution of a locally installed, versioned solc binary."""
from __future__ import annotations

import os
from pathlib import Path


def resolve_solc_binary(version: str) -> Path | None:
    """Resolve the exact configured/solc-select artifact without installing it."""
    if not isinstance(version, str) or not version:
        return None
    configured_path = os.getenv("AEGISFORGE_SOLC_BINARY", "").strip()
    if configured_path:
        path = Path(configured_path).expanduser()
    else:
        try:
            from solc_select.solc_select import artifact_path

            path = Path(artifact_path(version)).expanduser()
        except (ImportError, OSError, ValueError):
            return None
    if not path.is_file() or not os.access(path, os.X_OK):
        return None
    return path

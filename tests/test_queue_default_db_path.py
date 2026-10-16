import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _reported_db_path(env):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from shared.queue import DB_PATH; print(DB_PATH)",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return Path(result.stdout.strip())


def test_default_queue_database_path_is_repository_relative():
    env = os.environ.copy()
    env.pop("AEGISFORGE_DB_PATH", None)

    assert _reported_db_path(env) == ROOT / "data" / "agent_farm.db"


def test_queue_database_path_can_be_configured_with_environment(tmp_path):
    configured = tmp_path / "isolated" / "custom.db"
    env = os.environ.copy()
    env["AEGISFORGE_DB_PATH"] = str(configured)

    assert _reported_db_path(env) == configured

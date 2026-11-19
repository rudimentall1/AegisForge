from pathlib import Path


UNIT_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "systemd"
    / "aegisforge-worker@.service"
)


def test_worker_unit_runs_the_python_worker_directly_with_instance_argument():
    unit = UNIT_PATH.read_text(encoding="utf-8")

    assert "ExecStart=/opt/agent-farm/.venv/bin/python -m agents.worker %i" in unit
    assert "while true" not in unit
    assert "Restart=on-failure" in unit
    assert "KillSignal=SIGINT" in unit


def test_default_worker_manifest_covers_all_research_roles_but_not_executor():
    manifest = (
        UNIT_PATH.parent / "worker-roles.default"
    ).read_text(encoding="utf-8")
    roles = {
        line.strip()
        for line in manifest.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    from agents.worker import AGENTS

    assert roles == set(AGENTS) - {"executor"}

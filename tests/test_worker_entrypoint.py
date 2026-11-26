import pytest

import agents.worker as worker


def test_main_rejects_empty_role_before_creating_worker(monkeypatch, capsys):
    monkeypatch.setattr(worker.sys, "argv", ["agents.worker", ""])

    with pytest.raises(SystemExit) as exc:
        worker.main()

    assert exc.value.code == 2
    assert "Role must not be empty" in capsys.readouterr().err

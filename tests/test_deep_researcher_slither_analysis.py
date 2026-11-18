import json
import subprocess

from agents.deep_researcher.slither_analysis import (
    analyze_source,
    parse_slither_json,
)


def test_parse_slither_report_keeps_detector_findings_unconfirmed():
    payload = {
        "success": True,
        "results": {
            "detectors": [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "confidence": "Medium",
                    "description": "External call before state update.",
                    "elements": [{"type": "function", "name": "withdraw"}],
                }
            ]
        },
    }

    result = parse_slither_json(json.dumps(payload))

    assert result["status"] == "ANALYZED"
    assert result["findings"] == [
        {
            "detector": "reentrancy-eth",
            "impact": "HIGH",
            "confidence": "MEDIUM",
            "description": "External call before state update.",
            "elements": [{"type": "function", "name": "withdraw"}],
            "status": "UNVERIFIED_POTENTIAL",
        }
    ]
    assert result["vulnerabilities_confirmed"] is False


def test_parse_slither_report_rejects_malformed_json():
    result = parse_slither_json("{not-json")

    assert result["status"] == "INVALID_REPORT"
    assert result["findings"] == []
    assert result["vulnerabilities_confirmed"] is False


def test_analyze_source_invokes_slither_and_parses_report(monkeypatch):
    import agents.deep_researcher.slither_analysis as module

    payload = {
        "success": True,
        "results": {
            "detectors": [
                {
                    "check": "arbitrary-send-erc20",
                    "impact": "High",
                    "confidence": "High",
                    "description": "Potential arbitrary token transfer.",
                    "elements": [],
                }
            ]
        },
    }
    observed = {}

    monkeypatch.setattr(module.shutil, "which", lambda binary: "/usr/bin/slither")

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        source_path = command[1]
        with open(source_path, encoding="utf-8") as source_file:
            observed["source"] = source_file.read()
        return subprocess.CompletedProcess(
            command, 255, stdout=json.dumps(payload), stderr="detector findings"
        )

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    result = analyze_source("pragma solidity ^0.8.20; contract Vault {}", timeout=17)

    assert result["status"] == "ANALYZED"
    assert result["findings"][0]["detector"] == "arbitrary-send-erc20"
    assert result["vulnerabilities_confirmed"] is False
    assert observed["source"] == "pragma solidity ^0.8.20; contract Vault {}"
    assert observed["command"][0] == "/usr/bin/slither"
    assert observed["command"][-2:] == ["--json", "-"]
    assert observed["kwargs"]["timeout"] == 17


def test_analyze_source_reports_tool_unavailable(monkeypatch):
    import agents.deep_researcher.slither_analysis as module

    monkeypatch.setattr(module.shutil, "which", lambda binary: None)

    result = analyze_source("pragma solidity ^0.8.20; contract Vault {}")

    assert result["status"] == "TOOL_UNAVAILABLE"
    assert result["findings"] == []
    assert result["vulnerabilities_confirmed"] is False


def test_analyze_source_reports_timeout(monkeypatch):
    import agents.deep_researcher.slither_analysis as module

    monkeypatch.setattr(module.shutil, "which", lambda binary: "/usr/bin/slither")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(module.subprocess, "run", timeout)

    result = analyze_source("pragma solidity ^0.8.20; contract Vault {}", timeout=3)

    assert result["status"] == "TIMEOUT"
    assert result["findings"] == []
    assert result["vulnerabilities_confirmed"] is False



def test_analyze_source_supports_etherscan_multifile_standard_json(monkeypatch):
    import agents.deep_researcher.slither_analysis as module

    project = {
        "language": "Solidity",
        "sources": {
            "contracts/Vault.sol": {
                "content": "pragma solidity ^0.8.20; import './Guard.sol'; contract Vault is Guard {}"
            },
            "contracts/Guard.sol": {
                "content": "pragma solidity ^0.8.20; contract Guard {}"
            },
        },
        "settings": {
            "remappings": ["@openzeppelin/=lib/openzeppelin-contracts/"]
        },
    }
    observed = {}
    monkeypatch.setattr(module.shutil, "which", lambda binary: "/usr/bin/slither")

    def fake_run(command, **kwargs):
        observed["command"] = command
        target = command[1]
        observed["is_directory"] = __import__("os").path.isdir(target)
        observed["files"] = sorted(
            path.relative_to(target).as_posix()
            for path in __import__("pathlib").Path(target).rglob("*.sol")
        )
        observed["vault_source"] = (
            __import__("pathlib").Path(target) / "contracts/Vault.sol"
        ).read_text(encoding="utf-8")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps({"success": True, "results": {"detectors": []}}),
            stderr="",
        )

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    etherscan_source = "{" + json.dumps(project) + "}"

    result = analyze_source(etherscan_source)

    assert result["status"] == "ANALYZED"
    assert result["source_mode"] == "multi_file"
    assert result["source_file_count"] == 2
    assert observed["is_directory"] is True
    assert observed["files"] == ["contracts/Guard.sol", "contracts/Vault.sol"]
    assert "import './Guard.sol';" in observed["vault_source"]
    assert "--solc-remaps" in observed["command"]
    assert "@openzeppelin/=lib/openzeppelin-contracts/" in observed["command"]


def test_analyze_source_rejects_multifile_path_traversal(monkeypatch):
    import agents.deep_researcher.slither_analysis as module

    project = {
        "language": "Solidity",
        "sources": {
            "../outside.sol": {"content": "pragma solidity ^0.8.20; contract Outside {}"}
        },
    }
    monkeypatch.setattr(module.shutil, "which", lambda binary: "/usr/bin/slither")

    result = analyze_source("{" + json.dumps(project) + "}")

    assert result["status"] == "INVALID_SOURCE_PROJECT"
    assert result["findings"] == []
    assert result["vulnerabilities_confirmed"] is False

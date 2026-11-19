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
    observed = []
    monkeypatch.setattr(module.shutil, "which", lambda binary: "/usr/bin/slither")

    def fake_run(command, **kwargs):
        source_path = __import__("pathlib").Path(command[1])
        observed.append({
            "source": source_path.read_text(encoding="utf-8"),
            "relative_path": source_path.relative_to(kwargs["cwd"]).as_posix(),
            "command": command,
        })
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
    assert result["analysis_entrypoints_count"] == 2
    assert sorted(item["relative_path"] for item in observed) == [
        "contracts/Guard.sol",
        "contracts/Vault.sol",
    ]
    assert any("import './Guard.sol';" in item["source"] for item in observed)
    assert all("--solc-remaps" in item["command"] for item in observed)
    assert all(
        "@openzeppelin/=lib/openzeppelin-contracts/" in item["command"]
        for item in observed
    )


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



def test_analyze_source_rejects_empty_normalized_project_path(monkeypatch):
    import agents.deep_researcher.slither_analysis as module

    project = {
        "language": "Solidity",
        "sources": {
            ".": {"content": "pragma solidity ^0.8.20; contract Invalid {}"}
        },
    }
    monkeypatch.setattr(module.shutil, "which", lambda binary: "/usr/bin/slither")

    result = analyze_source("{" + json.dumps(project) + "}")

    assert result["status"] == "INVALID_SOURCE_PROJECT"
    assert result["vulnerabilities_confirmed"] is False


def test_analyze_source_reports_missing_solidity_compiler(monkeypatch):
    import agents.deep_researcher.slither_analysis as module

    monkeypatch.setattr(module.shutil, "which", lambda binary: "/usr/bin/slither")
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, stdout="", stderr="solc executable not found"
        ),
    )

    result = analyze_source("pragma solidity ^0.8.20; contract Vault {}")

    assert result["status"] == "COMPILER_UNAVAILABLE"
    assert result["vulnerabilities_confirmed"] is False



def test_analyze_source_selects_verified_solidity_compiler_without_global_switch(monkeypatch):
    import agents.deep_researcher.slither_analysis as module

    observed = {}
    monkeypatch.setattr(
        module.shutil,
        "which",
        lambda binary: (
            "/usr/bin/solc"
            if binary == "solc"
            else None if binary == "solc-select"
            else "/usr/bin/slither"
        ),
    )

    def fake_run(command, **kwargs):
        if command[0] == "/usr/bin/solc":
            observed["compiler_env"] = kwargs["env"].get("SOLC_VERSION")
            return subprocess.CompletedProcess(
                command, 0, stdout="Version: 0.8.20+commit.a1b79de6", stderr=""
            )
        observed["slither_env"] = kwargs["env"].get("SOLC_VERSION")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps({"success": True, "results": {"detectors": []}}),
            stderr="",
        )

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    result = analyze_source(
        "pragma solidity ^0.8.20; contract Vault {}",
        compiler_version="v0.8.20+commit.a1b79de6",
    )

    assert result["status"] == "ANALYZED"
    assert result["compiler_version"] == "0.8.20"
    assert observed["compiler_env"] == "0.8.20"
    assert observed["slither_env"] == "0.8.20"


def test_analyze_source_rejects_mismatched_solidity_compiler(monkeypatch):
    import agents.deep_researcher.slither_analysis as module

    monkeypatch.setattr(
        module.shutil,
        "which",
        lambda binary: (
            "/usr/bin/solc"
            if binary == "solc"
            else None if binary == "solc-select"
            else "/usr/bin/slither"
        ),
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 0, stdout="Version: 0.8.19+commit.7dd6d404", stderr=""
        )

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    result = analyze_source(
        "pragma solidity ^0.8.20; contract Vault {}",
        compiler_version="v0.8.20+commit.a1b79de6",
    )

    assert result["status"] == "COMPILER_VERSION_MISMATCH"
    assert result["vulnerabilities_confirmed"] is False


def test_analyze_source_rejects_untrusted_compiler_version(monkeypatch):
    import agents.deep_researcher.slither_analysis as module

    monkeypatch.setattr(module.shutil, "which", lambda binary: "/usr/bin/slither")
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not execute")),
    )

    result = analyze_source(
        "pragma solidity ^0.8.20; contract Vault {}",
        compiler_version="0.8.20; echo unsafe",
    )

    assert result["status"] == "INVALID_CONFIGURATION"
    assert result["vulnerabilities_confirmed"] is False



def test_analyze_source_can_install_exact_compiler_without_global_switch(monkeypatch):
    import agents.deep_researcher.slither_analysis as module

    observed = {"install_commands": [], "installed": False}
    monkeypatch.setenv("AEGISFORGE_AUTO_INSTALL_SOLC", "1")
    monkeypatch.setattr(
        module.shutil,
        "which",
        lambda binary: {
            "solc-select": "/usr/bin/solc-select",
            "solc": "/usr/bin/solc",
            "slither": "/usr/bin/slither",
        }.get(binary),
    )

    def fake_run(command, **kwargs):
        if command[0] == "/usr/bin/solc":
            assert kwargs["env"]["SOLC_VERSION"] == "0.8.20"
            if not observed["installed"]:
                return subprocess.CompletedProcess(
                    command, 1, stdout="", stderr="requested solc version not installed"
                )
            return subprocess.CompletedProcess(
                command, 0, stdout="Version: 0.8.20+commit.a1b79de6", stderr=""
            )
        if command[0] == "/usr/bin/solc-select":
            observed["install_commands"].append(command)
            observed["installed"] = True
            return subprocess.CompletedProcess(command, 0, stdout="installed", stderr="")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps({"success": True, "results": {"detectors": []}}),
            stderr="",
        )

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    result = analyze_source(
        "pragma solidity ^0.8.20; contract Vault {}",
        compiler_version="v0.8.20+commit.a1b79de6",
    )

    assert result["status"] == "ANALYZED"
    assert result["compiler_installed"] is True
    assert observed["install_commands"] == [
        ["/usr/bin/solc-select", "install", "0.8.20"]
    ]


def test_analyze_source_does_not_install_compiler_without_opt_in(monkeypatch):
    import agents.deep_researcher.slither_analysis as module

    monkeypatch.setenv("AEGISFORGE_AUTO_INSTALL_SOLC", "0")
    monkeypatch.setattr(
        module.shutil,
        "which",
        lambda binary: {
            "solc-select": "/usr/bin/solc-select",
            "solc": "/usr/bin/solc",
            "slither": "/usr/bin/slither",
        }.get(binary),
    )
    observed = {"install_called": False}

    def fake_run(command, **kwargs):
        if command[0] == "/usr/bin/solc":
            return subprocess.CompletedProcess(
                command, 1, stdout="", stderr="requested solc version not installed"
            )
        if command[0] == "/usr/bin/solc-select":
            observed["install_called"] = True
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    result = analyze_source(
        "pragma solidity ^0.8.20; contract Vault {}",
        compiler_version="v0.8.20+commit.a1b79de6",
    )

    assert result["status"] == "COMPILER_UNAVAILABLE"
    assert observed["install_called"] is False
    assert result["vulnerabilities_confirmed"] is False


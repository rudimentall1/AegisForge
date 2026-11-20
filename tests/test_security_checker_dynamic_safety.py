from agents.security_checker.agent import SecurityChecker


def test_foundry_validation_reports_missing_finding_specific_integration():
    checker = SecurityChecker.__new__(SecurityChecker)
    findings = [
        {"rule": "reentrancy", "severity": "HIGH"},
        {"rule": "unchecked-call", "severity": "MEDIUM"},
        {"rule": "informational", "severity": "LOW"},
    ]

    results = checker._run_foundry_fork_validation(
        findings,
        "arbitrum",
        "0x" + "11" * 20,
    )

    assert len(results) == 2
    assert all(item["dynamic_verified"] is False for item in results)
    assert all(item["status"] == "SKIPPED" for item in results)
    assert all(
        item["reason"] == "finding_specific_execution_not_integrated"
        for item in results
    )
    assert all(
        item["required_next_step"] == "implement_finding_specific_fork_execution"
        for item in results
    )


def test_foundry_validation_never_claims_a_finding_is_confirmed():
    checker = SecurityChecker.__new__(SecurityChecker)
    results = checker._run_foundry_fork_validation(
        [{"rule": "reentrancy", "severity": "CRITICAL"}],
        "arbitrum",
        "0x" + "22" * 20,
    )

    assert results[0]["dynamic_verified"] is False
    assert results[0]["confirmed"] is False
    assert results[0]["status"] == "SKIPPED"
    assert results[0]["reason"] == "finding_specific_execution_not_integrated"


def test_security_checker_materializes_source_files_before_running_slither(monkeypatch):
    from types import SimpleNamespace
    import shutil

    checker = SecurityChecker.__new__(SecurityChecker)
    checker.github = SimpleNamespace(BASE_URL="https://api.github.com")
    files = {
        "contracts/Vault.sol": "pragma solidity ^0.8.20; contract Vault {}",
        "foundry.toml": "[profile.default]\nsrc = 'contracts'\n",
    }
    observed = {}

    monkeypatch.setattr(checker, "_repo_parts", lambda name: ("owner", "repo"))
    monkeypatch.setattr(checker, "_get", lambda url: {"default_branch": "main"})
    monkeypatch.setattr(
        checker,
        "_get_tree",
        lambda owner, repo, branch: {
            "tree": [
                {"type": "blob", "path": "contracts/Vault.sol"},
                {"type": "blob", "path": "foundry.toml"},
            ],
            "truncated": False,
        },
    )
    monkeypatch.setattr(
        checker,
        "_select_solidity_files",
        lambda paths: ["contracts/Vault.sol"],
    )
    monkeypatch.setattr(
        checker,
        "_select_supporting_files",
        lambda paths: ["foundry.toml"],
    )
    monkeypatch.setattr(
        checker,
        "_get_file",
        lambda owner, repo, path: files.get(path),
    )
    monkeypatch.setattr(checker, "_scan_source", lambda path, content: [])
    monkeypatch.setattr(
        checker,
        "_security_posture",
        lambda **kwargs: {"score": 80, "posture": "STRONG", "signals": []},
    )
    monkeypatch.setenv("AEGISFORGE_ENABLE_REPOSITORY_SLITHER", "1")
    monkeypatch.delenv("AEGISFORGE_ENABLE_MYTHRIL", raising=False)
    monkeypatch.delenv("AEGISFORGE_ENABLE_LOCAL_LLM_REVIEW", raising=False)
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name: "/usr/bin/slither" if name == "slither" else None,
    )

    def fake_slither(repo_path):
        from pathlib import Path

        root = Path(repo_path)
        observed["repo_path"] = str(root)
        observed["solidity"] = (root / "contracts" / "Vault.sol").read_text()
        observed["config"] = (root / "foundry.toml").read_text()
        return [
            {
                "rule": "slither_test_detector",
                "severity": "HIGH",
                "file": "contracts/Vault.sol",
                "description": "synthetic Slither result",
                "status": "POTENTIAL_RISK",
            }
        ]

    monkeypatch.setattr(checker, "_run_slither_analysis", fake_slither)

    result = checker._inspect_repository(
        {
            "name": "owner/repo",
            "url": "https://github.com/owner/repo",
            "smart_contract_project": True,
            "risk_flags": [],
        }
    )

    from pathlib import Path

    assert observed["solidity"] == files["contracts/Vault.sol"]
    assert observed["config"] == files["foundry.toml"]
    assert not Path(observed["repo_path"]).exists()
    assert result["analysis_tool_status"]["slither"] == "COMPLETED"
    assert result["analysis_scope"] == "pattern_scan_and_slither_static_analysis"
    assert result["finding_summary"]["high"] == 1
    assert result["dynamic_validation_status"] == "FINDING_SPECIFIC_VALIDATION_NOT_IMPLEMENTED"
    assert result["dynamic_validation"][0]["dynamic_verified"] is False

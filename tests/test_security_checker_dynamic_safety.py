from agents.security_checker.agent import SecurityChecker


def test_foundry_validation_is_skipped_until_an_isolated_runner_exists():
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
        item["reason"] == "isolated_fork_runner_not_configured"
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

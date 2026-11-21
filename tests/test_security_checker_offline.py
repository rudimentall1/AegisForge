def test_security_checker_construction_does_not_require_github_credentials(monkeypatch):
    import agents.security_checker.agent as security_module

    def fail_if_initialized():
        raise AssertionError("GitHub client must be lazy for offline on-chain review")

    monkeypatch.setattr(security_module, "GitHubClient", fail_if_initialized)
    checker = security_module.SecurityChecker()
    assert checker.github is None

import hashlib
from datetime import datetime, timezone

from agents.crypto_analyst.agent import CryptoAnalyst
from agents.lab_runner.agent import LabRunner
from agents.source_researcher.agent import SourceResearcher
from agents.worker import AGENTS, SUCCESS_STATUSES
from orchestrator.master import AutonomousPlanner
from shared.action_intent import build_action_intent
from shared.capability_policy import CapabilityDecision, CapabilityPolicy
from shared.public_source import _allowed_https_url
from shared.task import Task


def _fake_fetch(url):
    text = {
        "https://blog.ethereum.org/en/2015/08/04/ethereum-protocol-update-1": "If your keys date back from Go 1.0 rc or C++ 0.9.36, regenerate all of your keys. The C++ client now relies upon boost::random_device.",
        "https://1inch.com/blog/post/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool": "Profanity used a random 32-bit vector to seed 256-bit private keys. Researchers published proof-of-concept for the affected generator.",
        "https://blog.ethereum.org/2015/08/07/security-alert-1-windowsalethzero-2": "Key files may not be written; users should confirm the underlying key exists.",
        "https://blog.ethereum.org/2016/06/24/security-alert-smart-contract-wallets-created-in-frontier-are-vulnerable-to-phishing-attacks": "Smart contract wallets created in Frontier were vulnerable to phishing attacks.",
    }.get(url, "Synthetic test source.")
    return {
        "source_url": url, "final_url": url, "status_code": 200, "fetch_status": "fetched",
        "title": "Synthetic test source", "text": text, "excerpt": text[:500],
        "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "content_bytes": len(text.encode()), "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }


class _FakeGithub:
    BASE_URL = "https://api.github.com"

    def get_json(self, url, params=None, **kwargs):
        query = (params or {}).get("q", "")
        return {"items": [{
            "html_url": "https://github.com/example/project/issues/1",
            "url": "https://api.github.com/repos/example/project/issues/1",
            "repository_url": "https://api.github.com/repos/example/project",
            "title": f"Lead for {query}", "body": "A discovery lead, not proof.",
            "created_at": "2022-01-01T00:00:00Z", "updated_at": "2022-01-02T00:00:00Z",
        }]}


def test_source_researcher_preserves_provenance_and_confounds():
    agent = SourceResearcher(github=_FakeGithub(), fetcher=_fake_fetch)
    task = Task(task_id="t1", description="Research early EVM key-generation issues")
    result = agent.run(task).result
    assert task.status == "source_researched"
    assert result["research_track"] == "evm_key_forensics"
    assert result["source_summary"]["sources_fetched_http_200"] == 4
    classes = {source["classification"] for source in result["sources"]}
    assert "early_client_key_generation_warning" in classes
    assert "vanity_generator_entropy_weakness_report" in classes
    assert "key_file_creation_or_storage_issue" in classes
    assert "smart_contract_wallet_logic_issue" in classes
    assert result["scope_guards"]["no_real_wallet_key_recovery"] is True
    assert result["source_leads"][0]["evidence_role"] == "discovery_lead_only"


def test_crypto_analyst_does_not_mark_claims_confirmed():
    sources = [
        {"source_id": "early", "source_url": "https://blog.ethereum.org/en/2015/08/04/ethereum-protocol-update-1", "status_code": 200, "classification": "early_client_key_generation_warning"},
        {"source_id": "prof", "source_url": "https://1inch.com/blog/post/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool", "status_code": 200, "classification": "vanity_generator_entropy_weakness_report"},
    ]
    task = Task(task_id="t2", description="analyze", result={"research_track": "evm_key_forensics", "stage": "sources", "sources": sources})
    result = CryptoAnalyst().run(task).result
    assert result["stage"] == "analysis"
    assert result["analysis_summary"]["claims_confirmed_by_this_agent"] == 0
    assert result["hypotheses"][0]["status"] == "SOURCE_SUPPORTED_REPRODUCTION_PENDING"
    assert result["hypotheses"][1]["status"] == "SOURCE_SUPPORTED_REPRODUCTION_PENDING"
    assert result["hypotheses"][2]["status"] == "UNPROVEN"


def test_lab_runner_only_uses_tiny_synthetic_seed_space():
    result = LabRunner.run_synthetic_entropy_demo()
    assert result["synthetic_seed_recovered"] is True
    assert result["candidate_space"] == 1 << 12
    assert result["uses_real_private_keys"] is False
    assert result["uses_real_wallet_addresses"] is False
    assert result["historical_implementation_reproduced"] is False


def test_new_roles_are_registered_and_have_allowed_capabilities():
    expected = {
        "source_researcher": ("research", "source_researched"),
        "crypto_analyst": ("analyze", "crypto_analyzed"),
        "lab_runner": ("run_synthetic_lab", "lab_completed"),
    }
    policy = CapabilityPolicy()
    for role, (action, _status) in expected.items():
        assert role in AGENTS
        intent = build_action_intent(role, Task(task_id="t", description="test"))
        assert policy.check(intent)["decision"] == CapabilityDecision.ALLOW
        assert intent.action == action
    assert SUCCESS_STATUSES["source_researcher"] == "source_researched"
    assert SUCCESS_STATUSES["crypto_analyst"] == "crypto_analyzed"
    assert SUCCESS_STATUSES["lab_runner"] == "lab_completed"


def test_planner_routes_forensics_and_bounds_followup_rounds():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    base = {"research_track": "evm_key_forensics", "source_search_rounds": 1}
    cases = [
        ({"role": "source_researcher", "result": {**base, "stage": "sources"}}, "crypto_analyst"),
        ({"role": "crypto_analyst", "result": {**base, "stage": "analysis"}}, "lab_runner"),
        ({"role": "lab_runner", "result": {**base, "stage": "lab"}}, "validator"),
        ({"role": "validator", "result": {**base, "stage": "validation", "research_validation": {"status": "INCONCLUSIVE"}},}, "source_researcher"),
        ({"role": "validator", "result": {**base, "stage": "validation", "source_search_rounds": 3, "research_validation": {"status": "INCONCLUSIVE"}}}, None),
    ]
    for task, expected_role in cases:
        assert planner._choose_next_raw(task)[1] == expected_role


def test_source_url_allowlist_rejects_arbitrary_hosts():
    assert _allowed_https_url("https://blog.ethereum.org/en/test")
    assert _allowed_https_url("https://1inch.com/blog/post/test")
    assert not _allowed_https_url("http://blog.ethereum.org/test")
    assert not _allowed_https_url("https://example.com/test")


def test_validator_keeps_toy_lab_inconclusive_and_rechecks_sources():
    from agents.validator.agent import Validator

    source_task = Task(task_id="source", description="Research early EVM key-generation issues")
    source_result = SourceResearcher(github=_FakeGithub(), fetcher=_fake_fetch).run(source_task).result
    analysis_task = Task(task_id="analysis", description="Analyze", result=source_result)
    analysis_result = CryptoAnalyst().run(analysis_task).result
    lab_task = Task(task_id="lab", description="Run synthetic lab", result=analysis_result)
    lab_result = LabRunner().run(lab_task).result

    validator = Validator.__new__(Validator)
    validator.source_fetcher = _fake_fetch
    validation_task = Task(task_id="validation", description="Validate dossier", result=lab_result)
    validated = validator.run(validation_task)

    report = validated.result["research_validation"]
    assert validated.status == "validated"
    assert report["status"] == "INCONCLUSIVE"
    assert report["historical_reproduction_confirmed"] is False
    assert report["verified_historical_claims"] == []
    assert report["sources_rechecked_http_200"] == 4
    assert report["exact_source_fingerprints_matching"] == 4
    assert report["toy_lab_scope_verified"] is True


def test_validator_does_not_trust_a_bare_historical_reproduction_boolean():
    from agents.validator.agent import Validator

    sources = [
        {
            "source_id": "early",
            "source_url": "https://blog.ethereum.org/en/2015/08/04/ethereum-protocol-update-1",
            "status_code": 200,
            "content_sha256": hashlib.sha256(
                "If your keys date back from Go 1.0 rc or C++ 0.9.36, regenerate all of your keys. The C++ client now relies upon boost::random_device.".encode()
            ).hexdigest(),
            "classification": "early_client_key_generation_warning",
        },
        {
            "source_id": "prof",
            "source_url": "https://1inch.com/blog/post/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool",
            "status_code": 200,
            "content_sha256": hashlib.sha256(
                "Profanity used a random 32-bit vector to seed 256-bit private keys. Researchers published proof-of-concept for the affected generator.".encode()
            ).hexdigest(),
            "classification": "vanity_generator_entropy_weakness_report",
        },
    ]
    experiment = LabRunner.run_synthetic_entropy_demo()
    experiment["historical_implementation_reproduced"] = True  # Unsupported assertion
    experiment["synthetic_test_only"] = True
    experiment["uses_real_private_keys"] = False
    experiment["uses_real_wallet_addresses"] = False

    validator = Validator.__new__(Validator)
    validator.source_fetcher = _fake_fetch
    task = Task(
        task_id="forged",
        description="Validate a claimed historical reproduction",
        result={
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "sources": sources,
            "hypotheses": [],
            "lab_experiments": [experiment],
        },
    )
    result = validator.run(task).result["research_validation"]
    assert result["historical_reproduction_confirmed"] is False
    assert result["status"] == "INCONCLUSIVE"

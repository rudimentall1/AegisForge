import hashlib
import json
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
        "https://raw.githubusercontent.com/johguse/profanity/186b9b27ab3e24a1899f648adcabcbf0e5f3131e/Dispatcher.cpp": "Synthetic pinned archived historical implementation source with createSeed.",
        "https://raw.githubusercontent.com/johguse/profanity/186b9b27ab3e24a1899f648adcabcbf0e5f3131e/Dispatcher.hpp": "Synthetic pinned archived historical implementation header.",
        "https://raw.githubusercontent.com/johguse/profanity/186b9b27ab3e24a1899f648adcabcbf0e5f3131e/profanity.cpp": "Synthetic pinned archived historical implementation entrypoint.",
        "https://raw.githubusercontent.com/johguse/profanity/186b9b27ab3e24a1899f648adcabcbf0e5f3131e/README.md": "Synthetic pinned archived historical repository readme.",
        "https://raw.githubusercontent.com/johguse/profanity/0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6/Dispatcher.cpp": "Synthetic pre-disclosure source with createSeed and mt19937_64.",
        "https://raw.githubusercontent.com/johguse/profanity/0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6/Dispatcher.hpp": "Synthetic pre-disclosure source header.",
        "https://raw.githubusercontent.com/johguse/profanity/0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6/profanity.cpp": "Synthetic pre-disclosure source entrypoint.",
        "https://raw.githubusercontent.com/johguse/profanity/0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6/README.md": "Synthetic pre-disclosure repository readme.",
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
        if url.endswith("/repos/johguse/profanity/commits/master"):
            return {"sha": "186b9b27ab3e24a1899f648adcabcbf0e5f3131e", "commit": {"committer": {"date": "2022-09-15T13:49:39Z"}}}
        if url.endswith("/repos/johguse/profanity/commits/v1.50"):
            return {"sha": "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6", "commit": {"committer": {"date": "2022-07-28T00:00:00Z"}}}
        query = (params or {}).get("q", "")
        return {"items": [{
            "html_url": "https://github.com/example/project/issues/1",
            "url": "https://api.github.com/repos/example/project/issues/1",
            "repository_url": "https://api.github.com/repos/example/project",
            "title": f"Ethereum key generation lead for {query}", "body": "A discovery lead, not proof.",
            "created_at": "2022-01-01T00:00:00Z", "updated_at": "2022-01-02T00:00:00Z",
        }]}


def test_source_researcher_preserves_provenance_and_confounds():
    agent = SourceResearcher(github=_FakeGithub(), fetcher=_fake_fetch)
    task = Task(task_id="t1", description="Research early EVM key-generation issues")
    result = agent.run(task).result
    assert task.status == "source_researched"
    assert result["research_track"] == "evm_key_forensics"
    assert result["source_summary"]["sources_fetched_http_200"] == 12
    assert result["source_summary"]["pinned_repository_files"] == 8
    assert result["source_summary"]["pinned_repository_revisions"] == 2
    assert {pin["commit_sha"] for pin in result["repository_pins"]} == {"186b9b27ab3e24a1899f648adcabcbf0e5f3131e", "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6"}
    assert {pin["revision_role"] for pin in result["repository_pins"]} == {"pre_disclosure_release", "post_disclosure_archive"}
    pinned = [source for source in result["sources"] if source.get("source_kind") == "pinned_repository_source"]
    assert len(pinned) == 8
    assert {source["revision_sha"] for source in pinned} == {"186b9b27ab3e24a1899f648adcabcbf0e5f3131e", "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6"}
    assert {source["revision_role"] for source in pinned} == {"pre_disclosure_release", "post_disclosure_archive"}
    assert all("/" + source["revision_sha"] + "/" in source["source_url"] for source in pinned)
    classes = {source["classification"] for source in result["sources"]}
    assert "early_client_key_generation_warning" in classes
    assert "vanity_generator_entropy_weakness_report" in classes
    assert "key_file_creation_or_storage_issue" in classes
    assert "smart_contract_wallet_logic_issue" in classes
    assert all(source["classification"] == "pinned_historical_implementation_source" for source in pinned)
    assert result["scope_guards"]["no_real_wallet_key_recovery"] is True
    assert result["source_leads"][0]["evidence_role"] == "discovery_lead_only"


def test_source_researcher_filters_unrelated_github_search_results():
    class MixedGithub:
        BASE_URL = "https://api.github.com"

        def get_json(self, url, params=None, **kwargs):
            return {"items": [
                {
                    "html_url": "https://github.com/example/other/issues/1",
                    "url": "https://api.github.com/repos/example/other/issues/1",
                    "repository_url": "https://api.github.com/repos/example/other",
                    "title": "Improve button layout on landing page",
                    "body": "CSS issue with responsive spacing.",
                },
                {
                    "html_url": "https://github.com/example/crypto/issues/2",
                    "url": "https://api.github.com/repos/example/crypto/issues/2",
                    "repository_url": "https://api.github.com/repos/example/crypto",
                    "title": "Profanity key generation entropy analysis",
                    "body": "Discussion of the synthetic seed space only.",
                },
            ]}

    result = SourceResearcher(github=MixedGithub(), fetcher=_fake_fetch).run(
        Task(task_id="filter", description="Research EVM key generation")
    ).result
    urls = {lead["source_url"] for lead in result["source_leads"]}
    assert "https://github.com/example/crypto/issues/2" in urls
    assert "https://github.com/example/other/issues/1" not in urls
    assert result["filtered_source_lead_count"] == 2
    assert result["source_summary"]["filtered_search_leads"] == 2
    assert result["source_leads"][0]["relevance"] == "keyword_screened_candidate"


def test_lead_relevance_requires_specific_signal_or_multiple_context_signals():
    relevant, signals = SourceResearcher._lead_relevance(
        "Profanity key generation", "Synthetic test only"
    )
    assert relevant is True
    assert "key generation" in signals["direct"]

    relevant, _ = SourceResearcher._lead_relevance(
        "Prevent profanity in generated text", "Prompt output contains profanity"
    )
    assert relevant is False

    relevant, _ = SourceResearcher._lead_relevance(
        "Wallet dashboard redesign", "Update button spacing"
    )
    assert relevant is False

    relevant, _ = SourceResearcher._lead_relevance(
        "Ethereum wallet weak key generation", "Key management and wallet security"
    )
    assert relevant is True

    relevant, _ = SourceResearcher._lead_relevance(
        "build(deps): bump the python-deps group", "Profanity private key entropy discussion"
    )
    assert relevant is False

    relevant, _ = SourceResearcher._lead_relevance(
        "Add autonomous EVM key-generation forensics research track",
        "Research task requirements", item_url="https://github.com/rudimentall1/AegisForge/issues/31"
    )
    assert relevant is False


def test_trusted_key_config_json_rejects_duplicate_keys():
    from agents.validator.agent import _reject_duplicate_json_keys

    valid = json.loads(
        '{"runner-a":"cHVibGljLWtleQ==","runner-b":"YW5vdGhlci1rZXk="}',
        object_pairs_hook=_reject_duplicate_json_keys,
    )
    assert set(valid) == {"runner-a", "runner-b"}

    import pytest
    with pytest.raises(ValueError, match="duplicate_json_key"):
        json.loads(
            '{"runner-a":"first","runner-a":"second"}',
            object_pairs_hook=_reject_duplicate_json_keys,
        )

    with pytest.raises(ValueError, match="duplicate_json_key"):
        json.loads(
            '{"outer":{"runner-a":"first","runner-a":"second"}}',
            object_pairs_hook=_reject_duplicate_json_keys,
        )


def test_validator_fails_closed_on_duplicate_trusted_key_ids(monkeypatch):
    from agents.validator.agent import Validator

    monkeypatch.setenv(
        "AEGISFORGE_LAB_TRUSTED_PUBLIC_KEYS",
        '{"runner-a":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","runner-a":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}',
    )
    experiment = LabRunner.run_synthetic_entropy_demo()
    task = Task(
        task_id="duplicate-trusted-key-id",
        description="Reject ambiguous trusted key configuration",
        result={
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "sources": [],
            "hypotheses": [],
            "lab_experiments": [experiment],
        },
    )

    report = Validator().run(task).result["research_validation"]
    assert report["lab_trusted_signing_key_count"] == 0
    assert report["lab_trusted_key_configuration_error"] == "ValueError"
    assert report["historical_reproduction_confirmed"] is False
    assert report["status"] == "INCONCLUSIVE"
    check = report["lab_execution_receipt_checks"][0]
    assert check["signature_verified_against_trusted_key"] is False
    assert check["authenticity"] != "SIGNED_AND_TRUSTED"


def test_validator_rejects_receipt_signed_by_untrusted_key_id(monkeypatch):
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agents.validator.agent import Validator

    signer = Ed25519PrivateKey.generate()
    trusted_but_different = Ed25519PrivateKey.generate()
    signer_private_bytes = signer.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    trusted_public_bytes = trusted_but_different.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    monkeypatch.setenv(
        "AEGISFORGE_LAB_SIGNING_KEY_B64",
        base64.b64encode(signer_private_bytes).decode("ascii"),
    )
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_ID", "untrusted-runner")
    monkeypatch.setenv(
        "AEGISFORGE_LAB_TRUSTED_PUBLIC_KEYS",
        json.dumps({"trusted-runner": base64.b64encode(trusted_public_bytes).decode("ascii")}),
    )

    experiment = LabRunner.run_synthetic_entropy_demo()
    report = Validator().run(Task(
        task_id="untrusted-receipt-key-id",
        description="Reject a validly signed receipt whose signer is not trusted",
        result={
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "sources": [],
            "hypotheses": [],
            "lab_experiments": [experiment],
        },
    )).result["research_validation"]

    assert report["lab_trusted_signing_key_count"] == 1
    assert report["lab_trusted_key_configuration_error"] is None
    assert report["historical_reproduction_confirmed"] is False
    assert report["status"] == "INCONCLUSIVE"
    check = report["lab_execution_receipt_checks"][0]
    assert check["signature_verified_against_trusted_key"] is False
    assert check["authenticity"] != "SIGNED_AND_TRUSTED"


def test_validator_rejects_invalid_signature_from_configured_trusted_key(monkeypatch):
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agents.validator.agent import Validator

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = "trusted-test-runner"
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_B64", base64.b64encode(private_bytes).decode("ascii"))
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_ID", key_id)
    monkeypatch.setenv(
        "AEGISFORGE_LAB_TRUSTED_PUBLIC_KEYS",
        json.dumps({key_id: base64.b64encode(public_bytes).decode("ascii")}),
    )

    experiment = LabRunner.run_synthetic_entropy_demo()
    # Preserve the receipt and its digest, but corrupt only the signature bytes.
    experiment["execution_receipt_envelope"]["signature"] = base64.b64encode(b"invalid-signature").decode("ascii")
    report = Validator().run(Task(
        task_id="invalid-signature-trusted-key",
        description="Reject a corrupted signature even when key ID is trusted",
        result={
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "sources": [],
            "hypotheses": [],
            "lab_experiments": [experiment],
        },
    )).result["research_validation"]

    assert report["lab_trusted_signing_key_count"] == 1
    assert report["lab_trusted_key_configuration_error"] is None
    assert report["historical_reproduction_confirmed"] is False
    assert report["status"] == "INCONCLUSIVE"
    check = report["lab_execution_receipt_checks"][0]
    assert check["integrity_verified"] is True
    assert check["signature_verified_against_trusted_key"] is False
    assert check["authenticity"] == "SIGNATURE_INVALID_OR_UNTRUSTED"


def test_validator_fails_closed_on_malformed_trusted_key_material(monkeypatch):
    from agents.validator.agent import Validator

    malformed_configs = [
        ('{"runner-a":"not base64!!!"}', "Error"),
        ('{"runner-a":"AAAA"}', "ValueError"),
        ('[]', "ValueError"),
    ]
    experiment = LabRunner.run_synthetic_entropy_demo()

    for raw_config, expected_error in malformed_configs:
        monkeypatch.setenv("AEGISFORGE_LAB_TRUSTED_PUBLIC_KEYS", raw_config)
        task = Task(
            task_id="malformed-trusted-key-material",
            description="Reject malformed trusted key material",
            result={
                "research_track": "evm_key_forensics",
                "stage": "lab",
                "sources": [],
                "hypotheses": [],
                "lab_experiments": [experiment],
            },
        )

        report = Validator().run(task).result["research_validation"]
        assert report["lab_trusted_signing_key_count"] == 0
        assert report["lab_trusted_key_configuration_error"] == expected_error
        assert report["historical_reproduction_confirmed"] is False
        assert report["status"] == "INCONCLUSIVE"
        check = report["lab_execution_receipt_checks"][0]
        assert check["signature_verified_against_trusted_key"] is False
        assert check["authenticity"] != "SIGNED_AND_TRUSTED"


def test_validator_reports_truncated_analysis_text_without_promoting_claims():
    from agents.validator.agent import Validator

    source_task = Task(task_id="truncated-source", description="Research historical EVM key generation")
    source_result = SourceResearcher(github=_FakeGithub(), fetcher=_fake_fetch).run(source_task).result

    def truncated_fetch(url):
        fetched = _fake_fetch(url)
        fetched["content_truncated_for_analysis"] = True
        return fetched

    validator = Validator.__new__(Validator)
    validator.source_fetcher = truncated_fetch
    validated = validator.run(Task(
        task_id="truncated-source-check",
        description="Validate truncated source evidence",
        result=source_result,
    ))

    report = validated.result["research_validation"]
    assert report["sources_with_truncated_analysis_text"] == 12
    assert report["sources_with_unknown_analysis_text_completeness"] == 0
    assert report["status"] == "INCONCLUSIVE"
    assert report["historical_reproduction_confirmed"] is False
    assert "source_analysis_text_truncated" in report["readiness_blockers"]
    # Truncation blocks readiness independently; pinned metadata remains valid.
    assert "pinned_revision_provenance_not_clean" not in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"
    assert any("truncated excerpt" in action for action in report["next_actions"])


def test_validator_detects_tampered_immutable_revision_url():
    from agents.validator.agent import Validator

    source_task = Task(task_id="source-tamper", description="Research historical EVM key generation")
    source_result = SourceResearcher(github=_FakeGithub(), fetcher=_fake_fetch).run(source_task).result
    pinned = next(source for source in source_result["sources"] if source.get("source_kind") == "pinned_repository_source")
    original_url = pinned["source_url"]
    pinned["source_url"] = original_url.replace(pinned["revision_sha"], "f" * 40, 1)

    validator = Validator.__new__(Validator)
    validator.source_fetcher = _fake_fetch
    validated = validator.run(Task(task_id="tamper-check", description="Validate tampered pin", result=source_result))
    report = validated.result["research_validation"]
    check = next(item for item in validated.result["research_source_checks"] if item["source_url"] == pinned["source_url"])
    assert check["immutable_revision_pin_valid"] is False
    assert report["pinned_revision_source_checks_failed"] == 1
    assert report["status"] == "INCONCLUSIVE"


def test_validator_rejects_consistently_forged_revision_pin():
    from agents.validator.agent import Validator

    source_task = Task(task_id="source-forged-pin", description="Research historical EVM key generation")
    source_result = SourceResearcher(github=_FakeGithub(), fetcher=_fake_fetch).run(source_task).result
    pinned = next(source for source in source_result["sources"] if source.get("source_kind") == "pinned_repository_source")
    original_sha = pinned["revision_sha"]
    forged_sha = "f" * 40
    pinned["revision_sha"] = forged_sha
    pinned["source_url"] = pinned["source_url"].replace(original_sha, forged_sha, 1)
    pinned["revision_url"] = f"https://github.com/{pinned['repository']}/tree/{forged_sha}"
    for pin in source_result["repository_pins"]:
        if pin.get("repository") == pinned["repository"] and pin.get("requested_ref") == pinned["repository_ref"]:
            pin["commit_sha"] = forged_sha
            pin["expected_commit_sha"] = forged_sha

    validator = Validator.__new__(Validator)
    validator.source_fetcher = _fake_fetch
    validated = validator.run(Task(task_id="forged-pin-check", description="Validate forged pin", result=source_result))
    report = validated.result["research_validation"]
    check = next(item for item in validated.result["research_source_checks"] if item["source_url"] == pinned["source_url"])
    assert check["immutable_revision_pin_valid"] is False
    assert report["pinned_revision_source_checks_failed"] == 4
    assert report["status"] == "INCONCLUSIVE"


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
    assert report["sources_rechecked_http_200"] == 12
    assert report["exact_source_fingerprints_matching"] == 12
    assert report["pinned_revision_sources_checked"] == 8
    assert report["pinned_revision_source_checks_passed"] == 8
    assert report["pinned_revision_source_checks_failed"] == 0
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



def test_public_source_streams_response_and_closes_it(monkeypatch):
    import shared.public_source as public_source

    class FakeResponse:
        status_code = 200
        headers = {"Content-Length": "48"}
        encoding = "utf-8"

        def __init__(self):
            self.closed = False

        @property
        def content(self):
            raise AssertionError("response.content would buffer the entire body")

        def iter_content(self, chunk_size):
            assert chunk_size == 64 * 1024
            yield b"<html><title>Example</title><p>Hello</p></html>"

        def close(self):
            self.closed = True

    response = FakeResponse()
    captured = {}

    def fake_get(url, **kwargs):
        captured.update(kwargs)
        return response

    monkeypatch.setattr(public_source.requests, "get", fake_get)
    result = public_source.fetch_public_source("https://blog.ethereum.org/test")

    assert captured["stream"] is True
    assert response.closed is True
    assert result["status_code"] == 200
    assert result["title"] == "Example"
    assert "Hello" in result["text"]
    assert result["content_bytes"] <= public_source.MAX_BODY_BYTES


def test_public_source_rejects_oversized_stream(monkeypatch):
    import pytest
    import shared.public_source as public_source

    class FakeResponse:
        status_code = 200
        headers = {}
        encoding = "utf-8"

        def __init__(self):
            self.closed = False

        def iter_content(self, chunk_size):
            yield b"x" * public_source.MAX_BODY_BYTES
            yield b"y"

        def close(self):
            self.closed = True

    response = FakeResponse()
    captured = {}

    def fake_get(url, **kwargs):
        captured.update(kwargs)
        return response

    monkeypatch.setattr(public_source.requests, "get", fake_get)
    with pytest.raises(ValueError, match="source_body_exceeds_limit"):
        public_source.fetch_public_source("https://blog.ethereum.org/test")

    assert captured["stream"] is True
    assert response.closed is True


def test_public_source_rejects_unallowlisted_redirect(monkeypatch):
    import pytest
    import shared.public_source as public_source

    class FakeResponse:
        status_code = 302
        headers = {"Location": "https://example.com/redirect-target"}

        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    response = FakeResponse()
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return response

    monkeypatch.setattr(public_source.requests, "get", fake_get)
    with pytest.raises(ValueError, match="redirect_target_not_allowlisted_https"):
        public_source.fetch_public_source("https://blog.ethereum.org/test")

    assert calls == ["https://blog.ethereum.org/test"]
    assert response.closed is True


def test_validator_rejects_complete_reproduction_claim_with_unpinned_revision():
    from agents.validator.agent import Validator

    # Even a fully populated evidence-shaped claim must not qualify if its
    # revision is not the independently pinned pre-disclosure release.
    experiment = {
        "experiment_id": "claimed-historical-reproduction",
        "historical_implementation_reproduced": True,
        "synthetic_test_only": True,
        "uses_real_private_keys": False,
        "uses_real_wallet_addresses": False,
        "pinned_source_revision": "f" * 40,
        "reproduction_source_role": "pre_disclosure_release",
        "synthetic_test_vector_id": "synthetic-vector-001",
        "reproduction_test_passed": True,
        "reproduction_artifact_sha256": "a" * 64,
        "reproduction_command": "python reproduce.py --synthetic-only",
    }
    validator = Validator.__new__(Validator)
    validator.source_fetcher = _fake_fetch
    result = validator.run(Task(
        task_id="forged-complete-reproduction",
        description="Reject an unpinned reproduction claim",
        result={
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "sources": [],
            "hypotheses": [],
            "lab_experiments": [experiment],
        },
    )).result["research_validation"]

    assert result["historical_reproduction_confirmed"] is False
    assert result["status"] == "INCONCLUSIVE"
    assert result["verified_historical_claims"] == []

def test_validator_rejects_artifact_digest_without_artifact_bytes():
    from agents.validator.agent import Validator, EXPECTED_EVM_FORENSICS_REVISIONS

    # A digest-shaped field does not prove that the artifact exists or that
    # the digest corresponds to evidence the validator can inspect.
    experiment = {
        "experiment_id": "digest-without-artifact",
        "historical_implementation_reproduced": True,
        "synthetic_test_only": True,
        "uses_real_private_keys": False,
        "uses_real_wallet_addresses": False,
        "pinned_source_revision": EXPECTED_EVM_FORENSICS_REVISIONS[("johguse/profanity", "v1.50")],
        "reproduction_source_role": "pre_disclosure_release",
        "synthetic_test_vector_id": "synthetic-vector-001",
        "reproduction_test_passed": True,
        "reproduction_artifact_sha256": "a" * 64,
        "reproduction_command": "python reproduce.py --synthetic-only",
    }
    validator = Validator.__new__(Validator)
    validator.source_fetcher = _fake_fetch
    result = validator.run(Task(
        task_id="digest-without-artifact",
        description="Reject detached artifact digest",
        result={
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "sources": [],
            "hypotheses": [],
            "lab_experiments": [experiment],
        },
    )).result["research_validation"]

    assert result["historical_reproduction_confirmed"] is False
    assert result["status"] == "INCONCLUSIVE"
    assert result["verified_historical_claims"] == []



def test_validator_rejects_artifact_with_mismatched_source_revision():
    import json
    from agents.validator.agent import Validator, EXPECTED_EVM_FORENSICS_REVISIONS

    revision = EXPECTED_EVM_FORENSICS_REVISIONS[("johguse/profanity", "v1.50")]
    command = "python reproduce.py --synthetic-only"
    vector_id = "synthetic-vector-001"
    artifact = json.dumps({
        "schema_version": 1,
        "source_revision": "f" * 40,
        "test_vector_id": vector_id,
        "command": command,
        "exit_code": 0,
        "test_passed": True,
    }, sort_keys=True)
    experiment = {
        "experiment_id": "artifact-revision-mismatch",
        "historical_implementation_reproduced": True,
        "synthetic_test_only": True,
        "uses_real_private_keys": False,
        "uses_real_wallet_addresses": False,
        "pinned_source_revision": revision,
        "reproduction_source_role": "pre_disclosure_release",
        "synthetic_test_vector_id": vector_id,
        "reproduction_test_passed": True,
        "reproduction_artifact": artifact,
        "reproduction_artifact_sha256": hashlib.sha256(artifact.encode("utf-8")).hexdigest(),
        "reproduction_command": command,
    }
    validator = Validator.__new__(Validator)
    validator.source_fetcher = _fake_fetch
    result = validator.run(Task(
        task_id="artifact-revision-mismatch",
        description="Reject artifact metadata that disagrees with the pinned source",
        result={
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "sources": [],
            "hypotheses": [],
            "lab_experiments": [experiment],
        },
    )).result["research_validation"]

    assert result["historical_reproduction_confirmed"] is False
    assert result["status"] == "INCONCLUSIVE"
    assert result["verified_historical_claims"] == []


def test_validator_rejects_artifact_with_false_execution_metadata():
    import json
    from agents.validator.agent import Validator, EXPECTED_EVM_FORENSICS_REVISIONS

    revision = EXPECTED_EVM_FORENSICS_REVISIONS[("johguse/profanity", "v1.50")]
    command = "python reproduce.py --synthetic-only"
    vector_id = "synthetic-vector-002"

    for case, artifact_fields in [
        ("wrong-vector", {"test_vector_id": "other-vector"}),
        ("wrong-command", {"command": "python fabricated.py"}),
        ("nonzero-exit", {"exit_code": 1, "test_passed": False}),
    ]:
        fields = {
            "schema_version": 1,
            "source_revision": revision,
            "test_vector_id": vector_id,
            "command": command,
            "exit_code": 0,
            "test_passed": True,
        }
        fields.update(artifact_fields)
        artifact = json.dumps(fields, sort_keys=True)
        experiment = {
            "experiment_id": case,
            "historical_implementation_reproduced": True,
            "synthetic_test_only": True,
            "uses_real_private_keys": False,
            "uses_real_wallet_addresses": False,
            "pinned_source_revision": revision,
            "reproduction_source_role": "pre_disclosure_release",
            "synthetic_test_vector_id": vector_id,
            "reproduction_test_passed": True,
            "reproduction_artifact": artifact,
            "reproduction_artifact_sha256": hashlib.sha256(artifact.encode("utf-8")).hexdigest(),
            "reproduction_command": command,
        }
        validator = Validator.__new__(Validator)
        validator.source_fetcher = _fake_fetch
        result = validator.run(Task(
            task_id=f"artifact-metadata-{case}",
            description="Reject inconsistent execution metadata in reproduction artifact",
            result={
                "research_track": "evm_key_forensics",
                "stage": "lab",
                "sources": [],
                "hypotheses": [],
                "lab_experiments": [experiment],
            },
        )).result["research_validation"]

        assert result["historical_reproduction_confirmed"] is False, case
        assert result["status"] == "INCONCLUSIVE", case
        assert result["verified_historical_claims"] == [], case



def test_lab_runner_records_observed_synthetic_subprocess_result():
    experiment = LabRunner.run_synthetic_entropy_demo()
    record = experiment["execution_record"]

    assert record["schema_version"] == 1
    assert record["record_kind"] == "local_subprocess_observation"
    assert record["executor"] == "python-subprocess"
    assert record["command"][0]
    assert record["command"][1:2] == ["-c"]
    assert record["command_sha256"] == hashlib.sha256(
        json.dumps(
            record["command"], ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    assert record["exit_code"] == 0
    assert record["timed_out"] is False
    assert record["test_passed"] is True
    assert record["stdout_sha256"] == hashlib.sha256(
        record["stdout"].encode("utf-8")
    ).hexdigest()
    assert record["stderr_sha256"] == hashlib.sha256(b"").hexdigest()
    assert record["stderr"] == ""
    assert record["stderr_sha256"] == hashlib.sha256(
        record["stderr"].encode("utf-8")
    ).hexdigest()
    assert experiment["synthetic_seed_recovered"] is True
    assert experiment["historical_implementation_reproduced"] is False



def test_validator_checks_lab_execution_record_consistency_not_authenticity():
    from copy import deepcopy
    from agents.validator.agent import Validator

    experiment = LabRunner.run_synthetic_entropy_demo()
    validator = Validator.__new__(Validator)
    validator.source_fetcher = _fake_fetch

    def validate(item):
        return validator.run(Task(
            task_id="lab-execution-record-check",
            description="Check internally consistent subprocess observations",
            result={
                "research_track": "evm_key_forensics",
                "stage": "lab",
                "sources": [],
                "hypotheses": [],
                "lab_experiments": [item],
            },
        )).result["research_validation"]

    valid_result = validate(deepcopy(experiment))
    assert valid_result["lab_execution_records_checked"] == 1
    assert valid_result["lab_execution_records_consistent"] is True
    assert valid_result["lab_execution_record_checks"][0]["internally_consistent"] is True
    assert valid_result["lab_execution_record_checks"][0]["successful_execution"] is True
    assert valid_result["lab_execution_records_passed"] is True
    assert valid_result["historical_reproduction_confirmed"] is False

    tampered = deepcopy(experiment)
    tampered["execution_record"]["stdout"] += "forged-after-run"
    tampered_result = validate(tampered)
    tampered_checks = tampered_result["lab_execution_record_checks"][0]["checks"]
    assert tampered_result["lab_execution_records_consistent"] is False
    assert tampered_checks["stdout_digest_matches"] is False
    assert tampered_result["lab_execution_records_passed"] is False
    assert tampered_result["historical_reproduction_confirmed"] is False

    for field, value, failed_check in (
        ("stderr", "unexpected stderr", "stderr_digest_matches"),
        ("command", experiment["execution_record"]["command"] + ["tampered"], "command_digest_matches"),
    ):
        changed = deepcopy(experiment)
        changed["execution_record"][field] = value
        checked = validate(changed)
        check = checked["lab_execution_record_checks"][0]
        assert check["checks"][failed_check] is False
        assert check["internally_consistent"] is False
        assert check["successful_execution"] is False
        assert checked["lab_execution_records_passed"] is False

    missing = deepcopy(experiment)
    missing.pop("execution_record")
    missing_result = validate(missing)
    missing_check = missing_result["lab_execution_record_checks"][0]
    assert missing_check["checks"]["record_present"] is False
    assert missing_check["successful_execution"] is False
    assert missing_result["lab_execution_records_passed"] is False

    failed_run = deepcopy(experiment)
    failed_run["execution_record"]["exit_code"] = 2
    failed_run["execution_record"]["test_passed"] = False
    failed_result = validate(failed_run)
    failed_check = failed_result["lab_execution_record_checks"][0]
    assert failed_check["internally_consistent"] is True
    assert failed_check["successful_execution"] is False
    assert failed_result["lab_execution_records_passed"] is False

    timed_out = deepcopy(experiment)
    timed_out["execution_record"]["exit_code"] = None
    timed_out["execution_record"]["timed_out"] = True
    timed_out["execution_record"]["test_passed"] = False
    timeout_result = validate(timed_out)
    timeout_check = timeout_result["lab_execution_record_checks"][0]
    assert timeout_check["internally_consistent"] is True
    assert timeout_check["successful_execution"] is False
    assert timeout_result["lab_execution_records_passed"] is False



def test_validator_rejects_trusted_receipt_not_bound_to_reproduction_claim(monkeypatch):
    import base64
    from copy import deepcopy
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agents.validator.agent import Validator, EXPECTED_EVM_FORENSICS_REVISIONS

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = "test-runner-key"
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_B64", base64.b64encode(private_bytes).decode("ascii"))
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_ID", key_id)
    monkeypatch.setenv("AEGISFORGE_LAB_TRUSTED_PUBLIC_KEYS", json.dumps({
        key_id: base64.b64encode(public_bytes).decode("ascii"),
    }))

    experiment = LabRunner.run_synthetic_entropy_demo()
    revision = EXPECTED_EVM_FORENSICS_REVISIONS[("johguse/profanity", "v1.50")]
    command = "python reproduce.py --synthetic-only"
    vector_id = "historical-reproduction-vector"
    artifact = json.dumps({
        "schema_version": 1,
        "source_revision": revision,
        "test_vector_id": vector_id,
        "command": command,
        "exit_code": 0,
        "test_passed": True,
    }, sort_keys=True)
    experiment.update({
        "historical_implementation_reproduced": True,
        "pinned_source_revision": revision,
        "reproduction_source_role": "pre_disclosure_release",
        "synthetic_test_vector_id": vector_id,
        "reproduction_test_passed": True,
        "reproduction_command": command,
        "reproduction_artifact": artifact,
        "reproduction_artifact_sha256": hashlib.sha256(artifact.encode("utf-8")).hexdigest(),
    })

    validator = Validator.__new__(Validator)
    validator.source_fetcher = _fake_fetch
    report = validator.run(Task(
        task_id="trusted-receipt-unbound",
        description="Reject a trusted receipt that does not bind the reproduction claim",
        result={
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "sources": [],
            "hypotheses": [],
            "lab_experiments": [experiment],
        },
    )).result["research_validation"]

    receipt_check = report["lab_execution_receipt_checks"][0]
    assert receipt_check["authenticity"] == "SIGNED_AND_TRUSTED"
    assert receipt_check["reproduction_binding_matches"] is False
    assert report["historical_reproduction_confirmed"] is False
    assert report["status"] == "INCONCLUSIVE"
    assert report["verified_historical_claims"] == []

    # Even a receipt that is correctly signed and bound to every reproduction
    # field must not count as independent execution attestation.
    from shared.lab_execution_receipt import receipt_sha256, sign_receipt

    bound_experiment = deepcopy(experiment)
    bound_receipt = deepcopy(bound_experiment["execution_receipt"])
    bound_receipt["inputs"]["source_revision"] = revision
    bound_receipt["inputs"]["test_vector_id"] = vector_id
    bound_receipt["inputs"]["reproduction_command"] = command
    bound_receipt["artifacts"]["reproduction_artifact_sha256"] = bound_experiment["reproduction_artifact_sha256"]
    # Attestation status supplied by a dossier or a signed ordinary receipt
    # is still untrusted input; only a future real verifier may derive it.
    bound_receipt["independent_runner_attestation_verified"] = True
    bound_experiment["independent_runner_attestation_verified"] = True
    bound_experiment["execution_receipt"] = bound_receipt
    bound_experiment["execution_receipt_sha256"] = receipt_sha256(bound_receipt)
    bound_experiment["execution_receipt_envelope"] = sign_receipt(
        bound_receipt, private_key=private_key, key_id=key_id
    )

    bound_report = validator.run(Task(
        task_id="trusted-receipt-bound-no-attestation",
        description="A bound signature is not independent runner attestation",
        result={
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "sources": [],
            "hypotheses": [],
            "lab_experiments": [bound_experiment],
        },
    )).result["research_validation"]
    bound_check = bound_report["lab_execution_receipt_checks"][0]
    assert bound_check["authenticity"] == "SIGNED_AND_TRUSTED"
    assert bound_check["reproduction_binding_matches"] is True
    assert bound_check["independent_runner_attestation_verified"] is False
    assert bound_report["independent_runner_attestation_available"] is False
    assert bound_report["historical_reproduction_confirmed"] is False
    assert bound_report["status"] == "INCONCLUSIVE"

    
    # Each reproduction binding dimension is independently security-critical.
    # Re-sign altered receipts to prove that trusted signature validity alone
    # cannot override a mismatch against the dossier.
    mismatches = [
        ("source_revision", lambda receipt: receipt["inputs"].update(source_revision="f" * 40)),
        ("test_vector_id", lambda receipt: receipt["inputs"].update(test_vector_id="different-vector")),
        ("reproduction_command", lambda receipt: receipt["inputs"].update(reproduction_command="python other.py")),
        ("reproduction_artifact_sha256", lambda receipt: receipt["artifacts"].update(reproduction_artifact_sha256="0" * 64)),
        ("experiment_id", lambda receipt: receipt.update(experiment_id="different-experiment")),
    ]
    for field_name, mutate in mismatches:
        mismatched_experiment = deepcopy(bound_experiment)
        mismatched_receipt = deepcopy(mismatched_experiment["execution_receipt"])
        mutate(mismatched_receipt)
        mismatched_experiment["execution_receipt"] = mismatched_receipt
        mismatched_experiment["execution_receipt_sha256"] = receipt_sha256(mismatched_receipt)
        mismatched_experiment["execution_receipt_envelope"] = sign_receipt(
            mismatched_receipt, private_key=private_key, key_id=key_id
        )
        mismatch_report = validator.run(Task(
            task_id=f"trusted-receipt-mismatch-{field_name}",
            description=f"Reject signed receipt with mismatched {field_name}",
            result={
                "research_track": "evm_key_forensics",
                "stage": "lab",
                "sources": [],
                "hypotheses": [],
                "lab_experiments": [mismatched_experiment],
            },
        )).result["research_validation"]
        mismatch_check = mismatch_report["lab_execution_receipt_checks"][0]
        assert mismatch_check["authenticity"] == "SIGNED_AND_TRUSTED"
        assert mismatch_check["reproduction_binding_matches"] is False
        assert mismatch_check["independent_runner_attestation_verified"] is False
        assert mismatch_report["historical_reproduction_confirmed"] is False
        assert mismatch_report["status"] == "INCONCLUSIVE"



def test_validator_rejects_receipt_payload_mutated_after_signing(monkeypatch):
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agents.validator.agent import Validator

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = "trusted-payload-test-runner"
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_B64", base64.b64encode(private_bytes).decode("ascii"))
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_ID", key_id)
    monkeypatch.setenv(
        "AEGISFORGE_LAB_TRUSTED_PUBLIC_KEYS",
        json.dumps({key_id: base64.b64encode(public_bytes).decode("ascii")}),
    )

    experiment = LabRunner.run_synthetic_entropy_demo()
    # The signed envelope remains intact; mutate the separately reported receipt.
    experiment["execution_receipt"]["execution"]["exit_code"] = 17
    report = Validator().run(Task(
        task_id="mutated-receipt-payload",
        description="Reject receipt content changed after signing",
        result={
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "sources": [],
            "hypotheses": [],
            "lab_experiments": [experiment],
        },
    )).result["research_validation"]

    check = report["lab_execution_receipt_checks"][0]
    assert check["integrity_verified"] is False
    assert check["digest_matches"] is False
    assert check["record_matches_receipt"] is False
    assert check["signature_verified_against_trusted_key"] is False
    assert check["authenticity"] == "SIGNATURE_INVALID_OR_UNTRUSTED"
    assert report["historical_reproduction_confirmed"] is False
    assert report["status"] == "INCONCLUSIVE"



def test_validator_rejects_trusted_key_id_with_wrong_public_key(monkeypatch):
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agents.validator.agent import Validator

    signer = Ed25519PrivateKey.generate()
    wrong_key = Ed25519PrivateKey.generate()
    signer_private_bytes = signer.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    wrong_public_bytes = wrong_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = "runner-key-fingerprint-mismatch"
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_B64", base64.b64encode(signer_private_bytes).decode("ascii"))
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_ID", key_id)
    monkeypatch.setenv(
        "AEGISFORGE_LAB_TRUSTED_PUBLIC_KEYS",
        json.dumps({key_id: base64.b64encode(wrong_public_bytes).decode("ascii")}),
    )

    experiment = LabRunner.run_synthetic_entropy_demo()
    report = Validator().run(Task(
        task_id="trusted-key-fingerprint-mismatch",
        description="Reject a trusted key ID mapped to a different public key",
        result={
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "sources": [],
            "hypotheses": [],
            "lab_experiments": [experiment],
        },
    )).result["research_validation"]

    assert report["lab_trusted_signing_key_count"] == 1
    assert report["lab_trusted_key_configuration_error"] is None
    check = report["lab_execution_receipt_checks"][0]
    assert check["integrity_verified"] is True
    assert check["signature_verified_against_trusted_key"] is False
    assert check["authenticity"] == "SIGNATURE_INVALID_OR_UNTRUSTED"
    assert check["signature_error"] == "signer_key_fingerprint_mismatch"
    assert report["historical_reproduction_confirmed"] is False
    assert report["status"] == "INCONCLUSIVE"


def test_validator_rejects_mutated_receipt_inside_signed_envelope(monkeypatch):
    import base64
    from copy import deepcopy
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from agents.validator.agent import Validator

    signer = Ed25519PrivateKey.generate()
    private_bytes = signer.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = "runner-mutated-envelope-receipt"
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_B64", base64.b64encode(private_bytes).decode("ascii"))
    monkeypatch.setenv("AEGISFORGE_LAB_SIGNING_KEY_ID", key_id)
    monkeypatch.setenv(
        "AEGISFORGE_LAB_TRUSTED_PUBLIC_KEYS",
        json.dumps({key_id: base64.b64encode(public_bytes).decode("ascii")}),
    )

    experiment = LabRunner.run_synthetic_entropy_demo()
    # Mutate only the copy embedded in the signed envelope. Keep the separately
    # evaluated receipt and its digest intact to isolate envelope verification.
    experiment["execution_receipt_envelope"]["receipt"] = deepcopy(
        experiment["execution_receipt_envelope"]["receipt"]
    )
    experiment["execution_receipt_envelope"]["receipt"]["execution"]["exit_code"] = 99
    report = Validator().run(Task(
        task_id="mutated-envelope-receipt",
        description="Reject a mutated receipt embedded in a signed envelope",
        result={
            "research_track": "evm_key_forensics",
            "stage": "lab",
            "sources": [],
            "hypotheses": [],
            "lab_experiments": [experiment],
        },
    )).result["research_validation"]

    check = report["lab_execution_receipt_checks"][0]
    assert check["integrity_verified"] is True
    assert check["signature_verified_against_trusted_key"] is False
    assert check["authenticity"] == "SIGNATURE_INVALID_OR_UNTRUSTED"
    assert check["signature_error"] == "receipt_digest_mismatch"
    assert report["historical_reproduction_confirmed"] is False
    assert report["status"] == "INCONCLUSIVE"

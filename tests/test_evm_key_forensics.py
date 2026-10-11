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
    assert valid_result["historical_reproduction_confirmed"] is False

    tampered = deepcopy(experiment)
    tampered["execution_record"]["stdout"] += "forged-after-run"
    tampered_result = validate(tampered)
    tampered_checks = tampered_result["lab_execution_record_checks"][0]["checks"]
    assert tampered_result["lab_execution_records_consistent"] is False
    assert tampered_checks["stdout_digest_matches"] is False
    assert tampered_result["historical_reproduction_confirmed"] is False

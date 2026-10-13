"""End-to-end evidence-flow tests for the EVM Key Forensics research track.

All upstream responses are deterministic synthetic fixtures. No historical
program is executed and no real wallet material is used.
"""
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from agents.crypto_analyst.agent import CryptoAnalyst
from agents.source_researcher.agent import SourceResearcher
from agents.validator.agent import Validator
from shared.task import Task


PRE_DISCLOSURE = "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6"
ARCHIVE = "186b9b27ab3e24a1899f648adcabcbf0e5f3131e"


class FakeGitHub:
    BASE_URL = "https://api.github.com"

    def get_json(self, url, params=None, **kwargs):
        if url.endswith("/repos/johguse/profanity/commits/v1.50"):
            return {"sha": PRE_DISCLOSURE}
        if url.endswith("/repos/johguse/profanity/commits/master"):
            return {"sha": ARCHIVE}
        return {"items": []}


def fake_public_fetch(url):
    if "ethereum-protocol-update-1" in url:
        body = (
            "If your keys date back from Go 1.0 rc or C++ 0.9.36, "
            "regenerate all of your keys. The C++ client now relies upon "
            "boost::random_device."
        )
    elif "1inch.com" in url:
        body = (
            "Profanity used a random 32-bit vector to seed 256-bit private "
            "keys. Public researchers reported a weakness in the generator."
        )
    elif "security-alert-1-windowsalethzero-2" in url:
        body = "Key files may not be written; confirm the underlying key exists."
    elif "smart-contract-wallets-created-in-frontier" in url:
        body = "Smart contract wallets created in Frontier were vulnerable to phishing attacks."
    elif PRE_DISCLOSURE in url:
        body = "Synthetic pinned pre-disclosure implementation fixture; no executable code."
    elif ARCHIVE in url:
        body = "Synthetic pinned archived implementation fixture; no executable code."
    else:
        body = "Synthetic source fixture for provenance and hash checks only."
    return {
        "source_url": url,
        "final_url": url,
        "status_code": 200,
        "fetch_status": "fetched",
        "title": "Synthetic fixture",
        "text": body,
        "excerpt": body,
        "content_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "content_bytes": len(body.encode("utf-8")),
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "content_truncated_for_analysis": False,
    }


def test_source_researcher_crypto_analyst_validator_preserve_evidence_boundaries():
    task = Task(
        task_id="evm-forensics-e2e",
        description="Trace public historical key-generation evidence without asserting reproduction",
    )

    researched = SourceResearcher(
        github=FakeGitHub(),
        fetcher=fake_public_fetch,
    ).run(task)
    assert researched.status == "source_researched"
    research_result = researched.result
    assert research_result["scope_guards"]["public_sources_only"] is True
    assert research_result["scope_guards"]["no_real_wallet_key_recovery"] is True

    analyzed = CryptoAnalyst().run(researched)
    assert analyzed.status == "crypto_analyzed"
    result = analyzed.result
    profanity = next(
        item for item in result["hypotheses"]
        if item["hypothesis_id"] == "H-PROFANITY-SEED-SPACE"
    )
    assert profanity["status"] == "SOURCE_SUPPORTED_REPRODUCTION_PENDING"
    assert profanity["source_ids"]
    assert all(
        source_id in {item["source_id"] for item in result["sources"]}
        for source_id in profanity["source_ids"]
    )
    assert result["analysis_summary"]["claims_confirmed_by_this_agent"] == 0

    validated = Validator(source_fetcher=fake_public_fetch).run(analyzed)
    assert validated.status == "validated"
    validation = validated.result["research_validation"]
    assert validated.result["stage"] == "validation"
    assert validation["sources_rechecked_http_200"] >= 2
    assert validation["exact_source_fingerprints_matching"] >= 2
    checked_by_id = {
        item["source_id"]: item
        for item in validated.result["research_source_checks"]
    }
    matching_digests = [
        source["content_sha256"]
        for source in result["sources"]
        if checked_by_id.get(source.get("source_id"), {}).get("content_fingerprint_matches") is True
    ]
    distinct_digests = set(matching_digests)
    assert validation["distinct_matching_source_fingerprints"] == len(distinct_digests)
    assert validation["independent_matching_source_fingerprints"] == len(distinct_digests)
    assert validation["matching_fingerprint_groups_with_duplicates"] == sum(
        matching_digests.count(digest) > 1 for digest in distinct_digests
    )
    assert validation["source_origin_independence_established"] is False
    assert "source_origin_independence_not_established" in validation["readiness_blockers"]
    assert validation["pinned_revision_source_checks_failed"] == 0
    assert validation["historical_reproduction_confirmed"] is False
    assert validation["status"] == "INCONCLUSIVE"
    assert "historical_reproduction_not_qualified" in validation["readiness_blockers"]
    assert validation["decision"] == "CONTINUE_RESEARCH"


def test_pipeline_keeps_missing_source_evidence_inconclusive():
    task = Task(
        task_id="evm-forensics-e2e-empty",
        description="Empty dossier must not become a finding",
        result={
            "research_track": "evm_key_forensics",
            "stage": "sources",
            "sources": [],
            "repository_pins": [],
            "source_leads": [],
        },
    )
    analyzed = CryptoAnalyst().run(task)
    validated = Validator(source_fetcher=fake_public_fetch).run(analyzed)
    report = validated.result["research_validation"]

    assert report["status"] == "INCONCLUSIVE"
    assert report["historical_reproduction_confirmed"] is False
    assert report["sources_rechecked_http_200"] == 0
    assert report["decision"] == "CONTINUE_RESEARCH"


def test_pipeline_detects_source_mutation_between_collection_and_validation():
    calls = {}
    target = "https://1inch.com/blog/post/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool"

    def changing_fetch(url):
        fetched = fake_public_fetch(url)
        calls[url] = calls.get(url, 0) + 1
        if url == target and calls[url] > 1:
            changed = fetched["text"] + " Post-collection mutation fixture."
            fetched["text"] = changed
            fetched["excerpt"] = changed
            fetched["content_sha256"] = hashlib.sha256(changed.encode("utf-8")).hexdigest()
            fetched["content_bytes"] = len(changed.encode("utf-8"))
        return fetched

    researched = SourceResearcher(
        github=FakeGitHub(),
        fetcher=changing_fetch,
    ).run(Task(
        task_id="evm-forensics-source-mutation",
        description="Detect source content changing after collection",
    ))
    analyzed = CryptoAnalyst().run(researched)
    validated = Validator(source_fetcher=changing_fetch).run(analyzed)
    report = validated.result["research_validation"]
    target_check = next(
        item for item in validated.result["research_source_checks"]
        if item["source_url"] == target
    )

    assert calls[target] >= 2
    assert target_check["recheck_status"] == "rechecked_http_200"
    assert target_check["content_fingerprint_matches"] is False
    assert report["exact_source_fingerprints_matching"] < report["sources_rechecked_http_200"]
    assert report["status"] == "INCONCLUSIVE"
    assert report["decision"] == "CONTINUE_RESEARCH"
    assert report["historical_reproduction_confirmed"] is False


def test_pipeline_rejects_pinned_source_metadata_that_disagrees_with_immutable_url():
    researched = SourceResearcher(
        github=FakeGitHub(),
        fetcher=fake_public_fetch,
    ).run(Task(
        task_id="evm-forensics-pinned-path-mismatch",
        description="Reject source metadata that disagrees with its immutable URL",
    ))
    analyzed = CryptoAnalyst().run(researched)
    result = analyzed.result
    pinned = next(
        source for source in result["sources"]
        if source.get("source_kind") == "pinned_repository_source"
    )
    original_path = pinned["source_file_path"]
    pinned["source_file_path"] = "tampered/" + original_path

    validated = Validator(source_fetcher=fake_public_fetch).run(analyzed)
    report = validated.result["research_validation"]
    check = next(
        item for item in validated.result["research_source_checks"]
        if item["source_id"] == pinned["source_id"]
    )

    assert check["content_fingerprint_matches"] is True
    assert check["immutable_revision_pin_valid"] is False
    assert report["pinned_revision_source_checks_failed"] >= 1
    assert "pinned_revision_provenance_not_clean" in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"
    assert report["historical_reproduction_confirmed"] is False


def test_pipeline_rejects_repository_pin_with_mutated_commit_sha():
    researched = SourceResearcher(
        github=FakeGitHub(),
        fetcher=fake_public_fetch,
    ).run(Task(
        task_id="evm-forensics-pinned-commit-mismatch",
        description="Reject a stored repository pin whose commit SHA was changed",
    ))
    analyzed = CryptoAnalyst().run(researched)
    pins = analyzed.result["repository_pins"]
    assert pins
    pins[0]["commit_sha"] = "f" * 40

    validated = Validator(source_fetcher=fake_public_fetch).run(analyzed)
    report = validated.result["research_validation"]

    assert report["pinned_revision_source_checks_failed"] >= 1
    assert "pinned_revision_provenance_not_clean" in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"
    assert report["decision"] == "CONTINUE_RESEARCH"
    assert report["historical_reproduction_confirmed"] is False

def test_pipeline_blocks_duplicate_source_ids_in_evidence_dossier():
    researched = SourceResearcher(
        github=FakeGitHub(),
        fetcher=fake_public_fetch,
    ).run(Task(
        task_id="evm-forensics-duplicate-source-id",
        description="Reject ambiguous source identity in evidence dossier",
    ))
    analyzed = CryptoAnalyst().run(researched)
    sources = analyzed.result["sources"]
    assert len(sources) >= 2
    sources[1]["source_id"] = sources[0]["source_id"]

    validated = Validator(source_fetcher=fake_public_fetch).run(analyzed)
    report = validated.result["research_validation"]

    assert report["source_identity_integrity_failed"] is True
    assert sources[0]["source_id"] in report["duplicate_source_ids"]
    assert "source_identity_integrity_failed" in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"
    assert report["historical_reproduction_confirmed"] is False


def test_pipeline_blocks_source_record_without_source_id():
    researched = SourceResearcher(
        github=FakeGitHub(),
        fetcher=fake_public_fetch,
    ).run(Task(
        task_id="evm-forensics-missing-source-id",
        description="Reject a source record without a stable identifier",
    ))
    analyzed = CryptoAnalyst().run(researched)
    sources = analyzed.result["sources"]
    sources[0].pop("source_id", None)

    validated = Validator(source_fetcher=fake_public_fetch).run(analyzed)
    report = validated.result["research_validation"]

    assert report["source_identity_integrity_failed"] is True
    assert report["sources_missing_source_id"] == 1
    assert "source_identity_integrity_failed" in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"
    assert report["historical_reproduction_confirmed"] is False

def test_pipeline_blocks_duplicate_canonical_source_urls():
    researched = SourceResearcher(
        github=FakeGitHub(),
        fetcher=fake_public_fetch,
    ).run(Task(
        task_id="evm-forensics-duplicate-source-url",
        description="Detect duplicate canonical URLs in the evidence dossier",
    ))
    analyzed = CryptoAnalyst().run(researched)
    sources = analyzed.result["sources"]
    assert len(sources) >= 2
    sources[1]["source_url"] = sources[0]["source_url"].rstrip("/") + "/"

    validated = Validator(source_fetcher=fake_public_fetch).run(analyzed)
    report = validated.result["research_validation"]

    assert report["duplicate_source_urls"]
    assert "duplicate_source_urls" in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"
    assert report["historical_reproduction_confirmed"] is False


def test_pipeline_blocks_hypothesis_references_to_missing_source_ids():
    researched = SourceResearcher(
        github=FakeGitHub(),
        fetcher=fake_public_fetch,
    ).run(Task(
        task_id="evm-forensics-dangling-source-reference",
        description="Reject hypothesis citations that do not exist in the dossier",
    ))
    analyzed = CryptoAnalyst().run(researched)
    hypothesis = analyzed.result["hypotheses"][0]
    hypothesis["source_ids"] = ["source-id-that-does-not-exist"]

    validated = Validator(source_fetcher=fake_public_fetch).run(analyzed)
    report = validated.result["research_validation"]

    assert report["hypotheses_with_invalid_source_references"] >= 1
    assert "hypothesis_source_references_invalid" in report["readiness_blockers"]
    assert any(
        "source-id-that-does-not-exist" in check["missing_source_references"]
        for check in report["hypothesis_checks"]
    )
    assert report["status"] == "INCONCLUSIVE"


def test_pipeline_reports_sources_omitted_by_recheck_limit():
    researched = SourceResearcher(
        github=FakeGitHub(),
        fetcher=fake_public_fetch,
    ).run(Task(
        task_id="evm-forensics-recheck-cap",
        description="Make source recheck coverage explicit when dossier exceeds its cap",
    ))
    analyzed = CryptoAnalyst().run(researched)
    sources = analyzed.result["sources"]
    assert sources
    original_count = len(sources)
    while len(sources) <= Validator.MAX_RESEARCH_SOURCE_RECHECKS:
        clone = dict(sources[-1])
        clone["source_id"] = f"synthetic-overflow-{len(sources)}"
        clone["source_url"] = f"https://github.com/johguse/profanity/issues/{1000 + len(sources)}"
        sources.append(clone)

    validated = Validator(source_fetcher=fake_public_fetch).run(analyzed)
    report = validated.result["research_validation"]

    assert report["sources_in_dossier"] == len(sources)
    assert report["source_recheck_limit"] == Validator.MAX_RESEARCH_SOURCE_RECHECKS
    assert report["sources_not_rechecked_due_to_limit"] == len(sources) - Validator.MAX_RESEARCH_SOURCE_RECHECKS
    assert "source_recheck_limit_exceeded" in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"

def test_pipeline_normalizes_default_https_port_and_url_fragment():
    researched = SourceResearcher(
        github=FakeGitHub(),
        fetcher=fake_public_fetch,
    ).run(Task(
        task_id="evm-forensics-default-port-url",
        description="Canonicalize equivalent HTTPS source URLs",
    ))
    analyzed = CryptoAnalyst().run(researched)
    sources = analyzed.result["sources"]
    assert len(sources) >= 2

    parts = urlsplit(sources[0]["source_url"])
    sources[1]["source_url"] = urlunsplit((
        parts.scheme,
        f"{parts.hostname}:443",
        parts.path.rstrip("/") + "/",
        parts.query,
        "irrelevant-fragment",
    ))

    validated = Validator(source_fetcher=fake_public_fetch).run(analyzed)
    report = validated.result["research_validation"]

    assert report["duplicate_source_urls"]
    assert "duplicate_source_urls" in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"


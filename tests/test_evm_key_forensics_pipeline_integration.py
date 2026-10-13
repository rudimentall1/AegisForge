"""End-to-end evidence-flow tests for the EVM Key Forensics research track.

All upstream responses are deterministic synthetic fixtures. No historical
program is executed and no real wallet material is used.
"""
import hashlib
from datetime import datetime, timezone

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

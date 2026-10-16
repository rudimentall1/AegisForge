from shared.research_case import ResearchCase
from shared.task import Task
from agents.crypto_analyst.agent import CryptoAnalyst
from agents.source_researcher.agent import SourceResearcher


PRE_DISCLOSURE = "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6"
POST_DISCLOSURE = "186b9b27ab3e24a1899f648adcabcbf0e5f3131e"
CASE_ID = "profanity-case-aware-test"


def _case():
    return ResearchCase(
        case_id=CASE_ID,
        target_repository="johguse/profanity",
        target_commit=PRE_DISCLOSURE,
        scope_url="https://github.com/rudimentall1/AegisForge/blob/main/docs/research/evm-key-forensics/KNOWN_VULNERABILITY_BENCHMARK.md",
        scope_digest="a" * 64,
        scope_reviewed_on="2026-10-16",
        hypothesis="Review the pinned Profanity seed-construction pattern without claiming runtime exploitability.",
        attacker_capability="Offline source reviewer only; no wallet or key material.",
        expected_invariant="Every claim is tied to pinned source and primary disclosure evidence.",
        falsification_criteria="Missing or contradictory source evidence remains inconclusive.",
        execution_mode="local",
        status="ready",
    )


class _FakeGitHub:
    BASE_URL = "https://api.github.com"

    def get_json(self, url, params=None, **kwargs):
        if "/commits/v1.50" in url:
            return {"sha": PRE_DISCLOSURE}
        if "/commits/master" in url:
            return {"sha": POST_DISCLOSURE}
        if "/search/issues" in url:
            return {"items": []}
        raise AssertionError(f"Unexpected GitHub API URL: {url}")


def _fake_fetcher(url):
    if "issues/61" in url:
        title = "Private key safety"
    elif "GHSA-9q2f-7hm7-62h6" in url:
        title = "Profanity weak PRNG security advisory"
    elif "CVE-2022-40769" in url:
        title = "Profanity key generation CVE record"
    else:
        title = "Profanity key generation source review"
    text = (
        "Profanity vanity address tool seed space private key generation "
        "std::random_device std::mt19937_64 weak PRNG. "
        f"Fixture for {url}. This is not a runtime reproduction."
    )
    import hashlib

    return {
        "text": text,
        "title": title,
        "final_url": url,
        "status_code": 200,
        "fetch_status": "ok",
        "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "content_bytes": len(text.encode()),
        "retrieved_at": "2026-10-16T00:00:00+00:00",
    }


def test_source_researcher_uses_case_specific_primary_sources():
    researcher = SourceResearcher(github=_FakeGitHub(), fetcher=_fake_fetcher)
    task = Task(
        task_id="source-test",
        description="Research this registered case.",
        payload={"research_case": _case()},
    )

    result = researcher.run(task).result
    urls = {source["source_url"] for source in result["sources"]}

    assert "https://github.com/johguse/profanity/issues/61" in urls
    assert "https://github.com/advisories/GHSA-9q2f-7hm7-62h6" in urls
    assert "https://nvd.nist.gov/vuln/detail/CVE-2022-40769" in urls
    assert "https://1inch.com/blog/post/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool" in urls
    assert not any("blog.ethereum.org/2015" in url for url in urls)
    assert not any("smart-contract-wallets-created-in-frontier" in url for url in urls)
    by_url = {source["source_url"]: source for source in result["sources"]}
    assert by_url["https://github.com/johguse/profanity/issues/61"]["source_kind"] == "maintainer_issue"
    assert by_url["https://github.com/advisories/GHSA-9q2f-7hm7-62h6"]["source_kind"] == "security_advisory"
    assert by_url["https://nvd.nist.gov/vuln/detail/CVE-2022-40769"]["source_kind"] == "vulnerability_database_record"
    assert result["repository_pin_errors"] == []
    assert result["source_summary"]["pinned_repository_files"] == 8


def test_crypto_analyst_focuses_on_the_registered_profanity_case():
    sources = [
        {
            "source_id": "pre-disclosure-dispatcher",
            "source_url": f"https://raw.githubusercontent.com/johguse/profanity/{PRE_DISCLOSURE}/Dispatcher.cpp",
            "repository": "johguse/profanity",
            "source_file_path": "Dispatcher.cpp",
            "revision_sha": PRE_DISCLOSURE,
            "status_code": 200,
            "content_sha256": "1" * 64,
            "source_kind": "pinned_repository_source",
            "classification": "pinned_historical_implementation_source",
        },
        {
            "source_id": "post-disclosure-dispatcher",
            "source_url": f"https://raw.githubusercontent.com/johguse/profanity/{POST_DISCLOSURE}/Dispatcher.cpp",
            "repository": "johguse/profanity",
            "source_file_path": "Dispatcher.cpp",
            "revision_sha": POST_DISCLOSURE,
            "status_code": 200,
            "content_sha256": "2" * 64,
            "source_kind": "pinned_repository_source",
            "classification": "pinned_historical_implementation_source",
        },
        {
            "source_id": "ghsa",
            "source_url": "https://github.com/advisories/GHSA-9q2f-7hm7-62h6",
            "status_code": 200,
            "content_sha256": "3" * 64,
            "source_kind": "security_advisory",
            "classification": "vanity_generator_entropy_weakness_report",
        },
        {
            "source_id": "maintainer-issue",
            "source_url": "https://github.com/johguse/profanity/issues/61",
            "status_code": 200,
            "content_sha256": "4" * 64,
            "source_kind": "maintainer_issue",
            "classification": "vanity_generator_entropy_weakness_report",
        },
    ]
    task = Task(
        task_id="crypto-test",
        description="Analyze the evidence for this registered case.",
        payload={"research_case": _case()},
        result={"sources": sources, "source_leads": []},
    )

    result = CryptoAnalyst().run(task).result

    assert [item["hypothesis_id"] for item in result["hypotheses"]] == [
        "H-PROFANITY-SEED-SPACE",
        "H-PROFANITY-HISTORICAL-RUNTIME",
        "H-PROFANITY-WALLET-EXPOSURE",
    ]
    assert result["hypotheses"][0]["status"] == "SOURCE_SUPPORTED_REPRODUCTION_PENDING"
    assert result["hypotheses"][1]["status"] == "NOT_ESTABLISHED"
    assert result["hypotheses"][2]["status"] == "UNPROVEN"
    assert result["analysis_summary"]["pinned_dispatcher_revision_count"] == 2
    assert result["analysis_summary"]["primary_disclosure_source_count"] == 2
    assert result["analysis_summary"]["claims_confirmed_by_this_agent"] == 0
    assert all(
        item["hypothesis_id"] != "H-EARLY-CLIENT-KEYGEN"
        for item in result["hypotheses"]
    )


def test_crypto_analyst_does_not_overstate_incomplete_pinned_evidence():
    task = Task(
        task_id="crypto-incomplete-test",
        description="Analyze incomplete evidence.",
        payload={"research_case": _case()},
        result={
            "sources": [
                {
                    "source_id": "only-one-revision",
                    "repository": "johguse/profanity",
                    "source_file_path": "Dispatcher.cpp",
                    "revision_sha": PRE_DISCLOSURE,
                    "status_code": 200,
                    "content_sha256": "1" * 64,
                    "source_kind": "pinned_repository_source",
                }
            ],
            "source_leads": [],
        },
    )

    result = CryptoAnalyst().run(task).result
    assert result["hypotheses"][0]["status"] == "OPEN_NO_PRIMARY_SOURCE_MATCH"


def test_failed_seed_fetch_keeps_url_specific_source_kind():
    def fail_fetch(url):
        raise ValueError("source_url_not_allowlisted_https")

    researcher = SourceResearcher(github=_FakeGitHub(), fetcher=fail_fetch)
    source = researcher._fetch_seed_source(
        "https://nvd.nist.gov/vuln/detail/CVE-2022-40769",
        "nvd_cve_record",
        {},
    )

    assert source["fetch_status"] == "fetch_error"
    assert source["source_kind"] == "vulnerability_database_record"
    assert source["classification"] == "unclassified_source"

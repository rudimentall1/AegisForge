from agents.source_researcher.agent import SourceResearcher
from tools.evm_key_forensics.known_vulnerability_benchmark import EXPECTED_LABELS, FIXTURES


def test_source_researcher_classifier_matches_benchmark_control_cases():
    """Keep the production source classifier aligned with benchmark expectations."""
    for fixture in FIXTURES:
        source = fixture["source"]
        advisory = fixture["advisory"]
        if fixture["case_id"] == "positive_profanity":
            # The source classifier gets source text only; advisory context is a
            # separate evidence type and must not be silently merged into source.
            url = "https://github.com/johguse/profanity/blob/pinned/Dispatcher.cpp"
            title = "Profanity Dispatcher.cpp"
        else:
            url = ""
            title = ""

        actual = SourceResearcher._classification(url, title, source)
        expected = EXPECTED_LABELS[fixture["case_id"]]
        assert actual == expected, (
            f"{fixture['case_id']}: expected {expected}, got {actual}"
        )


def test_empty_source_research_input_is_not_misreported_as_unclassified():
    assert SourceResearcher._classification("", "", "") == "inconclusive_missing_evidence"



def test_profane_word_and_seed_in_unrelated_context_do_not_trigger_finding():
    actual = SourceResearcher._classification(
        "https://github.com/example/profanity-docs",
        "Profanity private-key test documentation",
        "A 32-bit seed is recorded beside a private-key test fixture. "
        "This page does not describe key generation or an RNG implementation.",
    )
    assert actual == "unclassified_source"


def test_profane_seed_and_key_terms_without_rng_evidence_are_not_a_finding():
    actual = SourceResearcher._classification(
        "https://github.com/example/profanity-docs",
        "Profanity migration notes",
        "The migration notes mention a seed, a 32-bit value, and a private key, "
        "but provide no random generator or key-generation implementation details.",
    )
    assert actual == "unclassified_source"


def test_rng_and_private_key_vocabulary_without_generation_path_are_not_a_finding():
    actual = SourceResearcher._classification(
        "https://github.com/example/profanity-docs",
        "Profanity telemetry and private-key test fixtures",
        "A telemetry sampler uses mt19937_64 and records a 32-bit seed beside "
        "a private-key fixture. No vanity-address or key-generation path is described.",
    )
    assert actual == "unclassified_source"


def test_crypto_analyst_keeps_source_support_separate_from_reproduction():
    from agents.crypto_analyst.agent import CryptoAnalyst
    from shared.task import Task

    task = Task(
        task_id="benchmark-analysis",
        description="Evaluate the benchmark evidence without claiming reproduction",
        result={
            "research_track": "evm_key_forensics",
            "stage": "source_research",
            "sources": [
                {
                    "source_id": "pinned-source-1",
                    "classification": "vanity_generator_entropy_weakness_report",
                    "source_url": "https://github.com/johguse/profanity/blob/pinned/Dispatcher.cpp",
                },
                {
                    "source_id": "storage-confounder",
                    "classification": "key_file_creation_or_storage_issue",
                    "source_url": "https://example.invalid/key-files",
                },
            ],
            "source_leads": [],
        },
    )

    analyzed = CryptoAnalyst().run(task)
    result = analyzed.result
    profanity = next(
        item for item in result["hypotheses"]
        if item["hypothesis_id"] == "H-PROFANITY-SEED-SPACE"
    )

    assert analyzed.status == "crypto_analyzed"
    assert profanity["status"] == "SOURCE_SUPPORTED_REPRODUCTION_PENDING"
    assert profanity["source_ids"] == ["pinned-source-1"]
    assert result["analysis_summary"]["claims_confirmed_by_this_agent"] == 0
    assert result["confounder_sources"][0]["classification"] == "key_file_creation_or_storage_issue"
    assert result["next_experiment"]["explicit_limit"].startswith("This is not a reproduction")

def test_validator_keeps_empty_dossier_inconclusive():
    from agents.validator.agent import Validator
    from shared.task import Task

    task = Task(
        task_id="empty-forensics-dossier",
        description="Do not promote an empty dossier",
        result={
            "research_track": "evm_key_forensics",
            "stage": "analysis",
            "sources": [],
            "source_leads": [],
            "hypotheses": [],
            "lab_experiments": [],
        },
    )

    validated = Validator().run(task)
    report = validated.result["research_validation"]

    assert validated.status == "validated"
    assert report["status"] == "INCONCLUSIVE"
    assert report["historical_reproduction_confirmed"] is False
    assert report["sources_rechecked_http_200"] == 0
    assert "historical_reproduction_not_qualified" in report["readiness_blockers"]
    assert report["decision"] == "CONTINUE_RESEARCH"




def test_pipeline_surfaces_explicit_conflicting_claims_without_resolving_them():
    """Opposing structured assertions must block readiness, not become a vote."""
    from agents.crypto_analyst.agent import CryptoAnalyst
    from agents.validator.agent import Validator
    from shared.task import Task

    task = Task(
        task_id="conflicting-evidence-pipeline",
        description="Keep conflicting synthetic evidence unresolved",
        result={
            "research_track": "evm_key_forensics",
            "stage": "source_research",
            "sources": [
                {
                    "source_id": "source-supports",
                    "source_url": "https://example.invalid/source-a",
                    "classification": "unclassified_source",
                    "claim_assertions": [
                        {"claim_id": "historical-generator-uses-rng", "stance": "SUPPORTS"}
                    ],
                },
                {
                    "source_id": "source-refutes",
                    "source_url": "https://example.invalid/source-b",
                    "classification": "unclassified_source",
                    "claim_assertions": [
                        {"claim_id": "historical-generator-uses-rng", "stance": "REFUTES"}
                    ],
                },
            ],
            "source_leads": [],
            "hypotheses": [],
            "lab_experiments": [],
        },
    )

    analyzed = CryptoAnalyst().run(task)
    validated = Validator(source_fetcher=lambda _url: {}).run(analyzed)
    report = validated.result["research_validation"]

    assert validated.status == "validated"
    assert report["status"] == "INCONCLUSIVE"
    assert report["decision"] == "CONTINUE_RESEARCH"
    assert report["explicit_claim_assertions_checked"] == 2
    assert report["conflicting_source_claims"] == [
        {
            "claim_id": "historical-generator-uses-rng",
            "supporting_source_ids": ["source-supports"],
            "refuting_source_ids": ["source-refutes"],
        }
    ]
    assert "conflicting_source_claims_require_review" in report["readiness_blockers"]
    assert any("Resolve explicit opposing source assertions" in item for item in report["next_actions"])



def test_pipeline_does_not_treat_duplicate_source_records_as_independent_evidence():
    """Duplicated identity/URL records must remain blocked even if fetches match."""
    import hashlib

    from agents.crypto_analyst.agent import CryptoAnalyst
    from agents.validator.agent import Validator
    from shared.task import Task

    body = "Synthetic, non-authoritative source body for identity-integrity testing."
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    duplicate_source = {
        "source_id": "same-source-record",
        "source_url": "https://raw.githubusercontent.com/example/repo/0123456789012345678901234567890123456789/README.md",
        "status_code": 200,
        "content_sha256": digest,
        "classification": "unclassified_source",
    }
    task = Task(
        task_id="duplicate-source-integrity-pipeline",
        description="Ensure duplicated source records cannot inflate evidence independence",
        result={
            "research_track": "evm_key_forensics",
            "stage": "source_research",
            "sources": [dict(duplicate_source), dict(duplicate_source)],
            "source_leads": [],
            "hypotheses": [],
            "lab_experiments": [],
        },
    )

    analyzed = CryptoAnalyst().run(task)
    validated = Validator(
        source_fetcher=lambda _url: {
            "status_code": 200,
            "content_sha256": digest,
            "content_truncated_for_analysis": False,
            "retrieved_at": "2026-10-13T00:00:00Z",
        }
    ).run(analyzed)
    report = validated.result["research_validation"]

    assert report["status"] == "INCONCLUSIVE"
    assert report["decision"] == "CONTINUE_RESEARCH"
    assert "source_identity_integrity_failed" in report["readiness_blockers"]
    assert "duplicate_source_urls" in report["readiness_blockers"]
    assert report["sources_rechecked_http_200"] == 2
    assert report["exact_source_fingerprints_matching"] == 2
    assert report["pinned_revision_source_checks_passed"] == 0



def test_pipeline_rejects_source_fingerprint_mismatch_after_successful_refetch():
    """HTTP 200 is not enough when the fetched bytes differ from the recorded digest."""
    import hashlib

    from agents.crypto_analyst.agent import CryptoAnalyst
    from agents.validator.agent import Validator
    from shared.task import Task

    recorded_a = "Previously reviewed source body A."
    fresh_a = "Different source body returned on re-fetch."
    body_b = "Previously reviewed source body B."
    digest_a = hashlib.sha256(recorded_a.encode("utf-8")).hexdigest()
    fresh_digest_a = hashlib.sha256(fresh_a.encode("utf-8")).hexdigest()
    digest_b = hashlib.sha256(body_b.encode("utf-8")).hexdigest()
    url_a = (
        "https://raw.githubusercontent.com/example/repo/"
        "0123456789012345678901234567890123456789/source-a.txt"
    )
    url_b = (
        "https://raw.githubusercontent.com/example/repo/"
        "0123456789012345678901234567890123456789/source-b.txt"
    )
    task = Task(
        task_id="source-fingerprint-mismatch-pipeline",
        description="A changed source body must not count as a matching evidence fingerprint",
        result={
            "research_track": "evm_key_forensics",
            "stage": "source_research",
            "sources": [
                {
                    "source_id": "source-a",
                    "source_url": url_a,
                    "status_code": 200,
                    "content_sha256": digest_a,
                    "classification": "unclassified_source",
                },
                {
                    "source_id": "source-b",
                    "source_url": url_b,
                    "status_code": 200,
                    "content_sha256": digest_b,
                    "classification": "unclassified_source",
                },
            ],
            "source_leads": [],
            "hypotheses": [],
            "lab_experiments": [],
        },
    )

    def source_fetcher(url):
        return {
            "status_code": 200,
            "content_sha256": fresh_digest_a if url == url_a else digest_b,
            "content_truncated_for_analysis": False,
            "retrieved_at": "2026-10-13T00:00:00Z",
        }

    analyzed = CryptoAnalyst().run(task)
    validated = Validator(source_fetcher=source_fetcher).run(analyzed)
    report = validated.result["research_validation"]
    checks = {item["source_id"]: item for item in validated.result["research_source_checks"]}

    assert checks["source-a"]["recheck_status"] == "rechecked_http_200"
    assert checks["source-a"]["content_fingerprint_matches"] is False
    assert checks["source-b"]["content_fingerprint_matches"] is True
    assert report["sources_rechecked_http_200"] == 2
    assert report["exact_source_fingerprints_matching"] == 1
    assert report["status"] == "INCONCLUSIVE"
    assert report["decision"] == "CONTINUE_RESEARCH"
    assert "insufficient_independent_source_rechecks" in report["readiness_blockers"]



def test_pipeline_keeps_unavailable_and_truncated_sources_inconclusive():
    """A failed fetch and clipped analysis text must not satisfy evidence readiness."""
    import hashlib

    from agents.crypto_analyst.agent import CryptoAnalyst
    from agents.validator.agent import Validator
    from shared.task import Task

    body_a = "Synthetic source A."
    body_b = "Synthetic source B."
    digest_a = hashlib.sha256(body_a.encode("utf-8")).hexdigest()
    digest_b = hashlib.sha256(body_b.encode("utf-8")).hexdigest()
    url_a = (
        "https://raw.githubusercontent.com/example/repo/"
        "0123456789012345678901234567890123456789/source-a.txt"
    )
    url_b = (
        "https://raw.githubusercontent.com/example/repo/"
        "0123456789012345678901234567890123456789/source-b.txt"
    )
    task = Task(
        task_id="unavailable-and-truncated-source-pipeline",
        description="Unavailable or clipped source material cannot establish readiness",
        result={
            "research_track": "evm_key_forensics",
            "stage": "source_research",
            "sources": [
                {
                    "source_id": "source-unavailable",
                    "source_url": url_a,
                    "status_code": 200,
                    "content_sha256": digest_a,
                    "classification": "unclassified_source",
                },
                {
                    "source_id": "source-truncated",
                    "source_url": url_b,
                    "status_code": 200,
                    "content_sha256": digest_b,
                    "classification": "unclassified_source",
                },
            ],
            "source_leads": [],
            "hypotheses": [],
            "lab_experiments": [],
        },
    )

    def source_fetcher(url):
        if url == url_a:
            return {
                "status_code": 503,
                "content_sha256": "",
                "content_truncated_for_analysis": False,
                "retrieved_at": "2026-10-13T00:00:00Z",
            }
        return {
            "status_code": 200,
            "content_sha256": digest_b,
            "content_truncated_for_analysis": True,
            "retrieved_at": "2026-10-13T00:00:00Z",
        }

    analyzed = CryptoAnalyst().run(task)
    validated = Validator(source_fetcher=source_fetcher).run(analyzed)
    report = validated.result["research_validation"]
    checks = {
        item["source_id"]: item
        for item in validated.result["research_source_checks"]
    }

    assert checks["source-unavailable"]["recheck_status"] == "recheck_http_503"
    assert checks["source-unavailable"]["content_fingerprint_matches"] is False
    assert checks["source-truncated"]["recheck_status"] == "rechecked_http_200"
    assert checks["source-truncated"]["analysis_text_completeness"] == "TRUNCATED"
    assert report["sources_rechecked_http_200"] == 1
    assert report["exact_source_fingerprints_matching"] == 1
    assert report["sources_with_truncated_analysis_text"] == 1
    assert report["status"] == "INCONCLUSIVE"
    assert report["decision"] == "CONTINUE_RESEARCH"
    assert "insufficient_independent_source_rechecks" in report["readiness_blockers"]
    assert "source_analysis_text_truncated" in report["readiness_blockers"]



def test_pipeline_does_not_count_identical_content_at_distinct_urls_as_independent():
    """Two URLs serving the same bytes are not two independent content witnesses."""
    import hashlib

    from agents.crypto_analyst.agent import CryptoAnalyst
    from agents.validator.agent import Validator
    from shared.task import Task

    body = "Same synthetic advisory body copied to two distinct URLs."
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    revision = "0123456789012345678901234567890123456789"
    urls = [
        f"https://raw.githubusercontent.com/example/repo/{revision}/source-a.txt",
        f"https://raw.githubusercontent.com/example/repo/{revision}/source-b.txt",
    ]
    sources = [
        {
            "source_id": f"source-{index}",
            "source_url": url,
            "status_code": 200,
            "content_sha256": digest,
            "classification": "unclassified_source",
        }
        for index, url in enumerate(urls, start=1)
    ]
    task = Task(
        task_id="duplicate-content-distinct-urls",
        description="Do not confuse distinct URLs with independent source content",
        result={
            "research_track": "evm_key_forensics",
            "stage": "source_research",
            "sources": sources,
            "source_leads": [],
            "hypotheses": [],
            "lab_experiments": [],
        },
    )

    analyzed = CryptoAnalyst().run(task)
    validated = Validator(
        source_fetcher=lambda _url: {
            "status_code": 200,
            "content_sha256": digest,
            "content_truncated_for_analysis": False,
            "retrieved_at": "2026-10-13T00:00:00Z",
        }
    ).run(analyzed)
    report = validated.result["research_validation"]

    assert report["sources_rechecked_http_200"] == 2
    assert report["exact_source_fingerprints_matching"] == 2
    assert report["independent_matching_source_fingerprints"] == 0
    assert len(report["duplicate_source_content_fingerprints"]) == 1
    assert "duplicate_source_content_fingerprints" in report["readiness_blockers"]
    assert "insufficient_independent_source_rechecks" in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"
    assert report["decision"] == "CONTINUE_RESEARCH"



def test_pipeline_surfaces_declared_source_lineage_dependencies():
    """Explicitly copied claims remain linked to their cited upstream source."""
    import hashlib

    from agents.crypto_analyst.agent import CryptoAnalyst
    from agents.validator.agent import Validator
    from shared.task import Task

    revision = "0123456789012345678901234567890123456789"
    body_a = "Primary source statement."
    body_b = "Secondary article paraphrasing the primary source."
    digest_a = hashlib.sha256(body_a.encode("utf-8")).hexdigest()
    digest_b = hashlib.sha256(body_b.encode("utf-8")).hexdigest()
    sources = [
        {
            "source_id": "primary",
            "source_url": f"https://raw.githubusercontent.com/example/repo/{revision}/primary.txt",
            "status_code": 200,
            "content_sha256": digest_a,
            "classification": "unclassified_source",
        },
        {
            "source_id": "secondary",
            "source_url": f"https://raw.githubusercontent.com/example/repo/{revision}/secondary.txt",
            "status_code": 200,
            "content_sha256": digest_b,
            "classification": "unclassified_source",
            "derived_from_source_ids": ["primary"],
        },
    ]
    task = Task(
        task_id="explicit-source-lineage",
        description="Surface explicit source dependency declarations",
        result={
            "research_track": "evm_key_forensics",
            "stage": "source_research",
            "sources": sources,
            "source_leads": [],
            "hypotheses": [],
            "lab_experiments": [],
        },
    )

    analyzed = CryptoAnalyst().run(task)
    validated = Validator(
        source_fetcher=lambda url: {
            "status_code": 200,
            "content_sha256": digest_a if url.endswith("primary.txt") else digest_b,
            "content_truncated_for_analysis": False,
            "retrieved_at": "2026-10-13T00:00:00Z",
        }
    ).run(analyzed)
    report = validated.result["research_validation"]

    assert report["source_derivation_dependencies"] == {"secondary": ["primary"]}
    assert report["sources_with_declared_derivations"] == 1
    assert "source_derivation_dependencies_require_review" in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"
    assert report["decision"] == "CONTINUE_RESEARCH"


def test_pipeline_rejects_malformed_source_lineage_entries():
    """Non-string and empty lineage entries must not be silently discarded."""
    from agents.crypto_analyst.agent import CryptoAnalyst
    from agents.validator.agent import Validator
    from shared.task import Task

    revision = "0123456789012345678901234567890123456789"
    task = Task(
        task_id="malformed-source-lineage",
        description="Malformed declared lineage stays inconclusive",
        result={
            "research_track": "evm_key_forensics",
            "stage": "source_research",
            "sources": [
                {
                    "source_id": "source-a",
                    "source_url": f"https://raw.githubusercontent.com/example/repo/{revision}/a.txt",
                    "classification": "unclassified_source",
                    "derived_from_source_ids": ["source-b", 17, ""],
                },
                {
                    "source_id": "source-b",
                    "source_url": f"https://raw.githubusercontent.com/example/repo/{revision}/b.txt",
                    "classification": "unclassified_source",
                },
            ],
            "source_leads": [],
            "hypotheses": [],
            "lab_experiments": [],
        },
    )
    validated = Validator(source_fetcher=lambda _url: {}).run(CryptoAnalyst().run(task))
    report = validated.result["research_validation"]

    assert "source-a" in report["invalid_source_derivation_references"]
    assert "source_derivation_references_invalid" in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"
    assert report["decision"] == "CONTINUE_RESEARCH"


def test_pipeline_blocks_self_referential_and_cyclic_source_lineage():
    """Self references and cycles are invalid metadata, not source independence."""
    from agents.crypto_analyst.agent import CryptoAnalyst
    from agents.validator.agent import Validator
    from shared.task import Task

    revision = "0123456789012345678901234567890123456789"
    sources = [
        {
            "source_id": "source-a",
            "source_url": f"https://raw.githubusercontent.com/example/repo/{revision}/a.txt",
            "classification": "unclassified_source",
            "derived_from_source_ids": ["source-a", "source-b"],
        },
        {
            "source_id": "source-b",
            "source_url": f"https://raw.githubusercontent.com/example/repo/{revision}/b.txt",
            "classification": "unclassified_source",
            "derived_from_source_ids": ["source-a"],
        },
    ]
    task = Task(
        task_id="cyclic-source-lineage",
        description="Self-referential and cyclic lineage remains blocked",
        result={
            "research_track": "evm_key_forensics",
            "stage": "source_research",
            "sources": sources,
            "source_leads": [],
            "hypotheses": [],
            "lab_experiments": [],
        },
    )
    validated = Validator(source_fetcher=lambda _url: {}).run(CryptoAnalyst().run(task))
    report = validated.result["research_validation"]

    assert report["self_referential_source_derivations"] == ["source-a"]
    assert report["source_derivation_cycles"]
    assert "source_derivation_self_reference" in report["readiness_blockers"]
    assert "source_derivation_lineage_cycle" in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"
    assert report["decision"] == "CONTINUE_RESEARCH"


def test_distinct_source_content_does_not_claim_independent_origin():
    """Unique hashes establish content distinction, not independent publishers."""
    from agents.crypto_analyst.agent import CryptoAnalyst
    from agents.validator.agent import Validator
    from shared.task import Task

    task = Task(
        task_id="source-origin-independence",
        description="Distinct synthetic sources must not imply verified origin independence",
        result={
            "research_track": "evm_key_forensics",
            "stage": "source_research",
            "sources": [
                {
                    "source_id": "source-a",
                    "source_url": "https://raw.githubusercontent.com/example/repo/0123456789012345678901234567890123456789/a.txt",
                    "classification": "unclassified_source",
                    "content_sha256": "a" * 64,
                },
                {
                    "source_id": "source-b",
                    "source_url": "https://raw.githubusercontent.com/example/repo/0123456789012345678901234567890123456789/b.txt",
                    "classification": "unclassified_source",
                    "content_sha256": "b" * 64,
                },
            ],
            "source_leads": [],
            "hypotheses": [],
            "lab_experiments": [],
        },
    )
    validated = Validator(source_fetcher=lambda _url: {}).run(CryptoAnalyst().run(task))
    report = validated.result["research_validation"]

    assert report["distinct_matching_source_fingerprints"] == 0
    assert report["source_origin_independence_established"] is False
    assert report["source_independence_basis"] == (
        "unique_content_hashes_and_distinct_urls_do_not_verify_independent_origin"
    )
    assert "source_origin_independence_not_established" in report["readiness_blockers"]
    assert report["status"] == "INCONCLUSIVE"
    assert report["decision"] == "CONTINUE_RESEARCH"

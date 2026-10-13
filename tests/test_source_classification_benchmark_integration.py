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

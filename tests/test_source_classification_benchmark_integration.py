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

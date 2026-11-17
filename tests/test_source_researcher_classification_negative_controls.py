"""Synthetic negative controls for source-research classification."""
import pytest

from agents.source_researcher.agent import SourceResearcher


@pytest.mark.parametrize(
    "text",
    [
        "Profanity research notes mention seed, mt19937_64, and createSeed, but this is not evidence of the affected generator.",
        "Profanity retrospective mentions seed, mt19937_64, and createSeed, but these references are unrelated to any production code.",
        "Profanity retrospective mentions seed, mt19937_64 and createSeed, but this component has no createSeed function and does not implement Profanity.",
        "A benchmark mentions Profanity, seed, mt19937_64, and createSeed, but these references are unrelated to vanity generation.",
    ],
)
def test_explicitly_negative_target_context_overrides_lexical_overlap(text):
    result = SourceResearcher._classification(
        "https://example.invalid/research-notes",
        "Profanity RNG and key generation research notes",
        text,
    )
    assert result == "unclassified_source"

"""Adversarial negative controls for the source-research classification heuristic.

These cases use synthetic text only. A lexical overlap must not be treated as
positive evidence when the text explicitly says the target implementation is
not present or not represented.
"""
import pytest

from agents.source_researcher.agent import SourceResearcher


@pytest.mark.parametrize(
    "text",
    [
        (
            "Profanity research notes. This is not evidence of the affected generator. "
            "The seed, mt19937_64, and createSeed references are quoted examples."
        ),
        (
            "Profanity project retrospective: seed space, mt19937_64 and createSeed "
            "are mentioned, but they are unrelated to any production code."
        ),
    ],
)
def test_explicitly_unrelated_target_context_does_not_become_positive(text):
    result = SourceResearcher._classification(
        "https://example.invalid/research-notes",
        "Profanity research notes",
        text,
    )

    assert result == "unclassified_source"

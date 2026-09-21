from agents.researcher.agent import Researcher


def test_researcher_defaults_to_diversified_technology_scan():
    queries = Researcher.select_queries("Find promising emerging technologies")
    assert len(queries) == 8
    assert any("AI agents" in q for q in queries)
    assert any("energy" in q for q in queries)
    assert any("robotics" in q for q in queries)


def test_researcher_narrows_to_explicit_domain():
    queries = Researcher.select_queries("Research AI agents and robotics infrastructure")
    assert queries
    assert all(
        any(term in q.lower() for term in ("ai", "robot", "infrastructure", "distributed", "llm"))
        for q in queries
    )
    assert not any("smart contract security" == q for q in queries)


def test_research_signal_contains_decision_relevant_metadata():
    signal = Researcher._signal(
        {
            "name": "acme/project",
            "url": "https://github.com/acme/project",
            "description": "Autonomous infrastructure",
            "stars": 1200,
            "language": "Python",
            "updated": "2026-09-20T00:00:00Z",
        },
        "AI agents autonomous agents",
    )
    assert signal["signal"] == "high"
    assert signal["discovery_query"]
    assert signal["updated"]


def test_researcher_rotates_search_profiles():
    base = Researcher._rotated_query("AI agents autonomous agents", 0, 0)
    updated = Researcher._rotated_query("AI agents autonomous agents", 1, 0)
    stars = Researcher._rotated_query("AI agents autonomous agents", 2, 0)
    assert base == "AI agents autonomous agents"
    assert updated.endswith("sort:updated")
    assert stars.endswith("sort:stars")
    assert len({base, updated, stars}) == 3


def test_researcher_parses_bounded_cross_cycle_exclusions():
    description = (
        "Discover AI agents\n"
        "Discovery rotation: 4\n"
        "Previously discovered repositories to skip: acme/one, acme/two"
    )
    assert Researcher._rotation(description) == 4
    assert Researcher._excluded_repositories(description) == {"acme/one", "acme/two"}

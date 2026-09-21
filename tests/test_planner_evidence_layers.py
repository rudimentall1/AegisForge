from orchestrator.master import AutonomousPlanner


def test_technical_review_is_new_evidence_over_repository_discovery():
    research = {"repositories": [{"name": "acme/project", "stars": 100}]}
    review = {
        **research,
        "technical_review": [{
            "name": "acme/project",
            "technical_maturity": "mature",
            "technical_maturity_score": 8,
            "has_tests": True,
            "has_ci": True,
            "risk_flags": ["missing audit"],
        }],
    }
    novel = AutonomousPlanner.evidence_atoms(review) - AutonomousPlanner.evidence_atoms(research)
    assert novel
    assert any(atom.startswith("technical_review:") for atom in novel)

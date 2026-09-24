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


def test_opportunity_evidence_is_stable_across_volatile_scores():
    first = {"opportunities": [{
        "name": "acme/project", "url": "https://github.com/acme/project",
        "opportunity_score": 25, "reasons": ["good adoption"],
        "product_thesis": "Build an evidence-driven operations layer.",
        "problem_signal": "Teams lack decision evidence.",
        "target_customer": "Engineering teams",
        "commercial_readiness": "EARLY_SIGNAL",
    }]}
    second = {"opportunities": [{
        "name": "acme/project", "url": "https://github.com/acme/project",
        "opportunity_score": 72, "reasons": ["validated"],
        "product_thesis": "Build an evidence-driven operations layer.",
        "problem_signal": "Teams lack decision evidence.",
        "target_customer": "Engineering teams",
        "commercial_readiness": "VALIDATE",
    }]}
    atoms_a = AutonomousPlanner.evidence_atoms(first)
    atoms_b = AutonomousPlanner.evidence_atoms(second)
    assert atoms_a == atoms_b
    assert len([a for a in atoms_a if a.startswith("opportunity:")]) == 1

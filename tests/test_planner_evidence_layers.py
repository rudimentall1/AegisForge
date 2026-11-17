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


def test_analyst_decision_fields_count_as_distinct_evidence():
    from orchestrator.master import AutonomousPlanner

    discovered = {
        "opportunities": [{
            "name": "acme/project",
            "url": "https://github.com/acme/project",
            "target_customer": "Engineering teams",
            "problem_signal": "Teams lack operational evidence.",
            "product_thesis": "Build an evidence layer.",
        }]
    }
    analyzed = {
        "opportunities": [{
            **discovered["opportunities"][0],
            "operational_gap": "Deployments lack rollback verification.",
            "decision_criteria": "Rollback must be independently observable.",
            "analyst_assessment": "Current evidence does not prove recovery.",
        }]
    }

    old_atoms = AutonomousPlanner.evidence_atoms(discovered)
    new_atoms = AutonomousPlanner.evidence_atoms(analyzed)
    novel = new_atoms - old_atoms

    assert any(atom.startswith("opportunity_analysis:") for atom in novel)
    assert len([atom for atom in new_atoms if atom.startswith("opportunity:")]) == 1


def test_repeated_analyst_fields_do_not_create_false_novelty():
    from orchestrator.master import AutonomousPlanner

    result = {
        "opportunities": [{
            "name": "acme/project",
            "operational_gap": "No rollback verification.",
            "decision_criteria": "Require an observable recovery test.",
        }]
    }
    assert AutonomousPlanner.evidence_atoms(result) == AutonomousPlanner.evidence_atoms(result)

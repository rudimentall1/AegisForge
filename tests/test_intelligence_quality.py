from shared.intelligence_quality import IntelligenceQualityEvaluator


def _base_opportunity():
    return {
        "name": "acme/agent-control",
        "reasons": ["technical maturity", "tests detected"],
        "evidence": {
            "stars": 120,
            "technical_maturity_score": 10,
            "security_score": 8,
            "has_tests": True,
            "has_ci": True,
            "repository_tree": {"files_total": 40},
        },
        "target_customer": "Security teams operating autonomous payment agents in production.",
        "problem_signal": "Operators cannot prove which agent actions were authorized after execution.",
        "product_thesis": "Provide an auditable authority layer that verifies policy-bound agent actions.",
        "validation_experiment": "Instrument one production workflow and compare unauthorized-action detection before and after deployment.",
        "business_model": "Per-agent subscription with enterprise audit tier.",
        "commercial_readiness": "VALIDATE",
        "uncertainties": ["willingness to pay is not validated"],
    }


def test_quality_rewards_specific_evidence_and_explicit_unknowns():
    result = IntelligenceQualityEvaluator().evaluate(_base_opportunity())

    assert result["score"] >= 70
    assert result["dimensions"]["evidence"] >= 60
    assert "observed_evidence" in result["labels"]
    assert "inference" in result["labels"]
    assert "hypothesis" in result["labels"]
    assert "unknowns_explicit" in result["labels"]


def test_generic_dossier_is_penalized_for_template_language():
    opportunity = _base_opportunity()
    opportunity.update(
        {
            "target_customer": "Teams deploying AI agents, agent platforms, and autonomous workflows.",
            "problem_signal": "Deployment, orchestration, reliability, or security complexity",
            "product_thesis": "Build agent infrastructure or an autonomous workflow product around the capability demonstrated by the target.",
            "validation_experiment": "Check users, competing products, adoption, deployment friction, and willingness to pay before implementation.",
        }
    )

    result = IntelligenceQualityEvaluator().evaluate(opportunity)

    assert result["dimensions"]["specificity"] < 50


def test_partial_commercial_validation_with_confidence_gain_is_flagged():
    opportunity = _base_opportunity()
    opportunity.update(
        {
            "validation_type": "commercial",
            "validation_status": "PARTIAL",
            "validation_evidence": {
                "status": "PARTIAL",
                "type": "commercial",
                "metric": "public_commercial_signal",
                "value": 4,
            },
            "confidence_delta": 0.02,
        }
    )

    result = IntelligenceQualityEvaluator().evaluate(opportunity)

    assert result["dimensions"]["honesty"] <= 50

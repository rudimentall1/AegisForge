[Reading 46 lines from start (total: 46 lines, 0 remaining)]

from agents.opportunity_hunter.agent import OpportunityHunter


def test_commercial_dossier_is_actionable():
    hunter = OpportunityHunter()
    dossier = hunter._commercial_dossier(
        {
            "name": "example-agent-security",
            "description": "AI agent security infrastructure",
            "stars": 1200,
        },
        ["AI", "Security"],
        {
            "technical_maturity_score": 7,
            "has_tests": True,
            "has_ci": True,
        },
        {"security_posture": {"score": 82}},
        {"opportunity_score": 78},
    )

    assert dossier["target_customer"]
    assert dossier["problem_signal"]
    assert dossier["product_thesis"]
    assert dossier["validation_experiment"]
    assert dossier["business_model"]
    assert dossier["commercial_moat"]
    assert dossier["evidence"]["stars"] == 1200
    assert dossier["commercial_readiness"] == "VALIDATE"
    assert dossier["validation_type"] == "commercial"
    assert any("willingness to pay" in item for item in dossier["uncertainties"])


def test_commercial_dossier_exposes_uncertainty():
    hunter = OpportunityHunter()
    dossier = hunter._commercial_dossier(
        {"name": "unknown-tech", "description": "", "stars": 0},
        [],
        {"technical_maturity_score": 1, "has_tests": False, "has_ci": False},
        {"security_posture": {"score": 20}},
        {"opportunity_score": 10},
    )

    assert dossier["commercial_readiness"] == "EARLY_SIGNAL"
    assert len(dossier["uncertainties"]) >= 3


[executed on device: Gensyn2.play2go.cloud (8c50b8b0-eb42-4eae-ab08-e02c92862037)]
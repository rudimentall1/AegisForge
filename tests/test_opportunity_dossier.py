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



def test_dossiers_change_with_repository_capability():
    hunter = OpportunityHunter()
    common_analysis = {"opportunity_score": 80}
    technical = {
        "technical_maturity_score": 8,
        "has_tests": True,
        "has_ci": True,
        "stack": ["Python"],
        "readme_signal": "A robotics simulator for training and evaluating physical AI systems.",
    }
    robotics = hunter._commercial_dossier(
        {
            "name": "NVIDIA/cosmos",
            "description": "World foundation models and simulation tools for physical AI.",
            "topics": ["robotics", "simulation"],
            "stars": 10000,
        },
        ["AI"], technical, {}, common_analysis,
    )
    security = hunter._commercial_dossier(
        {
            "name": "Acme/agent-scanner",
            "description": "Security scanner for autonomous AI agents and tool permissions.",
            "topics": ["security", "agents"],
            "stars": 1000,
        },
        ["AI", "Security"], {**technical, "readme_signal": "Scans agent tool permissions for exploitable policy gaps."}, {"security_posture": {"score": 82}}, common_analysis,
    )

    assert robotics["domain"] != security["domain"]
    assert robotics["target_customer"] != security["target_customer"]
    assert robotics["problem_signal"] != security["problem_signal"]
    assert robotics["validation_experiment"] != security["validation_experiment"]
    assert "simulation" in robotics["domain"]
    assert "security" in security["domain"]


def test_stars_are_not_labeled_as_adoption():
    hunter = OpportunityHunter()
    analysis = hunter._score_repo(
        {"name": "popular/project", "description": "developer tool", "stars": 50000},
        {},
        {},
    )

    assert all("adoption" not in reason.lower() for reason in analysis["reasons"])
    assert any("public interest" in reason.lower() for reason in analysis["reasons"])



def test_agent_dossiers_preserve_repository_specific_capability():
    from shared.intelligence_quality import IntelligenceQualityEvaluator

    hunter = OpportunityHunter()
    analysis = {"opportunity_score": 80}
    technical = {
        "technical_maturity_score": 8,
        "has_tests": True,
        "has_ci": True,
        "stack": ["Python"],
    }

    first = hunter._commercial_dossier(
        {
            "name": "acme/agent-orchestrator",
            "description": "Distributed task scheduler for long-running scientific research jobs.",
            "topics": ["agent", "orchestration"],
            "stars": 1000,
        },
        ["AI"],
        technical,
        {},
        analysis,
    )
    second = hunter._commercial_dossier(
        {
            "name": "acme/agent-browser",
            "description": "Chromium automation toolkit for extracting structured data from websites.",
            "topics": ["agent", "browser"],
            "stars": 1000,
        },
        ["AI"],
        technical,
        {},
        analysis,
    )

    assert first["problem_signal"] != second["problem_signal"]
    assert first["product_thesis"] != second["product_thesis"]
    assert first["validation_experiment"] != second["validation_experiment"]
    batch = IntelligenceQualityEvaluator().evaluate_batch([
        {"name": "first", **first},
        {"name": "second", **second},
    ])
    assert batch["duplicate_rate"] == 0.0

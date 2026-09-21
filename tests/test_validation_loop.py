from agents.validator.agent import Validator
from orchestrator.master import AutonomousPlanner


class FakeGitHub:
    BASE_URL = "https://api.github.com"

    def get_json(self, url, **kwargs):
        if "/repos/acme/project" in url and "/git/trees/" not in url:
            return {"default_branch": "main", "archived": False,
                    "stargazers_count": 12, "forks_count": 3}
        return {"tree": [{"path": "README.md"}, {"path": "pyproject.toml"}]}


def test_validator_executes_bounded_repository_experiment():
    agent = Validator()
    result = agent._validate_repo(
        {"name": "acme/project", "url": "https://github.com/acme/project"},
        FakeGitHub(),
    )
    assert result["status"] == "VALIDATED"
    assert result["reproducibility"] == "PASS"
    assert result["stars_observed"] == 12


def test_opportunity_hunter_routes_to_validator():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    task = {
        "role": "opportunity_hunter",
        "result": {
            "repositories": [{"name": "acme/project"}],
            "opportunities": [{
                "name": "acme/project",
                "opportunity_score": 80,
                "commercial_readiness": "VALIDATE",
            }],
        },
    }
    decision = planner._choose_next_raw(task)
    assert decision[0] == "REFINE"
    assert decision[1] == "validator"


def test_validator_routes_evidence_back_to_opportunity_hunter():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    task = {
        "role": "validator",
        "result": {
            "opportunities": [{"name": "acme/project"}],
            "validation_results": [{
                "name": "acme/project",
                "status": "VALIDATED",
                "experiment": "technical_reproducibility",
            }],
        },
    }
    decision = planner._choose_next_raw(task)
    assert decision[0] == "REFINE"
    assert decision[1] == "opportunity_hunter"


def test_validation_evidence_is_durable_and_compact():
    planner = AutonomousPlanner.__new__(AutonomousPlanner)
    atoms = planner.evidence_atoms({
        "validation_results": [{
            "name": "acme/project",
            "status": "VALIDATED",
            "experiment": "technical_reproducibility",
            "source": "github_api",
            "large_payload": "x" * 10000,
        }]
    })
    assert any(atom.startswith("validation:") for atom in atoms)
    assert all(len(atom.encode("utf-8")) < 8192 for atom in atoms)

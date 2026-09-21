from agents.analyst.agent import Analyst
from shared.task import Task


def test_analyst_turns_research_into_product_hypotheses():
    task = Task(task_id="t1", description="analyze", status="queued")
    task.result = {
        "research_scope": "technology_intelligence",
        "repositories": [{
            "name": "acme/agent-core",
            "url": "https://github.com/acme/agent-core",
            "description": "Autonomous AI agent runtime",
            "stars": 1500,
            "language": "Python",
            "updated": "2026-09-20T00:00:00Z",
        }],
    }
    out = Analyst().run(task)
    assert out.status == "analyzed"
    assert len(out.result["opportunities"]) == 1
    opp = out.result["opportunities"][0]
    assert opp["target"] == "acme/agent-core"
    assert "thesis" in opp and "validation" in opp

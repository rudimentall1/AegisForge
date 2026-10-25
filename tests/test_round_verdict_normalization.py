import json
from types import SimpleNamespace

import pytest

from orchestrator.master import MasterOrchestrator


class _Rows:
    def __init__(self, values):
        self.values = values

    def fetchall(self):
        return [(json.dumps({"research_validation": {"verdict": value}}),) for value in self.values]


class _DB:
    def __init__(self, values):
        self.values = values

    def execute(self, *_args):
        return _Rows(self.values)


def _master_with_verdicts(*values):
    master = MasterOrchestrator.__new__(MasterOrchestrator)
    master.queue = SimpleNamespace(db=_DB(values))
    master.planner = SimpleNamespace(parse_result=json.loads)
    return master


@pytest.mark.parametrize(
    "verdict",
    ["REPRODUCED", "NOT_REPRODUCED", "INCONCLUSIVE", "OUT_OF_SCOPE"],
)
def test_round_verdict_preserves_supported_vocabulary(verdict):
    assert MasterOrchestrator._round_verdict(_master_with_verdicts(verdict), "root") == verdict


@pytest.mark.parametrize("verdict", ["CONFIRMED", "EXPLOITABLE", "unknown"])
def test_round_verdict_fails_closed_for_unsupported_statuses(verdict):
    assert MasterOrchestrator._round_verdict(_master_with_verdicts(verdict), "root") == "INCONCLUSIVE"


def test_round_verdict_skips_malformed_results_and_defaults_inconclusive():
    master = _master_with_verdicts("not-a-verdict")
    master.planner.parse_result = lambda _raw: {"other": "value"}
    assert MasterOrchestrator._round_verdict(master, "root") == "INCONCLUSIVE"


def test_round_verdict_finds_nested_validator_descendant(tmp_path):
    from shared.queue import TaskQueue

    queue = TaskQueue(db_path=tmp_path / "nested-round-verdict.sqlite3")
    root_id = queue.add("round root", role="source_researcher")
    assert queue.claim("source-worker", role="source_researcher")[0] == root_id
    queue.finish(root_id, result={"stage": "sources"})

    crypto_id = queue.add("analyze sources", role="crypto_analyst", parent_task_id=root_id)
    assert queue.claim("crypto-worker", role="crypto_analyst")[0] == crypto_id
    queue.finish(crypto_id, result={"stage": "analysis"})

    lab_id = queue.add("run bounded lab", role="lab_runner", parent_task_id=crypto_id)
    assert queue.claim("lab-worker", role="lab_runner")[0] == lab_id
    queue.finish(lab_id, result={"stage": "lab"})

    validator_id = queue.add("validate evidence", role="validator", parent_task_id=lab_id)
    assert queue.claim("validator-worker", role="validator")[0] == validator_id
    queue.finish(validator_id, result={
        "research_validation": {"verdict": "NOT_REPRODUCED"}
    })

    master = MasterOrchestrator.__new__(MasterOrchestrator)
    master.queue = queue
    from orchestrator.master import AutonomousPlanner
    master.planner = AutonomousPlanner(queue)

    assert MasterOrchestrator._round_verdict(master, root_id) == "NOT_REPRODUCED"
    queue.db.close()

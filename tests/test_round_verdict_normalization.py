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

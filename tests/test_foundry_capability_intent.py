from types import SimpleNamespace

from shared.action_intent import build_action_intent
from shared.capability_policy import CapabilityDecision, CapabilityPolicy


def _planned_task(capability_intent=None):
    round_spec = SimpleNamespace(
        target_source_paths=("src/Vault.sol",),
        test_harness_source="contract Harness {}",
        solc_version="0.8.24",
        positive_control_test="testExploit",
        negative_control_test="testSafeControl",
    )
    research_case = SimpleNamespace(
        target_repository="acme/vault",
        target_commit="a" * 40,
    )
    return SimpleNamespace(
        payload={
            "round_spec": round_spec,
            "research_case": research_case,
            "capability_intent": capability_intent or {},
        }
    )


def test_foundry_round_declares_shell_and_filesystem_but_no_network(monkeypatch):
    monkeypatch.setenv("AEGISFORGE_DOCKER_RUNTIME_AUTHORIZED", "1")
    intent = build_action_intent(
        "lab_runner", _planned_task(), agent_id="lab-runner-test"
    )
    assert intent.action == "run_foundry_test"
    assert intent.target == "acme/vault@" + ("a" * 40)
    assert intent.requires_shell is True
    assert intent.requires_filesystem is True
    assert intent.requires_network is False
    assert intent.read_only is True
    assert intent.privileged is True
    assert intent.parameters["docker_runtime_authorized"] is True
    assert intent.parameters["network_disabled"] is True
    assert intent.parameters["source_commit_pinned"] is True
    assert CapabilityPolicy().check(intent)["decision"] is CapabilityDecision.ALLOW


def test_explicit_task_intent_cannot_weaken_foundry_capability_requirements(monkeypatch):
    monkeypatch.delenv("AEGISFORGE_DOCKER_RUNTIME_AUTHORIZED", raising=False)
    task = _planned_task({
        "action": "run_synthetic_lab",
        "requires_shell": False,
        "requires_filesystem": False,
        "requires_network": True,
        "read_only": False,
        "privileged": False,
        "parameters": {"network_disabled": False},
    })
    intent = build_action_intent("lab_runner", task)
    assert intent.action == "run_foundry_test"
    assert intent.requires_shell is True
    assert intent.requires_filesystem is True
    assert intent.requires_network is False
    assert intent.read_only is True
    assert intent.privileged is True
    assert intent.parameters["docker_runtime_authorized"] is False
    assert intent.parameters["network_disabled"] is True


def test_foundry_requires_explicit_docker_runtime_authorization(monkeypatch):
    monkeypatch.delenv("AEGISFORGE_DOCKER_RUNTIME_AUTHORIZED", raising=False)
    intent = build_action_intent("lab_runner", _planned_task())
    decision = CapabilityPolicy().check(intent)
    assert decision["decision"] is CapabilityDecision.REQUIRE_EVIDENCE
    assert decision["reason"] == "evidence_required_for_sensitive_action"


def test_legacy_lab_runner_task_keeps_synthetic_capability():
    task = SimpleNamespace(payload={})
    intent = build_action_intent("lab_runner", task)
    assert intent.action == "run_synthetic_lab"
    assert intent.requires_shell is False
    assert intent.requires_filesystem is False

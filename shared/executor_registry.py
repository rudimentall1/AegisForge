from dataclasses import dataclass
from typing import Callable, Dict, Tuple

from shared.execution_gate import ExecutionGate, ExecutionGateError


class ExecutorRegistryError(ValueError):
    pass


@dataclass(frozen=True)
class ExecutorSpec:
    name: str
    action: str
    resource: str
    handler: Callable


class ExecutorRegistry:
    """Universal execution dispatch after capability authorization.

    Registry resolution is deliberately separate from policy: policy decides
    whether an action is allowed, while this registry decides which concrete
    executor can perform an already-authorized action.
    """

    def __init__(self, gate, evidence_ledger=None, role="executor"):
        if not isinstance(gate, ExecutionGate):
            raise ExecutorRegistryError("execution_gate_required")
        self.gate = gate
        self.evidence_ledger = evidence_ledger
        self.role = role
        self._executors: Dict[Tuple[str, str], ExecutorSpec] = {}

    def register(self, name, action, resource, handler):
        if not name or not action or not resource:
            raise ExecutorRegistryError("executor_identity_required")
        if not callable(handler):
            raise ExecutorRegistryError("executor_handler_required")
        key = (str(action), str(resource))
        if key in self._executors:
            raise ExecutorRegistryError("executor_already_registered")
        self._executors[key] = ExecutorSpec(
            name=str(name), action=str(action), resource=str(resource), handler=handler
        )
        return self._executors[key]

    def resolve(self, intent):
        key = (str(intent.action), str(intent.resource or ""))
        spec = self._executors.get(key)
        if spec is None:
            spec = self._executors.get((str(intent.action), "*"))
        if spec is None:
            raise ExecutorRegistryError("executor_not_registered")
        return spec

    def execute(self, grant, intent, evidence_ids=()):
        spec = self.resolve(intent)
        try:
            receipt = self.gate.execute(
                grant,
                intent,
                executor=lambda: spec.handler(intent),
                evidence_ids=evidence_ids,
            )
        except ExecutionGateError as exc:
            raise ExecutorRegistryError(str(exc)) from exc

        evidence = None
        if self.evidence_ledger is not None:
            evidence = self.evidence_ledger.record_execution_receipt(
                task_id=receipt.task_id,
                role=self.role,
                receipt=receipt,
            )
        return {"executor": spec.name, "receipt": receipt, "evidence": evidence}

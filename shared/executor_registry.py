import hashlib
import inspect
from dataclasses import dataclass
from typing import Callable, Dict, Tuple

from shared.execution_gate import ExecutionGate, ExecutionGateError
from shared.executor_identity import ExecutorIdentityRegistry, ExecutorIdentityRegistryError


class ExecutorRegistryError(ValueError):
    pass


def _implementation_digest(handler):
    try:
        source = inspect.getsource(handler)
    except (OSError, TypeError) as exc:
        raise ExecutorRegistryError("executor_implementation_digest_required") from exc
    descriptor = {
        "module": getattr(handler, "__module__", ""),
        "qualname": getattr(handler, "__qualname__", ""),
        "source": source,
    }
    canonical = repr(sorted(descriptor.items())).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True)
class ExecutorSpec:
    name: str
    action: str
    resource: str
    handler: Callable
    version: str = "1"
    implementation_digest: str = ""

    @property
    def executor_id(self):
        return self.name


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
        self.identity_registry = ExecutorIdentityRegistry(self.gate.db)
        self._executors: Dict[Tuple[str, str], ExecutorSpec] = {}
        self._identities: Dict[Tuple[str, str], str] = {}

    def register(
        self,
        name,
        action,
        resource,
        handler,
        version="1",
        implementation_digest=None,
    ):
        if not name or not action or not resource:
            raise ExecutorRegistryError("executor_identity_required")
        if not callable(handler):
            raise ExecutorRegistryError("executor_handler_required")
        if not version or not isinstance(version, str):
            raise ExecutorRegistryError("executor_version_required")
        digest = implementation_digest or _implementation_digest(handler)
        if not isinstance(digest, str) or not digest:
            raise ExecutorRegistryError("executor_implementation_digest_required")
        key = (str(action), str(resource))
        identity = (str(name), str(version))
        if key in self._executors:
            raise ExecutorRegistryError("executor_already_registered")
        try:
            self.identity_registry.register(str(name), str(version), digest)
        except ExecutorIdentityRegistryError as exc:
            raise ExecutorRegistryError(str(exc)) from exc
        existing_digest = self._identities.get(identity)
        if existing_digest is not None and existing_digest != digest:
            raise ExecutorRegistryError("executor_identity_conflict")
        if identity in self._identities:
            raise ExecutorRegistryError("executor_already_registered")
        self._executors[key] = ExecutorSpec(
            name=str(name),
            action=str(action),
            resource=str(resource),
            handler=handler,
            version=str(version),
            implementation_digest=digest,
        )
        self._identities[identity] = digest
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
                executor_id=spec.executor_id,
                executor_version=spec.version,
                executor_implementation_digest=spec.implementation_digest,
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

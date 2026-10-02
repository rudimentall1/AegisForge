import json
import socket
import os
import sys
import traceback

try:
    import resource
except ImportError:
    resource = None

from shared.queue import TaskQueue
from shared.task import Task
from shared.memory import Memory

from shared.capability_policy import (
    CapabilityPolicy,
    CapabilityDecision,
)

from shared.action_intent import build_action_intent
from shared.agent_identity import AgentIdentity
from shared.agent_authority import AgentAuthorityRegistry
from shared.evidence_ledger import EvidenceLedger
from shared.capability_grant import CapabilityGrant, CapabilityGrantError
from shared.capability_signing import CapabilitySigner, CapabilitySignatureError
from shared.execution_gate import ExecutionGate
from shared.executor_registry import ExecutorRegistry, ExecutorRegistryError
from shared.filesystem_executor import SafeFilesystemExecutor
from shared.artifact_executor import SafeArtifactPublisher
from shared.outcome_verifier import (
    FilesystemOutcomeVerifier,
    ArtifactOutcomeVerifier,
    OutcomeVerificationError,
)
from shared.http_executor import HttpApiExecutor, HttpExecutorError
from shared.http_outcome_verifier import HttpOutcomeVerifier, HttpOutcomeVerificationError
from shared.mcp_outcome_verifier import McpOutcomeVerifier, McpOutcomeVerificationError
from shared.outcome_verifier_registry import OutcomeVerifierRegistry, OutcomeVerifierRegistryError
from shared.outcome_proof import build_outcome_proof_payload, sign_outcome_proof, write_outcome_proof
from shared.evidence_manifest import build_manifest, digest
from shared.capability_policy import ActionIntent
import hashlib

from agents.researcher.agent import Researcher
from agents.analyst.agent import Analyst
from agents.developer.agent import Developer
from agents.security_checker.agent import SecurityChecker
from agents.opportunity_hunter.agent import OpportunityHunter
from agents.validator.agent import Validator
from model_research.agent import ModelResearcher


WORKFLOW_ID = "web3-security-pipeline-v1"

AGENTS = {
    "researcher": Researcher,
    "analyst": Analyst,
    "developer": Developer,
    "security_checker": SecurityChecker,
    "opportunity_hunter": OpportunityHunter,
    "validator": Validator,
    "model_researcher": ModelResearcher,
    "executor": None,
}

SUCCESS_STATUSES = {
    "researcher": "researched",
    "analyst": "analyzed",
    "developer": "developed",
    "security_checker": "security_checked",
    "opportunity_hunter": "opportunities_found",
    "validator": "validated",
    "model_researcher": "model_researched",
    "executor": "executed",
}


class Worker:
    def __init__(self, role: str):
        self._apply_memory_guard()

        if role not in AGENTS:
            raise ValueError(
                f"Unknown role: {role}. "
                f"Available: {', '.join(AGENTS)}"
            )

        self.role = role
        self.agent_identity = AgentIdentity.for_worker(
            role,
            socket.gethostname(),
        )
        self.agent_id = self.agent_identity.agent_id
        self.worker_id = (
            f"{role}-worker-{socket.gethostname()}-{os.getpid()}"
        )

        self.queue = TaskQueue()
        self.memory = Memory()

        self.policy = CapabilityPolicy()
        self.evidence_ledger = (
            EvidenceLedger(self.queue.db)
            if hasattr(self.queue, "db")
            else None
        )
        self.capability_signer = None
        if role in {"validator", "executor"}:
            signer_path = os.environ.get(
                "AEGISFORGE_CAPABILITY_KEY_PATH",
                "/opt/agent-farm/data/capability_ed25519.key",
            )
            self.capability_signer = CapabilitySigner.load_or_create(signer_path)

        if role == "validator":
            self.agent = Validator(
                evidence_ledger=self.evidence_ledger,
                capability_signer=self.capability_signer,
            )
        elif role == "executor":
            self.agent = None
        else:
            self.agent = AGENTS[role]()

    @staticmethod
    def _apply_memory_guard():
        """Bound a single agent process so one task cannot consume the host."""
        if resource is None or not hasattr(resource, "RLIMIT_AS"):
            return
        limit = 3 * 1024 * 1024 * 1024
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            if hard == resource.RLIM_INFINITY or hard > limit:
                hard = limit
            if soft == resource.RLIM_INFINITY or soft > hard:
                soft = hard
            resource.setrlimit(resource.RLIMIT_AS, (soft, hard))
        except (OSError, ValueError):
            pass

    def _capability_decision(self, task):
        intent = build_action_intent(
            self.role,
            task,
            agent_id=self.agent_id,
        )
        decision = self.policy.check(intent)
        return intent, decision


    def _record_capability_decision(self, task_id, intent, decision):
        intent_payload = intent.to_dict()
        canonical_intent = json.dumps(
            intent_payload,
            sort_keys=True,
            separators=(",", ":"),
        )
        intent_hash = hashlib.sha256(
            canonical_intent.encode("utf-8")
        ).hexdigest()
        audit = {
            "action": intent.action,
            "decision": decision["decision"].value,
            "intent": intent_payload,
            "intent_hash": intent_hash,
            "reason": decision["reason"],
            "role": intent.role,
            "target": intent.target,
        }
        atom = "capability_decision:" + json.dumps(
            audit,
            sort_keys=True,
            separators=(",", ":"),
        )
        if self.evidence_ledger is None:
            return

        try:
            result = self.evidence_ledger.record_observation(
                task_id,
                self.role,
                atom,
            )
            print(
                f"[{self.worker_id}] CAPABILITY EVIDENCE "
                f"decision={decision['decision'].value} "
                f"intent_hash={intent_hash[:12]} "
                f"observations={result['observations']}",
                flush=True,
            )
        except Exception as exc:
            # Audit failure never turns a BLOCK into ALLOW. The policy
            # decision remains authoritative and the action path below
            # still fails closed for terminal decisions.
            print(
                f"[{self.worker_id}] CAPABILITY EVIDENCE ERROR: {exc}",
                flush=True,
            )

    @staticmethod
    def _is_agent_failure(task):
        if not isinstance(task, Task):
            return False

        status = str(getattr(task, "status", "") or "").lower()

        if status.endswith("_failed"):
            return True

        result = getattr(task, "result", None)

        if isinstance(result, dict):
            if result.get("error"):
                return True

            if result.get("error_type"):
                return True

            if result.get("agent_error"):
                return True

        return False

    def _enqueue_execution_handoff(self, validator_task_id, result_value):
        if self.role != "validator" or not isinstance(result_value, dict):
            return None
        if result_value.get("validation_mode") != "capability_evidence":
            return None
        if result_value.get("status") != "VERIFIED":
            return None
        grant = result_value.get("capability_grant")
        intent = result_value.get("intent")
        result_agent_id = result_value.get("agent_id")
        grant_agent_id = grant.get("grant", {}).get("agent_id") if isinstance(grant, dict) else None
        intent_agent_id = intent.get("agent_id") if isinstance(intent, dict) else None
        if not isinstance(grant, dict) or not isinstance(intent, dict):
            return None
        if not result_agent_id or not grant_agent_id or not intent_agent_id:
            raise ExecutorRegistryError("execution_agent_identity_required")
        if len({str(result_agent_id), str(grant_agent_id), str(intent_agent_id)}) != 1:
            raise ExecutorRegistryError("execution_agent_identity_mismatch")
        evidence_ids = grant.get("grant", {}).get("evidence_ids") or []
        original_task_id = grant.get("grant", {}).get("task_id")
        if not original_task_id or original_task_id == validator_task_id:
            return None
        envelope = {
            "action": "execute_granted",
            "resource": "capability_grant",
            "destination": "internal",
            "read_only": False,
            "evidence_required": False,
            "original_task_id": original_task_id,
            "execution_intent": intent,
            "capability_grant": grant,
            "evidence_ids": list(evidence_ids),
        }
        task_id = self.queue.add(
            description=(
                "[CAPABILITY_EXECUTION] execute only the previously verified "
                f"grant for task {original_task_id}"
            ),
            role="executor",
            parent_task_id=validator_task_id,
            capability_intent=envelope,
            allow_failed_parent=False,
        )
        print(
            f"[{self.worker_id}] EXECUTION HANDOFF queued={task_id} "
            f"grant={grant.get('grant', {}).get('grant_id')}",
            flush=True,
        )
        return task_id

    def _signed_grant(self, payload):
        from shared.capability_signing import SignedCapabilityGrant
        try:
            return SignedCapabilityGrant.from_dict(payload)
        except CapabilitySignatureError as exc:
            raise ExecutorRegistryError(str(exc)) from exc

    def _execute_granted_task(self, task):
        payload = getattr(task, "payload", {}) or {}
        envelope = payload.get("capability_intent")
        if not isinstance(envelope, dict) or envelope.get("action") != "execute_granted":
            raise ExecutorRegistryError("execution_handoff_invalid")
        intent_data = envelope.get("execution_intent")
        grant_data = envelope.get("capability_grant")
        evidence_ids = envelope.get("evidence_ids") or []
        original_task_id = envelope.get("original_task_id")
        if not isinstance(intent_data, dict) or not isinstance(grant_data, dict):
            raise ExecutorRegistryError("execution_handoff_incomplete")
        if not original_task_id:
            raise ExecutorRegistryError("execution_origin_mismatch")
        try:
            intent = ActionIntent(**intent_data)
            signed_grant = self._signed_grant(grant_data)
            grant = self.capability_signer.verify(signed_grant)
        except (TypeError, ValueError, CapabilityGrantError, CapabilitySignatureError) as exc:
            raise ExecutorRegistryError(str(exc)) from exc
        if not getattr(intent, "agent_id", None) or not grant.agent_id:
            raise ExecutorRegistryError("execution_agent_identity_required")
        if str(intent.agent_id) != str(grant.agent_id):
            raise ExecutorRegistryError("execution_agent_identity_mismatch")
        if str(grant.task_id) != str(original_task_id):
            raise ExecutorRegistryError("execution_origin_mismatch")
        if sorted(str(v) for v in evidence_ids) != sorted(str(v) for v in grant.evidence_ids):
            raise ExecutorRegistryError("execution_evidence_mismatch")
        root = os.environ.get(
            "AEGISFORGE_EXECUTION_ROOT",
            "/opt/agent-farm/staging-execution",
        )
        adapter = SafeFilesystemExecutor(root)
        authority_registry = AgentAuthorityRegistry(self.queue.db)
        gate = ExecutionGate(
            db=self.queue.db,
            signer=self.capability_signer,
            authority_registry=authority_registry,
        )
        registry = ExecutorRegistry(
            gate,
            evidence_ledger=self.evidence_ledger,
            role="executor",
        )
        registry.register(
            "staging_delete",
            "delete",
            "staging_filesystem",
            adapter.delete,
        )
        artifact_adapter = SafeArtifactPublisher(root)
        registry.register(
            "staging_publish",
            "publish",
            "staging_artifact_store",
            artifact_adapter.publish,
        )

        http_adapter = HttpApiExecutor()
        registry.register(
            "http_api_request",
            "api_request",
            "http_api",
            http_adapter.execute,
        )
        mcp_adapter = HttpApiExecutor()
        def mcp_call(mcp_intent):
            from types import SimpleNamespace
            params = dict(getattr(mcp_intent, "parameters", {}) or {})
            endpoint = params.get("endpoint") or mcp_intent.target
            tool = str(params.get("tool") or "").strip()
            arguments = params.get("arguments", {})
            if not tool or not isinstance(arguments, dict):
                raise ExecutorRegistryError("mcp_tool_request_invalid")
            transport_intent = SimpleNamespace(
                target=endpoint,
                parameters={
                    "method": "POST",
                    "url": endpoint,
                    "headers": params.get("headers") or {},
                    "body": {
                        "jsonrpc": "2.0",
                        "id": params.get("request_id", "aegisforge"),
                        "method": "tools/call",
                        "params": {"name": tool, "arguments": arguments},
                    },
                },
            )
            return mcp_adapter.execute(transport_intent)
        registry.register(
            "mcp_tool_call",
            "mcp_tool_call",
            "mcp_server",
            mcp_call,
        )

        result = registry.execute(signed_grant, intent, evidence_ids=evidence_ids)
        receipt = result["receipt"]

        # Do not treat the executor's self-reported result as proof. Resolve
        # the typed outcome contract to an explicit independent verifier.
        try:
            contract = dict((intent.parameters or {}).get("outcome_contract") or {})
            verifier_registry = OutcomeVerifierRegistry()
            verifier_registry.register(
                "filesystem_delete",
                "state_match",
                "filesystem_independent_v1",
                lambda **kwargs: FilesystemOutcomeVerifier(root),
            )
            verifier_registry.register(
                "artifact_publish",
                "artifact_exists",
                "artifact_independent_v1",
                lambda **kwargs: ArtifactOutcomeVerifier(root),
            )
            verifier_registry.register(
                "http_state",
                "http_state",
                "http_independent_get_v1",
                lambda **kwargs: HttpOutcomeVerifier(
                    allowed_hosts=http_adapter.allowed_hosts,
                    timeout=http_adapter.timeout,
                ),
            )
            verifier_registry.register(
                "mcp_state",
                "mcp_state",
                "mcp_independent_read_v1",
                lambda **kwargs: McpOutcomeVerifier(
                    allowed_hosts=http_adapter.allowed_hosts,
                    timeout=http_adapter.timeout,
                ),
            )
            outcome = verifier_registry.verify(
                contract,
                intent,
                receipt,
                action=intent.action,
            )
        except (
            OutcomeVerifierRegistryError,
            OutcomeVerificationError,
            HttpExecutorError,
            HttpOutcomeVerificationError,
            McpOutcomeVerificationError,
        ) as exc:
            raise ExecutorRegistryError(str(exc)) from exc

        outcome["agent_id"] = receipt.agent_id
        outcome_evidence = self.evidence_ledger.record_outcome_verification(
            task_id=receipt.task_id,
            role="outcome_verifier",
            outcome=outcome,
        )
        proof_evidence = {
            "outcome_id": outcome.get("outcome_id"),
            "evidence_id": outcome_evidence.get("evidence_id"),
            "verifier": outcome.get("verifier"),
            "status": outcome.get("status"),
            "source": outcome_evidence.get("source"),
            "agent_id": receipt.agent_id,
            "executor_id": receipt.executor_id,
            "executor_version": receipt.executor_version,
        }
        manifest = build_manifest([
            {"id": "grant", "type": "capability_grant", "digest": digest(signed_grant.to_dict())},
            {"id": "receipt", "type": "execution_receipt", "digest": digest(receipt.to_dict())},
            {"id": "contract", "type": "outcome_contract", "digest": digest(contract)},
            {"id": "outcome", "type": "verified_outcome", "digest": digest(outcome)},
            {"id": "evidence", "type": "outcome_evidence", "digest": digest(proof_evidence)},
        ], agent_id=receipt.agent_id)
        proof_payload = build_outcome_proof_payload(
            grant=signed_grant.to_dict(),
            receipt=receipt.__dict__,
            outcome_contract=contract,
            outcome=outcome,
            evidence=proof_evidence,
            evidence_manifest=manifest,
        )
        proof = sign_outcome_proof(proof_payload, self.capability_signer)
        proof_dir = os.environ.get(
            "AEGISFORGE_OUTCOME_PROOF_DIR",
            "/opt/agent-farm/artifacts/outcome-proofs",
        )
        proof_path = write_outcome_proof(
            proof,
            os.path.join(proof_dir, f"{proof['proof_id']}.json"),
        )
        return {
            "agent": self.role,
            "execution_mode": "capability_grant",
            "status": "PROVEN",
            "original_task_id": original_task_id,
            "grant_id": grant.grant_id,
            "executor": result["executor"],
            "receipt": receipt.__dict__,
            "evidence": result["evidence"],
            "outcome": outcome,
            "outcome_evidence": outcome_evidence,
            "outcome_proof": {
                "proof_id": proof["proof_id"],
                "path": proof_path,
                "schema_version": proof["schema_version"],
                "key_id": proof["key_id"],
            },
        }

    def run_once(self):
        recovered = self.queue.recover_stale_running(
            stale_minutes=10
        )

        for task_id in recovered:
            print(
                f"[{self.worker_id}] "
                f"RECOVERED STALE TASK {task_id}",
                flush=True,
            )

        print(
            f"[DEBUG] checking queue role={self.role}",
            flush=True
        )

        task_row = self.queue.claim(
            self.worker_id,
            role=self.role,
        )

        if not task_row:
            return False

        task_id = task_row[0]
        description = task_row[1]
        parent_task_id = task_row[8]
        capability_intent = (
            task_row[10]
            if len(task_row) > 10
            else None
        )
        if isinstance(capability_intent, str) and capability_intent.strip():
            try:
                capability_intent = json.loads(capability_intent)
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    f"Invalid stored capability_intent for task {task_id}: {exc}"
                ) from exc

        print(
            f"[{self.worker_id}] "
            f"CLAIMED {task_id} ROLE={self.role}",
            flush=True,
        )

        try:
            parent_result = None

            if parent_task_id:
                parent_result = self.queue.get_result(
                    parent_task_id
                )

                if parent_result is None:
                    raise RuntimeError(
                        f"Parent task {parent_task_id} "
                        f"has no stored result"
                    )

                print(
                    f"[{self.worker_id}] "
                    f"LOADED PARENT RESULT "
                    f"{parent_task_id}",
                    flush=True,
                )

            task = Task(
                task_id=task_id,
                description=description,
                payload={
                    "role": self.role,
                    "agent_id": self.agent_id,
                    "agent_identity": self.agent_identity.to_dict(),
                    "workflow_id": WORKFLOW_ID,
                    "parent_task_id": parent_task_id,
                    "parent_result": parent_result,
                    "capability_intent": capability_intent,
                },
                result=parent_result,
                status="running",
            )

            print(
                f"[{self.worker_id}] "
                f"ROLE={self.role} START: {description}",
                flush=True,
            )

            if self.role == "executor":
                try:
                    result_value = self._execute_granted_task(task)
                    task.result = result_value
                    task.status = SUCCESS_STATUSES[self.role]
                    self.memory.save_task(task)
                    self.queue.finish(task_id, result=result_value)
                    outcome = result_value.get("outcome") or {}
                    receipt = result_value.get("receipt") or {}
                    self.queue.record_verified_outcome_feedback(
                        descendant_task_id=task_id,
                        status=result_value.get("status"),
                        verifier=outcome.get("verifier"),
                        outcome_id=outcome.get("outcome_id"),
                        receipt_id=receipt.get("receipt_id"),
                    )
                    print(
                        f"[{self.worker_id}] EXECUTED grant="
                        f"{result_value.get('grant_id')}",
                        flush=True,
                    )
                    return True
                except Exception as exc:
                    error = {
                        "error": str(exc),
                        "error_type": type(exc).__name__,
                    }
                    self.queue.fail(task_id, result=error)
                    print(
                        f"[{self.worker_id}] EXECUTION FAILED {task_id}: {exc}",
                        flush=True,
                    )
                    return False

            intent, decision = self._capability_decision(
                task
            )

            print(
                f"[{self.worker_id}] "
                f"CAPABILITY CHECK "
                f"{decision}",
                flush=True,
            )

            capability_decision = decision["decision"]
            self._record_capability_decision(
                task_id,
                intent,
                decision,
            )
            if capability_decision in {
                CapabilityDecision.BLOCK,
                CapabilityDecision.REQUIRE_EVIDENCE,
            }:
                evidence_required = (
                    capability_decision
                    == CapabilityDecision.REQUIRE_EVIDENCE
                )
                capability_result = {
                    "error": (
                        "capability_evidence_required"
                        if evidence_required
                        else "capability_blocked"
                    ),
                    "error_type": (
                        "CapabilityEvidenceRequired"
                        if evidence_required
                        else "CapabilityBlocked"
                    ),
                    "status": "blocked",
                    "reason": decision["reason"],
                    "decision": capability_decision.value,
                    "intent": intent.to_dict(),
                }
                if evidence_required:
                    capability_result["required_evidence"] = (
                        self.policy.required_evidence(intent)
                    )

                if evidence_required:
                    evidence_description = (
                        "[CAPABILITY_EVIDENCE_REQUEST] "
                        f"parent_task_id={task_id}; "
                        "verify authorization prerequisites without executing the "
                        "requested action; inspect authority scope, destination "
                        "constraints, reversibility controls, validation evidence, "
                        "and rollback readiness using the parent result."
                    )
                    evidence_task_id = self.queue.add(
                        description=evidence_description,
                        role="validator",
                        parent_task_id=task_id,
                        capability_intent={
                            "action": "verify",
                            "resource": "authorization_prerequisites",
                            "destination": "internal",
                            "data_scope": "validation_evidence",
                            "read_only": True,
                            "evidence_required": False,
                        },
                        allow_failed_parent=True,
                    )
                    capability_result["evidence_request"] = {
                        "task_id": evidence_task_id,
                        "role": "validator",
                        "status": "pending",
                    }

                self.memory.save_task(task)
                self.queue.fail(
                    task_id,
                    result=capability_result,
                )

                print(
                    f"[{self.worker_id}] "
                    f"CAPABILITY TERMINAL DECISION "
                    f"decision={capability_decision.value}",
                    flush=True,
                )

                return False


            result = self.agent.run(task)

            print(
                f"[{self.worker_id}] DEBUG AFTER AGENT:",
                type(result),
                "status=",
                getattr(result, "status", "NO_STATUS"),
                "task.result=",
                getattr(result, "result", "NO_RESULT"),
                flush=True,
            )

            # Agent returned a Task.
            if isinstance(result, Task):

                # IMPORTANT:
                # Do not convert agent failure into success.
                if self._is_agent_failure(result):
                    error_result = result.result

                    self.memory.save_task(result)

                    self.queue.fail(
                        task_id,
                        result=error_result,
                    )

                    print(
                        f"[{self.worker_id}] "
                        f"AGENT FAILED {task_id}: "
                        f"status={result.status}",
                        flush=True,
                    )

                    return False

                result_value = result.result
                result.status = SUCCESS_STATUSES[self.role]
                result_value = result.result

                task = result

            else:
                result_value = result
                task.result = result_value
                task.status = SUCCESS_STATUSES[self.role]

            # Defensive final validation.
            if isinstance(result_value, dict):
                if (
                    result_value.get("error")
                    or result_value.get("error_type")
                ):
                    self.memory.save_task(task)

                    self.queue.fail(
                        task_id,
                        result=result_value,
                    )

                    print(
                        f"[{self.worker_id}] "
                        f"RESULT VALIDATION FAILED {task_id}",
                        flush=True,
                    )

                    return False

            if isinstance(result_value, dict):
                result_value.setdefault("agent_id", self.agent_id)
                result_value.setdefault("agent_identity", self.agent_identity.to_dict())

            task.result = result_value
            task.status = SUCCESS_STATUSES[self.role]

            execution_task_id = self._enqueue_execution_handoff(
                task_id,
                result_value,
            )
            if execution_task_id:
                result_value = dict(result_value)
                result_value["execution_request"] = {
                    "task_id": execution_task_id,
                    "role": "executor",
                    "status": "pending",
                }
                task.result = result_value

            self.memory.save_task(task)

            self.queue.finish(
                task_id,
                result=result_value,
            )

            print(
                f"[{self.worker_id}] "
                f"ROLE={self.role} RESULT: {task.status}",
                flush=True,
            )

            print(
                f"[{self.worker_id}] "
                f"COMPLETED {task_id}",
                flush=True,
            )

            return True

        except Exception as exc:
            error = {
                "error": str(exc),
                "type": type(exc).__name__,
                "traceback": traceback.format_exc(),
            }

            try:
                self.queue.fail(
                    task_id,
                    result=error,
                )
            except Exception:
                traceback.print_exc()

            print(
                f"[{self.worker_id}] "
                f"FAILED {task_id}: {exc}",
                flush=True,
            )

            traceback.print_exc()

            return False


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python -m agents.worker "
            "<role>"
        )
        print(
            "Roles:",
            ", ".join(AGENTS),
        )
        sys.exit(1)

    role = sys.argv[1].strip().lower()

    worker = Worker(role)

    print(
        f"[{worker.worker_id}] "
        f"STARTED ROLE={role} "
        f"WORKFLOW={WORKFLOW_ID}",
        flush=True,
    )

    idle_cycles = 0

    while True:
        try:
            worked = worker.run_once()

            if worked:
                idle_cycles = 0
            else:
                idle_cycles += 1

                # Report idle state only once per minute.
                if idle_cycles % 12 == 0:
                    print(
                        f"[{worker.worker_id}] "
                        f"IDLE ROLE={role}",
                        flush=True,
                    )

            import time
            time.sleep(5)

        except KeyboardInterrupt:
            print(
                f"[{worker.worker_id}] STOPPED",
                flush=True,
            )
            break


if __name__ == "__main__":
    main()
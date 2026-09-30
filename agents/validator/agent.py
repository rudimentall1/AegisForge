import json
from shared.task import Task
from shared.github_client import GitHubClient
from shared.capability_policy import ActionIntent, CapabilityDecision, CapabilityPolicy
from shared.evidence_ledger import EvidenceLedger
from shared.capability_grant import issue_capability_grant

class Validator:
    """Run bounded, reproducible validation experiments on opportunity dossiers."""
    name = "validator"

    def __init__(self, evidence_ledger=None):
        self.evidence_ledger = evidence_ledger
    MAX_OPPORTUNITIES = 4
    PROBE_PATHS = ("README.md", "SECURITY.md", "pyproject.toml", "package.json",
                   "Cargo.toml", "go.mod", ".github/workflows")
    MANIFESTS = ("pyproject.toml", "requirements.txt", "package.json",
                 "Cargo.toml", "go.mod", "Gemfile", "pom.xml")

    def _repo_parts(self, opportunity):
        value = opportunity.get("name") or opportunity.get("repository") or ""
        if "/" not in value:
            url = str(opportunity.get("url") or "")
            if "github.com/" in url:
                value = url.split("github.com/", 1)[1].split("#", 1)[0].split("?", 1)[0]
        parts = value.strip("/").split("/")
        return (parts[0], parts[1]) if len(parts) == 2 else (None, None)

    def _validation_type(self, opportunity):
        requested = str(opportunity.get("validation_type") or "").lower()
        if requested in {"technical", "adoption", "dependency", "security", "commercial"}:
            return requested
        uncertainties = " ".join(str(x) for x in opportunity.get("uncertainties", [])).lower()
        if "security" in uncertainties:
            return "security"
        if "test" in uncertainties or "technical" in uncertainties:
            return "technical"
        if "market" in uncertainties or "commercial" in uncertainties:
            return "commercial"
        return "adoption"

    def _validate_repo(self, opportunity, client):
        owner, repo = self._repo_parts(opportunity)
        if not owner or not repo:
            return {"name": opportunity.get("name"), "status": "BLOCKED",
                    "experiment": "repository_identity",
                    "reason": "repository identity could not be resolved"}
        result = {"name": opportunity.get("name"), "experiment": "technical_reproducibility",
                  "status": "VALIDATED", "checks": []}
        try:
            metadata = client.get_json(
                f"{client.BASE_URL}/repos/{owner}/{repo}", cache_ttl=1800, timeout=20)
            if not metadata:
                result.update(status="BLOCKED", reason="repository metadata unavailable")
                return result
            result["checks"].append({"check": "repository_exists", "passed": True})
            result["default_branch"] = metadata.get("default_branch")
            result["archived"] = bool(metadata.get("archived"))
            result["stars_observed"] = int(metadata.get("stargazers_count") or 0)
            result["forks_observed"] = int(metadata.get("forks_count") or 0)
            tree = client.get_json(
                f"{client.BASE_URL}/repos/{owner}/{repo}/git/trees/{metadata.get('default_branch') or 'HEAD'}",
                params={"recursive": "1"}, cache_ttl=1800, timeout=20)
            paths = {item.get("path") for item in (tree or {}).get("tree", [])
                     if isinstance(item, dict) and item.get("path")}
            matched = [p for p in self.PROBE_PATHS
                       if p in paths or any(x.startswith(p + "/") for x in paths)]
            result["checks"].append({"check": "canonical_files_probe", "passed": bool(matched),
                                     "matched": matched[:8]})

            validation_type = self._validation_type(opportunity)
            result["validation_type"] = validation_type

            if validation_type == "technical":
                manifests = [p for p in self.MANIFESTS if p in paths]
                result["checks"].append({"check": "implementation_manifest", "passed": bool(manifests),
                                         "matched": manifests[:6]})
                result["experiment_metric"] = "implementation_evidence"
                result["experiment_value"] = len(manifests)

            elif validation_type == "adoption":
                result["checks"].append({
                    "check": "adoption_signals",
                    "passed": (result["stars_observed"] > 0 or result["forks_observed"] > 0),
                })
                result["experiment_metric"] = "community_signal"
                result["experiment_value"] = result["stars_observed"] + result["forks_observed"]

            elif validation_type == "dependency":
                manifests = [p for p in self.MANIFESTS if p in paths]
                result["checks"].append({"check": "dependency_manifest", "passed": bool(manifests),
                                         "matched": manifests[:6]})
                result["experiment_metric"] = "dependency_manifest_count"
                result["experiment_value"] = len(manifests)

            elif validation_type == "security":
                security_files = [p for p in ("SECURITY.md", ".github/workflows") if p in paths]
                result["checks"].append({"check": "security_controls_probe",
                                         "passed": bool(security_files),
                                         "matched": security_files})
                result["experiment_metric"] = "security_control_surfaces"
                result["experiment_value"] = len(security_files)

            else:
                description = str(metadata.get("description") or "").strip()
                topics = metadata.get("topics") or []
                result["checks"].append({"check": "commercial_signal_probe",
                                         "passed": bool(description or topics),
                                         "description_present": bool(description),
                                         "topic_count": len(topics)})
                result["experiment_metric"] = "commercial_signal"
                result["experiment_value"] = len(topics) + (1 if description else 0)

            result["source"] = "github_api"
            result["reproducibility"] = "PASS" if matched else "PARTIAL"
            if not matched:
                result.update(status="PARTIAL",
                              reason="repository exists but canonical implementation evidence was not found")
        except Exception as exc:
            result.update(status="DEFERRED", source="github_api",
                          reason=f"{type(exc).__name__}: {str(exc)[:240]}")
        return result

    @staticmethod
    def _capability_intent(task):
        import json

        payload = getattr(task, "payload", {}) or {}
        intent = payload.get("capability_intent")
        if isinstance(intent, dict):
            return intent
        if isinstance(intent, str) and intent.strip():
            try:
                parsed = json.loads(intent)
            except (TypeError, ValueError):
                return {}
            return parsed if isinstance(parsed, dict) else {}
        return {}

    @classmethod
    def _is_capability_evidence_request(cls, task):
        intent = cls._capability_intent(task)
        return (
            intent.get("action") == "verify"
            and intent.get("resource") == "authorization_prerequisites"
        )

    def _verify_capability_request(self, task):
        payload = getattr(task, "payload", {}) or {}
        parent_result = payload.get("parent_result")
        intent_data = self._capability_intent(task)
        parent_task_id = payload.get("parent_task_id")

        checks = {
            "parent_decision_present": isinstance(parent_result, dict),
            "parent_requested_evidence": isinstance(parent_result, dict)
            and parent_result.get("error_type") == "CapabilityEvidenceRequired"
            and parent_result.get("decision") == CapabilityDecision.REQUIRE_EVIDENCE.value,
            "structured_intent_present": isinstance(parent_result, dict)
            and isinstance(parent_result.get("intent"), dict),
        }

        structured_parent_intent = (
            parent_result.get("intent", {}) if isinstance(parent_result, dict) else {}
        )
        policy_result = None
        required_evidence = []
        evidence_claims = (
            parent_result.get("evidence_claims", {})
            if isinstance(parent_result, dict)
            else {}
        )

        if checks["structured_intent_present"]:
            try:
                fields = {
                    key: structured_parent_intent.get(key)
                    for key in (
                        "role", "action", "target", "resource", "destination",
                        "data_scope", "irreversible", "requires_network",
                        "requires_shell", "requires_filesystem", "financial",
                        "privileged", "read_only", "evidence_required",
                    )
                    if key in structured_parent_intent
                }
                intent = ActionIntent(**fields)
                policy = CapabilityPolicy()
                policy_result = policy.check(intent)
                required_evidence = policy.required_evidence(intent)
                checks["policy_still_requires_evidence"] = (
                    policy_result.get("decision") == CapabilityDecision.REQUIRE_EVIDENCE
                )
            except (TypeError, ValueError, KeyError):
                checks["policy_still_requires_evidence"] = False

        ledger = self.evidence_ledger
        if ledger is None:
            # Validator() is also used directly by unit tests and external
            # callers. Do not silently treat missing ledger access as proof.
            checks["ledger_available"] = False
        else:
            checks["ledger_available"] = True

        def claim_passes(claim_type, value):
            if not isinstance(value, dict):
                return False
            status = value.get("status")
            source = value.get("source")
            evidence_id = value.get("evidence_id")
            if (
                status not in {"PASS", "PASSED", "VERIFIED"}
                or not source
                or not evidence_id
                or not isinstance(evidence_id, str)
            ):
                return False
            if not CapabilityPolicy().evidence_source_allowed(claim_type, source):
                return False
            if ledger is None:
                return False

            quality = ledger.evidence_quality(evidence_id)
            if not quality or quality.get("state") == "CONTESTED":
                return False
            if quality.get("kind") != "capability_evidence":
                return False
            if quality.get("latest_role") != source:
                return False

            try:
                recorded = json.loads(quality.get("value") or "{}")
            except (TypeError, ValueError):
                return False
            return (
                recorded.get("claim_type") == claim_type
                and recorded.get("status") in {"PASS", "PASSED", "VERIFIED"}
            )

        checks["required_evidence"] = required_evidence
        checks["evidence_claims_present"] = isinstance(evidence_claims, dict)
        checks["evidence_ledger_bound"] = {
            key: claim_passes(key, evidence_claims.get(key))
            for key in required_evidence
        }
        checks["missing_evidence"] = [
            key for key in required_evidence
            if not checks["evidence_ledger_bound"][key]
        ]
        checks["evidence_sufficient"] = (
            checks["ledger_available"]
            and not checks["missing_evidence"]
        )

        verified = (
            checks["parent_decision_present"]
            and checks["parent_requested_evidence"]
            and checks["structured_intent_present"]
            and checks["policy_still_requires_evidence"]
            and checks["evidence_claims_present"]
            and checks["evidence_sufficient"]
        )

        capability_grant = None
        if verified:
            intent = ActionIntent(**structured_parent_intent)
            evidence_ids = [
                value.get("evidence_id")
                for value in evidence_claims.values()
                if isinstance(value, dict) and value.get("evidence_id")
            ]
            capability_grant = issue_capability_grant(
                task_id=parent_task_id,
                intent=intent,
                policy_version=CapabilityPolicy.VERSION,
                evidence_ids=evidence_ids,
                authorized_scope=(intent.destination or intent.resource),
            ).to_dict()

        return {
            "agent": self.name,
            "validation_mode": "capability_evidence",
            "status": "VERIFIED" if verified else "INSUFFICIENT_EVIDENCE",
            "parent_task_id": parent_task_id,
            "parent_decision": (
                parent_result.get("decision")
                if isinstance(parent_result, dict) else None
            ),
            "intent": intent_data,
            "checks": checks,
            "policy_result": policy_result,
            "evidence_claims": evidence_claims,
            "capability_grant": capability_grant,
            "execution_performed": False,
        }

    @staticmethod
    def _apply_validation_update(opportunity, validation):
        status = validation.get("status")
        validation_type = validation.get("validation_type")
        before = max(0.0, min(1.0, float(opportunity.get("confidence", opportunity.get("opportunity_score", 0) / 100.0) or 0.0)))
        if status == "VALIDATED":
            delta = {"technical": 0.12, "adoption": 0.10, "dependency": 0.10, "security": 0.08, "commercial": 0.08}.get(validation_type, 0.06)
        elif status == "PARTIAL": delta = 0.02
        elif status == "DEFERRED": delta = 0.0
        else: delta = -0.10
        after = max(0.0, min(1.0, before + delta))
        score_before = int(opportunity.get("opportunity_score", round(before * 100)))
        score_after = max(0, min(100, round(after * 100)))
        uncertainties = [str(x) for x in opportunity.get("uncertainties", [])]
        markers = {"technical": ("test coverage is not established",), "security": ("security posture requires further validation",), "commercial": ("market/problem context is inferred from technical signals",), "adoption": ("adoption",), "dependency": ("dependency",)}.get(validation_type, ())
        if status == "VALIDATED": uncertainties = [u for u in uncertainties if not any(m in u.lower() for m in markers)]
        evidence = {
            "status": status,
            "type": validation_type,
            "metric": validation.get("experiment_metric"),
            "value": validation.get("experiment_value"),
        }
        history = list(opportunity.get("validation_history") or [])
        history.append(evidence)
        opportunity.update(
            confidence_before=round(before,3),
            confidence=round(after,3),
            confidence_delta=round(after-before,3),
            score_before_validation=score_before,
            opportunity_score=score_after,
            uncertainties=uncertainties,
            validation_evidence=evidence,
            validation_history=history[-6:],
        )
        if status == "VALIDATED": opportunity["commercial_readiness"] = "VALIDATE" if score_after >= 45 else "EARLY_SIGNAL"
        elif status in {"DEFERRED", "BLOCKED"}: opportunity["commercial_readiness"] = "EARLY_SIGNAL"
        return {"before":round(before,3), "after":round(after,3), "delta":round(after-before,3), "score_before":score_before, "score_after":score_after, "uncertainties_remaining":len(uncertainties)}

    def run(self, task: Task) -> Task:
        task.status = "validating"
        try:
            if self._is_capability_evidence_request(task):
                task.result = self._verify_capability_request(task)
                task.status = "validated"
                return task

            result = dict(task.result or {})
            opportunities = [x for x in result.get("opportunities", [])
                             if isinstance(x, dict)][:self.MAX_OPPORTUNITIES]
            if not opportunities:
                task.status = "validation_failed"
                task.result = {"agent": self.name, "error_type": "NoOpportunities",
                               "error": "no opportunity dossier available"}
                return task
            client = GitHubClient()
            validations = [self._validate_repo(x, client) for x in opportunities]
            updates = []
            for opportunity, validation in zip(opportunities, validations):
                opportunity["validation_status"] = validation.get("status")
                opportunity["validation_reproducibility"] = validation.get("reproducibility")
                updates.append(self._apply_validation_update(opportunity, validation))
            result["opportunities"] = opportunities
            result["validation_updates"] = updates
            result["validation_confidence"] = round(sum(item["after"] for item in updates) / len(updates), 3) if updates else None
            result["validation_results"] = validations
            result["validation_summary"] = {
                "experiments": len(validations),
                "validated": sum(v.get("status") == "VALIDATED" for v in validations),
                "partial": sum(v.get("status") == "PARTIAL" for v in validations),
                "deferred": sum(v.get("status") == "DEFERRED" for v in validations),
                "blocked": sum(v.get("status") == "BLOCKED" for v in validations),
            }
            result["validated_by"] = self.name
            task.result, task.status = result, "validated"
        except Exception as exc:
            task.status = "validation_failed"
            task.result = {"agent": self.name, "error_type": type(exc).__name__,
                           "error": str(exc)}
        return task

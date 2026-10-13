import base64
import hashlib
import json
import os
from shared.task import Task
from shared.public_source import ALLOWED_SOURCE_HOSTS, fetch_public_source
from urllib.parse import urlparse
from shared.github_client import GitHubClient
from shared.capability_policy import ActionIntent, CapabilityDecision, CapabilityPolicy
from shared.evidence_ledger import EvidenceLedger
from shared.capability_grant import issue_capability_grant
from shared.capability_signing import CapabilitySigner
from shared.agent_authority import AgentAuthorityRegistry
from shared.agent_identity_signing import AgentIdentitySigner

EXPECTED_EVM_FORENSICS_REVISIONS = {
    ("johguse/profanity", "v1.50"): "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6",
    ("johguse/profanity", "master"): "186b9b27ab3e24a1899f648adcabcbf0e5f3131e",
}


def _reject_duplicate_json_keys(pairs):
    """Reject ambiguous JSON objects in operator-provisioned trust configuration."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result
from shared.signed_action_intent import ActionIntentSigner
from shared.lab_execution_receipt import LabExecutionReceiptError, receipt_sha256, verify_signed_receipt

class Validator:
    """Run bounded, reproducible validation experiments on opportunity dossiers."""
    name = "validator"

    def __init__(self, evidence_ledger=None, capability_signer=None, authority_registry=None, agent_identity_signer=None, agent_identity_key_dir=None, source_fetcher=None):
        self.evidence_ledger = evidence_ledger
        self.source_fetcher = source_fetcher or fetch_public_source
        self.capability_signer = capability_signer or CapabilitySigner.generate()
        self.agent_identity_signer = agent_identity_signer
        self.agent_identity_key_dir = agent_identity_key_dir or os.environ.get("AEGISFORGE_AGENT_IDENTITY_KEY_DIR", "/var/lib/aegisforge/identities")
        self.authority_registry = authority_registry
        if self.authority_registry is None and evidence_ledger is not None:
            self.authority_registry = AgentAuthorityRegistry(evidence_ledger.db)
    MAX_OPPORTUNITIES = 4
    MAX_RESEARCH_SOURCE_RECHECKS = 12
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
                # GitHub can validate technical existence and public project signals,
                # but it cannot establish willingness to pay. Never label a commercial
                # hypothesis as validated from stars, forks, or repository metadata.
                description = str(metadata.get("description") or "").strip()
                topics = metadata.get("topics") or []
                result.update(
                    status="PARTIAL",
                    reason="public repository evidence cannot establish buyer demand or willingness to pay",
                )
                result["checks"].append({"check": "commercial_signal_probe",
                                         "passed": bool(description or topics),
                                         "description_present": bool(description),
                                         "topic_count": len(topics),
                                         "limitation": "not evidence of willingness_to_pay"})
                result["experiment_metric"] = "public_commercial_signal"
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
                        "privileged", "read_only", "evidence_required", "parameters",
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
            evidence_ids = [
                value.get("evidence_id")
                for value in evidence_claims.values()
                if isinstance(value, dict) and value.get("evidence_id")
            ]
            if self.authority_registry is None:
                raise RuntimeError("authority_registry_required")
            parent_agent_id = parent_result.get("agent_id")
            intent_agent_id = structured_parent_intent.get("agent_id")
            if parent_agent_id and intent_agent_id and str(parent_agent_id) != str(intent_agent_id):
                raise RuntimeError("agent_identity_mismatch")
            agent_id = parent_agent_id or intent_agent_id
            if not agent_id:
                raise RuntimeError("agent_identity_required")
            structured_parent_intent = dict(structured_parent_intent)
            structured_parent_intent["agent_id"] = str(agent_id)
            intent = ActionIntent(**structured_parent_intent)
            parameters = dict(getattr(intent, "parameters", {}) or {})
            outcome_contract = parameters.get("outcome_contract", {})
            if not isinstance(outcome_contract, dict):
                outcome_contract = {}
            self.authority_registry.register(agent_id)
            authority = self.authority_registry.get(agent_id)
            if self.agent_identity_signer is None or self.agent_identity_signer.identity.agent_id != str(agent_id):
                key_path = os.path.join(self.agent_identity_key_dir, f"{agent_id}.key")
                self.agent_identity_signer = AgentIdentitySigner.load_or_create(
                    key_path, agent_id=str(agent_id), role=self.name
                )
            signed_agent_identity = self.agent_identity_signer.sign_identity()
            signed_action_intent = ActionIntentSigner(self.agent_identity_signer).sign(intent)
            grant = issue_capability_grant(
                task_id=parent_task_id,
                intent=intent,
                policy_version=authority.policy_version,
                evidence_ids=evidence_ids,
                authorized_scope=(intent.destination or intent.resource),
                outcome_contract=outcome_contract,
                authority_state=authority.state,
                authority_context=authority,
                signed_action_intent=signed_action_intent,
            )
            capability_grant = self.capability_signer.sign(grant, signed_agent_identity).to_dict()

        return {
            "agent": self.name,
            "agent_id": structured_parent_intent.get("agent_id") if verified else None,
            "validation_mode": "capability_evidence",
            "status": "VERIFIED" if verified else "INSUFFICIENT_EVIDENCE",
            "parent_task_id": parent_task_id,
            "parent_decision": (
                parent_result.get("decision")
                if isinstance(parent_result, dict) else None
            ),
            # The execution handoff must carry the original authorized intent,
            # not the validator request that triggered this verification.
            "intent": structured_parent_intent if verified else intent_data,
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
        elif status == "PARTIAL": delta = 0.0
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

    def _validate_evm_forensics_dossier(self, task: Task) -> Task:
        """Check provenance and scope without equating source access with proof."""
        result = dict(task.result or {})
        sources = [item for item in result.get("sources", []) if isinstance(item, dict)]

        # Contradictions are only recorded when upstream stages provide explicit,
        # structured assertions. Do not infer support/refutation from keywords.
        claim_assertions = []
        for source in sources:
            assertions = source.get("claim_assertions", [])
            if not isinstance(assertions, list):
                continue
            for assertion in assertions:
                if not isinstance(assertion, dict):
                    continue
                claim_id = str(assertion.get("claim_id") or "").strip()
                stance = str(assertion.get("stance") or "").strip().upper()
                source_id = str(source.get("source_id") or "").strip()
                if claim_id and stance in {"SUPPORTS", "REFUTES"} and source_id:
                    claim_assertions.append({
                        "claim_id": claim_id,
                        "stance": stance,
                        "source_id": source_id,
                    })
        claim_stances = {}
        for assertion in claim_assertions:
            claim_stances.setdefault(assertion["claim_id"], {}).setdefault(
                assertion["stance"], set()
            ).add(assertion["source_id"])
        conflicting_claims = [
            {
                "claim_id": claim_id,
                "supporting_source_ids": sorted(stances.get("SUPPORTS", set())),
                "refuting_source_ids": sorted(stances.get("REFUTES", set())),
            }
            for claim_id, stances in sorted(claim_stances.items())
            if stances.get("SUPPORTS") and stances.get("REFUTES")
        ]
        source_id_counts = {}
        for source in sources:
            source_id = str(source.get("source_id") or "").strip()
            if source_id:
                source_id_counts[source_id] = source_id_counts.get(source_id, 0) + 1
        missing_source_id_count = sum(
            not str(source.get("source_id") or "").strip() for source in sources
        )
        duplicate_source_ids = sorted(
            source_id for source_id, count in source_id_counts.items() if count > 1
        )
        source_identity_integrity_failed = bool(missing_source_id_count or duplicate_source_ids)
        source_ids = set(source_id_counts)

        # Preserve explicit source-lineage declarations. Two distinct pages may
        # repeat a single upstream report; URL and content fingerprints alone
        # cannot establish independent origin.
        declared_derivations = {}
        invalid_derivation_references = []
        self_referential_derivations = []
        for source in sources:
            source_id = str(source.get("source_id") or "").strip()
            derived_from = source.get("derived_from_source_ids", [])
            if not isinstance(derived_from, list):
                invalid_derivation_references.append(source_id or "<missing-source-id>")
                continue
            # Every declared entry must be a non-empty string. Silently dropping
            # malformed values would make a partially invalid lineage look valid.
            malformed_entries = any(
                not isinstance(origin, str) or not origin.strip()
                for origin in derived_from
            )
            normalized_origins = sorted({
                origin.strip() for origin in derived_from
                if isinstance(origin, str) and origin.strip()
            })
            if malformed_entries or len(normalized_origins) != len(derived_from):
                invalid_derivation_references.append(source_id or "<missing-source-id>")
            missing_origins = [origin for origin in normalized_origins if origin not in source_ids]
            if missing_origins:
                invalid_derivation_references.append(source_id or "<missing-source-id>")
            if source_id and source_id in normalized_origins:
                self_referential_derivations.append(source_id)
            if source_id and normalized_origins:
                declared_derivations[source_id] = normalized_origins

        # Detect cycles in the declared graph. This validates the metadata shape,
        # not whether any source's asserted lineage is factually true.
        derivation_cycles = []
        visit_state = {}
        stack = []

        def visit_derivation(source_id):
            state = visit_state.get(source_id, 0)
            if state == 2:
                return
            if state == 1:
                cycle_start = stack.index(source_id) if source_id in stack else 0
                cycle = tuple(stack[cycle_start:] + [source_id])
                if cycle not in derivation_cycles:
                    derivation_cycles.append(cycle)
                return
            visit_state[source_id] = 1
            stack.append(source_id)
            for origin in declared_derivations.get(source_id, []):
                if origin in declared_derivations:
                    visit_derivation(origin)
            stack.pop()
            visit_state[source_id] = 2

        for source_id in sorted(declared_derivations):
            visit_derivation(source_id)
        sources_with_declared_derivations = sorted(declared_derivations)
        source_derivation_dependencies = {
            source_id: origins for source_id, origins in sorted(declared_derivations.items())
        }

        # A dossier may contain multiple records for the same URL, or silently
        # exceed the recheck budget. Surface both explicitly rather than letting
        # the report imply that every listed source was independently checked.
        source_url_counts = {}
        for source in sources:
            raw_url = str(source.get("source_url") or "").strip()
            parsed_url = urlparse(raw_url)
            if parsed_url.scheme and parsed_url.hostname:
                scheme = parsed_url.scheme.lower()
                host = parsed_url.hostname.lower().rstrip(".")
                try:
                    port = parsed_url.port
                except ValueError:
                    # Malformed ports must not be silently collapsed into a
                    # different canonical identity.
                    port = f"invalid:{parsed_url.netloc.rsplit(':', 1)[-1]}"
                if (scheme, port) in {("https", 443), ("http", 80)}:
                    port = None
                path = parsed_url.path.rstrip("/") or "/"
                query = parsed_url.query
                normalized_url = (scheme, host, port, path, query)
                source_url_counts[normalized_url] = source_url_counts.get(normalized_url, 0) + 1
        duplicate_source_urls = sorted(
            f"{scheme}://{host}"
            + (f":{port}" if port is not None else "")
            + path
            + (f"?{query}" if query else "")
            for (scheme, host, port, path, query), count in source_url_counts.items()
            if count > 1
        )
        source_recheck_limit = self.MAX_RESEARCH_SOURCE_RECHECKS
        sources_not_rechecked_due_to_limit = max(0, len(sources) - source_recheck_limit)
        source_checks = []

        repository_pins = [item for item in result.get("repository_pins", []) if isinstance(item, dict)]
        pinned_revision_checks = []

        for source in sources[:source_recheck_limit]:
            url = str(source.get("source_url") or "")
            parsed = urlparse(url)
            allowlisted = parsed.scheme == "https" and parsed.hostname in ALLOWED_SOURCE_HOSTS
            digest = str(source.get("content_sha256") or "")
            digest_ok = len(digest) == 64 and all(char in "0123456789abcdef" for char in digest.lower())
            check = {
                "source_id": source.get("source_id"),
                "source_url": url,
                "allowlisted_https": allowlisted,
                "reported_fetch_success": source.get("status_code") == 200,
                "reported_digest_well_formed": digest_ok,
                "recheck_status": "not_attempted",
                "content_fingerprint_matches": False,
            }
            if allowlisted:
                try:
                    fresh = self.source_fetcher(url)
                    check["recheck_status"] = "rechecked_http_200" if fresh.get("status_code") == 200 else f"recheck_http_{fresh.get('status_code')}"
                    check["content_fingerprint_matches"] = bool(digest_ok) and fresh.get("content_sha256") == digest
                    truncation = fresh.get("content_truncated_for_analysis")
                    check["rechecked_content_truncated_for_analysis"] = (
                        truncation if isinstance(truncation, bool) else None
                    )
                    check["analysis_text_completeness"] = (
                        "TRUNCATED" if truncation is True
                        else "COMPLETE" if truncation is False
                        else "UNKNOWN"
                    )
                    check["rechecked_at"] = fresh.get("retrieved_at")
                except Exception as exc:
                    check["recheck_status"] = "recheck_error"
                    check["recheck_error_type"] = type(exc).__name__
            if source.get("source_kind") == "pinned_repository_source":
                path_parts = parsed.path.strip("/").split("/")
                revision_sha = str(source.get("revision_sha") or "").lower()
                repository = str(source.get("repository") or "")
                repository_ref = str(source.get("repository_ref") or "")
                revision_role = str(source.get("revision_role") or "")
                expected_revision_sha = EXPECTED_EVM_FORENSICS_REVISIONS.get((repository, repository_ref))
                pin_matches = any(
                    item.get("repository") == repository
                    and item.get("requested_ref") == repository_ref
                    and str(item.get("commit_sha") or "").lower() == revision_sha
                    and str(item.get("expected_commit_sha") or "").lower() == expected_revision_sha
                    and item.get("revision_role") == revision_role
                    for item in repository_pins
                )
                immutable_pin_valid = (
                    parsed.scheme == "https"
                    and parsed.hostname == "raw.githubusercontent.com"
                    and len(path_parts) >= 4
                    and "/".join(path_parts[:2]) == repository
                    and len(revision_sha) == 40
                    and all(char in "0123456789abcdef" for char in revision_sha)
                    and expected_revision_sha is not None
                    and revision_sha == expected_revision_sha
                    and path_parts[2].lower() == revision_sha
                    and "/".join(path_parts[3:]) == str(source.get("source_file_path") or "")
                    and source.get("revision_url") == f"https://github.com/{repository}/tree/{revision_sha}"
                    and pin_matches
                )
                check["immutable_revision_pin_valid"] = immutable_pin_valid
                pinned_revision_checks.append({
                    "source_id": source.get("source_id"),
                    "revision_sha": revision_sha,
                    "valid": immutable_pin_valid,
                })
            source_checks.append(check)

        hypotheses = [item for item in result.get("hypotheses", []) if isinstance(item, dict)]
        hypothesis_checks = []
        for hypothesis in hypotheses:
            refs = hypothesis.get("source_ids") or []
            if not isinstance(refs, list):
                refs = []
                refs_shape_valid = False
            else:
                refs_shape_valid = all(isinstance(ref, str) and bool(ref.strip()) for ref in refs)
            normalized_refs = [ref for ref in refs if isinstance(ref, str) and ref.strip()]
            missing_refs = [ref for ref in normalized_refs if ref not in source_ids]
            hypothesis_checks.append({
                "hypothesis_id": hypothesis.get("hypothesis_id"),
                "source_reference_count": len(refs),
                "source_reference_shape_valid": refs_shape_valid,
                "missing_source_references": missing_refs,
                "has_source_reference": bool(normalized_refs),
            })
        hypotheses_with_missing_sources = sum(
            bool(item["missing_source_references"]) or not item["source_reference_shape_valid"]
            for item in hypothesis_checks
        )

        experiments = [item for item in result.get("lab_experiments", []) if isinstance(item, dict)]

        # Validate observed subprocess records for internal consistency. This is
        # not an authenticity claim: a record supplied by another agent can be
        # fabricated unless the runner itself is independently trusted/attested.
        execution_record_checks = []
        for item in experiments:
            record = item.get("execution_record")
            command = record.get("command") if isinstance(record, dict) else None
            stdout = record.get("stdout") if isinstance(record, dict) else None
            stderr = record.get("stderr") if isinstance(record, dict) else None
            timed_out = record.get("timed_out") if isinstance(record, dict) else None
            exit_code = record.get("exit_code") if isinstance(record, dict) else None
            command_digest = (
                hashlib.sha256(json.dumps(
                    command, ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")).hexdigest()
                if isinstance(command, list) and command else None
            )
            stdout_digest = (
                hashlib.sha256(stdout.encode("utf-8")).hexdigest()
                if isinstance(stdout, str) else None
            )
            stderr_digest = (
                hashlib.sha256(stderr.encode("utf-8")).hexdigest()
                if isinstance(stderr, str) else None
            )
            test_passed = record.get("test_passed") if isinstance(record, dict) else None
            checks = {
                "record_present": isinstance(record, dict),
                "schema_version_valid": isinstance(record, dict)
                    and record.get("schema_version") == 1,
                "record_kind_valid": isinstance(record, dict)
                    and record.get("record_kind") == "local_subprocess_observation",
                "executor_valid": isinstance(record, dict)
                    and record.get("executor") == "python-subprocess",
                "command_digest_matches": command_digest is not None
                    and command_digest == record.get("command_sha256"),
                "stdout_digest_matches": stdout_digest is not None
                    and stdout_digest == record.get("stdout_sha256"),
                "stderr_digest_matches": stderr_digest is not None
                    and stderr_digest == record.get("stderr_sha256"),
                "execution_outcome_well_formed": (
                    isinstance(record, dict)
                    and isinstance(timed_out, bool)
                    and isinstance(test_passed, bool)
                    and (
                        (timed_out is True and exit_code is None and test_passed is False)
                        or
                        (timed_out is False and isinstance(exit_code, int)
                         and not isinstance(exit_code, bool)
                         and (exit_code == 0 or test_passed is False))
                    )
                ),
            }
            # Structural consistency and successful execution are different
            # claims: a well-formed failed run is consistent, but never passing.
            internally_consistent = all(checks.values())
            successful_execution = (
                internally_consistent
                and timed_out is False
                and exit_code == 0
                and test_passed is True
            )
            execution_record_checks.append({
                "experiment_id": item.get("experiment_id"),
                "checks": checks,
                "internally_consistent": internally_consistent,
                "successful_execution": successful_execution,
            })
        # Trusted keys must be explicitly provisioned by the operator as a JSON
        # object mapping key IDs to base64-encoded raw 32-byte Ed25519 public keys.
        trusted_lab_keys = {}
        trusted_lab_keys_config_error = None
        raw_trusted_keys = os.environ.get("AEGISFORGE_LAB_TRUSTED_PUBLIC_KEYS", "").strip()
        if raw_trusted_keys:
            try:
                parsed_trusted_keys = json.loads(
                    raw_trusted_keys, object_pairs_hook=_reject_duplicate_json_keys
                )
                if not isinstance(parsed_trusted_keys, dict):
                    raise ValueError("trusted_key_map_must_be_object")
                for key_id, encoded_key in parsed_trusted_keys.items():
                    if not isinstance(key_id, str) or not key_id.strip() or not isinstance(encoded_key, str):
                        raise ValueError("trusted_key_entry_malformed")
                    decoded_key = base64.b64decode(encoded_key, validate=True)
                    if len(decoded_key) != 32:
                        raise ValueError("trusted_ed25519_public_key_must_be_32_bytes")
                    trusted_lab_keys[key_id] = decoded_key
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                trusted_lab_keys = {}
                trusted_lab_keys_config_error = type(exc).__name__

        # A canonical receipt detects accidental or post-run mutation. Signature
        # trust is a separate check against operator-provisioned public keys.
        execution_receipt_checks = []
        for item in experiments:
            receipt = item.get("execution_receipt")
            reported_digest = item.get("execution_receipt_sha256")
            record = item.get("execution_record")
            digest_valid = False
            receipt_error = None
            try:
                calculated_digest = receipt_sha256(receipt)
                digest_valid = calculated_digest == reported_digest
            except (LabExecutionReceiptError, TypeError, ValueError) as exc:
                calculated_digest = None
                receipt_error = type(exc).__name__
            receipt_execution = receipt.get("execution") if isinstance(receipt, dict) else None
            receipt_inputs = receipt.get("inputs") if isinstance(receipt, dict) else None
            receipt_artifacts = receipt.get("artifacts") if isinstance(receipt, dict) else None
            command = record.get("command") if isinstance(record, dict) else None
            stdout = record.get("stdout") if isinstance(record, dict) else None
            command_matches_receipt = (
                isinstance(record, dict)
                and isinstance(receipt_inputs, dict)
                and receipt_inputs.get("argv") == command
                and receipt_inputs.get("script_source_sha256") == record.get("script_source_sha256")
                and isinstance(receipt_artifacts, dict)
                and receipt_artifacts.get("script_source_sha256") == record.get("script_source_sha256")
            )
            result_payload_digest = None
            if isinstance(stdout, str):
                try:
                    parsed_stdout = json.loads(stdout)
                    result_payload_digest = hashlib.sha256(json.dumps(
                        parsed_stdout, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                    ).encode("utf-8")).hexdigest()
                except (TypeError, ValueError):
                    result_payload_digest = None
            result_payload_digest_matches = (
                isinstance(receipt_artifacts, dict)
                and result_payload_digest is not None
                and receipt_artifacts.get("result_payload_sha256") == result_payload_digest
            )
            record_matches_receipt = (
                isinstance(receipt_execution, dict)
                and isinstance(record, dict)
                and receipt.get("experiment_id") == item.get("experiment_id")
                and receipt_execution.get("exit_code") == record.get("exit_code")
                and receipt_execution.get("timed_out") == record.get("timed_out")
                and receipt_execution.get("test_passed") == record.get("test_passed")
                and receipt_execution.get("stdout_sha256") == record.get("stdout_sha256")
                and receipt_execution.get("stderr_sha256") == record.get("stderr_sha256")
                and command_matches_receipt
                and result_payload_digest_matches
            )
            envelope = item.get("execution_receipt_envelope")
            signature_verified = False
            signature_error = None
            verified_signer_key_id = None
            if isinstance(envelope, dict):
                try:
                    signature_result = verify_signed_receipt(
                        envelope, trusted_public_keys=trusted_lab_keys
                    )
                    # The authenticated envelope must bind to the exact receipt
                    # and digest being evaluated here, not merely contain some
                    # other validly signed receipt.
                    signature_verified = (
                        signature_result.get("valid") is True
                        and envelope.get("receipt") == receipt
                        and signature_result.get("receipt_sha256") == reported_digest
                    )
                    verified_signer_key_id = (
                        signature_result.get("key_id") if signature_verified else None
                    )
                except (LabExecutionReceiptError, TypeError, ValueError) as exc:
                    signature_error = str(exc)
            signed = isinstance(envelope, dict)
            # A trusted signature over a generic execution receipt is not enough:
            # bind the receipt to the exact reproduction claim and artifact.
            receipt_inputs = receipt.get("inputs") if isinstance(receipt, dict) else None
            receipt_artifacts = receipt.get("artifacts") if isinstance(receipt, dict) else None
            reproduction_binding_matches = (
                isinstance(receipt_inputs, dict)
                and isinstance(receipt_artifacts, dict)
                and receipt.get("experiment_id") == item.get("experiment_id")
                and receipt_inputs.get("source_revision") == item.get("pinned_source_revision")
                and receipt_inputs.get("test_vector_id") == item.get("synthetic_test_vector_id")
                and receipt_inputs.get("reproduction_command") == item.get("reproduction_command")
                and receipt_artifacts.get("reproduction_artifact_sha256") == item.get("reproduction_artifact_sha256")
            )
            # A trusted Ed25519 signature only authenticates the signer's
            # statement. This pipeline has no independent runner attestation
            # verifier yet, so even a correctly bound receipt cannot qualify a
            # historical reproduction by itself.
            independent_runner_attestation_verified = False
            execution_receipt_checks.append({
                "experiment_id": item.get("experiment_id"),
                "reproduction_binding_matches": reproduction_binding_matches,
                "independent_runner_attestation_verified": independent_runner_attestation_verified,
                "receipt_present": isinstance(receipt, dict),
                "digest_matches": digest_valid,
                "record_matches_receipt": record_matches_receipt,
                "command_matches_receipt": command_matches_receipt,
                "result_payload_digest_matches": result_payload_digest_matches,
                "integrity_verified": digest_valid and record_matches_receipt,
                "signature_present": signed,
                "signature_verified_against_trusted_key": signature_verified,
                "signer_key_id": verified_signer_key_id,
                "authenticity": "SIGNED_AND_TRUSTED" if signature_verified else ("SIGNATURE_INVALID_OR_UNTRUSTED" if signed else "UNTRUSTED_UNSIGNED"),
                "signature_error": signature_error,
                "trusted_key_configuration_error": trusted_lab_keys_config_error,
                "error_type": receipt_error,
            })

        toy_only = bool(experiments) and all(
            item.get("synthetic_test_only") is True
            and item.get("uses_real_private_keys") is False
            and item.get("uses_real_wallet_addresses") is False
            and item.get("historical_implementation_reproduced") is False
            for item in experiments
        )
        def is_immutable_hex(value, length):
            text = str(value or "")
            return len(text) == length and all(char in "0123456789abcdef" for char in text.lower())

        # A dossier-supplied artifact is self-asserted. Historical reproduction
        # qualification additionally requires a receipt for the same experiment
        # whose signature verifies against an operator-provisioned trusted key.
        # This raises provenance confidence; it still does not prove the signer
        # operated an isolated runner or that the scientific claim is true.
        trusted_receipt_experiment_ids = {
            check.get("experiment_id")
            for check in execution_receipt_checks
            if check.get("integrity_verified") is True
            and check.get("authenticity") == "SIGNED_AND_TRUSTED"
            and check.get("signature_verified_against_trusted_key") is True
            and check.get("reproduction_binding_matches") is True
            and check.get("independent_runner_attestation_verified") is True
        }

        # Never trust a bare boolean asserted by a previous agent. A historical
        # reproduction must link to an immutable revision, a synthetic test
        # vector, a passing reproduction test, a content-addressed artifact,
        # and a trusted receipt for the same experiment.
        qualified_reproductions = []
        for item in experiments:
            artifact = item.get("reproduction_artifact")
            artifact_digest = item.get("reproduction_artifact_sha256")
            artifact_bytes_present = isinstance(artifact, str) and bool(artifact.strip())
            artifact_digest_matches = (
                artifact_bytes_present
                and is_immutable_hex(artifact_digest, 64)
                and hashlib.sha256(artifact.encode("utf-8")).hexdigest() == str(artifact_digest).lower()
            )
            # Hash integrity alone is not enough: require a structured artifact
            # whose claimed metadata agrees with the dossier. This is a
            # consistency gate, not proof that the command actually ran.
            artifact_record = None
            if artifact_digest_matches:
                try:
                    parsed_artifact = json.loads(artifact)
                    if isinstance(parsed_artifact, dict):
                        artifact_record = parsed_artifact
                except (TypeError, ValueError):
                    artifact_record = None
            artifact_record_matches = (
                isinstance(artifact_record, dict)
                and artifact_record.get("schema_version") == 1
                and artifact_record.get("source_revision") == item.get("pinned_source_revision")
                and artifact_record.get("test_vector_id") == item.get("synthetic_test_vector_id")
                and artifact_record.get("command") == item.get("reproduction_command")
                and artifact_record.get("exit_code") == 0
                and artifact_record.get("test_passed") is True
            )
            if not (
                item.get("historical_implementation_reproduced") is True
                and item.get("synthetic_test_only") is True
                and item.get("uses_real_private_keys") is False
                and item.get("uses_real_wallet_addresses") is False
                # A self-asserted SHA-shaped string is not enough: only the
                # explicitly pinned pre-disclosure revision is eligible for a
                # historical reproduction claim. The archived master snapshot
                # is contextual evidence, not an affected-version reproduction target.
                and item.get("pinned_source_revision") == EXPECTED_EVM_FORENSICS_REVISIONS.get(("johguse/profanity", "v1.50"))
                and item.get("reproduction_source_role") == "pre_disclosure_release"
                and str(item.get("synthetic_test_vector_id") or "").strip()
                and item.get("reproduction_test_passed") is True
                and artifact_digest_matches
                and artifact_record_matches
                and str(item.get("reproduction_command") or "").strip()
                and item.get("experiment_id") in trusted_receipt_experiment_ids
            ):
                continue
            qualified_reproductions.append(item)

        historical_reproduction = bool(qualified_reproductions)
        rechecked = sum(item.get("recheck_status") == "rechecked_http_200" for item in source_checks)
        matching = sum(item.get("content_fingerprint_matches") is True for item in source_checks)
        # Different URLs can still serve the exact same bytes (for example,
        # mirrors or copied advisories). Treat repeated matching fingerprints
        # as one content item, not independent evidence.
        matching_source_digests = {}
        for source, check in zip(sources[:source_recheck_limit], source_checks):
            digest = str(source.get("content_sha256") or "").lower()
            if check.get("content_fingerprint_matches") is True and digest:
                matching_source_digests.setdefault(digest, []).append(
                    str(source.get("source_id") or "")
                )
        duplicate_source_content_fingerprints = {
            digest: sorted(source_ids)
            for digest, source_ids in matching_source_digests.items()
            if len(source_ids) > 1
        }
        independent_matching_fingerprints = len(matching_source_digests) - len(
            duplicate_source_content_fingerprints
        )
        pinned_checks_passed = sum(item.get("valid") is True for item in pinned_revision_checks)
        pinned_checks_failed = sum(item.get("valid") is False for item in pinned_revision_checks)
        truncated_sources = sum(
            item.get("analysis_text_completeness") == "TRUNCATED" for item in source_checks
        )
        unknown_completeness_sources = sum(
            item.get("analysis_text_completeness") == "UNKNOWN" for item in source_checks
        )
        readiness_blockers = []
        if conflicting_claims:
            readiness_blockers.append("conflicting_source_claims_require_review")
        if source_identity_integrity_failed:
            readiness_blockers.append("source_identity_integrity_failed")
        if duplicate_source_urls:
            readiness_blockers.append("duplicate_source_urls")
        if duplicate_source_content_fingerprints:
            readiness_blockers.append("duplicate_source_content_fingerprints")
        # Unique bytes are not proof of independent reporting or origin.
        # This validator has no independently verified publisher/origin graph yet.
        readiness_blockers.append("source_origin_independence_not_established")
        if source_derivation_dependencies:
            readiness_blockers.append("source_derivation_dependencies_require_review")
        if invalid_derivation_references:
            readiness_blockers.append("source_derivation_references_invalid")
        if self_referential_derivations:
            readiness_blockers.append("source_derivation_self_reference")
        if derivation_cycles:
            readiness_blockers.append("source_derivation_lineage_cycle")
        if hypotheses_with_missing_sources:
            readiness_blockers.append("hypothesis_source_references_invalid")
        if sources_not_rechecked_due_to_limit:
            readiness_blockers.append("source_recheck_limit_exceeded")
        if not historical_reproduction:
            readiness_blockers.append("historical_reproduction_not_qualified")
        if rechecked < 2 or matching < 2 or independent_matching_fingerprints < 2:
            readiness_blockers.append("insufficient_independent_source_rechecks")
        if pinned_checks_passed < 1 or pinned_checks_failed:
            readiness_blockers.append("pinned_revision_provenance_not_clean")
        if truncated_sources:
            readiness_blockers.append("source_analysis_text_truncated")
        if unknown_completeness_sources:
            readiness_blockers.append("source_analysis_text_completeness_unknown")
        status = "READY_FOR_HUMAN_REVIEW" if not readiness_blockers else "INCONCLUSIVE"

        next_actions = []
        if conflicting_claims:
            next_actions.append("Resolve explicit opposing source assertions claim by claim; do not choose a side from keyword counts or source volume.")
        if not any(item.get("classification") == "early_client_key_generation_warning" for item in sources):
            next_actions.append("Find primary material describing exact early-client version boundaries.")
        if not any(item.get("classification") == "vanity_generator_entropy_weakness_report" for item in sources):
            next_actions.append("Find the primary Profanity vulnerability report and affected revision.")
        if not historical_reproduction:
            next_actions.append("Reproduce a pinned historical implementation with synthetic test vectors, test command, passing result and SHA-256 artifact evidence; the toy demonstration is insufficient.")
        if duplicate_source_urls:
            next_actions.append("Deduplicate repeated source URLs or document why multiple records intentionally refer to the same canonical resource.")
        if hypotheses_with_missing_sources:
            next_actions.append("Repair hypothesis source references so every cited source ID exists and each reference list has the expected shape.")
        if sources_not_rechecked_due_to_limit:
            next_actions.append("Split the dossier into bounded validation batches or prioritize evidence; sources beyond the recheck cap were not re-fetched.")
        if rechecked < 2:
            next_actions.append("Independently re-fetch at least two allowlisted primary sources.")
        if matching < 2 or independent_matching_fingerprints < 2:
            next_actions.append("Require matching SHA-256 fingerprints for at least two distinct source contents; distinct content is not proof of independent origin.")
        next_actions.append("Establish publisher/origin independence with separately verified provenance before treating sources as independent evidence.")
        if truncated_sources:
            next_actions.append("Review full source material or explicitly scope claims to the truncated excerpt; do not treat clipped text as complete analysis.")
        if unknown_completeness_sources:
            next_actions.append("Re-fetch sources with explicit content_truncated_for_analysis metadata before relying on analysis-text completeness.")
        next_actions.append("Keep address-cohort claims unproven until tested against an aggregate control sample.")

        result["research_track"] = "evm_key_forensics"
        result["stage"] = "validation"
        result["research_source_checks"] = source_checks
        if pinned_checks_failed:
            next_actions.append("Repair invalid pinned-revision metadata before treating historical source snapshots as reproducible evidence.")
        result["research_validation"] = {
            "schema_version": "evm-forensics-validation-v1",
            "status": status,
            "readiness_blockers": readiness_blockers,
            "pinned_revision_sources_checked": len(pinned_revision_checks),
            "pinned_revision_source_checks_passed": pinned_checks_passed,
            "pinned_revision_source_checks_failed": pinned_checks_failed,
            "decision": "CONTINUE_RESEARCH" if status == "INCONCLUSIVE" else "READY_FOR_HUMAN_REVIEW",
            "sources_in_dossier": len(sources),
            "source_identity_integrity_failed": source_identity_integrity_failed,
            "sources_missing_source_id": missing_source_id_count,
            "duplicate_source_ids": duplicate_source_ids,
            "duplicate_source_urls": duplicate_source_urls,
            "duplicate_source_content_fingerprints": duplicate_source_content_fingerprints,
            # Legacy metric counts distinct matching content hashes only; it does
            # not establish epistemic or publisher independence.
            "independent_matching_source_fingerprints": independent_matching_fingerprints,
            "distinct_matching_source_fingerprints": independent_matching_fingerprints,
            "source_origin_independence_established": False,
            "source_independence_basis": "unique_content_hashes_and_distinct_urls_do_not_verify_independent_origin",
            "source_derivation_dependencies": source_derivation_dependencies,
            "sources_with_declared_derivations": len(sources_with_declared_derivations),
            "invalid_source_derivation_references": sorted(set(invalid_derivation_references)),
            "self_referential_source_derivations": sorted(set(self_referential_derivations)),
            "source_derivation_cycles": [list(cycle) for cycle in derivation_cycles],
            "hypotheses_with_invalid_source_references": hypotheses_with_missing_sources,
            "source_recheck_limit": source_recheck_limit,
            "sources_not_rechecked_due_to_limit": sources_not_rechecked_due_to_limit,
            "sources_rechecked_http_200": rechecked,
            "exact_source_fingerprints_matching": matching,
            "sources_with_truncated_analysis_text": truncated_sources,
            "sources_with_unknown_analysis_text_completeness": unknown_completeness_sources,
            "explicit_claim_assertions_checked": len(claim_assertions),
            "conflicting_source_claims": conflicting_claims,
            "hypotheses_checked": len(hypothesis_checks),
            "hypothesis_checks": hypothesis_checks,
            "lab_experiment_count": len(experiments),
            "toy_lab_scope_verified": toy_only,
            "lab_execution_records_checked": len(execution_record_checks),
            "lab_execution_records_consistent": bool(execution_record_checks) and all(item["internally_consistent"] for item in execution_record_checks),
            "lab_execution_records_passed": bool(execution_record_checks) and all(item["successful_execution"] for item in execution_record_checks),
            "lab_execution_record_checks": execution_record_checks,
            "lab_execution_receipts_checked": len(execution_receipt_checks),
            "lab_execution_receipts_integrity_verified": bool(execution_receipt_checks) and all(item["integrity_verified"] for item in execution_receipt_checks),
            "lab_execution_receipts_trusted": bool(execution_receipt_checks) and all(item["integrity_verified"] and item["authenticity"] == "SIGNED_AND_TRUSTED" for item in execution_receipt_checks),
            "lab_trusted_signing_key_count": len(trusted_lab_keys),
            "lab_trusted_key_configuration_error": trusted_lab_keys_config_error,
            "lab_execution_receipt_checks": execution_receipt_checks,
            "historical_reproduction_confirmed": historical_reproduction,
            "independent_runner_attestation_available": False,
            "verified_historical_claims": [],
            "interpretation": "Source provenance and experiment scope were checked. Signed receipts authenticate signer statements but do not prove isolated execution; independent runner attestation is not implemented, so historical reproduction remains unqualified.",
            "next_actions": next_actions,
            "review_type": "evm_key_forensics_dossier_validation",
        }
        task.result = result
        task.status = "validated"
        return task

    def run(self, task: Task) -> Task:
        task.status = "validating"
        try:
            if isinstance(task.result, dict) and task.result.get("research_track") == "evm_key_forensics":
                return self._validate_evm_forensics_dossier(task)
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
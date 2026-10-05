[Reading 1000 lines from start (total: 2659 lines, 1659 remaining)]

import hashlib
import json
import os
import sys
import time
from collections import Counter

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from shared.queue import TaskQueue
from shared.result_codec import decode as decode_result
from shared.evidence_ledger import EvidenceLedger
from shared.action_intent import default_capability_intent


DECISIONS = {
    "CONTINUE",
    "REFINE",
    "VERIFY",
    "BRANCH",
    "ESCALATE",
    "COMPLETE",
    "ABORT",
}

MAX_TASKS_PER_GOAL = 50
MAX_TASKS_PER_PLAN = 6
MAX_LIVE_TASKS = 24
STAGNATION_LIMIT = 3

MAX_FAILED_RECOVERIES_PER_CYCLE = 3
MAX_RETRIES_PER_TASK = 3
FAILED_RETRY_COOLDOWN_SECONDS = 60

RESEARCH_GOALS = (
    "Discover promising AI agent and autonomous software technologies, "
    "analyze technical maturity and security, identify commercial opportunities, "
    "and propose concrete product directions",
    "Discover promising energy storage, grid, and distributed-energy technologies, "
    "analyze technical maturity and security, identify commercial opportunities, "
    "and propose concrete product directions",
    "Discover promising robotics, embodied AI, and autonomous-machine technologies, "
    "analyze technical maturity and security, identify commercial opportunities, "
    "and propose concrete product directions",
    "Discover promising cybersecurity and security-automation technologies, "
    "analyze technical maturity and security, identify commercial opportunities, "
    "and propose concrete product directions",
    "Discover promising Web3, blockchain, and decentralized infrastructure technologies, "
    "analyze technical maturity and security, identify commercial opportunities, "
    "and propose concrete product directions",
    "Discover promising privacy, cryptography, confidential-computing, and zero-knowledge technologies, "
    "analyze technical maturity and security, identify commercial opportunities, "
    "and propose concrete product directions",
)


class AutonomousPlanner:

    def __init__(self, queue=None):
        self.queue = queue or TaskQueue()
        self.evidence_ledger = EvidenceLedger(self.queue.db)

    # =========================================================
    # RESULT NORMALIZATION
    # =========================================================

    @staticmethod
    def parse_result(raw):
        if raw is None:
            return None

        if isinstance(raw, (dict, list)):
            return raw

        return decode_result(raw)

    @staticmethod
    def compact_context(result, limit=3500):
        if result is None:
            return "No result."

        try:
            text = json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
                default=str,
            )
        except Exception:
            text = str(result)

        if len(text) > limit:
            text = text[:limit] + "\n...[truncated]"

        return text

    # =========================================================
    # FINGERPRINT / DEDUP
    # =========================================================

    @staticmethod
    def fingerprint(parent_id, role, description):
        value = (
            f"{parent_id}|{role}|{description}"
        ).encode("utf-8")

        return hashlib.sha256(value).hexdigest()[:20]

    # =========================================================
    # TASK VALIDATION
    # =========================================================

    @staticmethod
    def successful(task):
        if task["status"] != "completed":
            return False

        result = task["result"]

        if result is None:
            return False

        if isinstance(result, dict):
            if result.get("error"):
                return False

            if result.get("error_type"):
                return False

            if result.get("agent_error"):
                return False

        return True

    # =========================================================
    # INFORMATION GAIN
    # =========================================================

    def information_gain(self, result):
        """
        Estimate how much actionable information the result contains.

        Structured research outputs are considered useful when they contain
        objectives, plans, actions, hypotheses, experiments, benchmarks,
        findings, targets, opportunities, evidence or security metrics.
        """
        if result is None:
            return 0.0

        if isinstance(result, str):
            return 0.25 if result.strip() else 0.0

        if isinstance(result, list):
            if not result:
                return 0.0
            return min(1.0, 0.25 + 0.10 * len(result))

        if not isinstance(result, dict):
            return 0.0

        score = 0.0

        strong_fields = (
            "objective",
            "research_plan",
            "research_plan_created",
            "next_actions",
            "actions",
            "recommendations",
            "hypotheses",
            "experiments",
            "benchmarks",
            "benchmark",
            "regression_criteria",
            "regression_gates",
            "security_findings",
            "findings",
            "targets",
            "projects",
            "opportunities",
            "evidence",
        )

        for key in strong_fields:
            value = result.get(key)

            if value is None:
                continue

            if isinstance(value, bool):
                if value:
                    score += 0.30
            elif isinstance(value, (list, tuple, set)):
                if value:
                    score += 0.25
            elif isinstance(value, dict):
                if value:
                    score += 0.25
            elif isinstance(value, str):
                if value.strip():
                    score += 0.20
            else:
                score += 0.10

        status = str(result.get("status", "")).lower()

        if status in {
            "research_plan_created",
            "analysis_completed",
            "research_completed",
            "security_checked",
            "opportunities_found",
        }:
            score += 0.35

        security_count_fields = (
            "total_findings",
            "critical_findings",
            "high_findings",
            "medium_findings",
            "low_findings",
        )

        for key in security_count_fields:
            value = result.get(key)

            if isinstance(value, (int, float)) and value > 0:
                score += 0.20

        return min(1.0, score)

    @staticmethod
    def _items(result, keys):
        if not isinstance(result, dict):
            return []

        output = []

        for key in keys:
            value = result.get(key)

            if not value:
                continue

            if isinstance(value, list):
                output.extend(value)

            elif isinstance(value, dict):
                output.append(value)

            else:
                output.append(value)

        return output

    @classmethod
    def extract_targets(cls, result):
        items = cls._items(
            result,
            (
                "repositories",
                "projects",
                "targets",
                "findings",
                "vulnerabilities",
                "security_findings",
                "opportunities",
                "hypotheses",
            ),
        )

        targets = []

        for item in items[:15]:
            if isinstance(item, dict):
                name = (
                    item.get("name")
                    or item.get("repository")
                    or item.get("repo")
                    or item.get("project")
                    or item.get("title")
                    or item.get("id")
                    or item.get("address")
                    or item.get("contract")
                )

                url = item.get("url")

                if name:
                    if url:
                        targets.append(
                            f"{name} ({url})"
                        )
                    else:
                        targets.append(str(name))

                else:
                    targets.append(
                        json.dumps(
                            item,
                            ensure_ascii=False,
                            default=str,
                        )[:500]
                    )

            else:
                targets.append(str(item)[:500])

        return targets[:10]

    @classmethod
    def extract_security_findings(self, result):
        """
        Extract concrete security findings from the current result.

        Supports:
        - legacy top-level findings
        - nested security_reviews[].findings
        - security_summary counters
        - defensive list/dict result shapes
        """
        findings = []

        def add_finding(item, repository=None):
            if isinstance(item, str):
                findings.append({
                    "repository": repository,
                    "finding": item,
                })
                return

            if not isinstance(item, dict):
                return

            finding = dict(item)

            if repository and "repository" not in finding:
                finding["repository"] = repository

            findings.append(finding)

        if isinstance(result, list):
            for item in result:
                add_finding(item)

        elif isinstance(result, dict):
            # Legacy/direct findings.
            direct = result.get("security_findings")
            if isinstance(direct, list):
                for item in direct:
                    add_finding(item)

            findings_field = result.get("findings")
            if isinstance(findings_field, list):
                for item in findings_field:
                    add_finding(item)

            # Current SecurityChecker structure.
            security_reviews = result.get("security_reviews", [])

            if isinstance(security_reviews, list):
                for review in security_reviews:
                    if not isinstance(review, dict):
                        continue

                    repository = (
                        review.get("name")
                        or review.get("repository")
                    )

                    review_findings = review.get("findings", [])

                    if isinstance(review_findings, list):
                        for item in review_findings:
                            add_finding(
                                item,
                                repository=repository,
                            )

            # Defensive support for nested result objects.
            nested = result.get("security_review")
            if isinstance(nested, dict):
                nested_findings = nested.get("findings", [])
                if isinstance(nested_findings, list):
                    for item in nested_findings:
                        add_finding(item)

        return findings

    @classmethod
    def extract_opportunities(cls, result):
        return cls._items(
            result,
            (
                "opportunities",
                "commercial_opportunities",
                "recommendations",
            ),
        )[:10]

    @classmethod
    def extract_hypotheses(cls, result):
        return cls._items(
            result,
            (
                "hypotheses",
                "research_questions",
                "experiments",
            ),
        )[:10]

    @classmethod
    def has_security_signal(cls, result):
        return bool(
            cls.extract_security_findings(result)
        )

    @classmethod
    def has_research_signal(cls, result):
        return bool(
            cls.extract_hypotheses(result)
            or cls.extract_targets(result)
        )

    # =========================================================
    # HUMAN-READABLE TARGET BLOCK
    # =========================================================

    @staticmethod
    def format_items(items, limit=3000):
        if not items:
            return "- None"

        lines = []

        for item in items:
            if isinstance(item, dict):
                text = json.dumps(
                    item,
                    ensure_ascii=False,
                    default=str,
                )
            else:
                text = str(item)

            lines.append(f"- {text[:700]}")

        text = "\n".join(lines)

        if len(text) > limit:
            text = text[:limit] + "\n...[truncated]"

        return text

    # =========================================================
    # EVIDENCE NOVELTY
    # =========================================================

    @classmethod
    def evidence_signature(cls, result):
        """Build a stable, compact signature for decision-relevant evidence."""
        payload = {
            "targets": cls.extract_targets(result),
            "findings": cls.extract_security_findings(result),
            "opportunities": cls.extract_opportunities(result),
            "hypotheses": cls.extract_hypotheses(result),
        }
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        )

    @classmethod
    def evidence_atoms(cls, result):
        """Return normalized evidence atoms used to measure information gain."""
        atoms = set()

        def add(prefix, value):
            if value is None:
                return
            if isinstance(value, dict):
                value = json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                    separators=(",", ":"),
                )
            elif isinstance(value, (list, tuple, set)):
                value = json.dumps(
                    list(value),
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                    separators=(",", ":"),
                )
            else:
                value = str(value).strip()
            if value:
                atoms.add(f"{prefix}:{value}")

        # extract_targets() intentionally includes findings/opportunities for
        # planner routing, but evidence atoms must keep those categories
        # separate or the same finding is counted multiple times.
        if isinstance(result, dict):
            for key in ("repositories", "projects", "targets", "contracts", "addresses", "entities"):
                value = result.get(key)
                items = value[:20] if isinstance(value, list) else [value] if value else []
                for item in items:
                    # Durable evidence needs identity, not a second copy of
                    # full GitHub/API payloads or document contents.
                    if isinstance(item, dict):
                        compact = {}
                        for field in (
                            "name", "full_name", "url", "html_url", "address",
                            "symbol", "chain", "repository", "contract",
                        ):
                            if item.get(field) is not None:
                                compact[field] = item.get(field)
                        add("target", compact or item)
                    else:
                        add("target", item)

        for item in cls.extract_security_findings(result):
            add("finding", item)
        for item in cls.extract_opportunities(result):
            # Opportunity payloads can contain volatile fields such as score,
            # categories and reasons. Persist a stable identity plus the
            # decision-relevant thesis/uncertainty instead of hashing the full
            # dossier on every planner cycle. This prevents repeated workers
            # from turning one opportunity into hundreds of near-duplicate
            # evidence atoms.
            if isinstance(item, dict):
                compact = {
                    field: item.get(field)
                    for field in (
                        "name", "repository", "url", "target_customer",
                        "problem_signal", "product_thesis", "validation_type",
                    )
                    if item.get(field) is not None
                }
                add("opportunity", compact or item)
            else:
                add("opportunity", item)
        for item in cls.extract_hypotheses(result):
            add("hypothesis", item)

        if isinstance(result, dict):
            for key in ("evidence", "sources", "citations", "repositories"):
                value = result.get(key)
                if isinstance(value, list):
                    for item in value[:20]:
                        add(key, item)
                elif value:
                    add(key, value)

            # Analyst outputs are new decision evidence even when they refer
            # to repositories already discovered by Researcher. Keep only the
            # compact decision fields so the durable ledger does not become a
            # second copy of full task results.
            for key in ("analysis", "technology_signals"):
                value = result.get(key)
                if isinstance(value, list):
                    for item in value[:20]:
                        if isinstance(item, dict):
                            compact = {
                                field: item.get(field)
                                for field in (
                                    "name", "priority", "stars", "signal",
                                    "language", "technical_relevance",
                                    "adoption_signal", "activity_signal",
                                )
                                if item.get(field) is not None
                            }
                            add(key, compact or item)

            # Technical review is a new information layer above repository
            # discovery. Keep only stable assessment fields in the evidence
            # ledger so later planner decisions can recognize real progress
            # without persisting entire source trees or file contents.
            value = result.get("validation_results")
            if isinstance(value, list):
                for item in value[:20]:
                    if isinstance(item, dict):
                        compact = {
                            field: item.get(field)
                            for field in (
                                "name", "experiment", "validation_type", "status",
                                "reproducibility", "source", "default_branch",
                                "archived", "stars_observed", "forks_observed",
                                "experiment_metric", "experiment_value",
                            )
                            if item.get(field) is not None
                        }
                        add("validation", compact or item)

            value = result.get("technical_review")
            if isinstance(value, list):
                for item in value[:20]:
                    if isinstance(item, dict):
                        compact = {
                            field: item.get(field)
                            for field in (
                                "name", "technical_maturity",
                                "technical_maturity_score", "has_tests",
                                "has_ci", "has_security_policy",
                                "has_audits", "smart_contract_project",
                                "risk_flags", "security_signals",
                            )
                            if item.get(field) is not None
                        }
                        add("technical_review", compact or item)

            for key in ("status", "severity", "verdict"):
                if result.get(key) is not None:
                    add(key, result[key])

        return atoms

    @classmethod
    def novelty_against_history(cls, task, history):
        """Measure the fraction of current evidence not seen in ancestors."""
        current = cls.evidence_atoms(task.get("result"))
        if not current:
            return 0.0, 0, 0

        previous = set()
        for ancestor in history[1:]:
            previous.update(cls.evidence_atoms(ancestor.get("result")))

        novel = current - previous
        return len(novel) / len(current), len(novel), len(current)

    def evidence_quality_summary(self, result):
        """Summarize explainable ledger quality for the current result."""
        summary = {
            "atoms": 0,
            "unconfirmed": 0,
            "corroborated": 0,
            "multi_source": 0,
            "contested": 0,
            "quality_score": None,
        }
        quality_scores = []
        for atom in self.evidence_atoms(result):
            quality = self.evidence_ledger.evidence_quality(
                self.evidence_ledger.atom_id(atom)
            )
            if not quality:
                continue
            summary["atoms"] += 1
            quality_scores.append(quality["quality_score"])
            state = quality["state"]
            if state == "CONTESTED":
                summary["contested"] += 1
            elif state == "MULTI_SOURCE":
                summary["multi_source"] += 1
            elif state == "CORROBORATED":
                summary["corroborated"] += 1
            else:
                summary["unconfirmed"] += 1

        if quality_scores:
            summary["quality_score"] = min(quality_scores)
        return summary

    # =========================================================
    # AUTONOMOUS DECISION ENGINE
    # =========================================================

    def _choose_next_raw(self, task):
        """
        Decide the next autonomous action from the actual result.

        Important:
        Research results containing repositories/projects/candidates
        are treated as real research signals and routed to Analyst.
        """

        result = task.get("result")
        role = task.get("role")

        gain = self.information_gain(result)

        # -------------------------------------------------
        # Researcher produced concrete projects/repositories
        # -------------------------------------------------

        research_items = []

        if isinstance(result, dict):
            for key in (
                "repositories",
                "projects",
                "candidates",
                "results",
                "findings",
            ):
                value = result.get(key)

                if isinstance(value, list):
                    research_items.extend(value)

                elif isinstance(value, dict):
                    research_items.append(value)

                elif isinstance(value, str) and value.strip():
                    research_items.append(value)

        elif isinstance(result, list):
            research_items = result

        # -------------------------------------------------
        # Repeated-role guard
        # -------------------------------------------------

        history = self.branch_history(
            task,
            getattr(self, "_planning_tasks", {}),
        )

        recent_roles = self.recent_roles(
            history,
            limit=4,
        )

        if (
            research_items
            and role == "analyst"
            and self.repeated_role(recent_roles, 2)
        ):
            return (
                "REFINE",
                "developer",
                (
                    "Perform a focused technical investigation of the "
                    "highest-priority research targets. Do not repeat the "
                    "previous prioritization. Inspect repository structure, "
                    "implementation quality, security-sensitive components, "
                    "and technical feasibility. "
                    f"Targets: {self.format_items(research_items[:10])}. "
                    f"Previous evidence: {self.compact_context(result)}"
                ),
                (
                    "The branch already contains consecutive Analyst steps. "
                    "Repeating the same analysis would risk stagnation, so "
                    "the next action should extract new technical evidence."
                ),
                max(gain, 0.60),
            )

        if research_items and role == "analyst":
            repositories = (
                result.get("repositories", [])
                if isinstance(result, dict)
                else []
            )
            if isinstance(result, dict) and result.get("evaluated_by") == "opportunity_hunter":
                return (
                    "COMPLETE",
                    None,
                    None,
                    "Opportunity Hunter has completed the commercial refinement pass; retain the resulting opportunity package as the branch output.",
                    max(gain, 0.40),
                )
            return (
                "REFINE",
                "developer",
                (
                    "Perform implementation-level investigation of the "
                    "highest-priority research targets. Inspect architecture, "
                    "maturity, dependencies, security-sensitive components, "
                    "and technical feasibility. Do not repeat the prior "
                    "prioritization. "
                    f"Targets: {self.format_items((repositories or research_items)[:10])}. "
                    f"Analysis: {self.compact_context(result)}"
                ),
                "The Analyst has produced concrete research targets; the next step must extract new technical evidence.",
                max(gain, 0.60),
            )

        if research_items and role in {
            "researcher",
            "model_researcher",
        }:
            return (
                "CONTINUE",
                "analyst",
                (
                    "Analyze the concrete research candidates discovered "
                    "by the previous agent. Prioritize the strongest targets, "
                    "compare their technical relevance, and identify which "
                    "projects deserve deeper code/security investigation. "
                    f"Candidates discovered: {self.format_items(research_items[:10])}"
                ),
                (
                    "The previous research produced concrete projects or "
                    "repositories. The next rational step is structured "
                    "analysis instead of terminating the research branch."
                ),
                max(gain, 0.60),
            )

        # -------------------------------------------------
        # Technical review -> commercial opportunity
        # -------------------------------------------------
        # A Developer review is already the implementation-level evidence
        # gate. Do not fall back into Analyst target loops when no explicit
        # security finding was emitted; the product mission also requires
        # converting technically credible technologies into opportunities.
        if role == "developer" and isinstance(result, dict):
            technical_review = result.get("technical_review")
            existing_security_findings = self.extract_security_findings(result)
            if technical_review and not existing_security_findings:
                return (
                    "REFINE",
                    "opportunity_hunter",
                    (
                        "Translate the completed technical review into concrete "
                        "commercial opportunity dossiers. Identify target users, "
                        "problem signal, product thesis, validation experiment, "
                        "business model, moat, and uncertainties. "
                        f"Technical review: {self.compact_context(technical_review)}"
                    ),
                    "The Developer produced implementation-level evidence; the next step is commercial opportunity formation, not another generic target loop.",
                    max(gain, 0.50),
                )

        # -------------------------------------------------
        # Security findings
        # -------------------------------------------------

        security_findings = self.extract_security_findings(result)

        if security_findings:
            if role == "security_checker" and self.extract_opportunities(result):
                return (
                    "REFINE",
                    "opportunity_hunter",
                    (
                        "Translate the technically verified research into concrete commercial opportunities. "
                        "Assess the strongest product thesis, target users, deployment friction, and the next validation step. "
                        f"Opportunities: {self.format_items(self.extract_opportunities(result)[:10])}. "
                        f"Security context: {self.compact_context(security_findings[:10])}"
                    ),
                    "Security verification is complete enough to evaluate the commercial implications of the discovered technology.",
                    max(gain, 0.45),
                )

            if role == "security_checker":
                return (
                    "REFINE",
                    "developer",
                    (
                        "Perform a deeper technical investigation of the "
                        "security findings identified by the previous "
                        "Security Checker. Reproduce or technically validate "
                        "the suspected issue, inspect the affected "
                        "implementation, and determine concrete impact. "
                        f"Findings: {self.format_items(security_findings[:10])}. "
                        f"Previous result: {self.compact_context(result)}"
                    ),
                    (
                        "The branch already contains a Security Checker "
                        "step. Repeating security verification without new "
                        "technical evidence would risk stagnation, so the "
                        "next step is implementation-level investigation."
                    ),
                    max(gain, 0.70),
                )

            # SecurityChecker consumes Developer's technical_review.
            # Never create Analyst/Researcher -> SecurityChecker directly.
            if role == "developer" and isinstance(result, dict):
                if result.get("opportunities"):
                    return (
                        "REFINE",
                        "opportunity_hunter",
                        (
                            "Refine the product hypotheses using the completed technical review. "
                            f"Opportunities: {self.format_items(result.get('opportunities')[:10])}. "
                            f"Technical review: {self.compact_context(result.get('technical_review'))}"
                        ),
                        "Technical feasibility evidence is available; the next step is commercial validation rather than another generic code pass.",
                        max(gain, 0.45),
                    )
                technical_review = result.get("technical_review")

                if technical_review:
                    return (
                        "VERIFY",
                        "security_checker",
                        (
                            "Verify and deepen the following security findings "
                            "using the completed Developer technical review. "
                            f"Findings: {self.format_items(security_findings[:10])}. "
                            f"Technical review: "
                            f"{self.compact_context(technical_review)}"
                        ),
                        (
                            "The Developer produced a technical_review and "
                            "concrete security findings. Security Checker is "
                            "now contractually ready to validate them."
                        ),
                        max(gain, 0.70),
                    )

            # Findings from Analyst or another upstream role must first
            # pass through Developer so SecurityChecker receives the
            # required technical_review contract.
            repositories = (
                result.get("repositories", [])
                if isinstance(result, dict)
                else []
            )

            if repositories:
                return (
                    "REFINE",
                    "developer",
                    (
                        "Perform a focused technical investigation of the "
                        "repositories associated with the security findings. "
                        "Inspect repository structure, implementation quality, "
                        "security-sensitive components, and technical feasibility. "
                        f"Security findings: "
                        f"{self.format_items(security_findings[:10])}. "
                        f"Repositories: "
                        f"{self.format_items(repositories[:10])}. "
                        f"Previous evidence: {self.compact_context(result)}"
                    ),
                    (
                        "Security findings were produced before a Developer "
                        "technical review existed. Developer must establish "
                        "the technical evidence contract before SecurityChecker "
                        "can run."
                    ),
                    max(gain, 0.70),
                )


        # -------------------------------------------------
        # Research hypotheses / experiments
        # -------------------------------------------------

        hypotheses = self.extract_hypotheses(result)

        if hypotheses:
            return (
                "ESCALATE",
                "model_researcher",
                (
                    "Investigate the following hypotheses and experiments "
                    "using the previous evidence. "
                    f"Hypotheses: {self.format_items(hypotheses[:10])}. "
                    f"Context: {self.compact_context(result)}"
                ),
                (
                    "The result contains unresolved hypotheses or experiments "
                    "that require deeper model/research investigation."
                ),
                max(gain, 0.60),
            )

        # -------------------------------------------------
        # Opportunities
        # -------------------------------------------------

        opportunities = self.extract_opportunities(result)

        if opportunities:
            if role == "opportunity_hunter" and not result.get("validation_results"):
                return (
                    "REFINE",
                    "validator",
                    (
                        "Execute the validation experiment selected for each "
                        "opportunity based on its unresolved uncertainty. Use the "
                        "requested validation_type (technical, adoption, dependency, "
                        "security, or commercial), prefer authoritative evidence, "
                        "and record observed metrics plus remaining uncertainty. "
                        f"Opportunities: {self.format_items(opportunities[:10])}."
                    ),
                    "A commercial dossier is a hypothesis until a concrete validation experiment is executed.",
                    max(gain, 0.55),
                )

            if role == "validator":
                return (
                    "REFINE",
                    "opportunity_hunter",
                    (

[executed on device: Gensyn2.play2go.cloud (8c50b8b0-eb42-4eae-ab08-e02c92862037)]
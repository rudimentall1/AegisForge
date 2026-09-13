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
STAGNATION_LIMIT = 3


class AutonomousPlanner:

    def __init__(self, queue=None):
        self.queue = queue or TaskQueue()

    # =========================================================
    # RESULT NORMALIZATION
    # =========================================================

    @staticmethod
    def parse_result(raw):
        if raw is None:
            return None

        if isinstance(raw, (dict, list)):
            return raw

        try:
            return json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return raw

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
    def extract_security_findings(cls, result):
        return cls._items(
            result,
            (
                "security_findings",
                "vulnerabilities",
                "findings",
                "technical_review",
            ),
        )[:10]

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
        # Security findings
        # -------------------------------------------------

        security_findings = self.extract_security_findings(result)

        if security_findings:
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

            return (
                "VERIFY",
                "security_checker",
                (
                    "Verify and deepen the following security findings. "
                    f"Findings: {self.format_items(security_findings[:10])}. "
                    f"Previous result: {self.compact_context(result)}"
                ),
                (
                    "The result contains concrete security findings that "
                    "require verification before the branch can terminate."
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
            if role == "opportunity_hunter":
                return (
                    "REFINE",
                    "analyst",
                    (
                        "Independently analyze and prioritize the "
                        "opportunities discovered by the previous "
                        "Opportunity Hunter. Determine which opportunities "
                        "are technically credible, commercially meaningful, "
                        "and worth deeper investigation. "
                        f"Opportunities: {self.format_items(opportunities[:10])}. "
                        f"Context: {self.compact_context(result)}"
                    ),
                    (
                        "The branch already contains an Opportunity Hunter "
                        "step. Repeating the same role would risk stagnation, "
                        "so the opportunities should now be independently "
                        "analyzed and prioritized."
                    ),
                    max(gain, 0.40),
                )

            return (
                "REFINE",
                "opportunity_hunter",
                (
                    "Refine and validate the following opportunities. "
                    f"Opportunities: {self.format_items(opportunities[:10])}. "
                    f"Context: {self.compact_context(result)}"
                ),
                (
                    "The result contains concrete opportunities that can "
                    "be refined and validated."
                ),
                max(gain, 0.25),
            )

        # -------------------------------------------------
        # Multiple concrete targets
        # -------------------------------------------------

        targets = self.extract_targets(result)

        if len(targets) >= 2:

            history = self.branch_history(
                task,
                getattr(self, "_planning_tasks", {}),
            )

            recent_roles = self.recent_roles(
                history,
                limit=4,
            )

            # Avoid blindly repeating Analyst after Analyst.
            # Move from prioritization into technical inspection.
            if (
                role == "analyst"
                and self.repeated_role(recent_roles, 2)
            ):
                return (
                    "REFINE",
                    "developer",
                    (
                        "Perform a focused technical investigation of the "
                        "highest-priority targets identified by the previous "
                        "analysis. Inspect repository structure, implementation "
                        "quality, security-sensitive components, and technical "
                        "feasibility. "
                        f"Targets: {self.format_items(targets[:10])}. "
                        f"Previous evidence: {self.compact_context(result)}"
                    ),
                    (
                        "The branch already contains consecutive Analyst "
                        "steps. Additional prioritization would risk repeating "
                        "the same work, so the next step should extract new "
                        "technical information."
                    ),
                    max(gain, 0.60),
                )

            return (
                "CONTINUE",
                "analyst",
                (
                    "Analyze and prioritize these concrete targets: "
                    f"{self.format_items(targets[:10])}. "
                    f"Previous evidence: {self.compact_context(result)}"
                ),
                (
                    "Multiple concrete targets were identified and require "
                    "structured analysis."
                ),
                max(gain, 0.50),
            )

        # -------------------------------------------------
        # One concrete target
        # -------------------------------------------------

        if len(targets) == 1:
            return (
                "REFINE",
                "developer",
                (
                    "Perform a focused technical investigation of the "
                    f"identified target: {targets[0]}. "
                    f"Previous evidence: {self.compact_context(result)}"
                ),
                (
                    "A concrete target was identified and now requires "
                    "technical inspection."
                ),
                max(gain, 0.50),
            )

        # -------------------------------------------------
        # Generic useful research
        # -------------------------------------------------

        if gain >= 0.50:
            return (
                "CONTINUE",
                "researcher",
                (
                    "Deepen the previous investigation. Identify the most "
                    "important unresolved question, missing evidence, "
                    "contradiction, or assumption. Perform focused research "
                    "and return new evidence rather than repeating the "
                    "previous result."
                ),
                (
                    "The result contains useful information but no concrete "
                    "target was extracted. A focused follow-up investigation "
                    "may produce additional evidence."
                ),
                gain,
            )

        # -------------------------------------------------
        # Nothing useful
        # -------------------------------------------------

        return (
            "ABORT",
            None,
            None,
            (
                "The completed task produced no useful information "
                "for further autonomous work."
            ),
            0.0,
        )

    def choose_next(self, task):
        """
        Final decision gate for autonomous transitions.

        The raw decision engine selects the next action based on the
        actual result. This outer gate prevents immediate same-role
        transitions from creating autonomous branch stagnation.
        """

        decision = self._choose_next_raw(task)

        if not isinstance(decision, tuple) or len(decision) != 5:
            return decision

        decision_name, next_role, description, reason, gain = decision
        current_role = task.get("role")

        if (
            current_role
            and next_role
            and current_role == next_role
        ):
            history = self.branch_history(
                task,
                getattr(self, "_planning_tasks", {}),
            )

            recent_roles = self.recent_roles(
                history,
                limit=4,
            )

            alternate = self.alternate_role(
                current_role,
                recent_roles,
            )

            if alternate:
                return (
                    "REFINE",
                    alternate,
                    (
                        "Do not repeat the current worker role. "
                        "Perform a different type of investigation that "
                        "extracts new information from the current result. "
                        f"Previous planned role: {current_role}. "
                        f"Current evidence: {self.compact_context(task.get('result'))}"
                    ),
                    (
                        f"Blocked same-role transition "
                        f"{current_role} -> {next_role}. "
                        "The autonomous branch must change investigation "
                        "type to avoid stagnation."
                    ),
                    max(float(gain), 0.40),
                )

            return (
                "ABORT",
                None,
                None,
                (
                    f"Blocked same-role transition "
                    f"{current_role} -> {next_role}, and no safe "
                    "alternate worker role was available."
                ),
                0.0,
            )

        return decision

    def _load_tasks(self):
        rows = self.queue.all_tasks()

        tasks = {}

        for row in rows:
            (
                task_id,
                description,
                status,
                role,
                parent_task_id,
                raw_result,
                planner_decision,
                planner_decided_at,
                information_gain,
                fingerprint,
            ) = row

            tasks[task_id] = {
                "id": task_id,
                "description": description,
                "status": status,
                "role": role,
                "parent_task_id": parent_task_id,
                "result": self.parse_result(raw_result),
                "planner_decision": planner_decision,
                "planner_decided_at": planner_decided_at,
                "information_gain": information_gain,
                "fingerprint": fingerprint,
            }

        return tasks

    @staticmethod
    def _children(tasks):
        children = {}

        for task in tasks.values():
            parent = task["parent_task_id"]

            if parent:
                children.setdefault(parent, []).append(task)

        return children

    def _existing_fingerprints(self, tasks):
        result = set()

        for task in tasks.values():
            if task["fingerprint"]:
                result.add(task["fingerprint"])
                continue

            result.add(
                self.fingerprint(
                    task["parent_task_id"],
                    task["role"],
                    task["description"],
                )
            )

        return result

    # =========================================================
    # BRANCH HISTORY
    # =========================================================

    def branch_history(self, task, tasks):
        """
        Return the ancestor chain for the current task.

        The newest task is first. This lets the Master understand
        what has already happened in the current research branch instead
        of making decisions from the current result alone.
        """
        history = []
        current = task

        while current:
            history.append(current)

            parent_id = current.get("parent_task_id")

            if not parent_id:
                break

            current = tasks.get(parent_id)

        return history

    @staticmethod
    def recent_roles(history, limit=4):
        return [
            item.get("role")
            for item in history[:limit]
            if item.get("role")
        ]

    @staticmethod
    def alternate_role(current_role, recent_roles):
        """
        Select a different worker role when the planner would otherwise
        repeat the same role immediately.

        Preference is given to roles that extract a genuinely different
        type of information from the current branch.
        """
        preferences = {
            "analyst": [
                "developer",
                "security_checker",
                "researcher",
                "opportunity_hunter",
            ],
            "developer": [
                "security_checker",
                "analyst",
                "researcher",
                "opportunity_hunter",
            ],
            "security_checker": [
                "developer",
                "analyst",
                "researcher",
                "opportunity_hunter",
            ],
            "opportunity_hunter": [
                "analyst",
                "developer",
                "researcher",
                "model_researcher",
            ],
            "researcher": [
                "analyst",
                "developer",
                "security_checker",
                "opportunity_hunter",
            ],
            "model_researcher": [
                "analyst",
                "researcher",
                "developer",
                "security_checker",
            ],
        }

        recent = set(recent_roles or [])

        for role in preferences.get(current_role, []):
            if role != current_role and role not in recent:
                return role

        for role in preferences.get(current_role, []):
            if role != current_role:
                return role

        return None

    @staticmethod
    def same_role_transition(current_role, next_role, recent_roles):
        """
        Prevent autonomous branches from repeatedly routing to the
        same worker role without introducing a new type of work.

        Repeating a role is allowed only when the branch history does
        not already show that role as the immediate previous step.
        """
        if not current_role or not next_role:
            return False

        if current_role != next_role:
            return False

        if not recent_roles:
            return False

        return recent_roles[0] == current_role

    @staticmethod
    def repeated_role(recent_roles, count=2):
        """
        Return True when the same role appears consecutively
        at the head of the branch history.
        """
        if len(recent_roles) < count:
            return False

        return all(
            role == recent_roles[0]
            for role in recent_roles[:count]
        )

    # =========================================================
    # PLANNER
    # =========================================================

    def plan(self):
        tasks = self._load_tasks()
        self._planning_tasks = tasks

        # ---------------------------------------------------------
        # DAG INTEGRITY GUARD
        # ---------------------------------------------------------
        # Active tasks must never depend on a missing parent.
        # Historical failed orphan tasks remain preserved for audit.
        active_orphans = self.queue.active_orphans()

        if active_orphans:
            print(
                f"[MASTER] DAG INTEGRITY ERROR: "
                f"{len(active_orphans)} active orphan task(s) detected",
                flush=True,
            )

            for orphan in active_orphans:
                (
                    task_id,
                    description,
                    status,
                    role,
                    parent_task_id,
                ) = orphan

                print(
                    f"[MASTER] ORPHAN "
                    f"task={task_id} "
                    f"role={role} "
                    f"status={status} "
                    f"missing_parent={parent_task_id}",
                    flush=True,
                )

            return {
                "created": 0,
                "decisions": [],
                "state": "DAG_ERROR",
                "active_orphans": len(active_orphans),
            }

        if not tasks:
            return {
                "created": 0,
                "decisions": [],
                "state": "EMPTY",
            }

        # MAX_TASKS_PER_GOAL limits creation of new tasks only.
        # Existing completed tasks must still be evaluated by Master.

        children = self._children(tasks)
        fingerprints = self._existing_fingerprints(tasks)

        created = 0
        decisions = []

        for task in tasks.values():

            # Only successful tasks can produce a new decision.
            if not self.successful(task):
                continue

            # Persistent decision prevents repeated processing.
            if task["planner_decision"]:
                continue

            # A completed task without a persistent planner decision
            # must always be evaluated by Master, even if it already has
            # children created by an earlier planner version.
            decision = self.choose_next(task)

            # Backward compatibility: choose_next() may return either
            # the native decision dict or the compact tuple form.
            if isinstance(decision, tuple):
                if len(decision) != 5:
                    raise RuntimeError(
                        f"Invalid planner decision tuple length: {len(decision)}"
                    )

                decision = {
                    "decision": decision[0],
                    "role": decision[1],
                    "description": decision[2],
                    "reason": decision[3],
                    "information_gain": decision[4],
                    "tasks": [],
                }

                # Compact tuple form represents one next task.
                if decision["role"] and decision["description"]:
                    decision["tasks"] = [
                        (
                            decision["role"],
                            decision["description"],
                        )
                    ]

            if not isinstance(decision, dict):
                raise RuntimeError(
                    f"Invalid planner decision type: {type(decision).__name__}"
                )

            decision_name = decision.get(
                "decision",
                "ABORT",
            )

            if decision_name not in DECISIONS:
                decision_name = "ABORT"

            gain = float(
                decision.get(
                    "information_gain",
                    0.0,
                )
            )

            task_fp = self.fingerprint(
                task["parent_task_id"],
                task["role"],
                task["description"],
            )

            # Persist Master decision BEFORE creating children.
            self.queue.mark_planner_decision(
                task["id"],
                decision_name,
                gain,
                task_fp,
            )

            record = {
                "task_id": task["id"],
                "role": task["role"],
                "decision": decision_name,
                "reason": decision.get("reason", ""),
                "information_gain": gain,
            }

            decisions.append(record)

            print(
                f"[MASTER] DECISION "
                f"task={task['id']} "
                f"role={task['role']} "
                f"decision={decision_name} "
                f"gain={gain:.2f} "
                f"reason={decision.get('reason', '')}",
                flush=True,
            )

            if decision_name in {
                "COMPLETE",
                "ABORT",
            }:
                continue

            for child_role, description in decision.get(
                "tasks",
                [],
            ):

                if len(tasks) + created >= MAX_TASKS_PER_GOAL:
                    break

                child_fp = self.fingerprint(
                    task["id"],
                    child_role,
                    description,
                )

                if child_fp in fingerprints:
                    print(
                        f"[MASTER] DUPLICATE SKIPPED "
                        f"parent={task['id']} "
                        f"role={child_role}",
                        flush=True,
                    )
                    continue

                child_id = self.queue.add(
                    description=description,
                    role=child_role,
                    parent_task_id=task["id"],
                )

                fingerprints.add(child_fp)
                created += 1

                print(
                    f"[MASTER] NEW TASK "
                    f"parent={task['id']} "
                    f"role={child_role} "
                    f"id={child_id}",
                    flush=True,
                )

        return {
            "created": created,
            "decisions": decisions,
            "state": "OK",
        }


class MasterOrchestrator:

    def __init__(self):
        self.queue = TaskQueue()
        self.planner = AutonomousPlanner(self.queue)

    def bootstrap(self):
        rows = self.queue.all_tasks()

        if rows:
            return False

        task_id = self.queue.add(
            description="Find promising Web3 security projects",
            role="researcher",
        )

        print(
            f"[MASTER] BOOTSTRAP "
            f"role=researcher "
            f"id={task_id}",
            flush=True,
        )

        return True

    def show_state(self):
        rows = self.queue.all_tasks()

        if not rows:
            print(
                "[MASTER] STATE empty",
                flush=True,
            )
            return

        statuses = Counter()
        roles = Counter()
        decisions = Counter()

        for row in rows:
            (
                _,
                _,
                status,
                role,
                _,
                _,
                planner_decision,
                _,
                _,
                _,
            ) = row

            statuses[status] += 1

            if role:
                roles[role] += 1

            if planner_decision:
                decisions[planner_decision] += 1

        status_text = " ".join(
            f"{k}={v}"
            for k, v in sorted(statuses.items())
        )

        role_text = " ".join(
            f"{k}={v}"
            for k, v in sorted(roles.items())
        )

        decision_text = " ".join(
            f"{k}={v}"
            for k, v in sorted(decisions.items())
        )

        print(
            f"[MASTER] STATE "
            f"{status_text} "
            f"total={len(rows)} "
            f"roles=[{role_text}] "
            f"decisions=[{decision_text}]",
            flush=True,
        )

    def run(self):
        print(
            "[MASTER] Autonomous Decision Engine v3 started",
            flush=True,
        )

        while True:
            try:
                self.bootstrap()

                result = self.planner.plan()

                if result.get("created"):
                    print(
                        f"[MASTER] PLANNER "
                        f"created={result['created']}",
                        flush=True,
                    )

                self.show_state()

            except Exception as exc:
                print(
                    f"[MASTER] ERROR "
                    f"{type(exc).__name__}: {exc}",
                    flush=True,
                )

            time.sleep(15)


if __name__ == "__main__":
    MasterOrchestrator().run()

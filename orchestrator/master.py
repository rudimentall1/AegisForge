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


# ---------------------------------------------------------
# AUTONOMOUS WORKFLOW
# ---------------------------------------------------------
#
# The Master does NOT continuously seed the same global tasks.
#
# Instead:
#
#   Researcher
#       ↓
#     Analyst
#       ↓
#   ┌───┼───────────────┐
#   ↓   ↓               ↓
# Developer Security  Opportunity
#   │       │
#   └───────┘
#
# Every child task is attached to its parent through
# parent_task_id.
#
# The Worker automatically passes the parent's result
# into the child task.
# ---------------------------------------------------------

WORKFLOW = {
    "researcher": [
        (
            "analyst",
            "Analyze the Web3 security projects discovered by the researcher",
        ),
    ],

    "analyst": [
        (
            "developer",
            "Inspect the code and technical implementation of the analyzed Web3 projects",
        ),
        (
            "opportunity_hunter",
            "Identify practical opportunities, useful projects, and potential commercial value from the analysis",
        ),
    ],

    "developer": [
        (
            "security_checker",
            "Perform a defensive security review of the technically inspected project",
        ),
    ],

    "security_checker": [],
    "opportunity_hunter": [],
}

ROOT_ROLE = "researcher"

ROOT_DESCRIPTION = (
    "Find promising Web3 security projects"
)


class MasterOrchestrator:

    def __init__(self):
        self.queue = TaskQueue()

    # -----------------------------------------------------
    # HELPERS
    # -----------------------------------------------------

    @staticmethod
    def parse_result(raw_result):
        """
        queue.all_tasks() returns the raw JSON result string.
        Convert it into a Python object when possible.
        """
        if raw_result is None:
            return None

        if isinstance(raw_result, (dict, list)):
            return raw_result

        try:
            return json.loads(raw_result)
        except (TypeError, json.JSONDecodeError):
            return raw_result

    @staticmethod
    def result_is_successful(status, result):
        """
        A parent must be completed and have a real result.
        Error results are not expanded.
        """
        if status != "completed":
            return False

        if result is None:
            return False

        if isinstance(result, dict):
            if result.get("error"):
                return False

            error_type = result.get("error_type")
            if error_type:
                return False

        return True

    # -----------------------------------------------------
    # BOOTSTRAP
    # -----------------------------------------------------

    def bootstrap(self):
        """
        Create exactly ONE root task if the queue is empty.

        This is the only place where a root task is created.
        After that, the system evolves through parent/child
        dependencies.
        """
        rows = self.queue.all_tasks()

        if rows:
            return False

        task_id = self.queue.add(
            description=ROOT_DESCRIPTION,
            role=ROOT_ROLE,
        )

        print(
            f"[MASTER] BOOTSTRAP "
            f"role={ROOT_ROLE} "
            f"id={task_id}: "
            f"{ROOT_DESCRIPTION}",
            flush=True,
        )

        return True

    # -----------------------------------------------------
    # PLANNER
    # -----------------------------------------------------

    def plan(self):
        """
        Inspect completed tasks and create their next-stage
        children.

        Deduplication is based on:

            parent_task_id + child_role

        Therefore the same workflow can never accidentally
        generate duplicate children on every polling cycle.
        """
        rows = self.queue.all_tasks()

        if not rows:
            self.bootstrap()
            return

        # -------------------------------------------------
        # Build indexes
        # -------------------------------------------------

        tasks = {}

        children_by_parent = {}

        for row in rows:
            (
                task_id,
                description,
                status,
                role,
                parent_task_id,
                raw_result,
            ) = row

            result = self.parse_result(raw_result)

            tasks[task_id] = {
                "id": task_id,
                "description": description,
                "status": status,
                "role": role,
                "parent_task_id": parent_task_id,
                "result": result,
            }

            if parent_task_id:
                children_by_parent.setdefault(
                    parent_task_id,
                    []
                ).append(row)

        created = 0

        # -------------------------------------------------
        # Examine every completed task
        # -------------------------------------------------

        for task_id, task in tasks.items():

            role = task["role"]

            if role not in WORKFLOW:
                continue

            if not self.result_is_successful(
                task["status"],
                task["result"],
            ):
                continue

            next_stages = WORKFLOW[role]

            if not next_stages:
                continue

            existing_children = children_by_parent.get(
                task_id,
                []
            )

            existing_roles = {
                child[3]
                for child in existing_children
            }

            # ---------------------------------------------
            # Create missing children
            # ---------------------------------------------

            for child_role, description in next_stages:

                if child_role in existing_roles:
                    continue

                child_id = self.queue.add(
                    description=description,
                    role=child_role,
                    parent_task_id=task_id,
                )

                existing_roles.add(child_role)
                created += 1

                print(
                    f"[MASTER] PLANNED "
                    f"parent={task_id} "
                    f"role={child_role} "
                    f"id={child_id}: "
                    f"{description}",
                    flush=True,
                )

        if created > 0:
            print(
                f"[MASTER] PLAN: created {created} child task(s)",
                flush=True,
            )

    # -----------------------------------------------------
    # STATE
    # -----------------------------------------------------

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

        for row in rows:
            task_id, description, status, role, parent, result = row

            statuses[status] += 1

            if role:
                roles[role] += 1

        state_text = " ".join(
            f"{status}={count}"
            for status, count in sorted(statuses.items())
        )

        role_text = " ".join(
            f"{role}={count}"
            for role, count in sorted(roles.items())
        )

        print(
            f"[MASTER] STATE "
            f"{state_text} "
            f"total={len(rows)}",
            flush=True,
        )

    # -----------------------------------------------------
    # MAIN LOOP
    # -----------------------------------------------------

    def run(self):
        print(
            "[MASTER] Autonomous Orchestrator started",
            flush=True,
        )

        print(
            "[MASTER] Workflow: "
            "researcher -> analyst -> "
            "developer/security_checker/opportunity_hunter",
            flush=True,
        )

        while True:

            try:
                self.bootstrap()
                self.plan()
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

import os
import sys
import time

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from shared.queue import TaskQueue


ROLES = {
    "researcher": "Find promising Web3 security projects",
    "analyst": "Analyze promising Web3 security projects",
    "developer": "Inspect code and technical implementation of promising projects",
    "security_checker": "Check security risks and vulnerabilities in promising projects",
    "opportunity_hunter": "Find practical opportunities and potential value in promising projects",
}


class MasterOrchestrator:
    def __init__(self):
        self.queue = TaskQueue()

    def existing_workflows(self):
        """
        Returns descriptions of all tasks already known to the system.
        Completed/failed/running tasks are intentionally included.
        """
        rows = self.queue.all_tasks()

        return {
            description
            for _, description, _ in rows
        }

    def seed_tasks(self):
        existing = self.existing_workflows()
        added = 0

        for role, description in ROLES.items():

            if description in existing:
                print(
                    f"[MASTER] EXISTS role={role}: {description}",
                    flush=True,
                )
                continue

            task_id = self.queue.add(
                description=description,
                role=role,
            )

            existing.add(description)
            added += 1

            print(
                f"[MASTER] CREATED "
                f"role={role} "
                f"id={task_id}: "
                f"{description}",
                flush=True,
            )

        if added == 0:
            print(
                "[MASTER] No new role tasks needed",
                flush=True,
            )
        else:
            print(
                f"[MASTER] Created {added} role task(s)",
                flush=True,
            )

    def show_state(self):
        rows = self.queue.all_tasks()

        states = {}
        roles = {}

        for _, _, status in rows:
            states[status] = states.get(status, 0) + 1

        for role, description in ROLES.items():
            matching = [
                row
                for row in rows
                if row[1] == description
            ]

            if matching:
                roles[role] = matching[-1][2]
            else:
                roles[role] = "not_created"

        print(
            "[MASTER] STATE "
            + " ".join(
                f"{status}={count}"
                for status, count in sorted(states.items())
            )
            + f" total={len(rows)}",
            flush=True,
        )

        for role, status in roles.items():
            print(
                f"[MASTER] ROLE {role}: {status}",
                flush=True,
            )

    def run(self):
        print(
            "[MASTER] Orchestrator started",
            flush=True,
        )

        while True:
            self.seed_tasks()
            self.show_state()

            time.sleep(30)


if __name__ == "__main__":
    MasterOrchestrator().run()

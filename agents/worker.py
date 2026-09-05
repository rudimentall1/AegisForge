import json
import socket
import os
import sys
import traceback

from shared.queue import TaskQueue
from shared.task import Task
from shared.memory import Memory

from agents.researcher.agent import Researcher
from agents.analyst.agent import Analyst
from agents.developer.agent import Developer
from agents.security_checker.agent import SecurityChecker
from agents.opportunity_hunter.agent import OpportunityHunter


WORKFLOW_ID = "web3-security-pipeline-v1"

AGENTS = {
    "researcher": Researcher,
    "analyst": Analyst,
    "developer": Developer,
    "security_checker": SecurityChecker,
    "opportunity_hunter": OpportunityHunter,
}

SUCCESS_STATUSES = {
    "researcher": "researched",
    "analyst": "analyzed",
    "developer": "developed",
    "security_checker": "security_checked",
    "opportunity_hunter": "opportunities_found",
}


class Worker:
    def __init__(self, role: str):
        if role not in AGENTS:
            raise ValueError(
                f"Unknown role: {role}. "
                f"Available: {', '.join(AGENTS)}"
            )

        self.role = role
        self.worker_id = (
            f"{role}-worker-{socket.gethostname()}-{os.getpid()}"
        )

        self.queue = TaskQueue()
        self.memory = Memory()

        self.agent = AGENTS[role]()

    def run_once(self):
        task_row = self.queue.claim(
            self.worker_id,
            role=self.role,
        )

        if not task_row:
            print(
                f"[{self.worker_id}] "
                f"NO AVAILABLE TASKS FOR ROLE={self.role}",
                flush=True,
            )
            return False

        task_id = task_row[0]
        description = task_row[1]
        parent_task_id = task_row[8]

        print(
            f"[{self.worker_id}] "
            f"CLAIMED {task_id} ROLE={self.role}",
            flush=True,
        )

        try:
            parent_result = None

            if parent_task_id:
                parent_result = self.queue.get_result(parent_task_id)

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
                    "workflow_id": WORKFLOW_ID,
                    "parent_task_id": parent_task_id,
                    "parent_result": parent_result,
                },
                result=parent_result,
                status="running",
            )

            print(
                f"[{self.worker_id}] "
                f"ROLE={self.role} START: {description}",
                flush=True,
            )

            result = self.agent.run(task)

            print(
                f"[{self.worker_id}] DEBUG AFTER AGENT:",
                type(result),
                "task.result=",
                getattr(result, "result", "NO_RESULT"),
                flush=True,
            )

            # Agents may return the Task object itself.
            # Persist only its serializable result payload.
            if isinstance(result, Task):
                result = result.result

            task.result = result
            task.status = SUCCESS_STATUSES[self.role]

            # Persist in Memory.
            self.memory.save_task(task)

            # Persist in Queue for the next pipeline stage.
            self.queue.finish(
                task_id,
                result=result,
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

    worker.run_once()


if __name__ == "__main__":
    main()

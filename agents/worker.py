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

    def run_once(self):
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

            task.result = result_value
            task.status = SUCCESS_STATUSES[self.role]

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

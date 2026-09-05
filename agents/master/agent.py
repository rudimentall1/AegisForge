import uuid

from shared.task import Task
from shared.memory import Memory
from agents.researcher.agent import Researcher
from agents.checker.agent import Checker


class Master:
    def __init__(self):
        self.researcher = Researcher()
        self.checker = Checker()
        self.memory = Memory()

    def run(self, description: str) -> Task:
        task = Task(
            task_id=str(uuid.uuid4()),
            description=description,
        )

        print(f"[MASTER] Created task: {task.task_id}")

        self.memory.save_task(task)

        task = self.researcher.run(task)
        print(f"[RESEARCHER] Status: {task.status}")

        self.memory.save_task(task)

        task = self.checker.run(task)
        print(f"[CHECKER] Status: {task.status}")

        self.memory.save_task(task)

        return task

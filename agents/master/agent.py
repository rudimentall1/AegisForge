import uuid

from shared.task import Task
from shared.memory import Memory
from shared.queue import TaskQueue


class Master:

    def __init__(self):
        self.memory = Memory()
        self.queue = TaskQueue()

    def create_pipeline(self, description: str):
        """
        Create the autonomous AegisForge pipeline.

        DAG:

            researcher
                |
              analyst
              /     \
        developer   opportunity_hunter
            |
        security_checker

        SecurityChecker depends on Developer because it requires
        technical_review.
        """

        root_id = str(uuid.uuid4())

        root = Task(
            task_id=root_id,
            description=description,
            status="queued",
        )

        self.memory.save_task(root)

        print(f"[MASTER] Created root task: {root_id}", flush=True)

        # -----------------------------------------------------
        # 1. RESEARCHER
        # -----------------------------------------------------

        researcher_id = self.queue.add(
            description="Find promising Web3 security projects",
            role="researcher",
            parent_task_id=root_id,
        )

        print(
            f"[MASTER] researcher task: {researcher_id}",
            flush=True,
        )

        # -----------------------------------------------------
        # 2. ANALYST
        # -----------------------------------------------------

        analyst_id = self.queue.add(
            description=(
                "Analyze the Web3 security projects discovered "
                "by the researcher"
            ),
            role="analyst",
            parent_task_id=researcher_id,
        )

        print(
            f"[MASTER] analyst task: {analyst_id}",
            flush=True,
        )

        # -----------------------------------------------------
        # 3. DEVELOPER
        #
        # Developer receives Analyst result and produces
        # technical_review.
        # -----------------------------------------------------

        developer_id = self.queue.add(
            description=(
                "Inspect the code and technical implementation "
                "of the analyzed Web3 projects"
            ),
            role="developer",
            parent_task_id=analyst_id,
        )

        print(
            f"[MASTER] developer task: {developer_id}",
            flush=True,
        )

        # -----------------------------------------------------
        # 4. SECURITY CHECKER
        #
        # IMPORTANT:
        # SecurityChecker must receive Developer result because
        # it requires technical_review.
        # -----------------------------------------------------

        security_id = self.queue.add(
            description=(
                "Perform a defensive security review of the "
                "technically inspected Web3 projects"
            ),
            role="security_checker",
            parent_task_id=developer_id,
        )

        print(
            f"[MASTER] security_checker task: {security_id}",
            flush=True,
        )

        # -----------------------------------------------------
        # 5. OPPORTUNITY HUNTER
        #
        # OpportunityHunter receives Analyst result.
        # -----------------------------------------------------

        opportunity_id = self.queue.add(
            description=(
                "Identify practical opportunities, useful projects, "
                "and potential commercial value from the analysis"
            ),
            role="opportunity_hunter",
            parent_task_id=analyst_id,
        )

        print(
            f"[MASTER] opportunity_hunter task: {opportunity_id}",
            flush=True,
        )

        print(
            "[MASTER] Pipeline created successfully",
            flush=True,
        )

        return {
            "root_id": root_id,
            "researcher_id": researcher_id,
            "analyst_id": analyst_id,
            "developer_id": developer_id,
            "security_id": security_id,
            "opportunity_id": opportunity_id,
        }

    def run(self, description: str):
        """
        Entry point for creating a new autonomous pipeline.
        """

        return self.create_pipeline(description)


if __name__ == "__main__":
    master = Master()

    master.run(
        "Find promising Web3 security projects for further research"
    )

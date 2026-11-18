from agents.source_researcher.deployment_intake import DeploymentIntakeResearcher


class DeepResearcher(DeploymentIntakeResearcher):
    """Dedicated read-only worker for newly discovered EVM deployments."""

    name = "deep_researcher"

    def run(self, task):
        task = super().run(task)
        if task.status == "source_researched":
            task.status = "deep_researched"
        if isinstance(task.result, dict):
            task.result["agent"] = self.name
        return task

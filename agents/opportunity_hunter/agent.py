from shared.task import Task


class OpportunityHunter:
    name = "opportunity_hunter"

    def run(self, task: Task) -> Task:
        task.status = "hunting_opportunities"

        try:
            result = task.result or {}
            repositories = result.get("repositories", [])

            opportunities = []

            for repo in repositories:
                stars = repo.get("stars", 0)
                language = repo.get("language")

                if stars >= 100 or language == "Solidity":
                    potential = "HIGH"
                elif stars >= 20:
                    potential = "MEDIUM"
                else:
                    potential = "LOW"

                opportunities.append({
                    "name": repo.get("name"),
                    "url": repo.get("url"),
                    "potential": potential,
                    "language": language,
                })

            task.result = {
                **result,
                "opportunities": opportunities,
                "evaluated_by": self.name,
            }

            task.status = "opportunities_found"

        except Exception as exc:
            task.status = "opportunity_hunt_failed"
            task.result = {
                "agent": self.name,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }

        return task

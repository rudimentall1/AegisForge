from shared.task import Task


class Analyst:
    name = "analyst"

    def run(self, task: Task) -> Task:
        task.status = "analyzing"

        try:
            result = task.result or {}

            repositories = result.get("repositories", [])

            analysis = []

            for repo in repositories:
                stars = repo.get("stars", 0)

                if stars >= 500:
                    priority = "HIGH"
                elif stars >= 100:
                    priority = "MEDIUM"
                else:
                    priority = "LOW"

                analysis.append({
                    "name": repo.get("name"),
                    "url": repo.get("url"),
                    "stars": stars,
                    "priority": priority,
                    "language": repo.get("language"),
                    "description": repo.get("description"),
                })

            task.result = {
                "agent": self.name,
                "task": task.description,
                "repositories": repositories,
                "analysis": analysis,
                "count": len(analysis),
            }

            task.status = "analyzed"

        except Exception as exc:
            task.status = "analysis_failed"
            task.result = {
                "agent": self.name,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }

        return task

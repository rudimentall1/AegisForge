from shared.task import Task


class Checker:
    name = "checker"

    def evaluate_repository(self, repo: dict) -> dict:
        score = 0
        reasons = []

        stars = repo.get("stars", 0)

        if stars >= 500:
            score += 3
            reasons.append("500+ GitHub stars")
        elif stars >= 100:
            score += 2
            reasons.append("100+ GitHub stars")
        elif stars >= 20:
            score += 1
            reasons.append("20+ GitHub stars")

        if repo.get("language") in ("Solidity", "TypeScript", "Python", "Go"):
            score += 1
            reasons.append("relevant development language")

        if repo.get("description"):
            score += 1
            reasons.append("has project description")

        if score >= 4:
            rating = "HIGH"
        elif score >= 2:
            rating = "MEDIUM"
        else:
            rating = "LOW"

        return {
            "name": repo.get("name"),
            "url": repo.get("url"),
            "stars": stars,
            "rating": rating,
            "score": score,
            "reasons": reasons,
        }

    def run(self, task: Task) -> Task:
        task.status = "checking"

        repositories = task.result.get("repositories", [])

        if not repositories:
            task.status = "rejected"
            task.result = {
                "agent": self.name,
                "verified": False,
                "reason": "No repositories to check",
            }
            return task

        evaluated = [
            self.evaluate_repository(repo)
            for repo in repositories
        ]

        evaluated.sort(
            key=lambda x: x["score"],
            reverse=True,
        )

        task.result["evaluated"] = evaluated
        task.result["checked_by"] = self.name
        task.result["verified"] = True
        task.status = "verified"

        return task

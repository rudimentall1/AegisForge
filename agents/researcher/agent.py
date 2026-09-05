from shared.task import Task
from shared.github_client import GitHubClient


class Researcher:
    name = "researcher"

    SEARCH_QUERIES = [
        "smart contract security",
        "solidity security",
        "web3 security",
        "defi security",
        "smart contract audit",
    ]

    def __init__(self):
        self.github = GitHubClient()

    def run(self, task: Task) -> Task:
        task.status = "researching"

        try:
            repositories = []
            seen = set()

            for query in self.SEARCH_QUERIES:
                print(f"[Researcher] SEARCH: {query}", flush=True)

                results = self.github.search_repositories(
                    query,
                    limit=5,
                )

                for repo in results:
                    name = repo.get("name")

                    if not name or name in seen:
                        continue

                    seen.add(name)
                    repositories.append(repo)

            if not repositories:
                raise RuntimeError(
                    "GitHub returned zero repositories across all research queries"
                )

            task.result = {
                "agent": self.name,
                "task": task.description,
                "repositories": repositories,
                "count": len(repositories),
                "queries": self.SEARCH_QUERIES,
                "source": "github",
            }

            task.status = "researched"

            print(
                f"[Researcher] FOUND {len(repositories)} repositories",
                flush=True,
            )

        except Exception as exc:
            task.status = "research_failed"

            task.result = {
                "agent": self.name,
                "task": task.description,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }

            print(
                f"[Researcher] ERROR: {type(exc).__name__}: {exc}",
                flush=True,
            )

        return task

from shared.task import Task
from shared.github_client import GitHubClient


class Researcher:
    name = "researcher"

    # AegisForge is a technology-intelligence engine, not a Web3-only
    # scanner. The task description can narrow this universe when a goal
    # explicitly names a domain; otherwise we run a small diversified scan.
    THEME_QUERIES = {
        "AI": [
            "AI agents autonomous agents",
            "LLM inference agent infrastructure",
        ],
        "Robotics": [
            "robotics autonomous robotics",
            "robot foundation model embodied AI",
        ],
        "Energy": [
            "energy storage battery software",
            "grid energy optimization distributed energy",
        ],
        "Security": [
            "AI agent security authorization",
            "agent identity machine identity workload identity",
            "software supply chain security SBOM provenance",
            "API security runtime authorization",
            "post quantum cryptography migration cryptographic inventory",
            "cybersecurity security automation",
        ],
        "Web3": [
            "web3 infrastructure blockchain",
            "smart contract security",
        ],
        "Infrastructure": [
            "developer infrastructure distributed systems",
            "edge computing infrastructure",
        ],
        "Privacy": [
            "privacy cryptography zero knowledge",
            "confidential computing",
        ],
    }

    THEME_ALIASES = {
        "ai": "AI", "agent": "AI", "agents": "AI", "llm": "AI",
        "robot": "Robotics", "robotics": "Robotics", "embodied": "Robotics",
        "energy": "Energy", "battery": "Energy", "grid": "Energy",
        "security": "Security", "cybersecurity": "Security",
        "web3": "Web3", "blockchain": "Web3", "defi": "Web3", "solidity": "Web3",
        "infrastructure": "Infrastructure", "developer tools": "Infrastructure",
        "distributed systems": "Infrastructure", "edge": "Infrastructure",
        "privacy": "Privacy", "cryptography": "Privacy", "zk": "Privacy",
    }

    MAX_EXCLUDED_REPOSITORIES = 35

    @staticmethod
    def _rotation(description):
        marker = "Discovery rotation:"
        text = str(description or "")
        for line in text.splitlines():
            if marker in line:
                try:
                    return int(line.split(marker, 1)[1].strip())
                except ValueError:
                    break
        return 0

    @classmethod
    def _excluded_repositories(cls, description):
        marker = "Previously discovered repositories to skip:"
        text = str(description or "")
        for line in text.splitlines():
            if marker in line:
                raw = line.split(marker, 1)[1]
                return {
                    item.strip().lower()
                    for item in raw.split(",")
                    if item.strip()
                }
        return set()

    @staticmethod
    def _rotated_query(query, rotation, index):
        profiles = (
            "",
            "sort:updated",
            "sort:stars",
            "stars:10..10000 sort:stars",
            "pushed:>=2026-01-01 sort:updated",
            "stars:<100 sort:updated",
        )
        suffix = profiles[(rotation + index) % len(profiles)]
        return f"{query} {suffix}".strip()

    def __init__(self, github=None):
        self.github = github or GitHubClient()

    @classmethod
    def select_queries(cls, description):
        text = str(description or "").lower()
        themes = []
        for token, theme in cls.THEME_ALIASES.items():
            if token in text and theme not in themes:
                themes.append(theme)
        if not themes:
            # Diversification is deliberate: AegisForge should discover
            # cross-domain opportunities instead of repeatedly mining one niche.
            themes = ["AI", "Energy", "Robotics", "Security", "Infrastructure"]
        queries = []
        for theme in themes[:4]:
            queries.extend(cls.THEME_QUERIES[theme])
        return list(dict.fromkeys(queries))[:8]

    @staticmethod
    def _signal(repo, query):
        description = str(repo.get("description") or "").strip()
        stars = int(repo.get("stars") or 0)
        return {
            "name": repo.get("name"),
            "url": repo.get("url"),
            "description": description,
            "stars": stars,
            "language": repo.get("language"),
            "updated": repo.get("updated"),
            "discovery_query": query,
            "signal": "high" if stars >= 1000 else "medium" if stars >= 100 else "emerging",
        }

    def run(self, task: Task) -> Task:
        task.status = "researching"
        queries = self.select_queries(task.description)
        rotation = self._rotation(task.description)
        excluded = self._excluded_repositories(task.description)
        try:
            repositories = []
            seen = set()
            for index, query in enumerate(queries):
                rotated_query = self._rotated_query(query, rotation, index)
                for page in range(1, 6):
                    batch = self.github.search_repositories(
                        rotated_query,
                        page=page,
                    )
                    if not batch:
                        break

                    novel = []
                    for repo in batch:
                        name = str(repo.get("name") or "").lower()
                        if not name or name in excluded or name in seen:
                            continue
                        seen.add(name)
                        novel.append(repo)

                    repositories.extend(
                        self._signal(repo, rotated_query)
                        for repo in novel
                    )

                    if novel:
                        break

            repositories = repositories[:20]
            task.status = "researched"
            return task.complete({
                "count": len(repositories),
                "queries": queries,
                "rotation": rotation,
                "repositories": repositories,
                "summary": "Research completed with bounded pagination and cross-cycle exclusion.",
            })
        except Exception as exc:
            task.status = "failed"
            return task.fail(str(exc))

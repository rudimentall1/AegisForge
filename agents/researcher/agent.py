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
            "cybersecurity security automation",
            "application security vulnerability detection",
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

    def __init__(self):
        self.github = GitHubClient()

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
            signals = []

            for index, query in enumerate(queries):
                search_query = self._rotated_query(query, rotation, index)
                print(f"[Researcher] SEARCH: {search_query}", flush=True)
                for repo in self.github.search_repositories(search_query, limit=5):
                    name = str(repo.get("name") or "").strip()
                    if not name or name.lower() in excluded or name.lower() in seen:
                        continue
                    seen.add(name.lower())
                    repositories.append(repo)
                    signals.append(self._signal(repo, search_query))

            if not repositories:
                raise RuntimeError("GitHub returned zero repositories for research queries")

            task.result = {
                "agent": self.name,
                "task": task.description,
                "research_scope": "technology_intelligence",
                "repositories": repositories,
                "technology_signals": signals,
                "count": len(repositories),
                "queries": queries,
                "rotation": rotation,
                "excluded_count": len(excluded),
                "source": "github",
            }
            task.status = "researched"
            print(f"[Researcher] FOUND {len(repositories)} repositories across {len(queries)} queries", flush=True)
        except Exception as exc:
            task.status = "research_failed"
            task.result = {
                "agent": self.name,
                "task": task.description,
                "queries": queries,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
            print(f"[Researcher] ERROR: {type(exc).__name__}: {exc}", flush=True)
        return task

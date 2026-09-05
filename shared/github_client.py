import os
import sqlite3
import time
import requests

from pathlib import Path
from dotenv import load_dotenv


PROJECT_ROOT = Path("/opt/agent-farm")
DB_PATH = PROJECT_ROOT / "data" / "agent_farm.db"

load_dotenv(PROJECT_ROOT / ".env")


class GitHubClient:
    BASE_URL = "https://api.github.com"

    def __init__(self):
        self.token = os.getenv("GITHUB_TOKEN")

        if not self.token:
            raise RuntimeError("GITHUB_TOKEN is not configured")

        self.session = requests.Session()

        self.session.headers.update({
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "agent-farm/1.0",
        })

        self._init_cache()

    def _init_cache(self):
        self.db = sqlite3.connect(
            DB_PATH,
            timeout=30,
            check_same_thread=False,
        )

        self.db.execute("""
            CREATE TABLE IF NOT EXISTS github_cache (
                cache_key TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        """)

        self.db.commit()

    def search_repositories(
        self,
        query: str,
        limit: int = 5,
        cache_ttl: int = 3600,
    ):
        import json

        cache_key = f"repo_search:{query}:{limit}"

        cached = self.db.execute(
            """
            SELECT data, created_at
            FROM github_cache
            WHERE cache_key = ?
            """,
            (cache_key,),
        ).fetchone()

        now = int(time.time())

        if cached:
            data, created_at = cached

            if now - created_at < cache_ttl:
                print("[GitHub] CACHE HIT")
                return json.loads(data)

        print("[GitHub] API SEARCH:", query)

        response = self.session.get(
            f"{self.BASE_URL}/search/repositories",
            params={
                "q": query,
                "sort": "stars",
                "order": "desc",
                "per_page": limit,
            },
            timeout=20,
        )

        remaining = response.headers.get(
            "X-RateLimit-Remaining",
            "unknown",
        )

        print(
            f"[GitHub] HTTP {response.status_code} | "
            f"remaining={remaining}"
        )

        if response.status_code == 403:
            raise RuntimeError(
                "GitHub rate limit exceeded"
            )

        response.raise_for_status()

        items = []

        for repo in response.json().get("items", []):
            items.append({
                "name": repo.get("full_name"),
                "description": repo.get("description"),
                "stars": repo.get("stargazers_count", 0),
                "language": repo.get("language"),
                "url": repo.get("html_url"),
                "updated": repo.get("updated_at"),
            })

        self.db.execute(
            """
            INSERT OR REPLACE INTO github_cache
            (cache_key, data, created_at)
            VALUES (?, ?, ?)
            """,
            (
                cache_key,
                json.dumps(items, ensure_ascii=False),
                now,
            ),
        )

        self.db.commit()

        return items

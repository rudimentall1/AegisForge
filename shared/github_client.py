import os
import sqlite3
import time
import requests

from pathlib import Path
from dotenv import load_dotenv


PROJECT_ROOT = Path("/opt/agent-farm")
DB_PATH = PROJECT_ROOT / "data" / "agent_farm.db"

load_dotenv(PROJECT_ROOT / ".env", override=True)


class GitHubClient:
    BASE_URL = "https://api.github.com"
    CACHE_RETENTION_SECONDS = 7 * 24 * 60 * 60
    MAX_CACHE_ROWS = 500
    MAX_CACHE_ENTRY_BYTES = 256 * 1024

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

        self.db.execute("""
            CREATE TABLE IF NOT EXISTS github_rate_state (
                resource TEXT PRIMARY KEY,
                remaining INTEGER NOT NULL,
                reset_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_status INTEGER
            )
        """)

        self.db.commit()
        self._cleanup_cache()

    def _cleanup_cache(self, now=None):
        now = int(time.time()) if now is None else int(now)
        cutoff = now - self.CACHE_RETENTION_SECONDS

        self.db.execute(
            "DELETE FROM github_cache WHERE created_at < ?",
            (cutoff,),
        )
        self.db.execute(
            """
            DELETE FROM github_cache
            WHERE cache_key IN (
                SELECT cache_key
                FROM github_cache
                ORDER BY created_at DESC, cache_key DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (self.MAX_CACHE_ROWS,),
        )
        self.db.commit()

    def _rate_state(self, resource="core"):
        row = self.db.execute(
            """
            SELECT remaining, reset_at, updated_at, last_status
            FROM github_rate_state
            WHERE resource = ?
            """,
            (resource,),
        ).fetchone()

        if not row:
            return None

        return {
            "remaining": int(row[0]),
            "reset_at": int(row[1]),
            "updated_at": int(row[2]),
            "last_status": row[3],
        }

    def _rate_blocked(self, resource="core"):
        import time

        state = self._rate_state(resource)

        if not state:
            return False

        now = int(time.time())

        if (
            state["remaining"] <= 0
            and state["reset_at"] > now
        ):
            return True

        return False

    def _update_rate_state(self, response):
        import time

        resource = (
            response.headers.get(
                "X-RateLimit-Resource"
            )
            or "core"
        )

        remaining = response.headers.get(
            "X-RateLimit-Remaining"
        )

        reset_at = response.headers.get(
            "X-RateLimit-Reset"
        )

        if remaining is None or reset_at is None:
            return

        try:
            remaining = int(remaining)
            reset_at = int(reset_at)
        except ValueError:
            return

        self.db.execute(
            """
            INSERT OR REPLACE INTO github_rate_state
            (resource, remaining, reset_at, updated_at, last_status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                resource,
                remaining,
                reset_at,
                int(time.time()),
                response.status_code,
            ),
        )

        self.db.commit()

    def _rate_error(self, response):
        import time

        remaining = response.headers.get(
            "X-RateLimit-Remaining",
            "unknown",
        )

        reset = response.headers.get(
            "X-RateLimit-Reset",
            "unknown",
        )

        resource = response.headers.get(
            "X-RateLimit-Resource",
            "core",
        )

        message = None

        try:
            message = response.json().get(
                "message"
            )
        except Exception:
            pass

        now = int(time.time())

        try:
            reset_int = int(reset)
        except (TypeError, ValueError):
            reset_int = 0

        if (
            remaining == "0"
            and reset_int > now
        ):
            cooldown = (
                reset_int - now
            )
        else:
            cooldown = 0

        return (
            "GitHub API unavailable: "
            f"HTTP {response.status_code}; "
            f"resource={resource}; "
            f"remaining={remaining}; "
            f"reset={reset}; "
            f"cooldown={cooldown}s; "
            f"message={message}"
        )

    def _cache_get(self, cache_key, cache_ttl):
        import json

        row = self.db.execute(
            """
            SELECT data, created_at
            FROM github_cache
            WHERE cache_key = ?
            """,
            (cache_key,),
        ).fetchone()

        if not row:
            return None

        data, created_at = row

        if int(time.time()) - created_at >= cache_ttl:
            return None

        return json.loads(data)

    def _cache_put(self, cache_key, data):
        import json

        encoded = json.dumps(data, ensure_ascii=False)
        if len(encoded.encode("utf-8")) > self.MAX_CACHE_ENTRY_BYTES:
            self._cleanup_cache()
            return False

        self.db.execute(
            """
            INSERT OR REPLACE INTO github_cache
            (cache_key, data, created_at)
            VALUES (?, ?, ?)
            """,
            (
                cache_key,
                encoded,
                int(time.time()),
            ),
        )
        self.db.commit()
        self._cleanup_cache()
        return True

    def get_json(
        self,
        url,
        params=None,
        cache_ttl=3600,
        timeout=30,
    ):
        import json

        query_key = json.dumps(
            params or {},
            sort_keys=True,
            ensure_ascii=False,
        )

        cache_key = f"json:{url}:{query_key}"

        cached = self._cache_get(
            cache_key,
            cache_ttl,
        )

        if cached is not None:
            print(
                f"[GitHub] CACHE HIT: {url}",
                flush=True,
            )
            return cached

        if self._rate_blocked("core"):
            state = self._rate_state("core")

            raise RuntimeError(
                "GitHub API cooldown active: "
                f"remaining={state['remaining']}; "
                f"reset={state['reset_at']}"
            )

        response = self.session.get(
            url,
            params=params,
            timeout=timeout,
        )

        self._update_rate_state(response)

        remaining = response.headers.get(
            "X-RateLimit-Remaining",
            "unknown",
        )

        print(
            f"[GitHub] HTTP {response.status_code} | "
            f"remaining={remaining} | {url}",
            flush=True,
        )

        if response.status_code in (403, 429):
            raise RuntimeError(
                self._rate_error(response)
            )

        if response.status_code == 404:
            return None

        response.raise_for_status()

        data = response.json()

        self._cache_put(
            cache_key,
            data,
        )

        return data

    def search_repositories(
        self,
        query: str,
        limit: int = 5,
        cache_ttl: int = 3600,
    ):
        params = {
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": limit,
        }

        print(
            "[GitHub] API SEARCH:",
            query,
            flush=True,
        )

        data = self.get_json(
            f"{self.BASE_URL}/search/repositories",
            params=params,
            cache_ttl=cache_ttl,
            timeout=20,
        )

        if not data:
            return []

        items = []

        for repo in data.get("items", []):
            items.append({
                "name": repo.get("full_name"),
                "description": repo.get("description"),
                "stars": repo.get(
                    "stargazers_count",
                    0,
                ),
                "language": repo.get("language"),
                "url": repo.get("html_url"),
                "updated": repo.get("updated_at"),
            })

        return items

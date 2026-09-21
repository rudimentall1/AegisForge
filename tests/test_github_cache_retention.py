import sqlite3
import time

import shared.github_client as github_client


def make_client(tmp_path):
    db_path = tmp_path / "github.sqlite"
    github_client.DB_PATH = db_path
    client = github_client.GitHubClient.__new__(github_client.GitHubClient)
    client.db = sqlite3.connect(db_path)
    client.db.execute("""
        CREATE TABLE github_cache (
            cache_key TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    client.db.commit()
    return client


def test_cache_cleanup_removes_expired_and_excess(tmp_path):
    client = make_client(tmp_path)
    now = int(time.time())
    old = now - client.CACHE_RETENTION_SECONDS - 1
    rows = [(f"k{i}", "{}", now - i) for i in range(510)]
    rows.append(("expired", "{}", old))
    client.db.executemany("INSERT INTO github_cache VALUES (?, ?, ?)", rows)
    client.db.commit()

    client._cleanup_cache(now=now)

    count = client.db.execute("SELECT count(*) FROM github_cache").fetchone()[0]
    assert count == client.MAX_CACHE_ROWS
    assert client.db.execute(
        "SELECT 1 FROM github_cache WHERE cache_key = 'expired'"
    ).fetchone() is None

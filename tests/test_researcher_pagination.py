from agents.researcher.agent import Researcher
from shared.task import Task


class FakeGitHub:
    def __init__(self):
        self.calls = []

    def search_repositories(self, query, limit=5, cache_ttl=3600, page=1):
        self.calls.append((query, page))
        if page == 1:
            return [
                {"name": "old/a", "description": "old", "stars": 100, "language": "Python", "url": "u1", "updated": "now"},
                {"name": "old/b", "description": "old", "stars": 90, "language": "Python", "url": "u2", "updated": "now"},
            ]
        if page == 2:
            return [
                {"name": "new/a", "description": "new", "stars": 80, "language": "Python", "url": "u3", "updated": "now"},
            ]
        return []


def test_researcher_paginates_when_first_page_is_exhausted():
    fake = FakeGitHub()
    researcher = Researcher(github=fake)

    task = Task(
        task_id="test-1",
        description="Discover promising AI agent technologies" + chr(10)
        + "Previously discovered repositories to skip: old/a,old/b",
    )

    result = researcher.run(task)

    assert task.status == "researched"
    assert result.result["count"] == 1
    assert result.result["repositories"][0]["name"] == "new/a"
    assert any(page == 2 for _, page in fake.calls)


def test_researcher_does_not_pay_for_extra_pages_when_page_is_novel():
    fake = FakeGitHub()

    def search(query, limit=5, cache_ttl=3600, page=1):
        fake.calls.append((query, page))
        if page != 1:
            return []
        suffix = str(len(fake.calls))
        return [{
            "name": "new/" + suffix,
            "description": "new",
            "stars": 80,
            "language": "Python",
            "url": "u" + suffix,
            "updated": "now",
        }]

    fake.search_repositories = search
    researcher = Researcher(github=fake)

    task = Task(task_id="test-2", description="AI agents")
    result = researcher.run(task)

    assert result.result["count"] == 2
    assert fake.calls
    assert all(page == 1 for _, page in fake.calls)

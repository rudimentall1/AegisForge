import pytest

import shared.queue as queue_module
from shared.queue import TaskQueue


@pytest.fixture
def queue(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "DB_PATH", tmp_path / "queue.db")
    instance = TaskQueue()
    yield instance
    instance.db.close()


def test_create_human_review_is_idempotent_per_open_case(queue):
    first = queue.create_human_review("case-a", "all branches terminal")
    repeated = queue.create_human_review("case-a", "all branches terminal")
    different = queue.create_human_review("case-a", "deadline_exceeded:round-1", task_id="task-2")
    repeated_different = queue.create_human_review("case-a", "deadline_exceeded:round-1", task_id="task-3")

    assert repeated == first
    assert different != first
    assert repeated_different == different
    rows = queue.list_human_reviews()
    assert len(rows) == 2
    by_reason = {row["reason"]: row for row in rows}
    assert by_reason["all branches terminal"]["id"] == first
    assert by_reason["all branches terminal"]["task_id"] is None
    assert by_reason["deadline_exceeded:round-1"]["id"] == different
    assert by_reason["deadline_exceeded:round-1"]["task_id"] == "task-2"


def test_list_human_reviews_filters_by_status(queue):
    open_id = queue.create_human_review("case-a", "needs review")
    resolved_id = queue.create_human_review("case-b", "needs review")
    assert queue.resolve_human_review(resolved_id, "Reviewed; no further action")

    assert [item["id"] for item in queue.list_human_reviews("OPEN")] == [open_id]
    resolved = queue.list_human_reviews("RESOLVED")
    assert [item["id"] for item in resolved] == [resolved_id]


def test_resolve_human_review_changes_status_once(queue):
    review_id = queue.create_human_review("case-a", "all branches terminal")

    assert queue.resolve_human_review(review_id, "Continue with a human-approved new hypothesis")
    assert queue.list_human_reviews("OPEN") == []
    record = queue.list_human_reviews("RESOLVED")[0]
    assert record["status"] == "RESOLVED"
    assert record["resolution"] == "Continue with a human-approved new hypothesis"
    assert record["resolved_at"]
    assert not queue.resolve_human_review(review_id, "second resolution")


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"case_id": "", "reason": "reason"}, "human_review_case_id_required"),
        ({"case_id": "case-a", "reason": " "}, "human_review_reason_required"),
    ],
)
def test_create_human_review_rejects_missing_required_values(queue, kwargs, message):
    with pytest.raises(ValueError, match=message):
        queue.create_human_review(**kwargs)


def test_resolve_human_review_rejects_empty_resolution(queue):
    review_id = queue.create_human_review("case-a", "all branches terminal")
    with pytest.raises(ValueError, match="human_review_resolution_required"):
        queue.resolve_human_review(review_id, " ")

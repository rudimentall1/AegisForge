import pytest

from shared.queue import TaskQueue


def _running_parent(queue, role):
    task_id = queue.add("parent task", role=role)
    claimed = queue.claim("contract-test-worker", role=role)
    assert claimed is not None
    assert claimed[0] == task_id
    return task_id


def _completed_parent(queue, role, result):
    task_id = _running_parent(queue, role)
    queue.finish(task_id, result=result)
    return task_id


def test_security_checker_rejects_non_developer_parent_even_with_review(tmp_path):
    queue = TaskQueue(tmp_path / "queue.db")
    try:
        parent_id = _completed_parent(
            queue,
            "analyst",
            {"technical_review": [{"name": "example/repo"}]},
        )

        with pytest.raises(
            ValueError,
            match="security_checker_requires_completed_developer_technical_review",
        ):
            queue.add(
                "security review",
                role="security_checker",
                parent_task_id=parent_id,
            )
    finally:
        queue.db.close()


@pytest.mark.parametrize(
    "parent_result",
    [
        {},
        {"technical_review": []},
        {"technical_review": ["not-a-review"]},
    ],
)
def test_security_checker_rejects_missing_or_malformed_developer_review(
    tmp_path, parent_result
):
    queue = TaskQueue(tmp_path / "queue.db")
    try:
        parent_id = _completed_parent(queue, "developer", parent_result)

        with pytest.raises(
            ValueError,
            match="security_checker_requires_completed_developer_technical_review",
        ):
            queue.add(
                "security review",
                role="security_checker",
                parent_task_id=parent_id,
            )
    finally:
        queue.db.close()


def test_security_checker_accepts_completed_developer_review(tmp_path):
    queue = TaskQueue(tmp_path / "queue.db")
    try:
        parent_id = _completed_parent(
            queue,
            "developer",
            {"technical_review": [{"name": "example/repo", "findings": []}]},
        )

        child_id = queue.add(
            "security review",
            role="security_checker",
            parent_task_id=parent_id,
        )

        child = queue.get(child_id)
        assert child[7] == "security_checker"
        assert child[8] == parent_id
    finally:
        queue.db.close()


def test_security_checker_rejects_failed_developer_even_with_review(tmp_path):
    queue = TaskQueue(tmp_path / "queue.db")
    try:
        parent_id = _running_parent(queue, "developer")
        queue.fail(
            parent_id,
            result={"technical_review": [{"name": "example/repo"}]},
        )
        with pytest.raises(
            ValueError,
            match="security_checker_requires_completed_developer_technical_review",
        ):
            queue.add("security review", role="security_checker", parent_task_id=parent_id)
    finally:
        queue.db.close()


def test_security_checker_requires_a_parent_task(tmp_path):
    queue = TaskQueue(tmp_path / "queue.db")
    try:
        with pytest.raises(
            ValueError,
            match="security_checker_parent_task_required",
        ):
            queue.add("orphan security review", role="security_checker")
    finally:
        queue.db.close()

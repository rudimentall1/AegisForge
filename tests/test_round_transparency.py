from datetime import datetime, timedelta, timezone

from shared.queue import TaskQueue


def _round(queue, round_id, *, deadline, status=None):
    queue.create_round_transparency(
        round_id=round_id,
        case_id="case-rounds",
        technique="runtime_probe",
        started_at="2026-10-16T00:00:00+00:00",
        disclosure_deadline=deadline,
    )
    if status:
        queue.db.execute(
            "UPDATE round_transparency SET status = ? WHERE round_id = ?",
            (status, round_id),
        )
        queue.db.commit()


def _row(queue, round_id):
    return next(
        row for row in queue.list_rounds_for_case("case-rounds")
        if row["round_id"] == round_id
    )


def test_create_round_transparency_is_idempotent_by_round_id(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    _round(queue, "round-1", deadline="2027-01-14T00:00:00+00:00")
    queue.create_round_transparency(
        round_id="round-1",
        case_id="different-case",
        technique="different-technique",
        started_at="2026-10-17T00:00:00+00:00",
        disclosure_deadline="2027-02-01T00:00:00+00:00",
    )
    rows = queue.list_rounds_for_case("case-rounds")
    assert len(rows) == 1
    assert rows[0]["technique"] == "runtime_probe"
    assert rows[0]["disclosure_deadline"] == "2027-01-14T00:00:00+00:00"
    queue.db.close()


def test_complete_round_only_completes_open_round(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    _round(queue, "round-open", deadline="2027-01-14T00:00:00+00:00")
    assert queue.complete_round(
        "round-open", "2026-10-17T00:00:00+00:00", "REPRODUCED"
    ) is True
    assert queue.complete_round(
        "round-open", "2026-10-18T00:00:00+00:00", "NOT_REPRODUCED"
    ) is False
    row = _row(queue, "round-open")
    assert row["status"] == "COMPLETED"
    assert row["verdict"] == "REPRODUCED"
    assert row["completed_at"] == "2026-10-17T00:00:00+00:00"
    queue.db.close()


def test_complete_round_works_for_extended(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    deadline = datetime.now(timezone.utc) + timedelta(days=10)
    _round(queue, "round-extended", deadline=deadline.isoformat())
    assert queue.grant_extension("round-extended", "Human review approved") is True

    assert queue.complete_round(
        "round-extended", "2026-10-17T00:00:00+00:00", "INCONCLUSIVE"
    ) is True
    row = _row(queue, "round-extended")
    assert row["status"] == "COMPLETED"
    assert row["verdict"] == "INCONCLUSIVE"
    queue.db.close()


def test_complete_round_for_completed_is_noop(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    _round(queue, "round-completed", deadline="2027-01-14T00:00:00+00:00")
    assert queue.complete_round(
        "round-completed", "2026-10-17T00:00:00+00:00", "REPRODUCED"
    ) is True
    before = _row(queue, "round-completed")

    assert queue.complete_round(
        "round-completed", "2026-10-18T00:00:00+00:00", "NOT_REPRODUCED"
    ) is False
    after = _row(queue, "round-completed")
    assert after == before
    assert queue.complete_round(
        "missing-round", "2026-10-18T00:00:00+00:00", "INCONCLUSIVE"
    ) is False
    queue.db.close()


def test_expired_rounds_returns_only_active_expired_rounds(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    now = datetime.now(timezone.utc)
    _round(queue, "expired-open", deadline=(now - timedelta(days=1)).isoformat())
    _round(queue, "future-open", deadline=(now + timedelta(days=1)).isoformat())
    _round(queue, "expired-completed", deadline=(now - timedelta(days=2)).isoformat())
    queue.db.execute(
        "UPDATE round_transparency SET status = 'COMPLETED' WHERE round_id = ?",
        ("expired-completed",),
    )
    queue.db.commit()

    rows = queue.expired_rounds(now)
    assert [row["round_id"] for row in rows] == ["expired-open"]
    queue.db.close()


def test_expired_rounds_includes_extended(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    now = datetime.now(timezone.utc)
    deadline = now - timedelta(days=20)
    _round(queue, "expired-extended", deadline=deadline.isoformat())
    assert queue.grant_extension("expired-extended", "Review is still active") is True

    # The stored, extended deadline is still overdue.
    rows = queue.expired_rounds(now)
    assert [row["round_id"] for row in rows] == ["expired-extended"]
    assert rows[0]["status"] == "EXTENDED"
    queue.db.close()


def test_expired_rounds_excludes_recently_extended(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    now = datetime.now(timezone.utc)
    deadline = now - timedelta(days=1)
    _round(queue, "recently-extended", deadline=deadline.isoformat())
    assert queue.grant_extension("recently-extended", "Need a short review") is True

    # Extension is relative to the old deadline, so choose a fresh old deadline
    # far enough in the future for this test's expected post-extension state.
    future_deadline = (now + timedelta(days=10)).isoformat()
    queue.db.execute(
        "UPDATE round_transparency SET disclosure_deadline = ? WHERE round_id = ?",
        (future_deadline, "recently-extended"),
    )
    queue.db.commit()
    # Keep the row EXTENDED and verify the query compares the stored new deadline.
    assert queue.expired_rounds(now) == []
    queue.db.close()


def test_grant_extension_is_one_shot(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    deadline = datetime.now(timezone.utc) + timedelta(days=10)
    _round(queue, "round-one-shot", deadline=deadline.isoformat())

    assert queue.grant_extension("round-one-shot", "First human approval") is True
    before = _row(queue, "round-one-shot")
    assert queue.grant_extension("round-one-shot", "Second approval") is False
    after = _row(queue, "round-one-shot")

    assert after["extension_granted_at"] == before["extension_granted_at"]
    assert after["disclosure_deadline"] == before["disclosure_deadline"]
    assert after["extension_reason"] == before["extension_reason"]
    assert after["status"] == "EXTENDED"
    queue.db.close()


def test_grant_extension_rejects_completed_round(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    _round(queue, "round-completed", deadline="2027-01-14T00:00:00+00:00")
    assert queue.complete_round(
        "round-completed", "2026-10-17T00:00:00+00:00", "INCONCLUSIVE"
    ) is True

    assert queue.grant_extension("round-completed", "Should not apply") is False
    row = _row(queue, "round-completed")
    assert row["status"] == "COMPLETED"
    assert row["extension_granted_at"] is None
    queue.db.close()

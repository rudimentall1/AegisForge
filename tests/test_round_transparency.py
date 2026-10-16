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
    row = queue.list_rounds_for_case("case-rounds")[0]
    assert row["status"] == "COMPLETED"
    assert row["verdict"] == "REPRODUCED"
    assert row["completed_at"] == "2026-10-17T00:00:00+00:00"
    queue.db.close()


def test_expired_rounds_returns_only_open_expired_rounds(tmp_path):
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


def test_grant_extension_moves_deadline_and_sets_extended_status(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    deadline = datetime.now(timezone.utc) + timedelta(days=10)
    _round(queue, "round-extension", deadline=deadline.isoformat())

    assert queue.grant_extension("round-extension", "Evidence review in progress") is True
    row = queue.list_rounds_for_case("case-rounds")[0]
    new_deadline = datetime.fromisoformat(row["disclosure_deadline"])
    assert new_deadline == deadline + timedelta(days=14)
    assert row["status"] == "EXTENDED"
    assert row["extension_granted_at"] is not None
    assert row["extension_reason"] == "Evidence review in progress"
    assert queue.expired_rounds(datetime.now(timezone.utc)) == []
    queue.db.close()


def test_grant_extension_rejects_completed_round(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    _round(queue, "round-completed", deadline="2027-01-14T00:00:00+00:00")
    assert queue.complete_round(
        "round-completed", "2026-10-17T00:00:00+00:00", "INCONCLUSIVE"
    ) is True

    assert queue.grant_extension("round-completed", "Should not apply") is False
    row = queue.list_rounds_for_case("case-rounds")[0]
    assert row["status"] == "COMPLETED"
    assert row["extension_granted_at"] is None
    queue.db.close()

from datetime import datetime, timedelta, timezone

from shared.queue import TaskQueue


def _round(
    queue,
    round_id,
    *,
    case_id="case-rounds",
    deadline="2027-01-14T00:00:00+00:00",
    status=None,
):
    queue.create_round_transparency(
        round_id=round_id,
        case_id=case_id,
        technique="runtime_probe",
        started_at="2026-10-16T00:00:00+00:00",
        disclosure_deadline=deadline,
    )
    if status:
        queue.db.execute(
            "UPDATE round_transparency SET status = ? WHERE case_id = ? AND round_id = ?",
            (status, case_id, round_id),
        )
        queue.db.commit()


def _row(queue, round_id, case_id="case-rounds"):
    rows = queue.list_rounds_for_case(case_id)
    return next(row for row in rows if row["round_id"] == round_id)


def test_two_cases_same_round_id_create_separate_rows(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    _round(queue, "r1-source-pattern", case_id="profanity-round-test-1")
    _round(queue, "r1-source-pattern", case_id="profanity-round-test-2")

    first = queue.list_rounds_for_case("profanity-round-test-1")
    second = queue.list_rounds_for_case("profanity-round-test-2")
    assert len(first) == len(second) == 1
    assert first[0]["round_id"] == second[0]["round_id"] == "r1-source-pattern"
    assert first[0]["case_id"] == "profanity-round-test-1"
    assert second[0]["case_id"] == "profanity-round-test-2"
    queue.db.close()


def test_create_round_transparency_is_idempotent_by_case_and_round(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    _round(queue, "round-1")
    queue.create_round_transparency(
        round_id="round-1",
        case_id="case-rounds",
        technique="different-technique",
        started_at="2026-10-17T00:00:00+00:00",
        disclosure_deadline="2027-02-01T00:00:00+00:00",
    )
    rows = queue.list_rounds_for_case("case-rounds")
    assert len(rows) == 1
    assert rows[0]["technique"] == "runtime_probe"
    assert rows[0]["disclosure_deadline"] == "2027-01-14T00:00:00+00:00"
    queue.db.close()


def test_complete_round_scoped_by_case_and_round(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    _round(queue, "shared-round", case_id="case-one")
    _round(queue, "shared-round", case_id="case-two")

    assert queue.complete_round(
        "case-one", "shared-round", "2026-10-17T00:00:00+00:00", "REPRODUCED"
    ) is True
    assert _row(queue, "shared-round", "case-one")["status"] == "COMPLETED"
    assert _row(queue, "shared-round", "case-two")["status"] == "OPEN"
    queue.db.close()


def test_complete_round_only_completes_open_round(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    _round(queue, "round-open")
    assert queue.complete_round(
        "case-rounds", "round-open", "2026-10-17T00:00:00+00:00", "REPRODUCED"
    ) is True
    assert queue.complete_round(
        "case-rounds", "round-open", "2026-10-18T00:00:00+00:00", "NOT_REPRODUCED"
    ) is False
    row = _row(queue, "round-open")
    assert row["status"] == "COMPLETED"
    assert row["verdict"] == "REPRODUCED"
    assert row["completed_at"] == "2026-10-17T00:00:00+00:00"
    queue.db.close()


def test_complete_round_works_for_extended(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    deadline = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    _round(queue, "round-extended", deadline=deadline)
    assert queue.grant_extension("case-rounds", "round-extended", "Human review approved") is True

    assert queue.complete_round(
        "case-rounds", "round-extended", "2026-10-17T00:00:00+00:00", "INCONCLUSIVE"
    ) is True
    row = _row(queue, "round-extended")
    assert row["status"] == "COMPLETED"
    assert row["verdict"] == "INCONCLUSIVE"
    queue.db.close()


def test_complete_round_for_completed_is_noop(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    _round(queue, "round-completed")
    assert queue.complete_round(
        "case-rounds", "round-completed", "2026-10-17T00:00:00+00:00", "REPRODUCED"
    ) is True
    before = _row(queue, "round-completed")

    assert queue.complete_round(
        "case-rounds", "round-completed", "2026-10-18T00:00:00+00:00", "NOT_REPRODUCED"
    ) is False
    after = _row(queue, "round-completed")
    assert after == before
    assert queue.complete_round(
        "case-rounds", "missing-round", "2026-10-18T00:00:00+00:00", "INCONCLUSIVE"
    ) is False
    queue.db.close()


def test_expired_rounds_returns_only_active_expired_rounds(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    now = datetime.now(timezone.utc)
    _round(queue, "expired-open", deadline=(now - timedelta(days=1)).isoformat())
    _round(queue, "future-open", deadline=(now + timedelta(days=1)).isoformat())
    _round(queue, "expired-completed", deadline=(now - timedelta(days=2)).isoformat())
    queue.db.execute(
        "UPDATE round_transparency SET status = 'COMPLETED' WHERE case_id = ? AND round_id = ?",
        ("case-rounds", "expired-completed"),
    )
    queue.db.commit()

    rows = queue.expired_rounds(now)
    assert [row["round_id"] for row in rows] == ["expired-open"]
    queue.db.close()


def test_expired_rounds_includes_extended(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    now = datetime.now(timezone.utc)
    deadline = (now - timedelta(days=20)).isoformat()
    _round(queue, "expired-extended", deadline=deadline)
    assert queue.grant_extension("case-rounds", "expired-extended", "Review is still active") is True

    rows = queue.expired_rounds(now)
    assert [row["round_id"] for row in rows] == ["expired-extended"]
    assert rows[0]["status"] == "EXTENDED"
    queue.db.close()


def test_expired_rounds_excludes_recently_extended(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    now = datetime.now(timezone.utc)
    deadline = (now - timedelta(days=1)).isoformat()
    _round(queue, "recently-extended", deadline=deadline)
    assert queue.grant_extension("case-rounds", "recently-extended", "Need a short review") is True

    row = _row(queue, "recently-extended")
    assert row["status"] == "EXTENDED"
    assert datetime.fromisoformat(row["disclosure_deadline"]) > now
    assert queue.expired_rounds(now) == []
    queue.db.close()


def test_grant_extension_scoped_by_case_and_round(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    deadline = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    _round(queue, "shared-round", case_id="case-one", deadline=deadline)
    _round(queue, "shared-round", case_id="case-two", deadline=deadline)

    assert queue.grant_extension("case-one", "shared-round", "Approved") is True
    assert _row(queue, "shared-round", "case-one")["status"] == "EXTENDED"
    assert _row(queue, "shared-round", "case-two")["status"] == "OPEN"
    queue.db.close()


def test_grant_extension_is_one_shot(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    deadline = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    _round(queue, "round-one-shot", deadline=deadline)

    assert queue.grant_extension("case-rounds", "round-one-shot", "First human approval") is True
    before = _row(queue, "round-one-shot")
    assert queue.grant_extension("case-rounds", "round-one-shot", "Second approval") is False
    after = _row(queue, "round-one-shot")

    assert after["extension_granted_at"] == before["extension_granted_at"]
    assert after["disclosure_deadline"] == before["disclosure_deadline"]
    assert after["extension_reason"] == before["extension_reason"]
    assert after["status"] == "EXTENDED"
    queue.db.close()


def test_grant_extension_rejects_completed_round(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    _round(queue, "round-completed")
    assert queue.complete_round(
        "case-rounds", "round-completed", "2026-10-17T00:00:00+00:00", "INCONCLUSIVE"
    ) is True

    assert queue.grant_extension("case-rounds", "round-completed", "Should not apply") is False
    row = _row(queue, "round-completed")
    assert row["status"] == "COMPLETED"
    assert row["extension_granted_at"] is None
    queue.db.close()


def test_failed_round_has_no_verdict(tmp_path):
    queue = TaskQueue(db_path=tmp_path / "queue.sqlite")
    _round(queue, "failed-round")
    assert queue.fail_round(
        "case-rounds", "failed-round", "2026-10-17T00:00:00+00:00"
    ) is True
    row = _row(queue, "failed-round")
    assert row["status"] == "FAILED"
    assert row["verdict"] is None
    assert queue.fail_round(
        "case-rounds", "failed-round", "2026-10-18T00:00:00+00:00"
    ) is False
    queue.db.close()

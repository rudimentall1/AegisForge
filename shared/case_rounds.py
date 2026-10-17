"""Explicit, bounded continuation of an existing registered research case.

This command never resumes work automatically. An operator must supply the case
ID and --confirm-new-round. Each invocation creates one new root task and an
immutable round record while preserving the case's pinned target and evidence
history. It refuses to start while any task for the case is pending or running.
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone

from shared.queue import TaskQueue
from shared.research_case import CaseStatus, validate_task_binding


class CaseRoundError(ValueError):
    """A case round cannot safely be started."""


def start_case_round(queue: TaskQueue, case_id: str) -> dict:
    """Atomically enqueue one deliberate new round for a registered case."""
    if not isinstance(case_id, str) or not case_id.strip():
        raise CaseRoundError("case_id_required")

    db = queue.db
    try:
        db.execute("BEGIN IMMEDIATE")
        case = queue.get_research_case(case_id)
        if case is None:
            raise CaseRoundError("research_case_not_registered")
        if case.status not in {CaseStatus.READY, CaseStatus.RUNNING}:
            raise CaseRoundError(f"research_case_not_runnable:{case.status.value}")
        validate_task_binding(case, case_id)

        active = db.execute(
            """
            SELECT id, role, status FROM queue
            WHERE research_case_id = ? AND status IN ('pending', 'running')
            ORDER BY created_at LIMIT 1
            """,
            (case_id,),
        ).fetchone()
        if active:
            raise CaseRoundError(
                f"case_round_already_active:task={active[0]}:role={active[1]}:status={active[2]}"
            )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS research_case_rounds (
                round_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                round_number INTEGER NOT NULL,
                root_task_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                UNIQUE(case_id, round_number)
            )
            """
        )
        round_number = int(
            db.execute(
                "SELECT COALESCE(MAX(round_number), 0) + 1 "
                "FROM research_case_rounds WHERE case_id = ?",
                (case_id,),
            ).fetchone()[0]
        )
        # Include legacy roots in the sequence even if they predate this table.
        historical_roots = int(
            db.execute(
                """
                SELECT COUNT(*) FROM queue
                WHERE research_case_id = ? AND role = 'source_researcher'
                  AND parent_task_id IS NULL
                """,
                (case_id,),
            ).fetchone()[0]
        )
        round_number = max(round_number, historical_roots + 1)
        round_id = str(uuid.uuid4())
        root_task_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        description = (
            f"[CASE ROUND {round_number} run_id={round_id}] Continue registered "
            f"EVM Key Forensics case {case.case_id}. Target: "
            f"{case.target_repository}@{case.target_commit}. Approved scope: "
            f"{case.scope_url} (SHA-256 {case.scope_digest}). Hypothesis: "
            f"{case.hypothesis}. Re-evaluate prior evidence and identify a "
            f"materially distinct falsifiable next step. Preserve evidence continuity; "
            "do not repeat completed work without a documented reason. Use immutable "
            "public sources and local/synthetic experiments only. Do not execute "
            "live-network actions, handle wallet/key material, or mark a finding CONFIRMED."
        )
        # Keep the root's round identity in the queue row as well as the ledger.
        # The task and ledger row are committed atomically below.
        db.execute(
            """
            INSERT INTO queue
                (id, description, status, created_at, role, parent_task_id,
                 research_case_id, round_id)
            VALUES (?, ?, 'pending', ?, 'source_researcher', NULL, ?, ?)
            """,
            (
                root_task_id,
                queue._bounded_description(description),
                now,
                case_id,
                round_id,
            ),
        )
        db.execute(
            """
            INSERT INTO research_case_rounds
                (round_id, case_id, round_number, root_task_id, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (round_id, case_id, round_number, root_task_id, now),
        )
        db.commit()
        return {
            "status": "queued",
            "case_id": case_id,
            "round_number": round_number,
            "round_id": round_id,
            "root_task_id": root_task_id,
            "created_at": now,
        }
    except Exception:
        db.rollback()
        raise



def diagnose_case_state(queue: TaskQueue, case_id: str) -> dict:
    """Return a read-only, actionable lifecycle snapshot for one Research Case.

    State priority is active work, human-review block, terminal case, failed work,
    then idle awaiting explicit operator input. This function never mutates queue
    state or creates tasks.
    """
    if not isinstance(case_id, str) or not case_id.strip():
        raise CaseRoundError("case_id_required")

    case = queue.get_research_case(case_id)
    if case is None:
        return {
            "case_id": case_id,
            "state": "blocked",
            "reason": "research_case_not_registered",
            "counts": {"pending": 0, "running": 0, "completed": 0, "failed": 0},
            "open_reviews": 0,
        }

    rows = queue.db.execute(
        "SELECT status, COUNT(*) FROM queue WHERE research_case_id = ? GROUP BY status",
        (case_id,),
    ).fetchall()
    counts = {str(status): int(count) for status, count in rows}
    for status in ("pending", "running", "completed", "failed"):
        counts.setdefault(status, 0)

    open_reviews = int(queue.db.execute(
        "SELECT COUNT(*) FROM pending_human_review WHERE case_id = ? AND status = 'OPEN'",
        (case_id,),
    ).fetchone()[0])

    if counts["pending"] or counts["running"]:
        state, reason = "active", "case_has_active_tasks"
    elif open_reviews:
        state, reason = "blocked", "human_review_required"
    elif case.status in {
        CaseStatus.CONFIRMED,
        CaseStatus.REJECTED,
        CaseStatus.INCONCLUSIVE,
        CaseStatus.OUT_OF_SCOPE,
    }:
        state, reason = "terminal", f"research_case_terminal:{case.status.value}"
    elif counts["failed"]:
        state, reason = "blocked", "failed_tasks_require_operator_review"
    else:
        state, reason = "idle_awaiting_input", "explicit_operator_action_required"

    return {
        "case_id": case_id,
        "case_status": case.status.value,
        "state": state,
        "reason": reason,
        "counts": counts,
        "open_reviews": open_reviews,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", required=True, help="Existing immutable Research Case ID")
    parser.add_argument(
        "--confirm-new-round",
        action="store_true",
        help="Explicitly authorize creation of exactly one bounded research root",
    )
    args = parser.parse_args(argv)
    if not args.confirm_new_round:
        parser.error("starting a case round requires --confirm-new-round")

    queue = TaskQueue()
    try:
        result = start_case_round(queue, args.case_id)
    except (CaseRoundError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc)}, sort_keys=True))
        return 2
    finally:
        queue.db.close()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

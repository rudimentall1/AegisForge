import argparse
import json
import sys

from shared.outcome_proof import main as outcome_main
from shared.recovery_proof import main as recovery_main

TASK_ROLES = ("researcher", "analyst", "developer", "security_checker", "opportunity_hunter", "validator", "model_researcher")

def task_main(argv):
    from shared.queue import TaskQueue
    parser = argparse.ArgumentParser(prog="aegisforge tasks")
    sub = parser.add_subparsers(dest="command", required=True)
    submit = sub.add_parser("submit", help="submit a task to an existing worker")
    submit.add_argument("--role", required=True, choices=TASK_ROLES)
    submit.add_argument("description", help="task description; max 4096 bytes")
    submit.add_argument("--db", help=argparse.SUPPRESS)
    status = sub.add_parser("status", help="show task status")
    status.add_argument("task_id")
    status.add_argument("--db", help=argparse.SUPPRESS)
    result = sub.add_parser("result", help="show task result when available")
    result.add_argument("task_id")
    result.add_argument("--db", help=argparse.SUPPRESS)
    queue_cmd = sub.add_parser("queue", help="summarize queued work")
    queue_cmd.add_argument("--db", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    queue = TaskQueue(db_path=args.db)
    try:
        if args.command == "submit":
            if not args.description.strip():
                parser.error("description must not be empty")
            task_id = queue.add(args.description, role=args.role)
            print(json.dumps({"task_id": task_id, "status": "pending", "role": args.role}, indent=2))
            return 0
        if args.command == "status":
            row = queue.get(args.task_id)
            if row is None:
                print("NOT_FOUND")
                return 1
            keys = ("task_id", "description", "status", "worker", "created_at", "started_at", "finished_at", "role", "parent_task_id", "result", "capability_intent", "allow_failed_parent")
            print(json.dumps(dict(zip(keys, row)), indent=2, ensure_ascii=False, default=str))
            return 0
        if args.command == "result":
            row = queue.get(args.task_id)
            if row is None:
                print("NOT_FOUND")
                return 1
            value = queue.get_result(args.task_id)
            print(json.dumps({"task_id": args.task_id, "status": row[2], "result": value}, indent=2, ensure_ascii=False, default=str))
            return 0 if value is not None else 2
        total, statuses, roles, decisions = queue.summary()
        print(json.dumps({"total": total, "statuses": dict(statuses), "roles": dict(roles), "planner_decisions": dict(decisions)}, indent=2, ensure_ascii=False))
        return 0
    finally:
        queue.db.close()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "verify-recovery":
        raise SystemExit(recovery_main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "tasks":
        raise SystemExit(task_main(sys.argv[2:]))
    raise SystemExit(outcome_main(sys.argv[1:]))

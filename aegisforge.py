import argparse
import json
import sys

from shared.outcome_proof import main as outcome_main
from shared.recovery_proof import main as recovery_main

TASK_ROLES = ("researcher", "analyst", "developer", "security_checker", "opportunity_hunter", "validator", "model_researcher", "source_researcher", "crypto_analyst", "lab_runner")

def task_main(argv):
    from shared.queue import TaskQueue
    parser = argparse.ArgumentParser(prog="aegisforge tasks")
    sub = parser.add_subparsers(dest="command", required=True)
    submit = sub.add_parser("submit", help="submit a task to an existing worker")
    submit.add_argument("--role", required=True, choices=TASK_ROLES)
    submit.add_argument("--case-id", help="registered Research Case ID for forensic tasks")
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
    case_cmd = sub.add_parser("case", help="manage immutable research cases")
    case_sub = case_cmd.add_subparsers(dest="case_command", required=True)
    case_register = case_sub.add_parser("register", help="register a case from a JSON file")
    case_register.add_argument("json_file")
    case_register.add_argument("--db", help=argparse.SUPPRESS)
    case_show = case_sub.add_parser("show", help="show a registered case")
    case_show.add_argument("case_id")
    case_show.add_argument("--db", help=argparse.SUPPRESS)
    case_reviews = case_sub.add_parser("reviews", help="list pending human reviews")
    case_reviews.add_argument("--status", default="OPEN")
    case_reviews.add_argument("--db", help=argparse.SUPPRESS)
    case_resolve = case_sub.add_parser("resolve", help="resolve a pending human review")
    case_resolve.add_argument("review_id")
    case_resolve.add_argument("resolution")
    case_resolve.add_argument("--db", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    queue = TaskQueue(db_path=args.db)
    try:
        if args.command == "submit":
            from shared.research_case import CASE_REQUIRED_ROLES
            if not args.description.strip():
                parser.error("description must not be empty")
            if args.role in CASE_REQUIRED_ROLES and not args.case_id:
                parser.error(f"role {args.role!r} requires --case-id for a registered Research Case")
            task_id = queue.add(args.description, role=args.role, research_case_id=args.case_id)
            print(json.dumps({"task_id": task_id, "status": "pending", "role": args.role}, indent=2))
            return 0
        if args.command == "case":
            if args.case_command == "reviews":
                rows = queue.list_human_reviews(status=args.status)
                print(json.dumps({"reviews": rows, "count": len(rows)},
                                 indent=2, ensure_ascii=False, default=str))
                return 0
            if args.case_command == "resolve":
                ok = queue.resolve_human_review(args.review_id, args.resolution)
                print(json.dumps({
                    "review_id": args.review_id,
                    "resolved": bool(ok),
                    "resolution": args.resolution,
                }, indent=2, ensure_ascii=False))
                return 0 if ok else 1
            if args.case_command == "register":
                from pathlib import Path
                from shared.research_case import ResearchCase
                try:
                    payload = json.loads(Path(args.json_file).read_text(encoding="utf-8"))
                    case = ResearchCase(**payload)
                    case_id = queue.register_research_case(case)
                except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
                    print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
                    return 2
                print(json.dumps({"case_id": case_id, "status": case.status.value}, indent=2))
                return 0
            case = queue.get_research_case(args.case_id)
            if case is None:
                print("NOT_FOUND")
                return 1
            from dataclasses import asdict
            payload = asdict(case)
            payload["execution_mode"] = case.execution_mode.value
            payload["status"] = case.status.value
            print(json.dumps(payload, indent=2, ensure_ascii=False))
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

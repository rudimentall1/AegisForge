import json

from agents.master.agent import Master


def main():
    master = Master()

    task = master.run(
        "Find promising Web3 security projects for further research"
    )

    print("\n=== FINAL RESULT ===")
    print(json.dumps(
        {
            "task_id": task.task_id,
            "status": task.status,
            "result": task.result,
        },
        indent=2,
        ensure_ascii=False,
    ))


if __name__ == "__main__":
    main()

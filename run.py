from agents.master.agent import Master


def main():
    master = Master()

    result = master.run(
        "Find promising Web3 security projects, analyze them, evaluate opportunities and suggest development directions"
    )

    print("\n=== FINAL RESULT ===")

    print(result)


if __name__ == "__main__":
    main()

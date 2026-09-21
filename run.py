from agents.master.agent import Master


def main():
    master = Master()

    result = master.run(
        "Discover promising emerging technologies, analyze their technical maturity and security, identify commercial opportunities, and propose concrete product directions"
    )

    print("\n=== FINAL RESULT ===")

    print(result)


if __name__ == "__main__":
    main()

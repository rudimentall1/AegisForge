import sys

from shared.outcome_proof import main as outcome_main
from shared.recovery_proof import main as recovery_main


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "verify-recovery":
        raise SystemExit(recovery_main(sys.argv[2:]))
    raise SystemExit(outcome_main(sys.argv[1:]))

import logging
import re

from agents.config import RESCUE_WALLET_ADDRESS, RPC_ENDPOINTS


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [RESCUE] %(message)s",
)

RECIPIENT = RESCUE_WALLET_ADDRESS
NETWORKS = dict(RPC_ENDPOINTS)
_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def execute_rescue(chain: str, target_contract: str) -> bool:
    """Fail closed until a protocol-specific, owner-authorized rescue adapter exists.

    The previous implementation ignored target_contract and swept the EOA
    derived from a source-controlled fallback private key. That operation did
    not rescue assets from the target contract and is intentionally disabled.
    """
    chain_key = str(chain or "").strip().lower()
    if chain_key not in NETWORKS:
        logging.error("Rescue blocked: unsupported network %s", chain_key or "<empty>")
        return False
    if not isinstance(target_contract, str) or not _ADDRESS_RE.fullmatch(target_contract):
        logging.error("Rescue blocked: invalid target contract address")
        return False

    logging.critical(
        "Rescue blocked for %s on %s: protocol-specific owner authorization "
        "and a verified rescue adapter are required. No transaction was sent.",
        target_contract,
        chain_key,
    )
    return False


if __name__ == "__main__":
    import sys

    chain_arg = sys.argv[1] if len(sys.argv) > 1 else ""
    contract_arg = sys.argv[2] if len(sys.argv) > 2 else ""
    execute_rescue(chain_arg, contract_arg)

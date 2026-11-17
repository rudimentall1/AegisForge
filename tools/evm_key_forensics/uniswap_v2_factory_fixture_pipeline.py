"""Synthetic-only controls for the Uniswap V2 Factory source acceptance case."""


def synthetic_fee_setter_controls() -> dict:
    """Test a toy caller-equality predicate; this is not Solidity/EVM execution."""
    fee_to_setter = "synthetic-authorized-setter"
    authorized_caller = "synthetic-authorized-setter"
    unauthorized_caller = "synthetic-unprivileged-caller"

    def may_change_fee_to(caller: str) -> bool:
        return caller == fee_to_setter

    def may_rotate_setter(caller: str) -> bool:
        return caller == fee_to_setter

    controls = {
        "authorized_setter_can_change_fee_to": may_change_fee_to(authorized_caller),
        "unauthorized_caller_rejected_for_fee_to": not may_change_fee_to(unauthorized_caller),
        "authorized_setter_can_rotate_setter": may_rotate_setter(authorized_caller),
        "unauthorized_caller_rejected_for_setter_rotation": not may_rotate_setter(unauthorized_caller),
    }
    return {
        "stage": "synthetic_experiment",
        "status": "PASSED" if all(controls.values()) else "FAILED",
        "controls": controls,
        "model": "pure-python-fee-to-setter-equality-predicate",
        "uses_real_accounts": False,
        "solidity_compiled": False,
        "evm_executed": False,
        "rpc_used": False,
        "transactions_sent": False,
        "wallet_material_used": False,
        "interpretation": (
            "Only a toy Python equality predicate was exercised. This does not "
            "test the deployed Uniswap V2 Factory contract or its runtime behavior."
        ),
    }

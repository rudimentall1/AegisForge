from pathlib import Path

import agents.worker as worker


def test_worker_does_not_expose_legacy_host_poc_execution_pipeline():
    forbidden_symbols = (
        "analyze_contract_for_bounty",
        "run_foundry_poc_test",
        "process_target_contract",
        "run_slither_audit",
        "fetch_and_audit_contract",
        "fetch_contract_via_rpc",
        "send_telegram_alert",
    )
    for symbol in forbidden_symbols:
        assert not hasattr(worker, symbol)


def test_worker_source_contains_no_unisolated_legacy_poc_execution():
    source = Path(worker.__file__).read_text(encoding="utf-8")
    forbidden_fragments = (
        "forge test -vv",
        "OPENROUTER_API_KEY",
        "RED_TEAM_SYSTEM_PROMPT",
        "process_target_contract(",
        "fetch_and_audit_contract(",
    )
    for fragment in forbidden_fragments:
        assert fragment not in source
    assert "class Worker" in source
    assert "def main()" in source

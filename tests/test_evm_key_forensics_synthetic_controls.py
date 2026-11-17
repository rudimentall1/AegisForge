from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tools.evm_key_forensics.synthetic_control_experiment import (
    EXPERIMENT_ID,
    MAX_CANDIDATES,
    TARGET_SEED,
    run_controls,
)


def test_synthetic_control_experiment_has_expected_positive_and_negative_controls():
    result = run_controls()

    assert result["schema_version"] == 1
    assert result["experiment_id"] == EXPERIMENT_ID
    assert result["candidate_space"] == MAX_CANDIDATES
    assert result["overall_passed"] is True

    positive = result["controls"]["positive"]
    assert positive["expected"] == "target_found"
    assert positive["passed"] is True
    assert positive["matched_candidate"] == TARGET_SEED
    assert positive["attempts"] == TARGET_SEED + 1

    negative = result["controls"]["negative"]
    assert negative["expected"] == "target_not_found"
    assert negative["passed"] is True
    assert negative["matched_candidate"] is None
    assert negative["attempts"] == TARGET_SEED


def test_synthetic_control_experiment_explicitly_disclaims_historical_claims():
    result = run_controls()

    assert result["historical_profanity_code_executed"] is False
    assert result["historical_vulnerability_reproduced"] is False
    assert result["private_keys_derived"] is False
    assert result["public_keys_or_addresses_derived"] is False
    assert result["wallet_material_used"] is False
    assert result["network_access_used"] is False
    assert "no evidence" in result["interpretation"]


def test_synthetic_control_cli_emits_machine_readable_json():
    script = Path("tools/evm_key_forensics/synthetic_control_experiment.py")
    completed = subprocess.run(
        [sys.executable, str(script), "--pretty"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        shell=False,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["overall_passed"] is True
    assert result["controls"]["positive"]["passed"] is True
    assert result["controls"]["negative"]["passed"] is True

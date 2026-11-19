import json
import os
import re
import time
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from datetime import datetime, timezone


_TX_HASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")
_INCIDENT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_CENTS = Decimal("0.01")
_MIN_BOUNTY_RATE = Decimal("0.05")
_MAX_BOUNTY_RATE = Decimal("0.10")


def _money(value):
    return float(value.quantize(_CENTS, rounding=ROUND_HALF_UP))


def generate_whitehat_report(
    incident_id,
    chain,
    contract_address,
    vuln_type,
    severity,
    rescued_amount,
    tx_hash,
    *,
    reports_dir=None,
    rescue_receipt_verified=False,
    owner_authorized=False,
    bounty_agreed=False,
    bounty_rate=0.075,
):
    """Generate an advisory without claiming or settling an unverified rescue."""
    incident_id = str(incident_id)
    if not _INCIDENT_ID_RE.fullmatch(incident_id):
        raise ValueError("incident_id_invalid")

    try:
        amount = Decimal(str(rescued_amount))
        rate = Decimal(str(bounty_rate))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("report_amount_or_bounty_rate_invalid") from exc
    if not amount.is_finite() or amount < 0:
        raise ValueError("rescued_amount_invalid")
    if not rate.is_finite() or rate < _MIN_BOUNTY_RATE or rate > _MAX_BOUNTY_RATE:
        raise ValueError("bounty_rate_out_of_range")
    if not all(
        isinstance(flag, bool)
        for flag in (rescue_receipt_verified, owner_authorized, bounty_agreed)
    ):
        raise ValueError("rescue_and_bounty_flags_must_be_boolean")

    verified_tx = isinstance(tx_hash, str) and _TX_HASH_RE.fullmatch(tx_hash)
    rescue_confirmed = bool(
        rescue_receipt_verified
        and owner_authorized
        and verified_tx
    )
    if rescue_receipt_verified and owner_authorized and not verified_tx:
        raise ValueError("verified_rescue_requires_tx_hash")
    if bounty_agreed and not rescue_confirmed:
        raise ValueError("bounty_requires_verified_authorized_rescue")

    proposed_bounty = (
        (amount * rate).quantize(_CENTS, rounding=ROUND_HALF_UP)
        if rescue_confirmed
        else None
    )
    bounty_settlement = proposed_bounty if rescue_confirmed and bounty_agreed else Decimal("0")
    verified_rescued = amount if rescue_confirmed else Decimal("0")
    return_amount = (
        max(verified_rescued - bounty_settlement, Decimal("0"))
        if rescue_confirmed
        else Decimal("0")
    )
    status = (
        "RESCUED_AND_SECURED"
        if rescue_confirmed
        else "INCIDENT_DETECTED_RESPONSE_PENDING"
    )

    directory = Path(
        reports_dir
        or os.getenv("AEGISFORGE_REPORTS_DIR", "/opt/agent-farm/shared/reports")
    )
    directory.mkdir(parents=True, exist_ok=True)

    timestamp = time.time()
    timestamp_utc = datetime.now(timezone.utc).isoformat()
    report_data = {
        "report_version": "aegisforge.whitehat_advisory.v2",
        "incident_id": incident_id,
        "timestamp": timestamp,
        "timestamp_utc": timestamp_utc,
        "chain": str(chain),
        "target_contract": str(contract_address),
        "vulnerability": str(vuln_type),
        "severity": str(severity),
        "owner_authorized": bool(owner_authorized),
        "rescue_receipt_verified": bool(rescue_receipt_verified),
        "metrics": {
            "reported_amount_usd": _money(amount),
            "verified_rescued_usd": _money(verified_rescued),
            "proposed_bounty_rate": float(rate) if rescue_confirmed else None,
            "proposed_bounty_usd": _money(proposed_bounty) if proposed_bounty is not None else None,
            "bounty_agreed": bool(bounty_agreed),
            "bounty_settlement_usd": _money(bounty_settlement),
            "return_amount_usd": _money(return_amount),
        },
        "proof_of_rescue_tx": tx_hash if rescue_confirmed else None,
        "status": status,
    }

    if rescue_confirmed:
        response_statement = (
            "The report records an owner-authorized rescue with an independently "
            "verified transaction receipt."
        )
        tx_statement = f"- **Verified Rescue Transaction:** `{tx_hash}`"
        bounty_statement = (
            f"- **Proposed White-Hat Bounty ({float(rate) * 100:.2f}%):** "
            f"${_money(proposed_bounty):,.2f}"
        )
        settlement_statement = (
            f"- **Agreed Bounty Settlement:** ${_money(bounty_settlement):,.2f}"
            if bounty_agreed
            else "- **Bounty Agreement:** Not agreed; no bounty is deducted."
        )
    else:
        response_statement = (
            "No rescue is claimed in this report. A transaction hash or reported "
            "amount alone is not proof that assets were moved or secured."
        )
        tx_statement = "- **Verified Rescue Transaction:** None"
        bounty_statement = "- **Proposed White-Hat Bounty:** Not proposed until an authorized rescue is verified."
        settlement_statement = "- **Bounty Agreement:** None; no bounty is deducted."

    md_content = f"""# AegisForge White-Hat Security Advisory

**Incident ID:** {incident_id}
**Target Chain:** {str(chain).upper()}
**Vulnerable Contract:** `{contract_address}`
**Vulnerability Class:** {vuln_type} ({severity})
**Status:** {status}

## 1. Executive Summary

AegisForge recorded a security finding requiring owner review and response.

{response_statement}

## 2. Technical Details and Proof

- **Vector:** {vuln_type}
- **Severity:** {severity}
- **Owner Authorization:** {"Verified" if owner_authorized else "Not provided"}
- **Rescue Receipt Verification:** {"Verified" if rescue_receipt_verified else "Not verified"}
{tx_statement}

## 3. Funds and Bounty

- **Reported Amount:** ${_money(amount):,.2f}
- **Verified Rescued Total:** ${_money(verified_rescued):,.2f}
{bounty_statement}
{settlement_statement}
- **Net Returnable Amount:** ${_money(return_amount):,.2f}

Bounty terms are subject to a separate written agreement. A proposed rate is not an automatic entitlement or deduction.
"""

    json_path = directory / f"incident_{incident_id}.json"
    md_path = directory / f"incident_{incident_id}.md"

    json_path.write_text(
        json.dumps(report_data, indent=4, sort_keys=True),
        encoding="utf-8",
    )
    md_path.write_text(md_content, encoding="utf-8")
    return str(md_path)

import os
import json
import time

def generate_whitehat_report(incident_id, chain, contract_address, vuln_type, severity, rescued_amount, tx_hash):
    reports_dir = "/opt/agent-farm/shared/reports"
    os.makedirs(reports_dir, exist_ok=True)
    
    bounty_fee = rescued_amount * 0.075
    return_amount = rescued_amount - bounty_fee
    
    report_data = {
        "incident_id": incident_id,
        "timestamp": time.time(),
        "chain": chain,
        "target_contract": contract_address,
        "vulnerability": vuln_type,
        "severity": severity,
        "metrics": {
            "rescued_usd": rescued_amount,
            "proposed_bounty_usd": bounty_fee,
            "return_amount_usd": return_amount
        },
        "proof_of_rescue_tx": tx_hash,
        "status": "RESCUED_AND_SECURED"
    }
    
    md_content = f"""# 🛡️ AegisForge White-Hat Security Advisory & Secure Rescue Report

**Incident ID:** #{incident_id}  
**Target Chain:** {chain.upper()}  
**Vulnerable Contract:** \`{contract_address}\`  
**Vulnerability Class:** {vuln_type} ({severity})  
**Status:** 🚨 FUNDS SECURED BY WHITE-HAT AGENT

---

## 1. Executive Summary
Our automated monitoring and analysis framework detected a critical vulnerability in your smart contract deploy. To prevent imminent exploitation by malicious threat actors, our autonomous agent executed an emergency rescue transaction, securing the remaining pool funds to our secure multi-sig escrow address.

## 2. Technical Details & Proof of Concept (PoC)
- **Vector:** {vuln_type}
- **Severity:** {severity}
- **Rescue Transaction Hash:** \`{tx_hash}\`

## 3. Secure Escrow & Bounty Terms
- **Rescued Total:** ${rescued_amount:,.2f}
- **White-Hat Bounty (7.5%):** ${bounty_fee:,.2f}
- **Net Returnable Amount:** ${return_amount:,.2f}
"""

    json_path = os.path.join(reports_dir, f"incident_{incident_id}.json")
    md_path = os.path.join(reports_dir, f"incident_{incident_id}.md")
    
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    return md_path

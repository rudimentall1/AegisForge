from __future__ import annotations

from shared.task import Task


class CryptoAnalyst:
    """Turns source notes into falsifiable hypotheses without overstating them."""

    name = "crypto_analyst"

    def run(self, task: Task) -> Task:
        task.status = "analyzing_crypto_evidence"
        parent = dict(task.result or {})
        sources = [item for item in parent.get("sources", []) if isinstance(item, dict)]
        leads = [item for item in parent.get("source_leads", []) if isinstance(item, dict)]
        by_class = {}
        for source in sources:
            by_class.setdefault(source.get("classification"), []).append(source)
        early = by_class.get("early_client_key_generation_warning", [])
        profanity = by_class.get("vanity_generator_entropy_weakness_report", [])
        confounders = by_class.get("key_file_creation_or_storage_issue", []) + by_class.get("smart_contract_wallet_logic_issue", [])

        hypotheses = [
            {
                "hypothesis_id": "H-EARLY-CLIENT-KEYGEN",
                "question": "Which exact pre-release Ethereum client versions were affected by the early key-generation warning, and what implementation change removed the risk?",
                "status": "SOURCE_SUPPORTED_REPRODUCTION_PENDING" if early else "OPEN_NO_PRIMARY_SOURCE_MATCH",
                "source_ids": [item.get("source_id") for item in early if item.get("source_id")],
                "required_evidence": ["official warning with affected version boundary", "pinned source revisions before and after the fix", "reproducible synthetic-key test"],
                "what_this_does_not_prove": "It does not establish that every wallet created in 2015 is weak.",
            },
            {
                "hypothesis_id": "H-PROFANITY-SEED-SPACE",
                "question": "Can the published Profanity weakness be independently reproduced from a pinned historical revision using a synthetic test vector?",
                "status": "SOURCE_SUPPORTED_REPRODUCTION_PENDING" if profanity else "OPEN_NO_PRIMARY_SOURCE_MATCH",
                "source_ids": [item.get("source_id") for item in profanity if item.get("source_id")],
                "required_evidence": ["pinned vulnerable revision and comparison revision", "synthetic test vector", "reproduction of the historical derivation, not just a toy entropy demonstration"],
                "what_this_does_not_prove": "It does not identify any live address as vulnerable or establish compromise.",
            },
            {
                "hypothesis_id": "H-ADDRESS-COHORT-INFERENCE",
                "question": "Can aggregate evidence identify a historical cohort with a shared weak-generation method without claiming individual live addresses are exploitable?",
                "status": "UNPROVEN", "source_ids": [],
                "required_evidence": ["documented generator fingerprints", "aggregate false-positive analysis against a control sample", "independent review"],
                "what_this_does_not_prove": "Age, balance, inactivity, or vanity appearance alone is not proof of a weak key.",
            },
        ]
        result = dict(parent)
        result.update({
            "research_track": "evm_key_forensics", "stage": "analysis", "hypotheses": hypotheses,
            "analysis_summary": {
                "source_count": len(sources), "discovery_lead_count": len(leads),
                "early_client_warning_sources": len(early), "profanity_report_sources": len(profanity),
                "confounding_issue_sources": len(confounders), "claims_confirmed_by_this_agent": 0,
                "note": "This stage structures questions; it does not independently prove a vulnerability.",
            },
            "confounder_sources": [
                {"source_id": item.get("source_id"), "source_url": item.get("source_url"),
                 "classification": item.get("classification"),
                 "interpretation": "Different failure class; do not count as a weak-key-generator finding."}
                for item in confounders
            ],
            "next_experiment": {
                "type": "synthetic_entropy_demo",
                "purpose": "Show why a small seed space differs from a correctly sampled 256-bit key space.",
                "explicit_limit": "This is not a reproduction of Profanity, secp256k1, or a real wallet.",
            },
        })
        task.result = result
        task.status = "crypto_analyzed"
        return task

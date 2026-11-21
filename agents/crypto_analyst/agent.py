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
        payload = task.payload if isinstance(task.payload, dict) else {}
        case = payload.get("research_case")
        case_repository = (
            case.get("target_repository", "")
            if isinstance(case, dict)
            else getattr(case, "target_repository", "")
        )
        case_repository = str(case_repository or "").strip().lower().rstrip("/")
        if parent.get("research_track") == "onchain_solidity_source_research":
            signal_rows = []
            for source in parent.get("source_files", []):
                if not isinstance(source, dict):
                    continue
                for signal in source.get("signals", []):
                    if not isinstance(signal, dict):
                        continue
                    signal_rows.append({
                        "path": source.get("path"),
                        "line": signal.get("line"),
                        "signal": signal.get("signal"),
                        "excerpt": signal.get("excerpt"),
                    })
            grouped = {}
            for row in signal_rows:
                grouped.setdefault(row["signal"], []).append(row)
            hypotheses = []
            for signal_name, evidence in sorted(grouped.items()):
                hypotheses.append({
                    "hypothesis_id": "ONCHAIN-" + str(signal_name).upper(),
                    "question": (
                        "Does the observed " + str(signal_name)
                        + " construct violate the case invariant under an attacker-controlled call sequence?"
                    ),
                    "status": "NEEDS_DEEPER_ANALYSIS",
                    "evidence": evidence[:25],
                    "finding": False,
                    "requires": [
                        "interprocedural control-flow review",
                        "authorization and state-transition analysis",
                        "counterexample or negative-control validation",
                    ],
                })
            structural = parent.get("structural_analysis", {})
            structural_functions = [
                item for item in structural.get("functions", [])
                if isinstance(item, dict)
            ]
            functions_by_name = {}
            functions_by_identity = {}
            for item in structural_functions:
                functions_by_name.setdefault(item.get("name"), []).append(item)
                functions_by_identity.setdefault(
                    (item.get("path"), item.get("name")), item
                )

            def resolve_callee(caller, callee_name):
                candidates = functions_by_name.get(callee_name, [])
                same_file = [item for item in candidates if item.get("path") == caller.get("path")]
                return same_file[0] if same_file else (candidates[0] if len(candidates) == 1 else None)

            def walk_calls(current, trail, depth=0):
                if depth >= 8:
                    return []
                paths = []
                for callee_name in current.get("calls", []):
                    if len(paths) >= 25:
                        break
                    callee = resolve_callee(current, callee_name)
                    if callee is None:
                        continue
                    identity = (callee.get("path"), callee.get("name"))
                    if identity in trail:
                        continue
                    next_trail = trail + (identity,)
                    next_path = [
                        {
                            "path": item[0],
                            "function": item[1],
                            "line": functions_by_identity.get(item, {}).get("line"),
                        }
                        for item in next_trail
                    ]
                    if callee.get("external_calls") or callee.get("state_write_candidates"):
                        paths.append(next_path)
                    if len(paths) < 25:
                        paths.extend(
                            walk_calls(callee, next_trail, depth + 1)[:25 - len(paths)]
                        )
                return paths[:25]

            entrypoint_paths = {}
            for entry in structural_functions:
                if entry.get("visibility") not in {"public", "external"}:
                    continue
                entry_identity = (entry.get("path"), entry.get("name"))
                entry_ref = {
                    "path": entry.get("path"),
                    "function": entry.get("name"),
                    "line": entry.get("line"),
                }
                if entry.get("external_calls") or entry.get("state_write_candidates"):
                    entrypoint_paths.setdefault(entry_identity, []).append({
                        "entrypoint": entry_ref,
                        "path": [entry_ref],
                    })
                for path in walk_calls(entry, (entry_identity,)):
                    if not path:
                        continue
                    sink_identity = (path[-1]["path"], path[-1]["function"])
                    bucket = entrypoint_paths.setdefault(sink_identity, [])
                    path_key = tuple((step["path"], step["function"]) for step in path)
                    if len(bucket) < 25 and all(
                        tuple((step["path"], step["function"]) for step in item["path"]) != path_key
                        for item in bucket
                    ):
                        bucket.append({"entrypoint": entry_ref, "path": path})

            function_hypotheses = []
            function_hypotheses_truncated = False
            for function in structural_functions:
                if not (
                    function.get("external_calls")
                    or function.get("state_write_candidates")
                    or function.get("unresolved_calls")
                ):
                    continue
                if len(function_hypotheses) >= 500:
                    function_hypotheses_truncated = True
                    break
                identity = (function.get("path"), function.get("name"))
                reachable = entrypoint_paths.get(identity, [])
                function_hypotheses.append({
                    "hypothesis_id": "ONCHAIN-FUNCTION-" + str(function.get("path", "UNKNOWN")) + ":" + str(function.get("name", "UNKNOWN")),
                    "status": "NEEDS_DEEPER_ANALYSIS",
                    "finding": False,
                    "function": {
                        "path": function.get("path"),
                        "name": function.get("name"),
                        "line": function.get("line"),
                        "visibility": function.get("visibility"),
                        "modifiers": function.get("modifiers", []),
                    },
                    "entrypoints": [item["entrypoint"] for item in reachable],
                    "call_paths": [item["path"] for item in reachable],
                    "external_calls": function.get("external_calls", []),
                    "external_call_sites": function.get("external_call_sites", []),
                    "state_write_candidates": function.get("state_write_candidates", []),
                    "state_write_sites": function.get("state_write_sites", []),
                    "authorization_signals": function.get("authorization_signals", []),
                    "unresolved_calls": function.get("unresolved_calls", []),
                    "question": (
                        "Can an in-scope untrusted caller reach this external interaction or state mutation "
                        "without satisfying the case invariant?"
                    ),
                    "expected_invariant": parent.get("case", {}).get("expected_invariant"),
                    "falsification_criteria": parent.get("case", {}).get("falsification_criteria"),
                })
            hypotheses.extend(function_hypotheses)
            result = dict(parent)
            result.update({
                "stage": "analysis",
                "stage_history": list(parent.get("stage_history", [])) + ["analysis"],
                "onchain_source_analysis": {
                    "candidate_hypotheses": len(hypotheses),
                    "function_hypotheses": len(function_hypotheses),
                    "function_hypotheses_truncated": function_hypotheses_truncated,
                    "structural_functions": len(structural_functions),
                    "structural_analysis_complete": structural.get("analysis_complete", False),
                    "lexical_signals": len(signal_rows),
                    "finding_created": False,
                    "vulnerabilities_confirmed": 0,
                    "source_executed": False,
                    "conclusion": (
                        "CANDIDATES_FOR_REVIEW" if hypotheses else "NO_LEXICAL_CANDIDATES"
                    ),
                    "limitations": (
                        "Lexical signals are triage leads, not vulnerabilities. "
                        "No bytecode equivalence, runtime exploitability, or invariant violation is established."
                    ),
                },
                "hypotheses": hypotheses,
            })
            task.result = result
            task.status = "crypto_analyzed"
            return task
        if parent.get("research_track") == "uniswap_v2_factory_fixture":
            from tools.evm_key_forensics.uniswap_v2_factory_source_pattern import (
                PINNED_COMMIT,
                PINNED_GIT_BLOB_SHA1,
            )
            observation = parent.get("source_observation")
            observation = observation if isinstance(observation, dict) else {}
            target_commit = (
                case.get("target_commit") if isinstance(case, dict)
                else getattr(case, "target_commit", None)
            )
            source_records = [item for item in parent.get("sources", []) if isinstance(item, dict)]
            source_supported = (
                observation.get("conclusion") == "SOURCE_PATTERN_MATCHED"
                and observation.get("source_commit") == target_commit == PINNED_COMMIT
                and observation.get("source_git_blob_sha1") == PINNED_GIT_BLOB_SHA1
                and all(observation.get("checks", {}).values())
                and len(source_records) == 1
                and source_records[0].get("provenance_matches_case") is True
            )
            result = dict(parent)
            result.update({
                "stage": "analysis",
                "stage_history": list(parent.get("stage_history", [])) + ["analysis"],
                "solidity_analysis": {
                    "hypothesis_id": "SOL-UNISWAP-V2-FACTORY-FEE-SETTER-001",
                    "status": "SOURCE_PATTERN_MATCHED" if source_supported else "INCONCLUSIVE",
                    "source_supported": source_supported,
                    "claims_confirmed": 0,
                    "finding_created": False,
                    "question": (
                        "Does the pinned Uniswap V2 Factory source require feeToSetter "
                        "authorization before feeTo or feeToSetter mutations?"
                    ),
                    "what_this_does_not_prove": (
                        "Source-level authorization patterns do not establish compiled behavior, "
                        "current deployed bytecode identity, or runtime safety."
                    ),
                },
                "hypotheses": [{
                    "hypothesis_id": "SOL-UNISWAP-V2-FACTORY-FEE-SETTER-001",
                    "status": "SOURCE_SUPPORTED" if source_supported else "INCONCLUSIVE",
                    "source_ids": [
                        item.get("source_id") for item in source_records
                        if item.get("source_id")
                    ],
                    "finding": False,
                }],
                "analysis_summary": {
                    "claims_confirmed_by_this_agent": 0,
                    "vulnerabilities_confirmed": 0,
                },
            })
            task.result = result
            task.status = "crypto_analyzed"
            return task
        if parent.get("research_track") == "solidity_source_fixture":
            observation = parent.get("source_observation")
            observation = observation if isinstance(observation, dict) else {}
            target_commit = (
                case.get("target_commit") if isinstance(case, dict)
                else getattr(case, "target_commit", None)
            )
            source_supported = (
                observation.get("conclusion") == "SOURCE_PATTERN_MATCHED"
                and observation.get("source_commit") == target_commit
                and observation.get("source_git_blob_sha1")
                == "bd96f6661dcbf7b2d4948823ac0e7bfb4ba31fb1"
                and all(observation.get("checks", {}).values())
            )
            result = dict(parent)
            result.update({
                "stage": "analysis",
                "stage_history": list(parent.get("stage_history", [])) + ["analysis"],
                "solidity_analysis": {
                    "hypothesis_id": "SOL-OWNABLE-ACCESS-CONTROL-001",
                    "status": "SOURCE_PATTERN_MATCHED" if source_supported else "INCONCLUSIVE",
                    "source_supported": source_supported,
                    "claims_confirmed": 0,
                    "finding_created": False,
                    "question": "Does the pinned source route owner-only authorization through onlyOwner/_checkOwner and _msgSender?",
                    "what_this_does_not_prove": (
                        "This source observation does not establish compiled behavior, "
                        "deployed bytecode identity, runtime security, or exploitability."
                    ),
                },
                "hypotheses": [{
                    "hypothesis_id": "SOL-OWNABLE-ACCESS-CONTROL-001",
                    "status": "SOURCE_SUPPORTED" if source_supported else "INCONCLUSIVE",
                    "source_ids": [
                        item.get("source_id") for item in parent.get("sources", [])
                        if isinstance(item, dict) and item.get("source_id")
                    ],
                    "finding": False,
                }],
                "analysis_summary": {
                    "claims_confirmed_by_this_agent": 0,
                    "vulnerabilities_confirmed": 0,
                },
            })
            task.result = result
            task.status = "crypto_analyzed"
            return task
        if case_repository in {"johguse/profanity", "https://github.com/johguse/profanity"}:
            pinned_dispatcher_sources = [
                source for source in sources
                if source.get("repository") == "johguse/profanity"
                and source.get("source_file_path") == "Dispatcher.cpp"
                and source.get("revision_sha") in {
                    "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6",
                    "186b9b27ab3e24a1899f648adcabcbf0e5f3131e",
                }
                and source.get("status_code") == 200
                and isinstance(source.get("content_sha256"), str)
                and len(source["content_sha256"]) == 64
            ]
            primary_disclosures = [
                source for source in sources
                if source.get("source_kind") in {
                    "maintainer_issue", "security_advisory",
                    "vulnerability_database_record", "disclosure_analysis",
                }
                and source.get("status_code") == 200
                and source.get("content_sha256")
            ]
            relevant_sources = [
                source for source in sources
                if source.get("repository") == "johguse/profanity"
                or source in primary_disclosures
            ]
            source_ids = list(dict.fromkeys(
                str(source.get("source_id"))
                for source in relevant_sources
                if isinstance(source.get("source_id"), str) and source.get("source_id")
            ))
            source_supported = len(pinned_dispatcher_sources) >= 2 and bool(primary_disclosures)
            result = dict(parent)
            result.update({
                "research_track": "evm_key_forensics",
                "stage": "analysis",
                "case_analysis": {
                    "target_repository": "johguse/profanity",
                    "target_commit": (
                        case.get("target_commit") if isinstance(case, dict)
                        else getattr(case, "target_commit", None)
                    ),
                    "pinned_dispatcher_revision_count": len(pinned_dispatcher_sources),
                    "primary_disclosure_source_count": len(primary_disclosures),
                    "source_supported_seed_space_hypothesis": source_supported,
                },
                "hypotheses": [
                    {
                        "hypothesis_id": "H-PROFANITY-SEED-SPACE",
                        "question": (
                            case.get("hypothesis") if isinstance(case, dict)
                            else getattr(case, "hypothesis", None)
                        ) or "Does the pinned Profanity source seed its PRNG from one random_device result rather than independent entropy draws?",
                        "status": "SOURCE_SUPPORTED_REPRODUCTION_PENDING" if source_supported else "OPEN_NO_PRIMARY_SOURCE_MATCH",
                        "source_ids": source_ids,
                        "required_evidence": [
                            "exact immutable pre-disclosure and post-disclosure Dispatcher.cpp identities",
                            "upstream maintainer disclosure and public security advisory",
                            "runtime/toolchain behavior kept separate from source-level inference",
                            "bounded synthetic control tests; no historical application execution",
                        ],
                        "what_this_does_not_prove": "It does not establish effective runtime entropy, historical binary provenance, exploitability of every build, or exposure of any wallet.",
                    },
                    {
                        "hypothesis_id": "H-PROFANITY-HISTORICAL-RUNTIME",
                        "question": "Has AegisForge independently reproduced the behavior of the historical Profanity implementation?",
                        "status": "NOT_ESTABLISHED",
                        "source_ids": [],
                        "required_evidence": [
                            "isolated historical implementation test with synthetic-only vectors",
                            "pinned toolchain and runtime",
                            "independent runner attestation and trusted receipt",
                        ],
                        "what_this_does_not_prove": "A source review or toy entropy demonstration is not historical runtime reproduction.",
                    },
                    {
                        "hypothesis_id": "H-PROFANITY-WALLET-EXPOSURE",
                        "question": "Does this evidence establish that any particular wallet or address is vulnerable?",
                        "status": "UNPROVEN",
                        "source_ids": [],
                        "required_evidence": [
                            "separate authorized evidence and independent review; never infer from address appearance, age, balance, or inactivity",
                        ],
                        "what_this_does_not_prove": "No individual wallet is assessed by this case.",
                    },
                ],
                "analysis_summary": {
                    "source_count": len(sources),
                    "relevant_case_source_count": len(relevant_sources),
                    "pinned_dispatcher_revision_count": len(pinned_dispatcher_sources),
                    "primary_disclosure_source_count": len(primary_disclosures),
                    "claims_confirmed_by_this_agent": 0,
                    "note": "This is source-backed triage, not an exploit reproduction or wallet-exposure finding.",
                },
                "confounder_sources": [
                    {
                        "source_id": source.get("source_id"),
                        "source_url": source.get("source_url"),
                        "classification": source.get("classification"),
                        "interpretation": "Different failure class; excluded from the Profanity seed-space claim.",
                    }
                    for source in sources
                    if source.get("classification") in {
                        "key_file_creation_or_storage_issue",
                        "smart_contract_wallet_logic_issue",
                    }
                ],
                "next_experiment": {
                    "type": "synthetic_entropy_demo",
                    "purpose": "Check the case pipeline's synthetic controls and evidence integrity without executing historical Profanity.",
                    "explicit_limit": "This is not a reproduction of Profanity, secp256k1, or a real wallet.",
                },
            })
            task.result = result
            task.status = "crypto_analyzed"
            return task
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

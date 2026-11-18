from shared.task import Task
from shared.github_client import GitHubClient


class PipelineContractError(RuntimeError):
    """Raised when an upstream pipeline contract is missing."""


class SecurityChecker:
    name = "security_checker"

    MAX_FILES_PER_REPO = 20
    MAX_FILE_SIZE = 40000

    SOLIDITY_EXTENSIONS = (".sol",)

    SECURITY_FILE_NAMES = {
        "security.md",
        "security",
        "security.txt",
    }

    CONFIG_NAMES = {
        "foundry.toml",
        "hardhat.config.js",
        "hardhat.config.ts",
        "hardhat.config.cjs",
        "hardhat.config.mjs",
        "slither.config.json",
        "slither.config.yaml",
        "slither.config.yml",
        "package.json",
    }

    PRIORITY_DIRS = (
        "contracts/",
        "src/",
        "lib/",
        "test/",
        "tests/",
        "script/",
        "scripts/",
        "audit/",
        "audits/",
    )

    SECURITY_PATTERNS = {
        "unchecked_erc20": {
            "patterns": [".transfer(", ".transferFrom("],
            "severity": "HIGH",
            "description": "Unchecked ERC20 transfer return value; token transfer may fail silently"
        },
        "oracle_manipulation": {
            "patterns": ["getreserves(", "price0cumulativeLast", "spotprice"],
            "severity": "HIGH",
            "description": "Potential spot-price oracle manipulation vector via liquidity reserves"
        },
        "uninitialized_proxy": {
            "patterns": ["function initialize("],
            "severity": "CRITICAL",
            "description": "Proxy initialization function detected; ensure proper initializer modifiers/protection"
        },

        "tx_origin": {
            "patterns": ["tx.origin"],
            "severity": "HIGH",
            "description": (
                "tx.origin usage detected; may create "
                "authorization/phishing risks"
            ),
        },
        "delegatecall": {
            "patterns": ["delegatecall("],
            "severity": "HIGH",
            "description": (
                "delegatecall detected; implementation and "
                "storage-context risks require manual review"
            ),
        },
        "low_level_call": {
            "patterns": [".call{", ".call(", ".call.value("],
            "severity": "MEDIUM",
            "description": (
                "low-level call detected; return-value and "
                "reentrancy handling require review"
            ),
        },
        "selfdestruct": {
            "patterns": ["selfdestruct("],
            "severity": "HIGH",
            "description": (
                "selfdestruct detected; lifecycle and authorization "
                "must be reviewed"
            ),
        },
        "assembly": {
            "patterns": ["assembly {"],
            "severity": "MEDIUM",
            "description": (
                "inline assembly detected; compiler/storage/memory "
                "safety requires manual review"
            ),
        },
        "unchecked": {
            "patterns": ["unchecked {"],
            "severity": "MEDIUM",
            "description": (
                "unchecked arithmetic block detected"
            ),
        },
        "ecrecover": {
            "patterns": ["ecrecover("],
            "severity": "MEDIUM",
            "description": (
                "ecrecover detected; signature validation and "
                "malleability handling require review"
            ),
        },
        "block_timestamp": {
            "patterns": ["block.timestamp"],
            "severity": "LOW",
            "description": (
                "block.timestamp used; miner/validator timestamp "
                "assumptions require review"
            ),
        },
        "blockhash": {
            "patterns": ["blockhash("],
            "severity": "LOW",
            "description": (
                "blockhash used; entropy/randomness assumptions "
                "require review"
            ),
        },
        "transfer_send": {
            "patterns": [".transfer(", ".send("],
            "severity": "MEDIUM",
            "description": (
                "transfer/send detected; gas-stipend and failure "
                "semantics require review"
            ),
        },
    }

    ACCESS_CONTROL_PATTERNS = (
        "onlyowner",
        "onlyrole",
        "accesscontrol",
        "hasrole(",
        "_checkowner(",
        "msg.sender",
        "require(msg.sender",
        "if (msg.sender",
    )

    REENTRANCY_GUARD_PATTERNS = (
        "nonreentrant",
        "reentrancyguard",
        "reentrancy_guard",
    )

    @staticmethod
    def _repo_parts(name):
        if not name or "/" not in name:
            return None, None

        owner, repo = name.split("/", 1)

        if not owner or not repo:
            return None, None

        return owner, repo

    def __init__(self):
        self.github = GitHubClient()

    def _get(self, url, params=None):
        return self.github.get_json(
            url,
            params=params,
            cache_ttl=3600,
            timeout=30,
        )

    def _get_tree(self, owner, repo, branch):
        url = (
            f"{self.github.BASE_URL}/repos/"
            f"{owner}/{repo}/git/trees/{branch}"
        )

        return self._get(
            url,
            params={"recursive": "1"},
        )

    def _get_file(self, owner, repo, path):
        url = (
            f"{self.github.BASE_URL}/repos/"
            f"{owner}/{repo}/contents/{path}"
        )

        try:
            data = self.github.get_json(
                url,
                cache_ttl=3600,
                timeout=20,
            )

            if not isinstance(data, dict):
                return None

            content = data.get("content")

            if not content:
                return None

            if data.get("encoding") != "base64":
                return content[: self.MAX_FILE_SIZE]

            import base64

            decoded = base64.b64decode(
                content.replace("\n", "")
            ).decode(
                "utf-8",
                errors="replace",
            )

            return decoded[: self.MAX_FILE_SIZE]

        except Exception as exc:
            print(
                f"[SecurityChecker] FILE ERROR "
                f"{owner}/{repo}:{path} "
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )
            return None

    @staticmethod
    def _basename(path):
        return path.rsplit("/", 1)[-1].lower()

    def _select_solidity_files(self, paths):
        solidity = [
            path
            for path in paths
            if path.lower().endswith(
                self.SOLIDITY_EXTENSIONS
            )
        ]

        def priority(path):
            lower = path.lower()

            if lower.startswith("contracts/"):
                return 0

            if lower.startswith("src/"):
                return 1

            if lower.startswith("lib/"):
                return 2

            if lower.startswith("test/"):
                return 5

            if lower.startswith("tests/"):
                return 5

            return 3

        solidity.sort(key=priority)

        return solidity[: self.MAX_FILES_PER_REPO]

    def _select_supporting_files(self, paths):
        selected = []

        for path in paths:
            basename = self._basename(path)

            if basename in self.SECURITY_FILE_NAMES:
                selected.append(path)
                continue

            if basename in self.CONFIG_NAMES:
                selected.append(path)
                continue

            lower = path.lower()

            if any(
                lower.startswith(directory)
                for directory in (
                    ".github/workflows/",
                    "audit/",
                    "audits/",
                )
            ):
                selected.append(path)

        return selected[:10]

    def _scan_source(self, path, content):
        if not content:
            return []

        text = content.lower()
        findings = []

        for rule_id, rule in self.SECURITY_PATTERNS.items():
            matched = False

            for pattern in rule["patterns"]:
                if pattern in text:
                    matched = True
                    break

            if not matched:
                continue

            findings.append({
                "rule": rule_id,
                "severity": rule["severity"],
                "file": path,
                "description": rule["description"],
                "status": "POTENTIAL_RISK",
            })

        return findings

    @staticmethod
    def _has_any(text, patterns):
        text = text.lower()

        return any(
            pattern in text
            for pattern in patterns
        )

    def _security_posture(
        self,
        developer_review,
        source_text,
        support_text,
        findings,
    ):
        signals = []

        if developer_review.get("has_tests"):
            signals.append("tests_present")

        if developer_review.get("has_ci"):
            signals.append("ci_present")

        if developer_review.get("has_security_policy"):
            signals.append("security_policy")

        if developer_review.get("has_audits"):
            signals.append("audit_evidence")

        developer_signals = developer_review.get(
            "security_signals",
            [],
        )

        for signal in developer_signals:
            if signal not in signals:
                signals.append(signal)

        combined = (
            source_text
            + "\n"
            + support_text
        ).lower()

        access_control = self._has_any(
            combined,
            self.ACCESS_CONTROL_PATTERNS,
        )

        reentrancy_guard = self._has_any(
            combined,
            self.REENTRANCY_GUARD_PATTERNS,
        )

        if access_control:
            signals.append("access_control_signals")

        if reentrancy_guard:
            signals.append("reentrancy_guard_signals")

        severity_weight = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0,
        }

        risk_points = sum(
            severity_weight.get(
                finding["severity"],
                0,
            )
            for finding in findings
        )

        score = 100

        score -= min(
            risk_points * 5,
            60,
        )

        if not developer_review.get("has_tests"):
            score -= 15

        if not developer_review.get("has_ci"):
            score -= 10

        if (
            developer_review.get(
                "smart_contract_project"
            )
            and not developer_review.get(
                "has_security_policy"
            )
        ):
            score -= 5

        if reentrancy_guard:
            score += 5

        if access_control:
            score += 5

        score = max(
            0,
            min(100, score),
        )

        if any(
            finding["severity"] == "CRITICAL"
            for finding in findings
        ):
            posture = "CRITICAL_REVIEW"
        elif any(
            finding["severity"] == "HIGH"
            for finding in findings
        ):
            posture = "HIGH_REVIEW"
        elif score < 50:
            posture = "WEAK"
        elif score < 75:
            posture = "MODERATE"
        else:
            posture = "STRONG"

        return {
            "score": score,
            "posture": posture,
            "signals": list(
                dict.fromkeys(signals)
            ),
            "access_control_signals": access_control,
            "reentrancy_guard_signals": reentrancy_guard,
        }

    def _inspect_repository(
        self,
        developer_review,
    ):
        import os
        import shutil
        import tempfile
        from pathlib import Path, PurePosixPath

        name = developer_review.get("name")
        owner, repo = self._repo_parts(name)
        if not owner:
            raise RuntimeError(f"Invalid repository name: {name}")

        print(f"[SecurityChecker] INSPECT: {name}", flush=True)
        metadata_url = f"{self.github.BASE_URL}/repos/{owner}/{repo}"
        metadata = self._get(metadata_url) or {}
        branch = (
            metadata.get("default_branch")
            or developer_review.get("default_branch")
            or "main"
        )
        tree = self._get_tree(owner, repo, branch)
        if not tree:
            raise RuntimeError("Git tree unavailable")

        entries = tree.get("tree", [])
        paths = [
            entry.get("path")
            for entry in entries
            if entry.get("type") == "blob" and entry.get("path")
        ]
        solidity_files = [
            path for path in paths if path.lower().endswith(".sol")
        ]
        selected_solidity = self._select_solidity_files(paths)
        supporting_files = self._select_supporting_files(paths)

        findings = []
        file_errors = []
        source_files_read = []
        source_text_parts = []
        support_text_parts = []
        source_contents = {}
        supporting_contents = {}

        for path in selected_solidity:
            content = self._get_file(owner, repo, path)
            if content is None:
                file_errors.append(path)
                continue
            source_files_read.append(path)
            source_text_parts.append(content)
            source_contents[path] = content
            findings.extend(self._scan_source(path, content))

        for path in supporting_files:
            content = self._get_file(owner, repo, path)
            if content is None:
                file_errors.append(path)
                continue
            support_text_parts.append(content)
            supporting_contents[path] = content

        source_text = "\n".join(source_text_parts)
        support_text = "\n".join(support_text_parts)
        analysis_tool_status = {
            "pattern_scan": "COMPLETED",
            "slither": "DISABLED",
            "mythril": "DISABLED",
            "local_llm": "DISABLED",
        }

        with tempfile.TemporaryDirectory(
            prefix="aegisforge-security-checker-"
        ) as temporary_root:
            root = Path(temporary_root).resolve()
            for relative_name, content in {
                **supporting_contents,
                **source_contents,
            }.items():
                if (
                    not isinstance(relative_name, str)
                    or not relative_name
                    or "\\" in relative_name
                    or "\x00" in relative_name
                ):
                    file_errors.append(relative_name)
                    continue
                relative_path = PurePosixPath(relative_name)
                if (
                    relative_path.is_absolute()
                    or not relative_path.parts
                    or any(part in ("", ".", "..") for part in relative_path.parts)
                    or ":" in relative_path.parts[0]
                ):
                    file_errors.append(relative_name)
                    continue
                target = root.joinpath(*relative_path.parts)
                try:
                    target.resolve().relative_to(root)
                except ValueError:
                    file_errors.append(relative_name)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")

            slither_enabled = os.getenv(
                "AEGISFORGE_ENABLE_REPOSITORY_SLITHER", "0"
            ).strip().lower() in {"1", "true", "yes"}
            if slither_enabled:
                if shutil.which("slither") and source_files_read:
                    findings.extend(self._run_slither_analysis(str(root)))
                    analysis_tool_status["slither"] = "COMPLETED"
                else:
                    analysis_tool_status["slither"] = (
                        "TOOL_UNAVAILABLE" if not shutil.which("slither")
                        else "NO_SOURCE_FILES"
                    )

            mythril_enabled = os.getenv(
                "AEGISFORGE_ENABLE_MYTHRIL", "0"
            ).strip().lower() in {"1", "true", "yes"}
            if mythril_enabled:
                if shutil.which("myth") and source_files_read:
                    for source_path in source_files_read[:3]:
                        relative_path = PurePosixPath(source_path)
                        if (
                            relative_path.is_absolute()
                            or any(part in ("", ".", "..") for part in relative_path.parts)
                        ):
                            continue
                        target = root.joinpath(*relative_path.parts)
                        findings.extend(self._run_mythril_analysis(str(target)))
                    analysis_tool_status["mythril"] = "COMPLETED"
                else:
                    analysis_tool_status["mythril"] = (
                        "TOOL_UNAVAILABLE" if not shutil.which("myth")
                        else "NO_SOURCE_FILES"
                    )

        local_llm_enabled = os.getenv(
            "AEGISFORGE_ENABLE_LOCAL_LLM_REVIEW", "0"
        ).strip().lower() in {"1", "true", "yes"}
        if local_llm_enabled and source_text:
            findings.extend(self._run_llm_analysis(source_text))
            analysis_tool_status["local_llm"] = "COMPLETED"

        posture = self._security_posture(
            developer_review=developer_review,
            source_text=source_text,
            support_text=support_text,
            findings=findings,
        )
        critical = sum(f.get("severity") == "CRITICAL" for f in findings)
        high = sum(f.get("severity") == "HIGH" for f in findings)
        medium = sum(f.get("severity") == "MEDIUM" for f in findings)
        low = sum(f.get("severity") == "LOW" for f in findings)
        manual_review_required = bool(
            findings or developer_review.get("risk_flags")
        )

        dynamic_validation = (
            self._run_foundry_fork_validation(
                findings,
                developer_review.get("chain", "arbitrum"),
                developer_review.get("address", ""),
            )
            if findings
            else []
        )
        analysis_scope = (
            "pattern_scan_and_slither_static_analysis"
            if analysis_tool_status["slither"] == "COMPLETED"
            else "static_source_pattern_analysis"
        )
        if analysis_tool_status["mythril"] == "COMPLETED":
            analysis_scope += "_and_mythril_symbolic_analysis"

        return {
            "name": name,
            "dynamic_validation": dynamic_validation,
            "dynamic_validation_status": (
                "ISOLATED_RUNNER_REQUIRED" if findings else "NOT_REQUIRED"
            ),
            "analysis_tool_status": analysis_tool_status,
            "url": developer_review.get("url"),
            "smart_contract_project": developer_review.get(
                "smart_contract_project", False
            ),
            "solidity_files_total": len(solidity_files),
            "solidity_files_read": len(source_files_read),
            "files_read_errors": file_errors,
            "tree_truncated": bool(tree.get("truncated")),
            "security_posture": posture,
            "findings": findings,
            "finding_summary": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "total": len(findings),
            },
            "developer_risk_flags": developer_review.get("risk_flags", []),
            "manual_review_required": manual_review_required,
            "analysis_scope": analysis_scope,
            "not_a_confirmed_exploit": True,
        }


    def _run_slither_analysis(self, repo_path):
        import subprocess, json
        findings = []
        try:
            res = subprocess.run(
                ["slither", ".", "--json", "-"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=45
            )
            if res.stdout:
                data = json.loads(res.stdout)
                for detector in data.get("results", {}).get("detectors", []):
                    findings.append({
    "rule": "slither_" + detector.get('check', 'unknown'),
                        "severity": detector.get("impact", "MEDIUM").upper(),
                        "file": str(detector.get("elements", [{}])[0].get("source_mapping", {}).get("filename_relative", "unknown")),
                        "description": detector.get("description", "Slither finding"),
                        "status": "POTENTIAL_RISK"
                    })
        except Exception as e:
            print(f"[SecurityChecker] Slither execution skipped or failed: {e}", flush=True)
        return findings


    def _run_llm_analysis(self, source_text):
        import urllib.request
        import json
        findings = []
        try:
            prompt = (
                "You are an expert smart contract auditor. Analyze the following Solidity code snippet "
                "for deep logical vulnerabilities, reentrancy, access control flaws, or economic exploits. "
                "Return a JSON array of objects with keys: rule, severity (HIGH/CRITICAL), description. "
                "If no vulnerability is found, return an empty array [].\n\nCode:\n" + source_text[:3000]
            )
            payload = json.dumps({
                "model": "qwen2.5-coder:3b",
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 500}
            }).encode("utf-8")

            req = urllib.request.Request(
                "http://127.0.0.1:11434/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                text_response = res_data.get("response", "")
                # Попытка извлечь JSON из ответа модели
                if "[" in text_response and "]" in text_response:
                    json_str = text_response[text_response.find("["):text_response.rfind("]")+1]
                    parsed = json.loads(json_str)
                    for item in parsed:
                        findings.append({
                            "rule": f"llm_{item.get('rule', 'logical_flaw')}",
                            "severity": item.get("severity", "HIGH").upper(),
                            "file": "contract_semantic_review",
                            "description": item.get("description", "LLM detected logical vulnerability"),
                            "status": "POTENTIAL_RISK"
                        })
        except Exception as e:
            print(f"[SecurityChecker] LLM semantic analysis skipped or failed: {e}", flush=True)
        return findings


    def _run_mythril_analysis(self, contract_path):
        import subprocess
        findings = []
        try:
            # Запуск символьного анализа Mythril с таймаутом для предотвращения зависаний
            cmd = ["myth", "analyze", contract_path, "--max-depth", "10", "-f", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and result.stdout:
                import json
                data = json.loads(result.stdout)
                issues = data.get("issues", [])
                for issue in issues:
                    findings.append({
                        "rule": f"mythril_{issue.get('swc-id', 'logical')}",
                        "severity": issue.get("severity", "HIGH").upper(),
                        "file": contract_path,
                        "description": issue.get("description", "Symbolic execution detected logical flaw"),
                        "status": "CRITICAL_RISK"
                    })
        except Exception as e:
            print(f"[SecurityChecker] Mythril symbolic analysis skipped or failed: {e}", flush=True)
        return findings


    def _run_foundry_fork_validation(self, findings, chain, address):
        """Return explicit skips until an isolated Anvil/Foundry runner is configured.

        Never execute repository-controlled Foundry tests in the worker process.
        A passing generic forge test is not evidence that a specific finding is exploitable.
        """
        validation_results = []
        for finding in findings:
            if finding.get("severity") in {"MEDIUM", "HIGH", "CRITICAL"}:
                validation_results.append({
                    "rule": finding.get("rule"),
                    "dynamic_verified": False,
                    "confirmed": False,
                    "status": "SKIPPED",
                    "reason": "isolated_fork_runner_not_configured",
                    "required_next_step": "isolated_anvil_fork_runner",
                })
        return validation_results


    def run(self, task: Task) -> Task:
            task.status = "security_checking"

            try:
                parent = task.result or {}

                technical_reviews = parent.get(
                    "technical_review",
                    [],
                )

                if not technical_reviews:
                    raise PipelineContractError(
                        "Security Checker received no "
                        "technical_review from Developer"
                    )

                security_reviews = []
                errors = []

                total = len(
                    technical_reviews
                )

                print(
                    f"[SecurityChecker] "
                    f"STATIC SECURITY ANALYSIS "
                    f"OF {total} REPOSITORIES",
                    flush=True,
                )

                for index, review in enumerate(
                    technical_reviews,
                    1,
                ):
                    print(
                        f"[SecurityChecker] "
                        f"[{index}/{total}] "
                        f"{review.get('name')}",
                        flush=True,
                    )

                    try:
                        result = (
                            self._inspect_repository(
                                review
                            )
                        )

                        security_reviews.append(
                            result
                        )

                    except Exception as exc:
                        error = {
                            "name": review.get(
                                "name"
                            ),
                            "url": review.get(
                                "url"
                            ),
                            "error_type": type(
                                exc
                            ).__name__,
                            "error": str(exc),
                        }

                        errors.append(error)

                        print(
                            f"[SecurityChecker] ERROR "
                            f"{review.get('name')}: "
                            f"{type(exc).__name__}: "
                            f"{exc}",
                            flush=True,
                        )

                # Data-integrity gate:
                # a SecurityChecker task is successful only when every
                # technical review was inspected successfully.
                if len(security_reviews) != total or errors:
                    failed_names = [
                        item.get("name")
                        for item in errors
                        if item.get("name")
                    ]

                    task.status = "security_check_failed"

                    task.result = {
                        **parent,
                        "agent": self.name,
                        "task": task.description,
                        "parent_agent": parent.get("agent"),
                        "parent_task": parent.get("task"),
                        "security_reviews": security_reviews,
                        "security_checker_errors": errors,
                        "security_integrity": {
                            "expected_repositories": total,
                            "checked_repositories": len(
                                security_reviews
                            ),
                            "inspection_errors": len(errors),
                            "complete": False,
                            "failed_repositories": failed_names,
                        },
                        "error_type": "PartialSecurityInspectionFailure",
                        "error": (
                            "SecurityChecker integrity gate failed: "
                            f"{len(security_reviews)}/{total} "
                            "repositories inspected"
                        ),
                        "checked_by": self.name,
                        "security_analysis_type": (
                            "static_source_pattern_analysis"
                        ),
                    }

                    print(
                        "[SecurityChecker] INTEGRITY FAILURE: "
                        f"{len(security_reviews)}/{total} repositories checked; "
                        f"errors={len(errors)}",
                        flush=True,
                    )

                    return task

                if not security_reviews:
                    raise RuntimeError(
                        "Security Checker could not "
                        "inspect any repository"
                    )

                critical = sum(
                    item["finding_summary"]["critical"]
                    for item in security_reviews
                )

                high = sum(
                    item["finding_summary"]["high"]
                    for item in security_reviews
                )

                medium = sum(
                    item["finding_summary"]["medium"]
                    for item in security_reviews
                )

                low = sum(
                    item["finding_summary"]["low"]
                    for item in security_reviews
                )

                strong = sum(
                    item["security_posture"]["posture"]
                    == "STRONG"
                    for item in security_reviews
                )

                weak = sum(
                    item["security_posture"]["posture"]
                    == "WEAK"
                    for item in security_reviews
                )

                manual = sum(
                    item.get(
                        "manual_review_required",
                        False,
                    )
                    for item in security_reviews
                )

                task.result = {
                    **parent,
                    "agent": self.name,
                    "task": task.description,
                    "parent_agent": parent.get("agent"),
                    "parent_task": parent.get("task"),
                    "security_reviews": security_reviews,
                    "security_summary": {
                        "repositories_received": total,
                        "repositories_checked": len(
                            security_reviews
                        ),
                        "inspection_errors": len(
                            errors
                        ),
                        "strong": strong,
                        "weak": weak,
                        "manual_review_required": manual,
                        "critical_findings": critical,
                        "high_findings": high,
                        "medium_findings": medium,
                        "low_findings": low,
                        "total_findings": (
                            critical
                            + high
                            + medium
                            + low
                        ),
                    },
                    "security_checker_errors": errors,
                    "checked_by": self.name,
                    "security_analysis_type": (
                        "static_source_pattern_analysis"
                    ),
                }

                task.status = "security_checked"

                print(
                    f"[SecurityChecker] COMPLETE: "
                    f"{len(security_reviews)}/{total} "
                    f"repositories checked",
                    flush=True,
                )

                print(
                    f"[SecurityChecker] FINDINGS: "
                    f"critical={critical} "
                    f"high={high} "
                    f"medium={medium} "
                    f"low={low}",
                    flush=True,
                )

            except Exception as exc:
                task.status = "security_check_failed"

                task.result = {
                    "agent": self.name,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }

                print(
                    f"[SecurityChecker] FATAL: "
                    f"{type(exc).__name__}: {exc}",
                    flush=True,
                )

            return task

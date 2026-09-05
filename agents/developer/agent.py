from shared.task import Task
from shared.github_client import GitHubClient


class Developer:
    name = "developer"

    MAX_TREE_ENTRIES = 2500
    MAX_FILES_TO_READ = 50
    MAX_FILE_SIZE = 30000

    CONFIG_NAMES = {
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "requirements-dev.txt",
        "go.mod",
        "Cargo.toml",
        "foundry.toml",
        "remappings.txt",
        "hardhat.config.js",
        "hardhat.config.ts",
        "hardhat.config.cjs",
        "hardhat.config.mjs",
        "truffle-config.js",
        "ape-config.yaml",
        "slither.config.json",
        "slither.config.yaml",
        "slither.config.yml",
    }

    README_NAMES = {
        "readme.md",
        "readme",
        "readme.rst",
        "readme.txt",
    }

    SECURITY_NAMES = {
        "security.md",
        "security",
        "security.txt",
    }

    PRIORITY_DIRS = (
        "contracts/",
        "src/",
        "test/",
        "tests/",
        "script/",
        "scripts/",
        "audit/",
        "audits/",
        ".github/workflows/",
    )

    PRIORITY_EXTENSIONS = (
        ".sol",
        ".rs",
        ".go",
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".mjs",
        ".cjs",
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
        response = self.github.session.get(
            url,
            params=params,
            timeout=30,
        )

        if response.status_code == 404:
            return None

        response.raise_for_status()
        return response.json()

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
            response = self.github.session.get(
                url,
                timeout=20,
            )

            if response.status_code == 404:
                return None

            response.raise_for_status()

            data = response.json()

            if not isinstance(data, dict):
                return None

            return self._decode(data)

        except Exception as exc:
            print(
                f"[Developer] FILE ERROR "
                f"{owner}/{repo}:{path} "
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )
            return None

    @staticmethod
    def _decode(data):
        content = data.get("content")

        if not content:
            return None

        if data.get("encoding") != "base64":
            return content

        import base64

        try:
            return base64.b64decode(
                content.replace("\n", "")
            ).decode(
                "utf-8",
                errors="replace",
            )
        except Exception:
            return None

    @staticmethod
    def _basename(path):
        return path.rsplit("/", 1)[-1].lower()

    def _select_files(self, paths):
        selected = []

        for path in paths:
            lower = path.lower()
            basename = self._basename(path)

            if basename in self.CONFIG_NAMES:
                selected.append(path)
                continue

            if basename in self.README_NAMES:
                selected.append(path)
                continue

            if basename in self.SECURITY_NAMES:
                selected.append(path)
                continue

            if any(
                lower.startswith(directory)
                for directory in self.PRIORITY_DIRS
            ):
                selected.append(path)
                continue

            if lower.endswith(self.PRIORITY_EXTENSIONS):
                if (
                    "/test/" in lower
                    or "/tests/" in lower
                    or lower.startswith("test/")
                    or lower.startswith("tests/")
                ):
                    selected.append(path)

        def priority(path):
            lower = path.lower()
            basename = self._basename(path)

            if basename in self.SECURITY_NAMES:
                return 0

            if basename in self.CONFIG_NAMES:
                return 1

            if basename in self.README_NAMES:
                return 2

            if lower.startswith(".github/workflows/"):
                return 3

            if lower.startswith("contracts/"):
                return 4

            if lower.startswith("test/") or lower.startswith("tests/"):
                return 5

            if lower.startswith("audit/") or lower.startswith("audits/"):
                return 6

            if lower.startswith("src/"):
                return 7

            return 8

        selected.sort(key=priority)

        return selected[: self.MAX_FILES_TO_READ]

    @staticmethod
    def _classify_stack(paths, configs, language):
        stack = []

        if language:
            stack.append(language)

        joined = "\n".join(paths).lower()

        config_text = "\n".join(
            configs.values()
        ).lower()

        if ".sol" in joined:
            stack.append("Solidity/EVM")

        if "hardhat.config." in joined:
            stack.append("Hardhat")

        if "foundry.toml" in joined:
            stack.append("Foundry")

        if "package.json" in joined:
            stack.append("Node.js")

        if (
            "pyproject.toml" in joined
            or "requirements.txt" in joined
        ):
            stack.append("Python")

        if "go.mod" in joined:
            stack.append("Go")

        if "cargo.toml" in joined:
            stack.append("Rust")

        if "slither" in config_text:
            stack.append("Slither")

        if "echidna" in config_text:
            stack.append("Echidna")

        if "mythril" in config_text:
            stack.append("Mythril")

        if "openzeppelin" in config_text:
            stack.append("OpenZeppelin")

        return list(dict.fromkeys(stack))

    @staticmethod
    def _security_signals(
        paths,
        configs,
        source_text,
    ):
        signals = []

        joined = "\n".join(paths).lower()
        text = (
            "\n".join(configs.values())
            + "\n"
            + source_text
        ).lower()

        if ".sol" in joined:
            signals.append("solidity_code")

        if any(
            p.lower().startswith("contracts/")
            for p in paths
        ):
            signals.append("contracts_directory")

        if any(
            p.lower().startswith("test/")
            or p.lower().startswith("tests/")
            for p in paths
        ):
            signals.append("tests_present")

        if any(
            p.lower().startswith(".github/workflows/")
            for p in paths
        ):
            signals.append("ci_present")

        if any(
            p.lower().split("/")[-1]
            in {
                "security.md",
                "security",
                "security.txt",
            }
            for p in paths
        ):
            signals.append("security_policy")

        patterns = (
            ("slither", "slither"),
            ("mythril", "mythril"),
            ("echidna", "echidna"),
            ("foundry", "foundry"),
            ("hardhat", "hardhat"),
            ("openzeppelin", "openzeppelin"),
            ("fuzz", "fuzzing"),
            ("invariant", "invariant_testing"),
            ("coverage", "coverage"),
            ("codecov", "coverage"),
            ("semgrep", "semgrep"),
        )

        for pattern, signal in patterns:
            if pattern in text:
                signals.append(signal)

        return list(dict.fromkeys(signals))

    @staticmethod
    def _maturity(
        stars,
        source_files,
        tests,
        ci,
        security,
        configs,
        audits,
        fuzzing,
    ):
        score = 0

        if stars >= 10000:
            score += 3
        elif stars >= 1000:
            score += 2
        elif stars >= 100:
            score += 1

        if source_files >= 5:
            score += 1

        if source_files >= 20:
            score += 1

        if tests:
            score += 2

        if ci:
            score += 1

        if security:
            score += 1

        if configs:
            score += 1

        if audits:
            score += 1

        if fuzzing:
            score += 1

        if score >= 9:
            level = "HIGH"
        elif score >= 6:
            level = "MEDIUM"
        else:
            level = "LOW"

        return level, score

    def _inspect_repository(self, repo):
        name = repo.get("name")

        owner, repository = self._repo_parts(name)

        if not owner:
            raise RuntimeError(
                f"Invalid repository name: {name}"
            )

        print(
            f"[Developer] INSPECT: {name}",
            flush=True,
        )

        metadata_url = (
            f"{self.github.BASE_URL}/repos/"
            f"{owner}/{repository}"
        )

        metadata = self._get(metadata_url) or {}

        branch = (
            metadata.get("default_branch")
            or "main"
        )

        tree = self._get_tree(
            owner,
            repository,
            branch,
        )

        if not tree:
            raise RuntimeError(
                "Git tree unavailable"
            )

        truncated = bool(
            tree.get("truncated")
        )

        entries = tree.get("tree", [])

        paths = []

        for entry in entries:
            if entry.get("type") == "blob":
                path = entry.get("path")

                if path:
                    paths.append(path)

        total_files = len(paths)

        selected = self._select_files(paths)

        configs = {}
        readmes = {}
        security_files = {}
        file_errors = []

        for path in selected:
            content = self._get_file(
                owner,
                repository,
                path,
            )

            if content is None:
                file_errors.append(path)
                continue

            content = content[: self.MAX_FILE_SIZE]

            basename = self._basename(path)

            if basename in self.CONFIG_NAMES:
                configs[path] = content

            elif basename in self.README_NAMES:
                readmes[path] = content

            elif basename in self.SECURITY_NAMES:
                security_files[path] = content

        lower_paths = [
            path.lower()
            for path in paths
        ]

        solidity_files = [
            path
            for path in paths
            if path.lower().endswith(".sol")
        ]

        contract_files = [
            path
            for path in solidity_files
            if (
                path.lower().startswith("contracts/")
                or "/contracts/" in path.lower()
            )
        ]

        test_files = [
            path
            for path in paths
            if (
                path.lower().startswith("test/")
                or path.lower().startswith("tests/")
                or "/test/" in path.lower()
                or "/tests/" in path.lower()
                or ".test." in path.lower()
                or ".spec." in path.lower()
            )
        ]

        ci_files = [
            path
            for path in paths
            if path.lower().startswith(
                ".github/workflows/"
            )
        ]

        audit_files = [
            path
            for path in paths
            if (
                "audit" in path.lower()
                or "audits" in path.lower()
            )
        ]

        source_files = [
            path
            for path in paths
            if path.lower().endswith(
                self.PRIORITY_EXTENSIONS
            )
        ]

        source_text = "\n".join(
            list(configs.values())
            + list(readmes.values())
            + list(security_files.values())
        )

        security_signals = self._security_signals(
            paths,
            configs,
            source_text,
        )

        has_tests = bool(test_files)

        has_ci = bool(ci_files)

        has_security = bool(security_files)

        has_audits = bool(audit_files)

        has_fuzzing = any(
            signal in security_signals
            for signal in (
                "fuzzing",
                "invariant_testing",
                "echidna",
            )
        )

        smart_contract = bool(
            solidity_files
            or contract_files
            or "Solidity/EVM" in self._classify_stack(
                paths,
                configs,
                repo.get("language"),
            )
        )

        stack = self._classify_stack(
            paths,
            configs,
            repo.get("language"),
        )

        maturity, maturity_score = self._maturity(
            stars=repo.get("stars", 0),
            source_files=len(source_files),
            tests=has_tests,
            ci=has_ci,
            security=has_security,
            configs=bool(configs),
            audits=has_audits,
            fuzzing=has_fuzzing,
        )

        risk_flags = []

        if smart_contract and not has_tests:
            risk_flags.append(
                "smart_contracts_without_detected_tests"
            )

        if smart_contract and not has_ci:
            risk_flags.append(
                "smart_contracts_without_detected_ci"
            )

        if smart_contract and not has_security:
            risk_flags.append(
                "missing_security_policy"
            )

        if not readmes:
            risk_flags.append(
                "missing_readme"
            )

        if not configs:
            risk_flags.append(
                "no_detected_dependency_or_build_config"
            )

        if truncated:
            risk_flags.append(
                "github_tree_truncated"
            )

        return {
            "name": name,
            "url": repo.get("url"),
            "description": repo.get("description"),
            "stars": repo.get("stars", 0),
            "language": repo.get("language"),
            "updated": repo.get("updated"),
            "default_branch": branch,
            "size_kb": metadata.get("size"),
            "open_issues": metadata.get(
                "open_issues_count"
            ),
            "forks": metadata.get(
                "forks_count"
            ),
            "topics": metadata.get(
                "topics",
                [],
            ),
            "repository_tree": {
                "files_total": total_files,
                "files_selected": len(selected),
                "tree_truncated": truncated,
            },
            "stack": stack,
            "smart_contract_project": smart_contract,
            "solidity_files": len(
                solidity_files
            ),
            "contract_files": len(
                contract_files
            ),
            "source_files": len(
                source_files
            ),
            "test_files": len(
                test_files
            ),
            "ci_files": len(
                ci_files
            ),
            "audit_files": len(
                audit_files
            ),
            "selected_files": selected,
            "config_files": list(
                configs.keys()
            ),
            "security_files": list(
                security_files.keys()
            ),
            "readme_files": list(
                readmes.keys()
            ),
            "has_tests": has_tests,
            "has_ci": has_ci,
            "has_security_policy": has_security,
            "has_audits": has_audits,
            "security_signals": security_signals,
            "risk_flags": risk_flags,
            "technical_maturity": maturity,
            "technical_maturity_score": maturity_score,
            "file_read_errors": file_errors,
        }

    def run(self, task: Task) -> Task:
        task.status = "developing"

        try:
            parent = task.result or {}

            repositories = parent.get(
                "repositories",
                [],
            )

            if not repositories:
                raise RuntimeError(
                    "Developer received no repositories "
                    "from Analyst"
                )

            technical = []
            errors = []

            total = len(repositories)

            print(
                f"[Developer] RECURSIVE TREE INSPECTION "
                f"OF {total} REPOSITORIES",
                flush=True,
            )

            for index, repo in enumerate(
                repositories,
                1,
            ):
                print(
                    f"[Developer] "
                    f"[{index}/{total}] "
                    f"{repo.get('name')}",
                    flush=True,
                )

                try:
                    inspection = (
                        self._inspect_repository(repo)
                    )

                    technical.append(
                        inspection
                    )

                except Exception as exc:
                    error = {
                        "name": repo.get("name"),
                        "url": repo.get("url"),
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    }

                    errors.append(error)

                    print(
                        f"[Developer] ERROR "
                        f"{repo.get('name')}: "
                        f"{type(exc).__name__}: {exc}",
                        flush=True,
                    )

            if not technical:
                raise RuntimeError(
                    "Developer could not inspect "
                    "any repository"
                )

            high = sum(
                item.get(
                    "technical_maturity"
                ) == "HIGH"
                for item in technical
            )

            medium = sum(
                item.get(
                    "technical_maturity"
                ) == "MEDIUM"
                for item in technical
            )

            low = sum(
                item.get(
                    "technical_maturity"
                ) == "LOW"
                for item in technical
            )

            contracts = sum(
                item.get(
                    "smart_contract_project",
                    False,
                )
                for item in technical
            )

            tests = sum(
                item.get(
                    "has_tests",
                    False,
                )
                for item in technical
            )

            ci = sum(
                item.get(
                    "has_ci",
                    False,
                )
                for item in technical
            )

            audits = sum(
                item.get(
                    "has_audits",
                    False,
                )
                for item in technical
            )

            task.result = {
                **parent,
                "technical_review": technical,
                "developer_summary": {
                    "repositories_received": len(
                        repositories
                    ),
                    "repositories_inspected": len(
                        technical
                    ),
                    "inspection_errors": len(
                        errors
                    ),
                    "maturity_high": high,
                    "maturity_medium": medium,
                    "maturity_low": low,
                    "smart_contract_projects": contracts,
                    "projects_with_tests": tests,
                    "projects_with_ci": ci,
                    "projects_with_audits": audits,
                },
                "developer_errors": errors,
                "reviewed_by": self.name,
                "review_type": (
                    "github_recursive_git_tree_inspection"
                ),
            }

            task.status = "developed"

            print(
                f"[Developer] COMPLETE: "
                f"{len(technical)}/{total} inspected",
                flush=True,
            )

        except Exception as exc:
            task.status = "development_failed"

            task.result = {
                "agent": self.name,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }

            print(
                f"[Developer] FATAL: "
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )

        return task

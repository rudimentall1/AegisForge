from shared.task import Task


class OpportunityHunter:
    name = "opportunity_hunter"

    NARRATIVES = {
        "AI": [
            "agent",
            "ai",
            "llm",
            "machine learning",
            "autonomous",
        ],
        "Security": [
            "security",
            "audit",
            "guardian",
            "proof",
            "zk",
        ],
        "DeFi": [
            "defi",
            "yield",
            "swap",
            "liquidity",
            "dex",
        ],
        "Infrastructure": [
            "rpc",
            "node",
            "sdk",
            "protocol",
            "network",
        ],
        "Wallet": [
            "wallet",
            "account abstraction",
            "aa",
            "safe",
        ],
    }

    def _score_repo(self, repo, technical, security):
        score = 0
        reasons = []

        stars = repo.get("stars", 0)

        # Stars are a public-interest signal, not proof of adoption or buyer demand.
        if stars >= 10000:
            score += 20
            reasons.append("strong public interest signal")
        elif stars >= 1000:
            score += 15
            reasons.append("meaningful public interest signal")
        elif stars >= 100:
            score += 8
            reasons.append("public interest signal")

        maturity = technical.get(
            "technical_maturity_score",
            0
        )

        score += min(maturity * 3, 20)

        if maturity >= 6:
            reasons.append("technical maturity")

        posture = security.get(
            "security_posture",
            {}
        )

        security_score = posture.get(
            "score",
            0
        )

        score += security_score // 10

        if security_score >= 80:
            reasons.append("strong security posture")

        if technical.get("has_tests"):
            score += 5
            reasons.append("tests detected")

        if technical.get("has_ci"):
            score += 5
            reasons.append("CI pipeline")

        text = (
            str(repo.get("name", ""))
            + " "
            + str(repo.get("description", ""))
        ).lower()

        categories = []

        for category, words in self.NARRATIVES.items():
            if any(word in text for word in words):
                categories.append(category)
                score += 5

        score = min(score, 100)

        if score >= 75:
            signal = "HIGH"
        elif score >= 45:
            signal = "MEDIUM"
        else:
            signal = "LOW"

        return {
            "opportunity_score": score,
            "signal": signal,
            "categories": categories,
            "reasons": reasons,
        }

    @staticmethod
    def _commercial_dossier(repo, categories, technical, security, analysis):
        """Build a repository-specific opportunity hypothesis from observed evidence.

        This is deliberately deterministic: public popularity is evidence of interest,
        not evidence of a buyer. Every commercial claim is therefore separated from
        observed technical signals and explicit unknowns.
        """
        name = str(repo.get("name") or "unknown")
        description = str(repo.get("description") or "").strip()
        topics = [str(x) for x in (repo.get("topics") or [])]
        stack = [str(x) for x in (technical.get("stack") or [])]
        readme_signal = str(technical.get("readme_signal") or "").strip()
        corpus = " ".join([name, description, " ".join(topics), " ".join(stack), readme_signal]).lower()

        def has(*terms):
            return any(term in corpus for term in terms)

        domain = "general developer infrastructure"
        technology_surface = stack[:4] or [technical.get("language") or "repository"]
        customer = "Engineering teams evaluating or operating this technology."
        problem = "The repository exposes a technical capability, but the buyer problem is not yet established from public evidence."
        product = "A product built around the repository's concrete capability, with the commercial problem validated separately from technical interest."
        validation = "Interview teams using or evaluating this technology; identify a repeated costly workflow and test willingness to pay for a narrowly defined solution."
        model = "B2B SaaS or API pricing tied to the measurable workflow being protected or automated."

        if has("simulation", "simulator", "physical ai", "robotics", "autonomous vehicle", "cosmos", "isaac"):
            domain = "simulation and evaluation for physical/robotic AI"
            technology_surface = [x for x in (stack + topics) if x][:5] or ["simulation"]
            customer = "Robotics, autonomous-vehicle, and physical-AI teams that need repeatable simulation and evaluation before deploying models into the real world."
            problem = f"{description or name} appears to address simulation/evaluation of physical AI; the commercial pain hypothesis is reducing the cost, risk, or iteration time of validating models before real-world deployment."
            product = "A managed evaluation and evidence layer around simulation workloads: scenario management, reproducible runs, failure analysis, and deployment-readiness evidence."
            validation = "Run representative scenarios for one robotics/physical-AI team and measure simulation-to-deployment iteration time, failed-run detection, and infrastructure cost saved."
            model = "Usage-based simulation/evaluation infrastructure with team and enterprise tiers."
        elif has("mcp", "agent", "llm", "tool calling", "autonomous workflow", "orchestration") and not has("security", "vulnerability", "scanner", "audit", "guardian", "exploit"):
            domain = "AI-agent orchestration and control"
            technology_surface = [x for x in (stack + topics) if x][:5] or ["agent runtime"]
            observed_capability = description or readme_signal or name
            customer = f"Users of {name}: {observed_capability}"
            problem = (
                f"Observed capability: {observed_capability}. "
                "Validate its highest-cost production failure, bottleneck, or manual workflow "
                "before asserting a broader buyer problem."
            )
            product = (
                f"Operational product derived from {name}: {observed_capability}"
            )
            validation = (
                f"Test {name} with real users; measure failures, operator time, workflow "
                f"frequency, and willingness to pay around: {observed_capability}"
            )
            model = (
                f"Price the measurable workflow created by {name}; choose usage, workflow, "
                "or seat pricing only after buyer value is demonstrated."
            )
        elif has("security", "vulnerability", "scanner", "audit", "guardian", "policy", "exploit"):
            domain = "software security and continuous assurance"
            technology_surface = [x for x in (stack + topics) if x][:5] or ["security tooling"]
            customer = "Security and engineering teams responsible for software or high-value infrastructure."
            problem = f"{description or name} exposes a security-oriented capability; the commercial pain hypothesis is reducing the time and expertise required to detect, reproduce, prioritize, and remediate actionable risk."
            product = "Continuous assurance that turns repository/runtime evidence into reproducible findings, prioritized remediation, and verifiable closure."
            validation = "Run against representative repositories and compare precision, reproducibility, analyst minutes per finding, and remediation lead time with the existing security workflow."
            model = "B2B SaaS priced by repositories/assets, with enterprise deployment and compliance evidence."
        elif has("wallet", "transaction", "defi", "smart contract", "solidity", "evm", "blockchain", "rpc"):
            domain = "programmable financial and blockchain infrastructure"
            technology_surface = [x for x in (stack + topics) if x][:5] or ["blockchain infrastructure"]
            customer = "Wallet, protocol, infrastructure, and financial-automation teams operating programmable assets."
            problem = f"{description or name} points to blockchain/financial infrastructure; the commercial pain hypothesis is preventing expensive transaction, integration, or operational failures before value-bearing actions execute."
            product = "An evidence and control layer that validates transaction intent, execution context, and operational state before and after value-bearing actions."
            validation = "Replay representative historical transactions or workflows and measure prevented failures, false positives, integration effort, and financial/operational loss avoided."
            model = "API/SDK pricing by protected transaction or execution volume, with enterprise contracts."
        elif has("rpc", "node", "kubernetes", "observability", "operator", "storage", "database", "network"):
            domain = "distributed infrastructure operations"
            technology_surface = [x for x in (stack + topics) if x][:5] or ["infrastructure"]
            customer = "Infrastructure operators and platform teams running distributed services."
            problem = f"{description or name} indicates infrastructure capability; the commercial pain hypothesis is reducing downtime, diagnosis time, and operational toil when distributed components fail or drift."
            product = "Evidence-driven operations that correlates configuration, deployment, and runtime signals into reproducible incident and regression workflows."
            validation = "Monitor one live service and compare incident detection, diagnosis time, false alerts, and operator effort against the existing observability stack."
            model = "Infrastructure SaaS priced by monitored assets/events, with enterprise support and deployment options."
        elif has("dataset", "inference", "training", "embedding", "model", "machine learning"):
            domain = "machine-learning development infrastructure"
            technology_surface = [x for x in (stack + topics) if x][:5] or ["ML infrastructure"]
            customer = "ML engineering teams building, evaluating, or operating models at scale."
            problem = f"{description or name} indicates an ML capability; the commercial pain hypothesis is reducing iteration cost, evaluation uncertainty, or operational failure around model development."
            product = "A reproducible evaluation and operations layer that connects model inputs, runs, outputs, and production evidence."
            validation = "Apply it to one real model workflow and measure evaluation time, reproducibility, infrastructure cost, and production regressions detected."
            model = "Usage-based developer infrastructure with team and enterprise plans."

        maturity = technical.get("technical_maturity_score", 0)
        security_score = security.get("security_posture", {}).get("score", 0)
        evidence = {
            "stars": repo.get("stars", 0),
            "technical_maturity_score": maturity,
            "security_score": security_score,
            "has_tests": bool(technical.get("has_tests")),
            "has_ci": bool(technical.get("has_ci")),
            "stack": technology_surface,
            "topics": topics[:10],
            "repository_description": description,
            "readme_signal": readme_signal,
        }

        uncertainty = []
        if not technical.get("has_tests"):
            uncertainty.append("test coverage is not established")
        if not technical.get("has_ci"):
            uncertainty.append("CI evidence is not established")
        if security and security_score < 60:
            uncertainty.append("security posture requires further validation")
        if not description and not readme_signal:
            uncertainty.append("market/problem context is inferred from technical signals")
        uncertainty.append("willingness to pay and buyer demand are not validated")

        if "test coverage is not established" in uncertainty:
            validation_type = "technical"
        elif "security posture requires further validation" in uncertainty:
            validation_type = "security"
        else:
            validation_type = "commercial"

        return {
            "domain": domain,
            "technology_surface": technology_surface,
            "target_customer": customer,
            "problem_signal": problem,
            "product_thesis": product,
            "validation_experiment": validation,
            "validation_type": validation_type,
            "business_model": model,
            "commercial_moat": "Accumulated repository-specific evidence, validation history, and outcome data can compound into a decision dataset that a one-shot scanner cannot reproduce.",
            "evidence": evidence,
            "uncertainties": uncertainty,
            "source_description": description,
            "commercial_readiness": "VALIDATE" if analysis["opportunity_score"] >= 45 else "EARLY_SIGNAL",
        }

    def run(self, task: Task) -> Task:
        task.status = "hunting_opportunities"

        try:
            result = task.result or {}

            repositories = result.get(
                "repositories",
                []
            )

            technical_reviews = {
                item["name"]: item
                for item in result.get(
                    "technical_review",
                    []
                )
            }

            security_reviews = {
                item["name"]: item
                for item in result.get(
                    "security_reviews",
                    []
                )
            }

            opportunities = []

            for repo in repositories:
                name = repo.get("name")

                analysis = self._score_repo(
                    repo,
                    technical_reviews.get(
                        name,
                        {}
                    ),
                    security_reviews.get(
                        name,
                        {}
                    ),
                )

                dossier = self._commercial_dossier(
                    repo,
                    analysis["categories"],
                    technical_reviews.get(name, {}),
                    security_reviews.get(name, {}),
                    analysis,
                )

                opportunities.append({
                    "name": name,
                    "url": repo.get("url"),
                    **analysis,
                    **dossier,
                })

            opportunities.sort(
                key=lambda x: x["opportunity_score"],
                reverse=True,
            )

            task.result = {
                **result,
                "opportunities": opportunities,
                "evaluated_by": self.name,
            }

            task.status = "opportunities_found"

        except Exception as exc:
            task.status = "opportunity_hunt_failed"

            task.result = {
                "agent": self.name,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }

        return task

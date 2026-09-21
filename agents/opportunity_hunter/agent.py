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

        if stars >= 10000:
            score += 20
            reasons.append("large community")
        elif stars >= 1000:
            score += 15
            reasons.append("good adoption")
        elif stars >= 100:
            score += 8

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
        name = repo.get("name") or "unknown"
        description = str(repo.get("description") or "").strip()
        text = (name + " " + description + " " + " ".join(categories)).lower()

        if "security" in categories or "guardian" in text or "audit" in text:
            customer = "Security teams, protocol developers, and engineering organizations operating high-value software."
            problem = "Security review is fragmented across code, configuration, deployment evidence, and runtime signals, making continuous risk detection expensive."
            product = "Continuous security intelligence that turns repository and runtime evidence into prioritized, explainable remediation workflows."
            validation = "Run the detector against a representative repository set and measure precision, actionable findings, and analyst time saved."
            model = "B2B SaaS with repository/organization tiers and optional enterprise deployment."
        elif "AI" in categories or "agent" in text or "llm" in text:
            customer = "Teams deploying AI agents, agent platforms, and autonomous workflows."
            problem = "Agent behavior, tool permissions, and operational reliability are difficult to observe and control as systems become more autonomous."
            product = "An agent operations layer for evaluating, monitoring, and constraining autonomous workflows before and during execution."
            validation = "Instrument a real agent workflow and compare failure detection and remediation time with the existing manual process."
            model = "Usage-based developer platform with team and enterprise plans."
        elif "Wallet" in categories or "defi" in text or "swap" in text:
            customer = "Wallet providers, DeFi applications, and teams managing programmable financial operations."
            problem = "Users and automated systems need transaction intent and protocol risk evaluated before value-bearing actions are signed."
            product = "A transaction intelligence and policy layer that scores intent, protocol context, and authorization risk before execution."
            validation = "Replay historical transactions and measure how many known risky or anomalous actions would have been intercepted."
            model = "API/SDK pricing by protected transaction volume with enterprise contracts."
        elif "Infrastructure" in categories or "protocol" in text or "rpc" in text:
            customer = "Infrastructure operators and developers building on distributed systems."
            problem = "Infrastructure failures and compatibility risks are discovered late because operational evidence is scattered across code, deployments, and runtime behavior."
            product = "Evidence-driven infrastructure intelligence that detects operational risk and recommends targeted verification."
            validation = "Monitor a live service and compare detected incidents or regressions against its existing observability stack."
            model = "Developer SaaS plus enterprise observability and support."
        else:
            customer = "Engineering teams adopting emerging technology."
            problem = "Teams struggle to convert rapidly changing technical signals into validated product decisions."
            product = "A decision-intelligence layer that combines technical maturity, security, adoption, and validation evidence."
            validation = "Evaluate a fixed set of emerging technologies and compare generated recommendations with expert review."
            model = "Research/developer SaaS with team and enterprise tiers."

        maturity = technical.get("technical_maturity_score", 0)
        security_score = security.get("security_posture", {}).get("score", 0)
        evidence = {
            "stars": repo.get("stars", 0),
            "technical_maturity_score": maturity,
            "security_score": security_score,
            "has_tests": bool(technical.get("has_tests")),
            "has_ci": bool(technical.get("has_ci")),
        }
        uncertainty = []
        if not technical.get("has_tests"):
            uncertainty.append("test coverage is not established")
        if not technical.get("has_ci"):
            uncertainty.append("CI evidence is not established")
        if security and security_score < 60:
            uncertainty.append("security posture requires further validation")
        if not repo.get("description"):
            uncertainty.append("market/problem context is inferred from technical signals")

        return {
            "target_customer": customer,
            "problem_signal": problem,
            "product_thesis": product,
            "validation_experiment": validation,
            "business_model": model,
            "commercial_moat": "Provenance-rich evidence graph and accumulated validation history can make the system harder to replace than a one-shot repository scanner.",
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

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

                opportunities.append({
                    "name": name,
                    "url": repo.get("url"),
                    **analysis,
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

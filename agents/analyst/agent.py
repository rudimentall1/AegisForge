from shared.task import Task


class Analyst:
    name = "analyst"

    @staticmethod
    def _refined_opportunity(repo, opportunity):
        """Add a repository-grounded analytical layer to an existing dossier."""
        description = str(repo.get("description") or "").strip()
        language = repo.get("language") or "unknown"
        topics = repo.get("topics") or []
        evidence = opportunity.get("evidence") or {}
        technical_maturity = evidence.get("technical_maturity_score")
        tests = evidence.get("has_tests")
        ci = evidence.get("has_ci")
        security = evidence.get("security_score")
        capability = description or "Repository capability requires direct inspection."
        if tests is False:
            operational_gap = "Production confidence is constrained by the absence of repository tests; runtime behavior needs independent verification."
        elif ci and technical_maturity is not None and technical_maturity >= 7:
            operational_gap = "Repository maturity is stronger, so the key uncertainty shifts from basic implementation to deployment, integration, and measurable operational value."
        else:
            operational_gap = "The demonstrated capability is not yet equivalent to production readiness; verify behavior in a real workflow under operational constraints."
        criteria = [
            "Can the demonstrated capability be reproduced in a real user workflow?",
            "What measurable failure, cost, latency, or reliability problem does it remove?",
            "Which existing tool or workflow would a buyer replace or augment?",
        ]
        return {
            **opportunity,
            "analysis_layer": "independent_technical_reanalysis",
            "observed_capability": capability,
            "observed_stack": {"language": language, "topics": topics[:12]},
            "operational_gap": operational_gap,
            "decision_criteria": criteria,
            "analyst_assessment": "The repository demonstrates a technical capability, but the commercial thesis remains a hypothesis. This pass separates observed implementation signals from inference and identifies the next evidence required for a decision.",
            "uncertainties": list(opportunity.get("uncertainties") or []) + criteria,
            "evidence": {
                **evidence,
                "repository_description": description,
                "language": language,
                "has_tests": tests,
                "has_ci": ci,
                "security_score": security,
                "technical_maturity_score": technical_maturity,
            },
        }

    @staticmethod
    def _opportunity(repo, analysis):
        text = (
            f"{repo.get('name', '')} {repo.get('description', '')} "
            f"{repo.get('language', '')}"
        ).lower()
        if any(x in text for x in ("agent", "llm", "inference", "autonomous")):
            product = "agent infrastructure or an autonomous workflow product"
            problem = "deployment, orchestration, reliability, or security complexity"
        elif any(x in text for x in ("energy", "battery", "grid", "storage")):
            product = "energy optimization, monitoring, or asset-intelligence software"
            problem = "fragmented operational data and inefficient decision workflows"
        elif any(x in text for x in ("robot", "embodied", "drone")):
            product = "robotics operations, simulation, or fleet-intelligence software"
            problem = "deployment, observability, testing, or fleet coordination"
        elif any(x in text for x in ("security", "audit", "vulnerability", "threat")):
            product = "automated security assurance or continuous risk-intelligence software"
            problem = "security review is expensive, repetitive, and difficult to keep current"
        elif any(x in text for x in ("blockchain", "web3", "defi", "smart contract")):
            product = "transaction, protocol, or agent-security infrastructure"
            problem = "complex state and security signals make safe automation difficult"
        else:
            product = "developer or infrastructure tooling around the discovered technology"
            problem = "technical complexity creates a gap between capability and production adoption"

        return {
            "target": repo.get("name"),
            "url": repo.get("url"),
            "thesis": f"Build {product} around the capability demonstrated by the target.",
            "problem_signal": problem,
            "evidence": {
                "stars": repo.get("stars", 0),
                "priority": analysis.get("priority"),
                "language": repo.get("language"),
                "description": repo.get("description"),
            },
            "validation": "Check users, competing products, adoption, deployment friction, and willingness to pay before implementation.",
        }

    def run(self, task: Task) -> Task:
        task.status = "analyzing"
        try:
            result = task.result or {}
            repositories = result.get("repositories", [])
            existing_opportunities = result.get("opportunities", [])
            analysis = []
            opportunities = []

            if existing_opportunities:
                by_name = {
                    str(item.get("name") or item.get("target")): item
                    for item in existing_opportunities
                    if isinstance(item, dict)
                }
                for repo in repositories:
                    existing = by_name.get(str(repo.get("name") or ""))
                    if existing:
                        opportunities.append(self._refined_opportunity(repo, existing))

            for repo in repositories:
                stars = int(repo.get("stars", 0) or 0)
                if stars >= 500:
                    priority = "HIGH"
                elif stars >= 100:
                    priority = "MEDIUM"
                else:
                    priority = "LOW"

                item = {
                    "name": repo.get("name"),
                    "url": repo.get("url"),
                    "stars": stars,
                    "priority": priority,
                    "language": repo.get("language"),
                    "description": repo.get("description"),
                    "adoption_signal": "strong" if stars >= 1000 else "moderate" if stars >= 100 else "emerging",
                    "activity_signal": "recent" if repo.get("updated") else "unknown",
                }
                analysis.append(item)
                if not existing_opportunities:
                    opportunities.append(self._opportunity(repo, item))

            task.result = {
                "agent": self.name,
                "task": task.description,
                "research_scope": result.get("research_scope", "technology_intelligence"),
                "repositories": repositories,
                "analysis": analysis,
                "opportunities": opportunities[:10],
                "count": len(analysis),
            }
            task.status = "analyzed"
        except Exception as exc:
            task.status = "analysis_failed"
            task.result = {
                "agent": self.name,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        return task

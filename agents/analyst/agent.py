from shared.task import Task


class Analyst:
    name = "analyst"

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
            analysis = []
            opportunities = []

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

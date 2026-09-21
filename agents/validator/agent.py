from shared.task import Task
from shared.github_client import GitHubClient

class Validator:
    """Run bounded, reproducible validation experiments on opportunity dossiers."""
    name = "validator"
    MAX_OPPORTUNITIES = 4
    PROBE_PATHS = ("README.md", "SECURITY.md", "pyproject.toml", "package.json",
                   "Cargo.toml", "go.mod", ".github/workflows")

    def _repo_parts(self, opportunity):
        value = opportunity.get("name") or opportunity.get("repository") or ""
        if "/" not in value:
            url = str(opportunity.get("url") or "")
            if "github.com/" in url:
                value = url.split("github.com/", 1)[1].split("#", 1)[0].split("?", 1)[0]
        parts = value.strip("/").split("/")
        return (parts[0], parts[1]) if len(parts) == 2 else (None, None)

    def _validate_repo(self, opportunity, client):
        owner, repo = self._repo_parts(opportunity)
        if not owner or not repo:
            return {"name": opportunity.get("name"), "status": "BLOCKED",
                    "experiment": "repository_identity",
                    "reason": "repository identity could not be resolved"}
        result = {"name": opportunity.get("name"), "experiment": "technical_reproducibility",
                  "status": "VALIDATED", "checks": []}
        try:
            metadata = client.get_json(
                f"{client.BASE_URL}/repos/{owner}/{repo}", cache_ttl=1800, timeout=20)
            if not metadata:
                result.update(status="BLOCKED", reason="repository metadata unavailable")
                return result
            result["checks"].append({"check": "repository_exists", "passed": True})
            result["default_branch"] = metadata.get("default_branch")
            result["archived"] = bool(metadata.get("archived"))
            result["stars_observed"] = int(metadata.get("stargazers_count") or 0)
            result["forks_observed"] = int(metadata.get("forks_count") or 0)
            tree = client.get_json(
                f"{client.BASE_URL}/repos/{owner}/{repo}/git/trees/{metadata.get('default_branch') or 'HEAD'}",
                params={"recursive": "1"}, cache_ttl=1800, timeout=20)
            paths = {item.get("path") for item in (tree or {}).get("tree", [])
                     if isinstance(item, dict) and item.get("path")}
            matched = [p for p in self.PROBE_PATHS
                       if p in paths or any(x.startswith(p + "/") for x in paths)]
            result["checks"].append({"check": "canonical_files_probe", "passed": bool(matched),
                                     "matched": matched[:8]})
            result["source"] = "github_api"
            result["reproducibility"] = "PASS" if matched else "PARTIAL"
            if not matched:
                result.update(status="PARTIAL",
                              reason="repository exists but canonical implementation evidence was not found")
        except Exception as exc:
            result.update(status="DEFERRED", source="github_api",
                          reason=f"{type(exc).__name__}: {str(exc)[:240]}")
        return result

    def run(self, task: Task) -> Task:
        task.status = "validating"
        try:
            result = dict(task.result or {})
            opportunities = [x for x in result.get("opportunities", [])
                             if isinstance(x, dict)][:self.MAX_OPPORTUNITIES]
            if not opportunities:
                task.status = "validation_failed"
                task.result = {"agent": self.name, "error_type": "NoOpportunities",
                               "error": "no opportunity dossier available"}
                return task
            client = GitHubClient()
            validations = [self._validate_repo(x, client) for x in opportunities]
            for opportunity, validation in zip(opportunities, validations):
                opportunity["validation_status"] = validation.get("status")
                opportunity["validation_reproducibility"] = validation.get("reproducibility")
            result["opportunities"] = opportunities
            result["validation_results"] = validations
            result["validation_summary"] = {
                "experiments": len(validations),
                "validated": sum(v.get("status") == "VALIDATED" for v in validations),
                "partial": sum(v.get("status") == "PARTIAL" for v in validations),
                "deferred": sum(v.get("status") == "DEFERRED" for v in validations),
                "blocked": sum(v.get("status") == "BLOCKED" for v in validations),
            }
            result["validated_by"] = self.name
            task.result, task.status = result, "validated"
        except Exception as exc:
            task.status = "validation_failed"
            task.result = {"agent": self.name, "error_type": type(exc).__name__,
                           "error": str(exc)}
        return task

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from shared.github_client import GitHubClient
from shared.public_source import fetch_public_source
from shared.task import Task


SEED_SOURCES = (
    ("https://blog.ethereum.org/en/2015/08/04/ethereum-protocol-update-1", "ethereum_foundation"),
    ("https://1inch.com/blog/post/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool", "1inch_research"),
    ("https://blog.ethereum.org/2015/08/07/security-alert-1-windowsalethzero-2", "ethereum_foundation"),
    ("https://blog.ethereum.org/2016/06/24/security-alert-smart-contract-wallets-created-in-frontier-are-vulnerable-to-phishing-attacks", "ethereum_foundation"),
)
SEARCH_QUERY_ROUNDS = (
    ('"Profanity" "32-bit" vulnerability', '"Ethereum" "regenerate all of your keys"'),
    ('"Profanity" private key recovery', '"C++ 0.9.36" Ethereum key'),
    ("Ethereum early client weak key generation security", "Ethereum wallet random generator vulnerability"),
)

HISTORICAL_REPOSITORIES = (
    {
        "owner": "johguse",
        "repo": "profanity",
        "ref": "v1.50",
        "expected_commit_sha": "0b54ffc86aafbb206675b4bfecb2ea09ac7a79f6",
        "revision_role": "pre_disclosure_release",
        "files": ("Dispatcher.cpp", "Dispatcher.hpp", "profanity.cpp", "README.md"),
    },
    {
        "owner": "johguse",
        "repo": "profanity",
        "ref": "master",
        "expected_commit_sha": "186b9b27ab3e24a1899f648adcabcbf0e5f3131e",
        "revision_role": "post_disclosure_archive",
        "files": ("Dispatcher.cpp", "Dispatcher.hpp", "profanity.cpp", "README.md"),
    },
)


class SourceResearcher:
    """Collect primary-source candidates; retrieved text remains untrusted data."""

    name = "source_researcher"
    MAX_SEARCH_RESULTS_PER_QUERY = 5
    MAX_SOURCES = 20
    MAX_LEADS = 20
    MIN_DIRECT_RELEVANCE_SIGNALS = 1
    MIN_CONTEXT_RELEVANCE_SIGNALS = 2

    def __init__(self, github=None, fetcher=fetch_public_source):
        self.github = github or GitHubClient()
        self.fetcher = fetcher

    @staticmethod
    def source_id(url):
        return hashlib.sha256(str(url).encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _classification(url, title, text):
        if not any(str(value or "").strip() for value in (url, title, text)):
            return "inconclusive_missing_evidence"
        haystack = f"{url} {title or ''} {text or ''}".lower()
        # Normalize punctuation for phrases such as "vanity-address-tool".
        normalized = " ".join(haystack.replace("-", " ").split())
        # Explicit negative controls must win over the presence of keywords:
        # a sentence saying a generation path is absent is not positive evidence.
        explicit_negative_context = any(
            phrase in normalized
            for phrase in (
                "no vanity address", "no key generation",
                "does not describe key generation", "not a key generation",
                "no cryptographic use", "unrelated documentation",
            )
        )
        if explicit_negative_context:
            return "unclassified_source"
        profanity_context = "profanity" in normalized
        seed_space_signal = any(term in normalized for term in ("32 bit", "4 bln", "seed"))
        # "private key" can appear in tests or storage notes. Require a
        # generation-path reference, or a named vanity-generator source plus
        # an explicit seed-space and RNG signal.
        key_generation_context = any(
            term in normalized
            for term in ("key generation", "createseed", "vanity key", "vanity address", "vanity address tool", "affected generator")
        )
        # A project name plus seed/key vocabulary is not enough. Require an
        # explicit RNG/implementation signal so unrelated documentation cannot
        # become a security finding from lexical overlap alone.
        rng_implementation_signal = any(
            term in haystack
            for term in (
                "mt19937_64", "random_device", "random 32 bit vector",
                "random number generator", "reduced set of rng initializations",
                "weak prng", "weak random", "rng initialization",
            )
        )
        if profanity_context and seed_space_signal and key_generation_context and rng_implementation_signal:
            return "vanity_generator_entropy_weakness_report"
        if "regenerate all of your keys" in haystack or ("c++ 0.9.36" in haystack and "go 1.0 rc" in haystack):
            return "early_client_key_generation_warning"
        if "key files" in haystack and ("not be written" in haystack or "underlying key" in haystack):
            return "key_file_creation_or_storage_issue"
        if "smart contract wallet" in haystack and "phishing" in haystack:
            return "smart_contract_wallet_logic_issue"
        return "unclassified_source"

    @staticmethod
    def _focused_excerpt(text, maximum=900):
        text = " ".join(str(text or "").split())
        lower = text.lower()
        for marker in ("createseed", "random_device", "mt19937_64", "uniform_int_distribution", "regenerate all of your keys", "32-bit", "4 bln", "key files", "smart contract wallet", "phishing"):
            start = lower.find(marker)
            if start >= 0:
                left = max(0, start - 180)
                return text[left:left + maximum]
        return text[:maximum]

    def _fetch_pinned_repository_sources(self, existing, existing_pins):
        """Fingerprint source files at an immutable upstream commit; never execute downloaded code."""
        sources = []
        pins = list(existing_pins or [])
        errors = []
        for repository in HISTORICAL_REPOSITORIES:
            owner, repo, ref = repository["owner"], repository["repo"], repository["ref"]
            pin = next((item for item in pins if item.get("repository") == f"{owner}/{repo}" and item.get("requested_ref") == ref), None)
            expected_sha = str(repository.get("expected_commit_sha") or "").lower()
            if pin and pin.get("commit_sha"):
                commit_sha = str(pin["commit_sha"]).lower()
                if expected_sha and commit_sha != expected_sha:
                    errors.append({
                        "repository": f"{owner}/{repo}",
                        "requested_ref": ref,
                        "error_type": "PinnedRevisionMismatch",
                        "error": "stored_pin_does_not_match_expected_historical_revision",
                    })
                    continue
            else:
                endpoint = f"{self.github.BASE_URL}/repos/{owner}/{repo}/commits/{ref}"
                try:
                    commit = self.github.get_json(
                        endpoint, cache_ttl=3600, timeout=20, resource="core"
                    ) or {}
                    commit_sha = str(commit.get("sha") or "")
                    if len(commit_sha) != 40 or any(ch not in "0123456789abcdefABCDEF" for ch in commit_sha):
                        raise ValueError("upstream_commit_sha_missing_or_invalid")
                    commit_sha = commit_sha.lower()
                    if expected_sha and commit_sha != expected_sha:
                        raise ValueError("upstream_ref_sha_mismatch")
                    pin = {
                        "repository": f"{owner}/{repo}",
                        "requested_ref": ref,
                        "revision_role": repository.get("revision_role", "historical_reference"),
                        "expected_commit_sha": expected_sha or None,
                        "commit_sha": commit_sha,
                        "commit_url": f"https://github.com/{owner}/{repo}/commit/{commit_sha}",
                        "source_files": list(repository["files"]),
                        "pin_status": "immutable_commit_sha",
                    }
                    pins.append(pin)
                except Exception as exc:
                    errors.append({
                        "repository": f"{owner}/{repo}",
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:240],
                    })
                    continue

            for file_path in repository["files"]:
                source_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{commit_sha}/{file_path}"
                if source_url in existing and existing[source_url].get("status_code") == 200 and existing[source_url].get("content_sha256"):
                    sources.append(dict(existing[source_url]))
                    continue
                try:
                    fetched = self.fetcher(source_url)
                    text = fetched.pop("text", "") or fetched.get("excerpt", "")
                    sources.append({
                        "source_id": self.source_id(source_url),
                        "source_url": source_url,
                        "final_url": fetched.get("final_url") or source_url,
                        "source_family": "historical_implementation",
                        "source_kind": "pinned_repository_source",
                        "repository": f"{owner}/{repo}",
                        "repository_ref": ref,
                        "revision_role": repository.get("revision_role", "historical_reference"),
                        "revision_sha": commit_sha,
                        "revision_url": f"https://github.com/{owner}/{repo}/tree/{commit_sha}",
                        "source_file_path": file_path,
                        "title": fetched.get("title") or f"{owner}/{repo}/{file_path}",
                        "status_code": fetched.get("status_code"),
                        "fetch_status": fetched.get("fetch_status", "unknown"),
                        "content_sha256": fetched.get("content_sha256"),
                        "content_bytes": fetched.get("content_bytes"),
                        "retrieved_at": fetched.get("retrieved_at"),
                        "text_excerpt": self._focused_excerpt(text),
                        "classification": "pinned_historical_implementation_source",
                        "source_status_note": "Immutable source snapshot; retrieval and hashing do not prove vulnerability or execute code.",
                    })
                except Exception as exc:
                    errors.append({
                        "repository": f"{owner}/{repo}",
                        "revision_sha": commit_sha,
                        "file_path": file_path,
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:240],
                    })
        return sources, pins, errors

    def _fetch_seed_source(self, url, source_family, existing):
        old = existing.get(url)
        if old and old.get("status_code") == 200 and old.get("content_sha256"):
            return old
        try:
            fetched = self.fetcher(url)
            text = fetched.pop("text", "") or fetched.get("excerpt", "")
            return {
                "source_id": self.source_id(url),
                "source_url": url,
                "final_url": fetched.get("final_url") or url,
                "source_family": source_family,
                "source_kind": "official_publication",
                "title": fetched.get("title"),
                "status_code": fetched.get("status_code"),
                "fetch_status": fetched.get("fetch_status", "unknown"),
                "content_sha256": fetched.get("content_sha256"),
                "content_bytes": fetched.get("content_bytes"),
                "retrieved_at": fetched.get("retrieved_at"),
                "text_excerpt": self._focused_excerpt(text),
                "classification": self._classification(url, fetched.get("title"), text),
                "source_status_note": "Retrieval confirms availability, not the truth of every claim.",
            }
        except Exception as exc:
            return {
                "source_id": self.source_id(url), "source_url": url,
                "source_family": source_family, "source_kind": "official_publication",
                "fetch_status": "fetch_error", "status_code": None, "content_sha256": None,
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
                "classification": "unclassified_source", "fetch_error_type": type(exc).__name__,
            }

    @staticmethod
    def _lead_relevance(title, body, repository_url="", item_url=""):
        """Conservative triage: discovery leads need a crypto/key-generation signal."""
        haystack = f"{title or ''} {body or ''} {repository_url or ''}".lower()
        direct_signals = (
            "regenerate all of your keys", "weak key generation",
            "key generation", "private key", "seed space", "entropy",
            "secp256k1", "vanity address", "boost::random_device",
            "key derivation", "ethereum client", "wallet key",
        )
        context_signals = (
            "ethereum", "evm", "wallet", "cryptography", "cryptographic",
            "randomness", "blockchain", "seed", "keypair", "key pair",
        )
        title_text = str(title or "").lower()
        body_text = f"{body or ''} {repository_url or ''}".lower()
        direct = [term for term in direct_signals if term in haystack]
        context = [term for term in context_signals if term in haystack]
        title_direct = [term for term in direct_signals if term in title_text]
        chain_context = (
            "ethereum", "evm", "secp256k1", "go-ethereum", "ethereum client",
            "geth", "profanity", "vanity address", "ethereum wallet",
        )
        title_chain = [term for term in chain_context if term in title_text]
        body_chain = [term for term in chain_context if term in body_text]
        self_project = "github.com/rudimentall1/aegisforge/" in str(item_url or "").lower()
        relevant = not self_project and bool(title_direct) and bool(title_chain or body_chain)
        signals = {
            "direct": direct, "context": context,
            "title_direct": title_direct, "title_chain_context": title_chain,
            "body_chain_context": body_chain,
        }
        return relevant, signals

    def _search_issue_leads(self, query):
        data = self.github.get_json(
            f"{self.github.BASE_URL}/search/issues",
            params={"q": query, "per_page": self.MAX_SEARCH_RESULTS_PER_QUERY, "sort": "updated", "order": "desc"},
            cache_ttl=3600, timeout=20, resource="search",
        ) or {}
        leads = []
        filtered_count = 0
        for item in data.get("items", [])[:self.MAX_SEARCH_RESULTS_PER_QUERY]:
            source_url = item.get("html_url")
            if not source_url:
                filtered_count += 1
                continue
            title = item.get("title")
            body = str(item.get("body") or "")
            relevant, signals = self._lead_relevance(title, body, item.get("repository_url", ""), source_url)
            if not relevant:
                filtered_count += 1
                continue
            leads.append({
                "lead_id": self.source_id(source_url), "source_url": source_url,
                "api_url": item.get("url"), "repository_api_url": item.get("repository_url"),
                "title": title,
                "relevance": "keyword_screened_candidate",
                "relevance_signals": signals,
                "kind": "pull_request" if item.get("pull_request") else "issue",
                "created_at": item.get("created_at"), "updated_at": item.get("updated_at"),
                "excerpt": body[:900],
                "evidence_role": "discovery_lead_only",
                "warning": "Search results are leads, not independently validated technical claims.",
            })
        return leads, filtered_count

    def run(self, task: Task) -> Task:
        task.status = "researching_sources"
        parent = dict(task.result or {})
        round_number = int(parent.get("source_search_rounds", 0) or 0) + 1
        queries = SEARCH_QUERY_ROUNDS[min(round_number - 1, len(SEARCH_QUERY_ROUNDS) - 1)]
        sources_by_url = {
            item.get("source_url"): dict(item)
            for item in parent.get("sources", [])
            if isinstance(item, dict) and item.get("source_url")
        }
        for url, family in SEED_SOURCES:
            if len(sources_by_url) < self.MAX_SOURCES:
                source = self._fetch_seed_source(url, family, sources_by_url)
                sources_by_url[source["source_url"]] = source

        repository_pins = list(parent.get("repository_pins", []))
        pinned_sources, repository_pins, repository_pin_errors = self._fetch_pinned_repository_sources(
            sources_by_url, repository_pins
        )
        for source in pinned_sources:
            if len(sources_by_url) < self.MAX_SOURCES:
                sources_by_url[source["source_url"]] = source

        leads_by_url = {
            item.get("source_url"): dict(item)
            for item in parent.get("source_leads", [])
            if isinstance(item, dict) and item.get("source_url")
        }
        search_errors = list(parent.get("source_search_errors", []))
        query_history = list(parent.get("source_queries", []))
        filtered_lead_count = int(parent.get("filtered_source_lead_count", 0) or 0)
        for query in queries:
            query_history.append({"round": round_number, "query": query})
            try:
                leads, filtered_count = self._search_issue_leads(query)
                filtered_lead_count += filtered_count
                for lead in leads:
                    leads_by_url.setdefault(lead["source_url"], lead)
                    if len(leads_by_url) >= self.MAX_LEADS:
                        break
            except Exception as exc:
                search_errors.append({"round": round_number, "query": query, "error_type": type(exc).__name__, "error": str(exc)[:300]})

        result = dict(parent)
        result.pop("research_validation", None)
        result.update({
            "research_track": "evm_key_forensics", "stage": "sources",
            "objective": parent.get("objective") or task.description or "Research historical EVM key-generation weaknesses from primary sources.",
            "source_search_rounds": round_number,
            "sources": list(sources_by_url.values())[:self.MAX_SOURCES],
            "repository_pins": repository_pins,
            "repository_pin_errors": repository_pin_errors[-12:],
            "source_leads": list(leads_by_url.values())[:self.MAX_LEADS],
            "source_queries": query_history[-12:], "source_search_errors": search_errors[-12:],
            "filtered_source_lead_count": filtered_lead_count,
            "source_summary": {
                "sources_collected": len(sources_by_url),
                "sources_fetched_http_200": sum(item.get("status_code") == 200 for item in sources_by_url.values()),
                "pinned_repository_files": sum(item.get("source_kind") == "pinned_repository_source" for item in sources_by_url.values()),
                "pinned_repository_revisions": len(repository_pins),
                "repository_pin_errors": len(repository_pin_errors),
                "search_leads": len(leads_by_url), "filtered_search_leads": filtered_lead_count,
                "round": round_number,
            },
            "scope_guards": {
                "public_sources_only": True, "synthetic_experiments_only": True,
                "no_real_wallet_key_recovery": True, "no_target_list_of_live_addresses": True,
            },
            "next_research_questions": [
                "Pin exact historical client or generator revisions for source-supported claims.",
                "Separate weak generation from missing key files, weak user secrets, contract bugs, and key theft.",
                "Never infer a weak key from address age, balance, inactivity, or vanity appearance alone.",
            ],
        })
        task.result = result
        task.status = "source_researched"
        return task

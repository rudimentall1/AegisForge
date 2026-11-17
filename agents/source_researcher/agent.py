from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from shared.github_client import GitHubClient
from shared.public_source import fetch_public_source
from shared.task import Task
from shared.research_case import research_case_binding, validate_task_binding
from tools.evm_key_forensics.solidity_source_pattern import (
    PINNED_COMMIT,
    PINNED_GIT_BLOB_SHA1,
    PINNED_PATH,
    PINNED_REPOSITORY,
    inspect_source,
)
from tools.evm_key_forensics.uniswap_v2_factory_source_pattern import (
    PINNED_COMMIT as UNISWAP_FACTORY_COMMIT,
    PINNED_GIT_BLOB_SHA1 as UNISWAP_FACTORY_GIT_BLOB_SHA1,
    PINNED_PATH as UNISWAP_FACTORY_PATH,
    PINNED_REPOSITORY as UNISWAP_FACTORY_REPOSITORY,
    CONTRACT_ADDRESS as UNISWAP_FACTORY_ADDRESS,
    CHAIN_ID as UNISWAP_FACTORY_CHAIN_ID,
    EXPLORER_URL as UNISWAP_FACTORY_EXPLORER_URL,
    inspect_source as inspect_uniswap_factory_source,
)


SEED_SOURCES = (
    ("https://blog.ethereum.org/en/2015/08/04/ethereum-protocol-update-1", "ethereum_foundation"),
    ("https://1inch.com/blog/post/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool", "1inch_research"),
    ("https://blog.ethereum.org/2015/08/07/security-alert-1-windowsalethzero-2", "ethereum_foundation"),
    ("https://blog.ethereum.org/2016/06/24/security-alert-smart-contract-wallets-created-in-frontier-are-vulnerable-to-phishing-attacks", "ethereum_foundation"),
)
PROFANITY_SEED_SOURCES = (
    ("https://1inch.com/blog/post/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool", "1inch_disclosure"),
    ("https://github.com/johguse/profanity/issues/61", "upstream_maintainer_disclosure"),
    ("https://github.com/advisories/GHSA-9q2f-7hm7-62h6", "github_security_advisory"),
    ("https://nvd.nist.gov/vuln/detail/CVE-2022-40769", "nvd_cve_record"),
)
PROFANITY_SEARCH_QUERY_ROUNDS = (
    ('repo:johguse/profanity "private key safety"', '"Profanity" "createSeed" "mt19937_64"'),
    ('"CVE-2022-40769" Profanity', '"GHSA-9q2f-7hm7-62h6"'),
    ('"johguse/profanity" "random_device"', '"Profanity" "seed space" Ethereum'),
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
                "no vanity address or key generation path is described",
                "no key generation path is described",
                "does not describe key generation", "not a key generation",
                "no random generator or key generation implementation details",
                "no cryptographic use", "unrelated documentation",
                "not evidence of the affected generator",
                "unrelated to any production code",
                "has no createseed function", "no createseed function",
                "does not implement profanity", "unrelated to vanity generation",
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
            term in normalized
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

    @staticmethod
    def _seed_source_kind(url):
        normalized = str(url or "").lower()
        if "github.com/johguse/profanity/issues/" in normalized:
            return "maintainer_issue"
        if "github.com/advisories/" in normalized:
            return "security_advisory"
        if "nvd.nist.gov/vuln/detail/" in normalized:
            return "vulnerability_database_record"
        if "1inch.com/" in normalized:
            return "disclosure_analysis"
        return "official_publication"

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
                "source_kind": self._seed_source_kind(url),
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
                "source_family": source_family, "source_kind": self._seed_source_kind(url),
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

    def _run_solidity_source_fixture(self, task: Task, research_case) -> Task:
        """Load the checked-in immutable source fixture; never fetch or execute it."""
        payload = task.payload if isinstance(task.payload, dict) else {}
        case_id = payload.get("research_case_id")
        case = validate_task_binding(research_case, case_id)
        target_commit = str(getattr(case, "target_commit", "") or "")
        fixture_path = (
            Path(__file__).resolve().parents[2]
            / "tests" / "fixtures" / "solidity" / "Ownable.sol"
        )
        parent = dict(task.result or {})
        try:
            raw = fixture_path.read_bytes()
            source = raw.decode("utf-8")
            observation = inspect_source(
                source,
                source_commit=target_commit,
                source_path=PINNED_PATH,
            )
            source_read_ok = True
        except (OSError, UnicodeDecodeError) as exc:
            raw = b""
            observation = {
                "schema_version": "aegisforge-solidity-source-observation-v1",
                "repository": PINNED_REPOSITORY,
                "source_commit": target_commit,
                "source_path": PINNED_PATH,
                "conclusion": "INCONCLUSIVE",
                "errors": [f"fixture_read_failed:{type(exc).__name__}"],
                "finding": False,
                "vulnerability_confirmed": False,
                "source_executed": False,
            }
            source_read_ok = False

        source_url = (
            f"https://github.com/{PINNED_REPOSITORY}/blob/"
            f"{PINNED_COMMIT}/{PINNED_PATH}"
        )
        source_record = {
            "source_id": hashlib.sha256(source_url.encode("utf-8")).hexdigest()[:16],
            "source_url": source_url,
            "source_kind": "pinned_repository_source",
            "source_origin": "repository_checked_in_fixture",
            "repository": PINNED_REPOSITORY,
            "revision_sha": PINNED_COMMIT,
            "case_target_commit": target_commit,
            "source_file_path": PINNED_PATH,
            "fetch_status": "local_fixture_loaded" if source_read_ok else "local_fixture_unavailable",
            "content_bytes": len(raw),
            "content_sha256": hashlib.sha256(raw).hexdigest() if source_read_ok else None,
            "git_blob_sha1": observation.get("source_git_blob_sha1"),
            "classification": "solidity_access_control_negative_control",
            "source_status_note": (
                "Exact upstream source fixture; no HTTP fetch, compilation, or execution. "
                "A source pattern match is not a vulnerability finding."
            ),
        }
        result = dict(parent)
        result.update({
            "research_track": "solidity_source_fixture",
            "stage": "sources",
            "stage_history": list(parent.get("stage_history", [])) + ["source_research"],
            "research_case_binding": research_case_binding(case),
            "source_observation": observation,
            "sources": [source_record],
            "repository_pins": [{
                "repository": PINNED_REPOSITORY,
                "requested_ref": PINNED_COMMIT,
                "commit_sha": PINNED_COMMIT,
                "source_path": PINNED_PATH,
                "git_blob_sha1": PINNED_GIT_BLOB_SHA1,
                "pin_status": "immutable_commit_and_blob",
            }],
            "source_summary": {
                "sources_collected": 1 if source_read_ok else 0,
                "pinned_repository_files": 1 if source_read_ok else 0,
                "http_requests": 0,
            },
            "scope_guards": {
                "public_sources_only": True,
                "synthetic_experiments_only": True,
                "no_real_wallet_key_recovery": True,
                "no_live_network_access": True,
                "source_executed": False,
            },
        })
        task.result = result
        task.status = "source_researched"
        return task

    def _run_uniswap_v2_factory_fixture(self, task: Task, research_case) -> Task:
        """Load the pinned Uniswap V2 Factory source and provenance offline."""
        payload = task.payload if isinstance(task.payload, dict) else {}
        case_id = payload.get("research_case_id")
        case = validate_task_binding(research_case, case_id)
        target_commit = str(getattr(case, "target_commit", "") or "")
        root = Path(__file__).resolve().parents[2]
        fixture_path = root / "tests" / "fixtures" / "solidity" / "UniswapV2Factory.sol"
        manifest_path = root / "tests" / "fixtures" / "solidity" / "UniswapV2Factory.provenance.json"
        parent = dict(task.result or {})
        errors = []
        try:
            raw = fixture_path.read_bytes()
            source = raw.decode("utf-8")
            manifest_raw = manifest_path.read_bytes()
            manifest = json.loads(manifest_raw.decode("utf-8"))
            observation = inspect_uniswap_factory_source(
                source,
                source_commit=target_commit,
                source_path=UNISWAP_FACTORY_PATH,
            )
            case_scope_digest = hashlib.sha256(manifest_raw).hexdigest()
            provenance_matches = (
                manifest.get("schema_version") == "aegisforge-verified-source-provenance-v1"
                and manifest.get("chain_id") == UNISWAP_FACTORY_CHAIN_ID
                and manifest.get("contract_address") == UNISWAP_FACTORY_ADDRESS
                and manifest.get("explorer", {}).get("url") == UNISWAP_FACTORY_EXPLORER_URL
                and manifest.get("explorer", {}).get("reported_status") == "Source Code Verified Exact Match"
                and manifest.get("upstream_source", {}).get("repository") == UNISWAP_FACTORY_REPOSITORY
                and manifest.get("upstream_source", {}).get("commit") == UNISWAP_FACTORY_COMMIT
                and manifest.get("upstream_source", {}).get("path") == UNISWAP_FACTORY_PATH
                and manifest.get("upstream_source", {}).get("git_blob_sha1") == UNISWAP_FACTORY_GIT_BLOB_SHA1
                and case_scope_digest == getattr(case, "scope_digest", None)
                and getattr(case, "scope_url", None) == UNISWAP_FACTORY_EXPLORER_URL
                and target_commit == UNISWAP_FACTORY_COMMIT
            )
            if not provenance_matches:
                errors.append("case_or_provenance_manifest_mismatch")
                observation["errors"] = list(observation.get("errors", [])) + errors
                observation["conclusion"] = "INCONCLUSIVE"
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raw = b""
            manifest = {}
            provenance_matches = False
            observation = {
                "schema_version": "aegisforge-uniswap-v2-factory-observation-v1",
                "target_id": "uniswap-v2-factory-mainnet",
                "repository": UNISWAP_FACTORY_REPOSITORY,
                "source_commit": target_commit,
                "source_path": UNISWAP_FACTORY_PATH,
                "conclusion": "INCONCLUSIVE",
                "errors": [f"fixture_or_manifest_read_failed:{type(exc).__name__}"],
                "finding": False,
                "vulnerability_confirmed": False,
                "rpc_used": False,
                "source_executed": False,
            }
        source_url = (
            f"https://github.com/{UNISWAP_FACTORY_REPOSITORY}/blob/"
            f"{UNISWAP_FACTORY_COMMIT}/{UNISWAP_FACTORY_PATH}"
        )
        source_record = {
            "source_id": hashlib.sha256(source_url.encode("utf-8")).hexdigest()[:16],
            "source_url": source_url,
            "source_kind": "pinned_explorer_verified_source",
            "source_origin": "repository_checked_in_fixture",
            "repository": UNISWAP_FACTORY_REPOSITORY,
            "revision_sha": UNISWAP_FACTORY_COMMIT,
            "case_target_commit": target_commit,
            "source_file_path": UNISWAP_FACTORY_PATH,
            "fetch_status": "local_fixture_loaded" if raw else "local_fixture_unavailable",
            "content_bytes": len(raw),
            "content_sha256": hashlib.sha256(raw).hexdigest() if raw else None,
            "git_blob_sha1": observation.get("source_git_blob_sha1"),
            "contract_address": UNISWAP_FACTORY_ADDRESS,
            "chain_id": UNISWAP_FACTORY_CHAIN_ID,
            "explorer_verification_status": manifest.get("explorer", {}).get("reported_status"),
            "provenance_manifest_sha256": (
                hashlib.sha256(manifest_raw).hexdigest() if "manifest_raw" in locals() else None
            ),
            "provenance_matches_case": provenance_matches,
            "source_status_note": (
                "Pinned local source; Etherscan provenance is recorded in a checked-in manifest. "
                "No explorer or RPC request is made by this runner."
            ),
        }
        result = dict(parent)
        result.update({
            "research_track": "uniswap_v2_factory_fixture",
            "stage": "sources",
            "stage_history": list(parent.get("stage_history", [])) + ["source_research"],
            "research_case_binding": research_case_binding(case),
            "source_observation": observation,
            "sources": [source_record],
            "repository_pins": [{
                "repository": UNISWAP_FACTORY_REPOSITORY,
                "requested_ref": UNISWAP_FACTORY_COMMIT,
                "commit_sha": UNISWAP_FACTORY_COMMIT,
                "source_path": UNISWAP_FACTORY_PATH,
                "git_blob_sha1": UNISWAP_FACTORY_GIT_BLOB_SHA1,
                "pin_status": "immutable_commit_and_blob",
            }],
            "source_summary": {
                "sources_collected": 1 if raw else 0,
                "pinned_repository_files": 1 if raw else 0,
                "http_requests": 0,
            },
            "scope_guards": {
                "public_sources_only": True,
                "synthetic_experiments_only": True,
                "no_real_wallet_key_recovery": True,
                "no_live_network_access": True,
                "source_executed": False,
                "rpc_used": False,
                "transactions_sent": False,
            },
        })
        task.result = result
        task.status = "source_researched"
        return task

    def run(self, task: Task) -> Task:
        task.status = "researching_sources"
        parent = dict(task.result or {})
        payload = task.payload if isinstance(task.payload, dict) else {}
        research_case = payload.get("research_case")
        target_repository = str(getattr(research_case, "target_repository", "") or "").strip().lower().rstrip("/")
        if target_repository in {
            "openzeppelin/openzeppelin-contracts",
            "https://github.com/openzeppelin/openzeppelin-contracts",
        }:
            return self._run_solidity_source_fixture(task, research_case)
        if target_repository in {
            "uniswap/v2-core",
            "https://github.com/uniswap/v2-core",
        }:
            return self._run_uniswap_v2_factory_fixture(task, research_case)
        profanity_case = target_repository in {
            "johguse/profanity",
            "https://github.com/johguse/profanity",
        }
        seed_sources = PROFANITY_SEED_SOURCES if profanity_case else SEED_SOURCES
        query_rounds = PROFANITY_SEARCH_QUERY_ROUNDS if profanity_case else SEARCH_QUERY_ROUNDS
        round_number = int(parent.get("source_search_rounds", 0) or 0) + 1
        queries = query_rounds[min(round_number - 1, len(query_rounds) - 1)]
        sources_by_url = {
            item.get("source_url"): dict(item)
            for item in parent.get("sources", [])
            if isinstance(item, dict) and item.get("source_url")
        }
        for url, family in seed_sources:
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

import pytest

from shared.repository_policy import (
    RepositoryPolicyError,
    authorize_admitted_target_source,\n    authorize_case_repository,
    load_repository_allowlist,
    parse_github_repository,
    parse_repository_allowlist,
)
from shared.research_case import ResearchCase\nfrom shared.target_execution_admission import AdmittedTarget, AdapterProfile


def case(repository):
    return ResearchCase(
        case_id="repository-policy-test",
        target_repository=repository,
        target_commit="a" * 40,
        scope_url="https://example.com/security-scope",
        scope_digest="b" * 64,
        scope_reviewed_on="2026-11-14",
        hypothesis="A repository policy must authorize only a pinned target.",
        attacker_capability="The target case may contain an attacker-controlled repository string.",
        expected_invariant="Only explicitly allowlisted canonical GitHub repositories are fetched.",
        falsification_criteria="Any non-allowlisted or ambiguous repository identifier is rejected.",
        execution_mode="local",
        status="ready",
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("owner/repository", "owner/repository"),
        ("https://github.com/owner/repository", "owner/repository"),
        ("https://github.com/owner/repository.git", "owner/repository"),
        ("https://github.com/Owner/Repo.git", "Owner/Repo"),
    ],
)
def test_parse_only_supported_github_repository_forms(value, expected):
    assert parse_github_repository(value).full_name == expected


@pytest.mark.parametrize(
    "value",
    [
        "https://evil.example/owner/repo",
        "http://github.com/owner/repo",
        "https://github.com.evil.example/owner/repo",
        "https://github.com./owner/repo",
        "https://user:password@github.com/owner/repo",
        "https://github.com:443/owner/repo",
        "https://github.com/owner/repo?redirect=evil",
        "https://github.com/owner/repo#fragment",
        "https://github.com/owner/repo/tree/main",
        "https://github.com/owner/repo/",
        "https://github.com//repo",
        "https://github.com/owner/%2e%2e",
        "owner/repo/extra",
        "../repo",
        "owner/..",
        "owner\\repo",
        "owner/repo\n",
    ],
)
def test_rejects_noncanonical_or_ambiguous_repository_identifiers(value):
    with pytest.raises(RepositoryPolicyError):
        parse_github_repository(value)


def test_allowlist_is_explicit_and_case_insensitive():
    allowed = parse_repository_allowlist(["Owner/Repo"])
    assert allowed == frozenset({"owner/repo"})
    authorized = authorize_case_repository(case("https://github.com/owner/repo.git"), allowed)
    assert authorized.full_name == "owner/repo"
    assert authorized.clone_url == "https://github.com/owner/repo.git"


def test_empty_allowlist_denies_every_target():
    with pytest.raises(RepositoryPolicyError, match="allowlist_empty"):
        authorize_case_repository(case("owner/repo"), frozenset())


def test_non_allowlisted_repository_is_rejected():
    with pytest.raises(RepositoryPolicyError, match="not_allowlisted"):
        authorize_case_repository(case("owner/other"), frozenset({"owner/repo"}))


def test_allowlist_cannot_be_passed_as_a_single_string():
    with pytest.raises(RepositoryPolicyError, match="iterable_of_entries"):
        parse_repository_allowlist("owner/repo")


def test_allowlist_environment_is_deny_by_default():
    assert load_repository_allowlist({}) == frozenset()
    assert load_repository_allowlist({
        "AEGISFORGE_ALLOWED_TARGET_REPOSITORIES": "owner/one, owner/two"
    }) == frozenset({"owner/one", "owner/two"})


def test_invalid_environment_allowlist_fails_closed():
    with pytest.raises(RepositoryPolicyError):
        load_repository_allowlist({
            "AEGISFORGE_ALLOWED_TARGET_REPOSITORIES": "owner/one,https://evil.example/x/y"
        })


def test_authorization_requires_registered_case_type():
    with pytest.raises(RepositoryPolicyError, match="registered_research_case_required"):
        authorize_case_repository({"target_repository": "owner/repo"}, frozenset({"owner/repo"}))


def test_authorization_revalidates_policy_entries():
    with pytest.raises(RepositoryPolicyError):
        authorize_case_repository(case("owner/repo"), frozenset({"https://evil.example/a/b"}))



def test_source_authorization_requires_admitted_registry_context():
    registered_case = case("owner/repo")
    admitted = AdmittedTarget(
        task_id="task-1",
        case_id=registered_case.case_id,
        round_id="runtime-round-1",
        round_spec_id=None,
        adapter_profile=AdapterProfile.SLITHER_STATIC,
        research_case=registered_case,
        round_spec=None,
    )
    resolved, repository = authorize_admitted_target_source(
        admitted,
        frozenset({"owner/repo"}),
    )
    assert resolved is admitted
    assert repository.full_name == "owner/repo"


def test_source_authorization_rejects_non_admitted_context():
    with pytest.raises(RepositoryPolicyError, match="admitted_target_required"):
        authorize_admitted_target_source(
            {"research_case": case("owner/repo")},
            frozenset({"owner/repo"}),
        )

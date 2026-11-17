import hashlib

from agents.source_researcher.agent import HISTORICAL_REPOSITORIES, SourceResearcher


def _pins():
    return [
        {
            "repository": f"{item['owner']}/{item['repo']}",
            "requested_ref": item["ref"],
            "revision_role": item["revision_role"],
            "expected_commit_sha": item["expected_commit_sha"],
            "commit_sha": item["expected_commit_sha"],
            "source_files": list(item["files"]),
            "pin_status": "immutable_commit_sha",
        }
        for item in HISTORICAL_REPOSITORIES
    ]


def _fake_fetcher(calls):
    def fetcher(url):
        calls.append(url)
        body = f"synthetic fixture for {url}"
        return {
            "text": body,
            "final_url": url,
            "status_code": 200,
            "fetch_status": "ok",
            "content_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            "content_bytes": len(body.encode("utf-8")),
            "retrieved_at": "2026-10-11T00:00:00+00:00",
        }
    return fetcher


def test_pinned_sources_are_bound_to_expected_immutable_revisions():
    fetched_urls = []
    researcher = SourceResearcher(github=object(), fetcher=_fake_fetcher(fetched_urls))
    sources, pins, errors = researcher._fetch_pinned_repository_sources({}, _pins())

    expected_count = sum(len(item["files"]) for item in HISTORICAL_REPOSITORIES)
    assert errors == []
    assert len(sources) == expected_count
    assert len(fetched_urls) == expected_count
    assert len(pins) == len(HISTORICAL_REPOSITORIES)

    expected_revisions = {
        (f"{item['owner']}/{item['repo']}", item["ref"]): item["expected_commit_sha"]
        for item in HISTORICAL_REPOSITORIES
    }
    for source in sources:
        key = (source["repository"], source["repository_ref"])
        assert source["revision_sha"] == expected_revisions[key]
        assert f"/{source['revision_sha']}/{source['source_file_path']}" in source["source_url"]
        assert source["status_code"] == 200
        assert len(source["content_sha256"]) == 64
        assert source["source_kind"] == "pinned_repository_source"


def test_stored_pin_mismatch_skips_only_the_rejected_revision():
    pins = _pins()
    rejected_repository = pins[0]["repository"]
    rejected_ref = pins[0]["requested_ref"]
    rejected_expected_sha = pins[0]["expected_commit_sha"]
    pins[0]["commit_sha"] = "f" * 40
    fetched_urls = []
    researcher = SourceResearcher(github=object(), fetcher=_fake_fetcher(fetched_urls))

    sources, returned_pins, errors = researcher._fetch_pinned_repository_sources({}, pins)

    assert returned_pins == pins
    assert len(errors) == 1
    assert errors[0]["error_type"] == "PinnedRevisionMismatch"
    assert errors[0]["repository"] == rejected_repository
    assert len(sources) == len(HISTORICAL_REPOSITORIES[1]["files"])
    assert all(f"/{rejected_expected_sha}/" not in url for url in fetched_urls)
    assert any(rejected_repository in url for url in fetched_urls)  # the other pinned revision is still fetched
    assert rejected_ref != HISTORICAL_REPOSITORIES[1]["ref"]

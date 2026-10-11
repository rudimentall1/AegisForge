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


def test_pinned_sources_are_bound_to_expected_immutable_revisions():
    fetched_urls = []

    def fetcher(url):
        fetched_urls.append(url)
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

    researcher = SourceResearcher(github=object(), fetcher=fetcher)
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


def test_stored_pin_mismatch_is_rejected_without_fetching_source_files():
    pins = _pins()
    pins[0]["commit_sha"] = "f" * 40
    fetch_calls = []

    def fetcher(url):
        fetch_calls.append(url)
        raise AssertionError("source files must not be fetched for a rejected pin")

    researcher = SourceResearcher(github=object(), fetcher=fetcher)
    sources, returned_pins, errors = researcher._fetch_pinned_repository_sources({}, pins)

    assert sources == []
    assert returned_pins == pins
    assert fetch_calls == []
    assert len(errors) == 2
    assert all(item["error_type"] == "PinnedRevisionMismatch" for item in errors)

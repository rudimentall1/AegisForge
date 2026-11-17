import requests
import pytest

from shared.anchored_attestation_replay import ReplayAnchorUnavailable
from shared.http_replay_anchor_store import HttpReplayAnchorStore

GENESIS = "0" * 64
HEAD = "a" * 64


class Response:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self.payload = payload

    def raise_for_status(self):
        if self.status_code >= 400 and self.status_code != 409:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


class Session:
    def __init__(self, get_response=None, post_response=None):
        self.get_response = get_response
        self.post_response = post_response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if isinstance(self.get_response, Exception):
            raise self.get_response
        return self.get_response

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        if isinstance(self.post_response, Exception):
            raise self.post_response
        return self.post_response


def _store(session):
    return HttpReplayAnchorStore("https://anchor.example/", bearer_token="secret", session=session)


def test_get_anchor_validates_payload_and_encodes_provider_id():
    session = Session(get_response=Response(payload={
        "provider_id": "provider/a", "sequence": 0, "head_sha256": GENESIS,
    }))
    store = _store(session)
    assert store.get_anchor("provider/a")["sequence"] == 0
    method, url, kwargs = session.calls[0]
    assert method == "GET"
    assert url == "https://anchor.example/v1/anchors/provider%2Fa"
    assert kwargs["headers"]["Authorization"] == "Bearer secret"
    assert kwargs["timeout"] == 3.0


def test_get_anchor_fails_closed_on_unavailable_or_malformed_response():
    store = _store(Session(get_response=requests.Timeout("timeout")))
    with pytest.raises(ReplayAnchorUnavailable, match="external_anchor_unavailable_fail_closed"):
        store.get_anchor("provider")

    store = _store(Session(get_response=Response(payload={"sequence": 0})))
    with pytest.raises(ReplayAnchorUnavailable, match="external_anchor_envelope_invalid"):
        store.get_anchor("provider")


def test_cas_returns_false_only_for_explicit_conflict():
    session = Session(post_response=Response(status=409, payload={"error": "conflict"}))
    assert _store(session).compare_and_set_anchor(
        "provider", expected_sequence=0, expected_head_sha256=GENESIS,
        new_sequence=1, new_head_sha256=HEAD,
    ) is False
    _, url, kwargs = session.calls[0]
    assert url == "https://anchor.example/v1/anchors/provider/compare-and-set"
    assert kwargs["json"] == {
        "expected_sequence": 0, "expected_head_sha256": GENESIS,
        "new_sequence": 1, "new_head_sha256": HEAD,
    }


def test_cas_requires_explicit_success_response():
    session = Session(post_response=Response(payload={"updated": True}))
    assert _store(session).compare_and_set_anchor(
        "provider", expected_sequence=0, expected_head_sha256=GENESIS,
        new_sequence=1, new_head_sha256=HEAD,
    ) is True

    bad = _store(Session(post_response=Response(payload={"updated": False})))
    with pytest.raises(ReplayAnchorUnavailable, match="external_anchor_cas_response_invalid"):
        bad.compare_and_set_anchor(
            "provider", expected_sequence=0, expected_head_sha256=GENESIS,
            new_sequence=1, new_head_sha256=HEAD,
        )


def test_cas_timeout_is_reported_as_ambiguous_not_as_conflict():
    store = _store(Session(post_response=requests.Timeout("response lost")))
    with pytest.raises(ReplayAnchorUnavailable, match="external_anchor_cas_outcome_unknown"):
        store.compare_and_set_anchor(
            "provider", expected_sequence=0, expected_head_sha256=GENESIS,
            new_sequence=1, new_head_sha256=HEAD,
        )


def test_cas_rejects_invalid_sequence_and_hash_before_network_call():
    session = Session(post_response=Response(payload={"updated": True}))
    store = _store(session)
    with pytest.raises(ReplayAnchorUnavailable, match="external_anchor_cas_sequence_invalid"):
        store.compare_and_set_anchor(
            "provider", expected_sequence=0, expected_head_sha256=GENESIS,
            new_sequence=2, new_head_sha256=HEAD,
        )
    assert session.calls == []

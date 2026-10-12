from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from threading import Thread

import pytest
import requests

from shared.anchored_attestation_replay import ReplayAnchorUnavailable
from shared.http_replay_anchor_store import HttpReplayAnchorStore
from tools.replay_anchor.sqlite_service import GENESIS, make_handler, provision

TOKEN = "test-token-that-is-long-enough-for-local-reference-tests"
HEAD_A = "a" * 64
HEAD_B = "b" * 64


@pytest.fixture
def anchor_service(tmp_path):
    db_path = str(tmp_path / "independent-anchor.sqlite3")
    provision(db_path, "provider-test")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(db_path, TOKEN))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    store = HttpReplayAnchorStore(
        f"http://127.0.0.1:{server.server_port}", bearer_token=TOKEN
    )
    try:
        yield store, db_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_http_round_trip_and_conflict(anchor_service):
    store, _ = anchor_service
    assert store.get_anchor("provider-test") == {
        "provider_id": "provider-test", "sequence": 0, "head_sha256": GENESIS,
    }
    assert store.compare_and_set_anchor(
        "provider-test", expected_sequence=0, expected_head_sha256=GENESIS,
        new_sequence=1, new_head_sha256=HEAD_A,
    ) is True
    assert store.compare_and_set_anchor(
        "provider-test", expected_sequence=0, expected_head_sha256=GENESIS,
        new_sequence=1, new_head_sha256=HEAD_B,
    ) is False
    assert store.get_anchor("provider-test")["head_sha256"] == HEAD_A


def test_concurrent_competing_cas_has_exactly_one_winner(anchor_service):
    store, _ = anchor_service

    def attempt(head):
        return store.compare_and_set_anchor(
            "provider-test", expected_sequence=0, expected_head_sha256=GENESIS,
            new_sequence=1, new_head_sha256=head,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, (HEAD_A, HEAD_B)))
    assert sorted(results) == [False, True]
    anchor = store.get_anchor("provider-test")
    assert anchor["sequence"] == 1
    assert anchor["head_sha256"] in (HEAD_A, HEAD_B)


def test_many_concurrent_cas_requests_have_exactly_one_winner(anchor_service):
    store, _ = anchor_service
    candidates = [f"{i:064x}" for i in range(1, 17)]

    def attempt(head):
        return store.compare_and_set_anchor(
            "provider-test", expected_sequence=0, expected_head_sha256=GENESIS,
            new_sequence=1, new_head_sha256=head,
        )

    with ThreadPoolExecutor(max_workers=len(candidates)) as pool:
        results = list(pool.map(attempt, candidates))

    assert results.count(True) == 1
    assert results.count(False) == len(candidates) - 1
    anchor = store.get_anchor("provider-test")
    assert anchor["sequence"] == 1
    assert anchor["head_sha256"] in candidates


def test_service_requires_auth_and_explicit_genesis_provisioning(anchor_service):
    store, _ = anchor_service
    response = requests.get(
        store._base_url + "/v1/anchors/provider-test", timeout=2,
    )
    assert response.status_code == 401
    response = requests.get(
        store._base_url + "/v1/anchors/not-provisioned",
        headers={"Authorization": f"Bearer {TOKEN}"}, timeout=2,
    )
    assert response.status_code == 404
    with pytest.raises(ValueError, match="provider_anchor_already_exists"):
        provision(anchor_service[1], "provider-test")


def test_committed_anchor_survives_database_reopen(anchor_service):
    store, db_path = anchor_service
    assert store.compare_and_set_anchor(
        "provider-test", expected_sequence=0, expected_head_sha256=GENESIS,
        new_sequence=1, new_head_sha256=HEAD_A,
    )
    # Reopen the durable database through a new client/server handler context.
    from tools.replay_anchor.sqlite_service import connect
    with connect(db_path) as db:
        assert db.execute(
            "SELECT sequence,head_sha256 FROM replay_anchors WHERE provider_id=?",
            ("provider-test",),
        ).fetchone() == (1, HEAD_A)


class CommitThenLoseResponseSession:
    """Simulate a proxy dropping the response after the server commits CAS."""

    def __init__(self):
        self.real = requests.Session()

    def get(self, url, **kwargs):
        return self.real.get(url, **kwargs)

    def post(self, url, **kwargs):
        response = self.real.post(url, **kwargs)
        assert response.status_code == 200
        raise requests.Timeout("response lost after remote commit")


def test_lost_cas_response_is_ambiguous_but_reread_confirms_commit(anchor_service):
    store, _ = anchor_service
    uncertain = HttpReplayAnchorStore(
        store._base_url, bearer_token=TOKEN, session=CommitThenLoseResponseSession()
    )
    with pytest.raises(ReplayAnchorUnavailable, match="external_anchor_cas_outcome_unknown"):
        uncertain.compare_and_set_anchor(
            "provider-test", expected_sequence=0, expected_head_sha256=GENESIS,
            new_sequence=1, new_head_sha256=HEAD_A,
        )

    # Never translate a lost response into a conflict or retry blindly. Read the
    # authoritative anchor and reconcile against the exact intended successor.
    assert store.get_anchor("provider-test") == {
        "provider_id": "provider-test", "sequence": 1, "head_sha256": HEAD_A,
    }


def test_http_rejects_malformed_cas_without_mutating_anchor(anchor_service):
    store, _ = anchor_service
    headers = {"Authorization": f"Bearer {TOKEN}"}
    url = store._base_url + "/v1/anchors/provider-test/compare-and-set"

    missing_field = requests.post(url, headers=headers, json={"expected_sequence": 0}, timeout=2)
    assert missing_field.status_code == 400
    invalid_successor = requests.post(url, headers=headers, json={
        "expected_sequence": 0, "expected_head_sha256": GENESIS,
        "new_sequence": 2, "new_head_sha256": HEAD_A,
    }, timeout=2)
    assert invalid_successor.status_code == 400
    invalid_hash = requests.post(url, headers=headers, json={
        "expected_sequence": 0, "expected_head_sha256": GENESIS,
        "new_sequence": 1, "new_head_sha256": "not-a-hash",
    }, timeout=2)
    assert invalid_hash.status_code == 400
    assert store.get_anchor("provider-test")["sequence"] == 0


def test_committed_anchor_survives_http_server_restart(tmp_path):
    db_path = str(tmp_path / "restart-anchor.sqlite3")
    provision(db_path, "provider-restart")

    def start_server():
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(db_path, TOKEN))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    server, thread = start_server()
    store = HttpReplayAnchorStore(
        f"http://127.0.0.1:{server.server_port}", bearer_token=TOKEN
    )
    try:
        assert store.compare_and_set_anchor(
            "provider-restart", expected_sequence=0, expected_head_sha256=GENESIS,
            new_sequence=1, new_head_sha256=HEAD_B,
        ) is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    restarted, restarted_thread = start_server()
    try:
        after_restart = HttpReplayAnchorStore(
            f"http://127.0.0.1:{restarted.server_port}", bearer_token=TOKEN
        )
        assert after_restart.get_anchor("provider-restart") == {
            "provider_id": "provider-restart", "sequence": 1, "head_sha256": HEAD_B,
        }
    finally:
        restarted.shutdown()
        restarted.server_close()
        restarted_thread.join(timeout=2)


def test_post_database_open_failure_returns_service_unavailable(anchor_service, monkeypatch):
    store, _ = anchor_service
    import sqlite3
    import tools.replay_anchor.sqlite_service as service

    def fail_connect(_path):
        raise sqlite3.OperationalError("simulated database open failure")

    monkeypatch.setattr(service, "connect", fail_connect)
    response = requests.post(
        store._base_url + "/v1/anchors/provider-test/compare-and-set",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={
            "expected_sequence": 0,
            "expected_head_sha256": GENESIS,
            "new_sequence": 1,
            "new_head_sha256": HEAD_A,
        },
        timeout=2,
    )
    assert response.status_code == 503
    assert response.json() == {"error": "anchor_unavailable"}


def test_sqlite_update_failure_returns_503_without_advancing_anchor(anchor_service):
    store, db_path = anchor_service
    import sqlite3

    with sqlite3.connect(db_path) as db:
        db.execute("""CREATE TRIGGER reject_anchor_update
            BEFORE UPDATE ON replay_anchors
            BEGIN SELECT RAISE(ABORT, 'simulated storage write failure'); END""")

    response = requests.post(
        store._base_url + "/v1/anchors/provider-test/compare-and-set",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={
            "expected_sequence": 0,
            "expected_head_sha256": GENESIS,
            "new_sequence": 1,
            "new_head_sha256": HEAD_A,
        },
        timeout=2,
    )
    assert response.status_code == 503
    assert response.json() == {"error": "anchor_unavailable"}
    assert store.get_anchor("provider-test") == {
        "provider_id": "provider-test", "sequence": 0, "head_sha256": GENESIS,
    }

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

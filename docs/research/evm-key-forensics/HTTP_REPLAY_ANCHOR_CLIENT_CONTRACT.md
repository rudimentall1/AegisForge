# HTTP replay-anchor client contract

Status: client adapter and mocked contract tests implemented. No remote anchor service is included or qualified by this document.

## Why this exists

The pending-first attestation protocol needs an authoritative anchor outside the local SQLite backup/restore domain. `shared/http_replay_anchor_store.py` implements the existing `ReplayAnchorStore` interface over HTTPS-compatible JSON endpoints, so an independently operated service can be integrated without coupling the protocol to one database vendor.

## API expected by the client

`GET /v1/anchors/{provider_id}` returns exactly these fields:

```json
{"provider_id":"provider-id","sequence":0,"head_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}
```

`POST /v1/anchors/{provider_id}/compare-and-set` accepts:

```json
{"expected_sequence":0,"expected_head_sha256":"<64 lowercase hex chars>","new_sequence":1,"new_head_sha256":"<64 lowercase hex chars>"}
```

The server returns HTTP 200 with `{"updated":true}` only after the exact expected pair has been atomically replaced by the new pair. HTTP 409 is an explicit CAS conflict. Other errors and malformed responses fail closed. A network timeout is an ambiguous outcome, not a conflict; the caller must reread authoritative state before deciding whether recovery is safe.

## Security and operational requirements

- Use HTTPS in production and a narrowly scoped bearer credential. Do not log authorization headers.
- The service must authenticate callers and authorize each provider namespace independently.
- Reads must be authoritative, not served from a lagging replica.
- CAS must be linearizable across independent processes and hosts, comparing both sequence and head in one atomic operation.
- A successful CAS must be durable across process restart and documented failover/restore procedures. Split-brain writes must be prevented.
- Provision genesis explicitly for each provider; do not let arbitrary clients silently reset an existing provider to genesis.
- Treat 409 as a conflict only when the service contract guarantees no write occurred for that request.
- After timeout or connection loss, reread the authoritative anchor. Never retry based on a presumed failure.
- Protect anchor data and backups separately from the client SQLite registry. The client cannot detect a coordinated rollback of both systems without an independent witness.

## Qualification boundary

Tests in `tests/test_http_replay_anchor_store.py` validate request shape, response validation, explicit conflict handling, timeout ambiguity, and fail-closed behavior using a mocked HTTP session. They do not test a real server, linearizability, durable writes, authentication configuration, TLS deployment, failover, or rollback resistance. `qualification=NOT_ESTABLISHED` remains mandatory until a concrete service is deployed and tested under concurrency and fault injection.

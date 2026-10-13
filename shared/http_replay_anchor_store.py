"""Strict HTTP client for a separately operated replay-anchor service.

This module is a client adapter, not an anchor service. The remote service must
implement the documented linearizable read/CAS contract and keep durable state
outside the local SQLite backup/restore domain.
"""
from __future__ import annotations

from urllib.parse import quote
from typing import Mapping

import requests

from shared.anchored_attestation_replay import ReplayAnchorUnavailable, _validate_anchor


class HttpReplayAnchorStore:
    """HTTP implementation of ReplayAnchorStore with fail-closed response checks.

    Expected API:
      GET  {base_url}/v1/anchors/{provider_id}
           -> {"provider_id": str, "sequence": int, "head_sha256": str}
      POST {base_url}/v1/anchors/{provider_id}/compare-and-set
           JSON {"expected_sequence": int, "expected_head_sha256": str,
                 "new_sequence": int, "new_head_sha256": str}
           -> HTTP 200 {"updated": true}; HTTP 409 means CAS conflict.

    The server must make CAS linearizable and durable. HTTP status codes alone
    cannot establish that guarantee; deployment qualification is separate.
    """

    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str,
        timeout_seconds: float = 3.0,
        session: requests.Session | None = None,
    ) -> None:
        if not isinstance(base_url, str) or not base_url.startswith(("https://", "http://")):
            raise ValueError("anchor_base_url_must_be_http_or_https")
        if not isinstance(bearer_token, str) or not bearer_token.strip():
            raise ValueError("anchor_bearer_token_required")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise ValueError("anchor_timeout_must_be_positive")
        self._base_url = base_url.rstrip("/")
        self._timeout = float(timeout_seconds)
        self._session = session or requests.Session()
        self._headers = {
            "Authorization": f"Bearer {bearer_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _url(self, provider_id: str, suffix: str = "") -> str:
        if not isinstance(provider_id, str) or not provider_id:
            raise ReplayAnchorUnavailable("external_anchor_provider_invalid")
        return f"{self._base_url}/v1/anchors/{quote(provider_id, safe='')}{suffix}"

    def get_anchor(self, provider_id: str) -> Mapping[str, object]:
        try:
            response = self._session.get(
                self._url(provider_id), headers=self._headers, timeout=self._timeout
            )
            response.raise_for_status()
            payload = response.json()
            _validate_anchor(payload, provider_id=provider_id)
            return payload
        except ReplayAnchorUnavailable:
            raise
        except (requests.RequestException, ValueError, TypeError) as exc:
            raise ReplayAnchorUnavailable("external_anchor_unavailable_fail_closed") from exc

    def compare_and_set_anchor(
        self,
        provider_id: str,
        *,
        expected_sequence: int,
        expected_head_sha256: str,
        new_sequence: int,
        new_head_sha256: str,
    ) -> bool:
        if (type(expected_sequence) is not int or expected_sequence < 0 or
            type(new_sequence) is not int or new_sequence != expected_sequence + 1):
            raise ReplayAnchorUnavailable("external_anchor_cas_sequence_invalid")
        for head in (expected_head_sha256, new_head_sha256):
            if not isinstance(head, str) or len(head) != 64 or any(
                char not in "0123456789abcdef" for char in head
            ):
                raise ReplayAnchorUnavailable("external_anchor_cas_head_invalid")
        body = {
            "expected_sequence": expected_sequence,
            "expected_head_sha256": expected_head_sha256,
            "new_sequence": new_sequence,
            "new_head_sha256": new_head_sha256,
        }
        try:
            response = self._session.post(
                self._url(provider_id, "/compare-and-set"),
                headers=self._headers, json=body, timeout=self._timeout,
            )
            if response.status_code == 409:
                return False
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or set(payload) != {"updated"} or payload["updated"] is not True:
                raise ReplayAnchorUnavailable("external_anchor_cas_response_invalid")
            return True
        except ReplayAnchorUnavailable:
            raise
        except (requests.RequestException, ValueError, TypeError) as exc:
            # A timeout may mean the server committed CAS. Callers must reread
            # the authoritative anchor; never infer failure from a lost response.
            raise ReplayAnchorUnavailable("external_anchor_cas_outcome_unknown") from exc

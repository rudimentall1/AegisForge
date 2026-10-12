"""Single-node reference HTTP replay-anchor service.

This is a reference/development service, not a high-availability production
control plane. Put it behind TLS, keep its database outside client backup
restore paths, and do not claim rollback resistance for coordinated restores.
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

GENESIS = "0" * 64
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_BODY = 4096


def connect(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path, timeout=5.0, isolation_level=None)
    db.execute("PRAGMA busy_timeout=5000")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("""CREATE TABLE IF NOT EXISTS replay_anchors (
        provider_id TEXT PRIMARY KEY,
        sequence INTEGER NOT NULL CHECK(sequence >= 0),
        head_sha256 TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    )""")
    return db


def provision(path: str, provider_id: str) -> None:
    if not provider_id or len(provider_id) > 256:
        raise ValueError("provider_id_invalid")
    with connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute(
                "INSERT INTO replay_anchors(provider_id,sequence,head_sha256) VALUES(?,0,?)",
                (provider_id, GENESIS),
            )
            db.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            db.execute("ROLLBACK")
            raise ValueError("provider_anchor_already_exists") from exc
        except Exception:
            db.execute("ROLLBACK")
            raise


def make_handler(db_path: str, token: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ReplayAnchorReference/1"
        sys_version = ""

        def log_message(self, fmt, *args):
            # Avoid logging paths, payloads, or credentials by default.
            return

        def _send(self, status: int, payload: dict) -> None:
            raw = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _authorized(self) -> bool:
            supplied = self.headers.get("Authorization", "")
            expected = "Bearer " + token
            return hmac.compare_digest(supplied.encode(), expected.encode())

        def _route(self):
            path = urlparse(self.path).path
            match = re.fullmatch(r"/v1/anchors/([^/]+)(/compare-and-set)?", path)
            if not match:
                return None, None
            provider = unquote(match.group(1))
            if not provider or len(provider) > 256 or "/" in provider:
                return None, None
            return provider, bool(match.group(2))

        def do_GET(self):
            if not self._authorized():
                self._send(401, {"error": "unauthorized"})
                return
            provider, cas_route = self._route()
            if provider is None or cas_route:
                self._send(404, {"error": "not_found"})
                return
            try:
                with connect(db_path) as db:
                    row = db.execute(
                        "SELECT sequence,head_sha256 FROM replay_anchors WHERE provider_id=?",
                        (provider,),
                    ).fetchone()
                if row is None:
                    self._send(404, {"error": "anchor_not_provisioned"})
                    return
                self._send(200, {"provider_id": provider, "sequence": row[0], "head_sha256": row[1]})
            except sqlite3.Error:
                self._send(503, {"error": "anchor_unavailable"})

        def do_POST(self):
            if not self._authorized():
                self._send(401, {"error": "unauthorized"})
                return
            provider, cas_route = self._route()
            if provider is None or not cas_route:
                self._send(404, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                self._send(413, {"error": "request_body_size_invalid"})
                return
            try:
                body = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send(400, {"error": "json_invalid"})
                return
            keys = {"expected_sequence", "expected_head_sha256", "new_sequence", "new_head_sha256"}
            if not isinstance(body, dict) or set(body) != keys:
                self._send(400, {"error": "cas_envelope_invalid"})
                return
            es, eh, ns, nh = (body[k] for k in ("expected_sequence", "expected_head_sha256", "new_sequence", "new_head_sha256"))
            if (type(es) is not int or es < 0 or type(ns) is not int or ns != es + 1 or
                not isinstance(eh, str) or not HASH_RE.fullmatch(eh) or
                not isinstance(nh, str) or not HASH_RE.fullmatch(nh)):
                self._send(400, {"error": "cas_values_invalid"})
                return
            try:
                with connect(db_path) as db:
                    db.execute("BEGIN IMMEDIATE")
                    row = db.execute(
                        "SELECT sequence,head_sha256 FROM replay_anchors WHERE provider_id=?",
                        (provider,),
                    ).fetchone()
                    if row is None:
                        db.execute("ROLLBACK")
                        self._send(404, {"error": "anchor_not_provisioned"})
                        return
                    if row != (es, eh):
                        db.execute("ROLLBACK")
                        self._send(409, {"updated": False})
                        return
                    cursor = db.execute(
                        "UPDATE replay_anchors SET sequence=?,head_sha256=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE provider_id=? AND sequence=? AND head_sha256=?",
                        (ns, nh, provider, es, eh),
                    )
                    if cursor.rowcount != 1:
                        db.execute("ROLLBACK")
                        self._send(409, {"updated": False})
                        return
                    db.execute("COMMIT")
                self._send(200, {"updated": True})
            except sqlite3.Error:
                try:
                    db.execute("ROLLBACK")
                except Exception:
                    pass
                self._send(503, {"error": "anchor_unavailable"})

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, help="Anchor DB path; keep outside client backup domain")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address; default is loopback")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--token-env", default="REPLAY_ANCHOR_BEARER_TOKEN")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    provision_parser = sub.add_parser("provision")
    provision_parser.add_argument("provider_id")
    args = parser.parse_args()
    db_path = str(Path(args.db).expanduser().resolve())
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    if args.command == "provision":
        provision(db_path, args.provider_id)
        print("anchor_provisioned_at_genesis")
        return 0
    token = os.environ.get(args.token_env, "")
    if len(token) < 32:
        parser.error(f"{args.token_env} must contain at least 32 characters")
    if args.host not in ("127.0.0.1", "::1", "localhost"):
        parser.error("reference service must bind to loopback; use a TLS reverse proxy for remote access")
    server = ThreadingHTTPServer((args.host, args.port), make_handler(db_path, token))
    print(f"reference_anchor_service_listening_on={args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

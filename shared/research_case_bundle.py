"""Portable export and offline verification for one registered research case.

The bundle proves internal integrity and case/task linkage only. It does not
prove that a finding is exploitable or that the runner was trustworthy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path, PurePosixPath

from shared.research_case import (
    CaseStatus,
    ExecutionMode,
    ResearchCase,
    research_case_binding,
    verify_research_case_binding,
)
from shared.result_codec import decode

SCHEMA_VERSION = "aegisforge-research-case-bundle-v1"
MEMBERS = ("case.json", "tasks.json", "evidence.json")
ALL_MEMBERS = frozenset((*MEMBERS, "manifest.json"))
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 24 * 1024 * 1024
MAX_MEMBER_COUNT = 4
MAX_TASKS = 10_000
MAX_EVIDENCE_ROWS = 20_000

# A result records the case snapshot that existed when its task ran. Lifecycle
# status can advance later (ready -> running -> confirmed/inconclusive), so
# provenance checks compare the immutable investigation contract, not status.
_CASE_IMMUTABLE_FIELDS = (
    "case_id",
    "target_repository",
    "target_commit",
    "scope_url",
    "scope_digest",
    "scope_reviewed_on",
    "hypothesis",
    "attacker_capability",
    "expected_invariant",
    "falsification_criteria",
    "execution_mode",
)


def _same_case_contract(left: dict, right: dict) -> bool:
    return all(left.get(field) == right.get(field) for field in _CASE_IMMUTABLE_FIELDS)


class ResearchCaseBundleError(ValueError):
    """Raised when a case bundle is malformed, unsafe, or inconsistent."""


def _validate_task_parent_graph(tasks: list[dict]) -> set[str]:
    """Require every parent link to stay in the bundle and the graph to be acyclic."""
    task_ids = set()
    parents = {}
    for task in tasks:
        if not isinstance(task, dict):
            raise ResearchCaseBundleError("task_identity_invalid")
        task_id = task.get("id")
        parent_id = task.get("parent_task_id")
        if not isinstance(task_id, str) or not task_id or task_id in task_ids:
            raise ResearchCaseBundleError("task_identity_invalid")
        if parent_id is not None and not isinstance(parent_id, str):
            raise ResearchCaseBundleError("task_parent_identity_invalid")
        task_ids.add(task_id)
        parents[task_id] = parent_id

    for parent_id in parents.values():
        if parent_id is not None and parent_id not in task_ids:
            raise ResearchCaseBundleError("task_parent_not_in_case_bundle")

    # Iterative path walking avoids recursion limits on long or adversarial chains.
    finished = set()
    for start in parents:
        current = start
        path = set()
        while current is not None and current not in finished:
            if current in path:
                raise ResearchCaseBundleError("task_parent_cycle_detected")
            path.add(current)
            current = parents.get(current)
        finished.update(path)
    return task_ids


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ResearchCaseBundleError("bundle_json_not_canonicalizable") from exc


def _strict_json(raw: bytes, *, label: str) -> object:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ResearchCaseBundleError(f"{label}_duplicate_json_key:{key}")
            result[key] = value
        return result

    def reject_constant(value):
        raise ResearchCaseBundleError(f"{label}_nonstandard_json_constant:{value}")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise ResearchCaseBundleError(f"{label}_invalid_utf8") from exc
    except RecursionError as exc:
        raise ResearchCaseBundleError(f"{label}_nesting_limit_exceeded") from exc
    except json.JSONDecodeError as exc:
        raise ResearchCaseBundleError(f"{label}_invalid_json") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _readonly_connect(db_path: Path):
    resolved = db_path.resolve(strict=True)
    if not resolved.is_file():
        raise ResearchCaseBundleError("database_file_required")
    uri = resolved.as_uri() + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        return connection
    except sqlite3.Error as exc:
        raise ResearchCaseBundleError("database_open_failed") from exc


def _tables(connection) -> set[str]:
    return {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }


def _case_from_payload(payload: object) -> ResearchCase:
    if not isinstance(payload, dict):
        raise ResearchCaseBundleError("registered_case_payload_must_be_object")
    try:
        values = dict(payload)
        values["execution_mode"] = ExecutionMode(values["execution_mode"])
        values["status"] = CaseStatus(values["status"])
        return ResearchCase(**values)
    except (KeyError, TypeError, ValueError) as exc:
        raise ResearchCaseBundleError("registered_case_payload_invalid") from exc


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    if set(files) != ALL_MEMBERS:
        raise ResearchCaseBundleError("bundle_member_set_invalid")
    import io

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, files[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return output.getvalue()


def export_research_case_bundle(
    db_path: str | Path,
    case_id: str,
    output_path: str | Path,
) -> dict:
    """Export a registered case and its linked queue/evidence records read-only."""
    if not isinstance(case_id, str) or not case_id.strip():
        raise ResearchCaseBundleError("case_id_required")
    database = Path(db_path)
    output = Path(output_path)
    if output.exists() and output.is_symlink():
        raise ResearchCaseBundleError("output_path_must_not_be_symlink")
    if database.resolve() == output.resolve():
        raise ResearchCaseBundleError("output_must_not_overwrite_database")

    connection = _readonly_connect(database)
    try:
        tables = _tables(connection)
        if not {"research_cases", "queue"}.issubset(tables):
            raise ResearchCaseBundleError("database_missing_case_or_queue_table")
        case_row = connection.execute(
            "SELECT payload FROM research_cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if case_row is None:
            raise ResearchCaseBundleError("research_case_not_registered")
        case_payload = _strict_json(case_row["payload"].encode("utf-8"), label="case")
        case = _case_from_payload(case_payload)
        if case.case_id != case_id:
            raise ResearchCaseBundleError("registered_case_id_mismatch")
        binding = research_case_binding(case)

        queue_columns = {row["name"] for row in connection.execute("PRAGMA table_info(queue)")}
        required_columns = {"id", "description", "status", "created_at", "result", "research_case_id"}
        if not required_columns.issubset(queue_columns):
            raise ResearchCaseBundleError("queue_schema_missing_required_columns")
        selected = [
            column for column in (
                "id", "description", "status", "worker", "created_at", "started_at",
                "finished_at", "role", "parent_task_id", "result", "retry_count",
                "research_case_id", "planner_decision",
            )
            if column in queue_columns
        ]
        rows = connection.execute(
            "SELECT " + ", ".join(f'"{column}"' for column in selected)
            + " FROM queue WHERE research_case_id = ? ORDER BY created_at, id",
            (case_id,),
        ).fetchall()
        if len(rows) > MAX_TASKS:
            raise ResearchCaseBundleError("case_task_count_exceeds_limit")
        tasks = []
        for row in rows:
            item = dict(row)
            raw_result = item.pop("result", None)
            try:
                item["result"] = decode(raw_result)
            except (ValueError, TypeError, UnicodeError, OSError) as exc:
                raise ResearchCaseBundleError("task_result_decode_failed") from exc
            if item["result"] is not None and not isinstance(item["result"], (dict, list, str, int, float, bool)):
                raise ResearchCaseBundleError("task_result_type_unsupported")
            if isinstance(item["result"], dict):
                result_binding = item["result"].get("research_case_binding")
                if result_binding is not None:
                    try:
                        result_payload = verify_research_case_binding(result_binding)
                        # Validate the historical snapshot, including its lifecycle
                        # enum, before comparing the immutable case contract.
                        _case_from_payload(result_payload)
                    except (ValueError, TypeError) as exc:
                        raise ResearchCaseBundleError("task_result_case_binding_invalid") from exc
                    if not _same_case_contract(result_payload, case_payload):
                        raise ResearchCaseBundleError("task_result_case_binding_mismatch")
                elif item["status"] == "completed":
                    raise ResearchCaseBundleError("completed_task_missing_case_binding")
            tasks.append(item)

        evidence = []
        if "evidence_observations" in tables:
            evidence_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(evidence_observations)")
            }
            if {"atom_id", "task_id", "role", "observed_at", "case_id"}.issubset(evidence_columns):
                if "evidence_ledger" in tables:
                    evidence_rows = connection.execute(
                        """
                        SELECT o.atom_id, o.task_id, o.role, o.observed_at, o.case_id,
                               l.kind, l.value
                        FROM evidence_observations o
                        LEFT JOIN evidence_ledger l ON l.atom_id = o.atom_id
                        WHERE o.case_id = ?
                        ORDER BY o.observed_at, o.task_id, o.atom_id
                        LIMIT ?
                        """,
                        (case_id, MAX_EVIDENCE_ROWS + 1),
                    ).fetchall()
                else:
                    evidence_rows = connection.execute(
                        """
                        SELECT atom_id, task_id, role, observed_at, case_id
                        FROM evidence_observations
                        WHERE case_id = ?
                        ORDER BY observed_at, task_id, atom_id
                        LIMIT ?
                        """,
                        (case_id, MAX_EVIDENCE_ROWS + 1),
                    ).fetchall()
                if len(evidence_rows) > MAX_EVIDENCE_ROWS:
                    raise ResearchCaseBundleError("case_evidence_count_exceeds_limit")
                evidence = [dict(row) for row in evidence_rows]
        task_ids_for_case = _validate_task_parent_graph(tasks)
        for observation in evidence:
            if observation.get("task_id") not in task_ids_for_case:
                raise ResearchCaseBundleError("evidence_observation_task_not_in_case_bundle")
    except sqlite3.Error as exc:
        raise ResearchCaseBundleError("database_query_failed") from exc
    finally:
        connection.close()

    payloads = {
        "case.json": {"research_case_binding": binding},
        "tasks.json": {
            "schema_version": SCHEMA_VERSION,
            "case_id": case_id,
            "tasks": tasks,
        },
        "evidence.json": {
            "schema_version": SCHEMA_VERSION,
            "case_id": case_id,
            "observations": evidence,
        },
    }
    files = {name: _canonical_json(value) for name, value in payloads.items()}
    entries = [
        {"path": name, "sha256": _sha256(files[name]), "size": len(files[name])}
        for name in sorted(files)
    ]
    manifest_core = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "case_digest": binding["case_digest"],
        "entries": entries,
    }
    manifest = dict(manifest_core)
    manifest["bundle_sha256"] = _sha256(_canonical_json(manifest_core))
    files["manifest.json"] = _canonical_json(manifest)
    for name, raw in files.items():
        if len(raw) > MAX_MEMBER_BYTES:
            raise ResearchCaseBundleError(f"bundle_member_exceeds_size_limit:{name}")
    archive_bytes = _zip_bytes(files)
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ResearchCaseBundleError("bundle_archive_exceeds_size_limit")

    output.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{output.name}.", suffix=".tmp", dir=output.parent, delete=False
        ) as stream:
            temp_path = Path(stream.name)
            stream.write(archive_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, output)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()

    return verify_research_case_bundle(output)


def verify_research_case_bundle(bundle_path: str | Path) -> dict:
    """Verify ZIP safety, deterministic manifest hashes, and case/task linkage."""
    path = Path(bundle_path)
    if path.is_symlink() or not path.is_file():
        raise ResearchCaseBundleError("bundle_file_required")
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ResearchCaseBundleError("bundle_archive_exceeds_size_limit")

    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            if len(infos) != MAX_MEMBER_COUNT:
                raise ResearchCaseBundleError("bundle_member_count_invalid")
            names = [item.filename for item in infos]
            if len(set(names)) != len(names) or set(names) != ALL_MEMBERS:
                raise ResearchCaseBundleError("bundle_member_set_invalid")
            total_size = 0
            actual_total_size = 0
            files = {}
            for item in infos:
                name = item.filename
                pure = PurePosixPath(name)
                if (
                    not name or "\\" in name or pure.is_absolute()
                    or any(part in ("", ".", "..") for part in pure.parts)
                    or name.endswith("/")
                ):
                    raise ResearchCaseBundleError("unsafe_bundle_member_path")
                mode = (item.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise ResearchCaseBundleError("bundle_symlink_member_rejected")
                if item.flag_bits & 0x1:
                    raise ResearchCaseBundleError("encrypted_bundle_member_rejected")
                if item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ResearchCaseBundleError("unsupported_bundle_compression")
                if item.file_size > MAX_MEMBER_BYTES:
                    raise ResearchCaseBundleError(f"bundle_member_exceeds_size_limit:{name}")
                total_size += item.file_size
                if total_size > MAX_TOTAL_UNCOMPRESSED_BYTES:
                    raise ResearchCaseBundleError("bundle_uncompressed_size_exceeds_limit")
                chunks = []
                actual_size = 0
                with archive.open(item, "r") as stream:
                    while True:
                        remaining = MAX_MEMBER_BYTES - actual_size + 1
                        chunk = stream.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        actual_size += len(chunk)
                        if actual_size > MAX_MEMBER_BYTES:
                            raise ResearchCaseBundleError(f"bundle_member_exceeds_size_limit:{name}")
                        chunks.append(chunk)
                if actual_size != item.file_size:
                    raise ResearchCaseBundleError("bundle_member_size_mismatch")
                actual_total_size += actual_size
                if actual_total_size > MAX_TOTAL_UNCOMPRESSED_BYTES:
                    raise ResearchCaseBundleError("bundle_uncompressed_size_exceeds_limit")
                files[name] = b"".join(chunks)
    except zipfile.BadZipFile as exc:
        raise ResearchCaseBundleError("invalid_bundle_zip") from exc
    except (OSError, RuntimeError, EOFError, KeyError, zlib.error, zipfile.LargeZipFile) as exc:
        raise ResearchCaseBundleError("bundle_read_failed") from exc

    manifest = _strict_json(files["manifest.json"], label="manifest")
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "case_id", "case_digest", "entries", "bundle_sha256"
    }:
        raise ResearchCaseBundleError("manifest_fields_invalid")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ResearchCaseBundleError("unsupported_bundle_schema")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != len(MEMBERS):
        raise ResearchCaseBundleError("manifest_entries_invalid")
    expected_paths = set(MEMBERS)
    entry_paths = [entry.get("path") if isinstance(entry, dict) else None for entry in entries]
    if entry_paths != sorted(entry_paths):
        raise ResearchCaseBundleError("manifest_entries_not_sorted")
    seen_paths = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise ResearchCaseBundleError("manifest_entry_invalid")
        name = entry["path"]
        if name not in expected_paths or name in seen_paths:
            raise ResearchCaseBundleError("manifest_member_set_invalid")
        if type(entry["size"]) is not int or entry["size"] < 0:
            raise ResearchCaseBundleError("manifest_member_size_invalid")
        if (
            not isinstance(entry["sha256"], str)
            or len(entry["sha256"]) != 64
            or any(char not in "0123456789abcdef" for char in entry["sha256"])
        ):
            raise ResearchCaseBundleError("manifest_member_digest_invalid")
        raw = files[name]
        if entry["size"] != len(raw) or entry["sha256"] != _sha256(raw):
            raise ResearchCaseBundleError(f"bundle_member_digest_mismatch:{name}")
        seen_paths.add(name)
    if seen_paths != expected_paths:
        raise ResearchCaseBundleError("manifest_member_set_invalid")

    manifest_core = {key: manifest[key] for key in ("schema_version", "case_id", "case_digest", "entries")}
    if manifest["bundle_sha256"] != _sha256(_canonical_json(manifest_core)):
        raise ResearchCaseBundleError("bundle_manifest_digest_mismatch")

    case_file = _strict_json(files["case.json"], label="case")
    if not isinstance(case_file, dict) or set(case_file) != {"research_case_binding"}:
        raise ResearchCaseBundleError("case_file_schema_invalid")
    binding = case_file["research_case_binding"]
    try:
        case_payload = verify_research_case_binding(binding)
        validated_case = _case_from_payload(case_payload)
        if research_case_binding(validated_case) != binding:
            raise ResearchCaseBundleError("case_binding_not_canonical")
    except ValueError as exc:
        raise ResearchCaseBundleError("case_binding_invalid") from exc
    case_id = binding["case_id"]
    if (
        manifest["case_id"] != case_id
        or manifest["case_digest"] != binding["case_digest"]
        or case_payload.get("case_id") != case_id
    ):
        raise ResearchCaseBundleError("bundle_case_identity_mismatch")

    tasks_file = _strict_json(files["tasks.json"], label="tasks")
    if (
        not isinstance(tasks_file, dict)
        or tasks_file.get("schema_version") != SCHEMA_VERSION
        or tasks_file.get("case_id") != case_id
        or not isinstance(tasks_file.get("tasks"), list)
    ):
        raise ResearchCaseBundleError("tasks_file_schema_invalid")
    if len(tasks_file["tasks"]) > MAX_TASKS:
        raise ResearchCaseBundleError("case_task_count_exceeds_limit")
    task_ids = set()
    for task in tasks_file["tasks"]:
        if not isinstance(task, dict) or task.get("research_case_id") != case_id:
            raise ResearchCaseBundleError("task_case_identity_mismatch")
        task_id = task.get("id")
        if not isinstance(task_id, str) or not task_id or task_id in task_ids:
            raise ResearchCaseBundleError("task_identity_invalid")
        task_ids.add(task_id)
        result = task.get("result")
        if isinstance(result, dict) and result.get("research_case_binding") is not None:
            try:
                result_payload = verify_research_case_binding(
                    result["research_case_binding"]
                )
                # Validate the historical snapshot's enum values and required
                # fields too; excluding status from contract equality must not
                # make arbitrary status strings acceptable.
                _case_from_payload(result_payload)
            except ValueError as exc:
                raise ResearchCaseBundleError("task_result_case_binding_invalid") from exc
            if not _same_case_contract(result_payload, case_payload):
                raise ResearchCaseBundleError("task_result_case_binding_mismatch")
        elif task.get("status") == "completed":
            raise ResearchCaseBundleError("completed_task_missing_case_binding")

    _validate_task_parent_graph(tasks_file["tasks"])

    evidence_file = _strict_json(files["evidence.json"], label="evidence")
    if (
        not isinstance(evidence_file, dict)
        or evidence_file.get("schema_version") != SCHEMA_VERSION
        or evidence_file.get("case_id") != case_id
        or not isinstance(evidence_file.get("observations"), list)
    ):
        raise ResearchCaseBundleError("evidence_file_schema_invalid")
    if len(evidence_file["observations"]) > MAX_EVIDENCE_ROWS:
        raise ResearchCaseBundleError("case_evidence_count_exceeds_limit")
    for observation in evidence_file["observations"]:
        if not isinstance(observation, dict) or observation.get("case_id") != case_id:
            raise ResearchCaseBundleError("evidence_case_identity_mismatch")
        if observation.get("task_id") not in task_ids:
            raise ResearchCaseBundleError("evidence_observation_task_not_in_case_bundle")

    statuses = {}
    for task in tasks_file["tasks"]:
        status = str(task.get("status", "unknown"))
        statuses[status] = statuses.get(status, 0) + 1
    return {
        "valid": True,
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "case_digest": binding["case_digest"],
        "task_count": len(tasks_file["tasks"]),
        "task_status_counts": statuses,
        "evidence_observation_count": len(evidence_file["observations"]),
        "bundle_sha256": manifest["bundle_sha256"],
        "authenticity": "UNSIGNED_INTEGRITY_ONLY",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Export or verify portable AegisForge research-case evidence.")
    commands = parser.add_subparsers(dest="command", required=True)
    export_parser = commands.add_parser("export", help="Export a case from a SQLite queue database.")
    export_parser.add_argument("--db", required=True, help="Path to the SQLite database (opened read-only).")
    export_parser.add_argument("--case-id", required=True, help="Registered research case ID.")
    export_parser.add_argument("--output", required=True, help="Output ZIP bundle path.")
    verify_parser = commands.add_parser("verify", help="Verify a portable case evidence ZIP offline.")
    verify_parser.add_argument("bundle", help="Path to the ZIP bundle.")
    args = parser.parse_args(argv)

    try:
        if args.command == "export":
            result = export_research_case_bundle(args.db, args.case_id, args.output)
        else:
            result = verify_research_case_bundle(args.bundle)
        print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return 0
    except (ResearchCaseBundleError, OSError, ValueError, sqlite3.Error) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

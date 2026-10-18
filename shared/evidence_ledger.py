import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone


class EvidenceLedger:
    """Persistent normalized evidence with bounded provenance."""

    MAX_ATOM_VALUE_BYTES = 8192
    MAX_OBSERVATIONS = 5000

    def __init__(self, db):
        self.db = db
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS evidence_ledger (
                atom_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                confirmation_count INTEGER NOT NULL DEFAULT 0,
                independent_role_count INTEGER NOT NULL DEFAULT 0,
                latest_task_id TEXT,
                latest_role TEXT
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS evidence_provenance (
                atom_id TEXT NOT NULL,
                role TEXT NOT NULL,
                first_task_id TEXT NOT NULL,
                latest_task_id TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                observation_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (atom_id, role)
            )
        """)
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_last_seen
            ON evidence_ledger(last_seen)
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS evidence_observations (
                atom_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                role TEXT,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (atom_id, task_id)
            )
        """)
        observation_columns = {
            row[1] for row in self.db.execute("PRAGMA table_info(evidence_observations)")
        }
        if "case_id" not in observation_columns:
            self.db.execute("ALTER TABLE evidence_observations ADD COLUMN case_id TEXT")
        if "round_id" not in observation_columns:
            self.db.execute("ALTER TABLE evidence_observations ADD COLUMN round_id TEXT")
        if "round_spec_id" not in observation_columns:
            self.db.execute("ALTER TABLE evidence_observations ADD COLUMN round_spec_id TEXT")
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_observations_task
            ON evidence_observations(task_id)
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS evidence_contradictions (
                atom_id TEXT NOT NULL,
                other_atom_id TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                first_task_id TEXT NOT NULL,
                latest_task_id TEXT NOT NULL,
                latest_role TEXT NOT NULL,
                reason TEXT NOT NULL,
                PRIMARY KEY (atom_id, other_atom_id)
            )
        """)
        self.db.execute("""
            CREATE INDEX IF NOT EXISTS idx_evidence_contradictions_last_seen
            ON evidence_contradictions(last_seen)
        """)
        self.db.commit()

    @staticmethod
    def atom_id(atom):
        return hashlib.sha256(atom.encode("utf-8")).hexdigest()

    @staticmethod
    def split_atom(atom):
        kind, sep, value = str(atom).partition(":")
        return kind if sep else "unknown", value if sep else str(atom)

    def record(self, task_id, role, atoms, observed_at=None, commit=True):
        if not task_id or not atoms:
            return {"inserted": 0, "confirmed": 0, "contradictions": 0}
        if not role:
            role = "unknown"
        now = observed_at or datetime.now(timezone.utc).isoformat()
        inserted = 0
        confirmed = 0

        for atom in sorted(set(atoms or ())):
            atom = str(atom).strip()
            if not atom:
                continue
            kind, value = self.split_atom(atom)
            # Evidence is durable intelligence, not a raw-result archive.
            # Never persist oversized payloads even if a caller bypasses the
            # planner's normal compaction.
            encoded = value.encode("utf-8")
            if len(encoded) > self.MAX_ATOM_VALUE_BYTES:
                value = encoded[: self.MAX_ATOM_VALUE_BYTES].decode(
                    "utf-8", errors="ignore"
                )
                atom = f"{kind}:{value}"
            atom_id = self.atom_id(atom)
            row = self.db.execute(
                "SELECT confirmation_count FROM evidence_ledger WHERE atom_id = ?",
                (atom_id,),
            ).fetchone()
            provenance_row = self.db.execute(
                "SELECT observation_count, latest_task_id FROM evidence_provenance "
                "WHERE atom_id = ? AND role = ?",
                (atom_id, role),
            ).fetchone()
            provenance = provenance_row

            # A task may be revisited by the planner before its child is
            # created. Do not count the same task/role observation twice.
            if provenance_row is not None and provenance_row[1] == task_id:
                continue

            if row is None:
                inserted += 1
                self.db.execute(
                    """INSERT INTO evidence_ledger
                       (atom_id, kind, value, first_seen, last_seen,
                        confirmation_count, independent_role_count,
                        latest_task_id, latest_role)
                       VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?)""",
                    (atom_id, kind, value, now, now, task_id, role),
                )
            elif provenance is None:
                confirmed += 1
                self.db.execute(
                    """UPDATE evidence_ledger
                       SET last_seen = ?, latest_task_id = ?, latest_role = ?,
                           confirmation_count = confirmation_count + 1,
                           independent_role_count = independent_role_count + 1
                       WHERE atom_id = ?""",
                    (now, task_id, role, atom_id),
                )
            else:
                self.db.execute(
                    """UPDATE evidence_ledger
                       SET last_seen = ?, latest_task_id = ?, latest_role = ?,
                           confirmation_count = confirmation_count + 1
                       WHERE atom_id = ?""",
                    (now, task_id, role, atom_id),
                )

            if provenance is None:
                self.db.execute(
                    """INSERT INTO evidence_provenance
                       (atom_id, role, first_task_id, latest_task_id,
                        first_seen, last_seen, observation_count)
                       VALUES (?, ?, ?, ?, ?, ?, 1)""",
                    (atom_id, role, task_id, task_id, now, now),
                )
            else:
                self.db.execute(
                    """UPDATE evidence_provenance
                       SET latest_task_id = ?, last_seen = ?,
                           observation_count = observation_count + 1
                       WHERE atom_id = ? AND role = ?""",
                    (task_id, now, atom_id, role),
                )

        if commit:
            self.db.commit()
        contradictions = self.detect_contradictions(atoms)
        contradiction_count = self.record_contradictions(
            task_id, role, contradictions, observed_at=now, commit=commit
        )
        self.last_contradiction_count = contradiction_count
        return {
            "inserted": inserted,
            "confirmed": confirmed,
            "contradictions": contradiction_count,
        }

    def record_capability_claim(
        self,
        task_id,
        role,
        claim_type,
        status="PASS",
        details=None,
        observed_at=None,
        commit=True,
    ):
        """Record a canonical capability evidence claim and return its ledger id."""
        allowed_statuses = {"PASS", "PASSED", "VERIFIED", "FAIL", "FAILED", "REJECTED"}
        status = str(status or "").upper()
        if status not in allowed_statuses:
            raise ValueError(f"unsupported capability evidence status: {status}")

        payload = {
            "claim_type": str(claim_type),
            "status": status,
        }
        if details is not None:
            payload["details"] = details

        atom = "capability_evidence:" + json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        result = self.record_observation(
            task_id,
            role,
            atom,
            observed_at=observed_at,
            commit=commit,
        )
        return {
            "evidence_id": self.atom_id(atom),
            "claim_type": str(claim_type),
            "status": status,
            "source": role,
            "ledger_result": result,
        }

    def record_execution_receipt(
        self,
        task_id,
        role,
        receipt,
        observed_at=None,
        commit=True,
    ):
        """Persist an execution receipt as canonical evidence."""
        if receipt is None:
            raise ValueError("receipt_required")
        payload = receipt.to_dict() if hasattr(receipt, "to_dict") else dict(receipt)
        atom = "execution_receipt:" + json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        result = self.record_observation(
            task_id,
            role,
            atom,
            observed_at=observed_at,
            commit=commit,
        )
        return {
            "evidence_id": self.atom_id(atom),
            "receipt_id": payload.get("receipt_id"),
            "status": payload.get("status"),
            "source": role,
            "ledger_result": result,
        }

    def record_outcome_verification(
        self,
        task_id,
        role,
        outcome,
        observed_at=None,
        commit=True,
    ):
        """Persist independently verified execution outcome evidence."""
        if outcome is None:
            raise ValueError("outcome_required")
        payload = dict(outcome)
        atom = "outcome_verification:" + json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        result = self.record_observation(
            task_id,
            role,
            atom,
            observed_at=observed_at,
            commit=commit,
        )
        return {
            "evidence_id": self.atom_id(atom),
            "outcome_id": payload.get("outcome_id"),
            "status": payload.get("status"),
            "verifier": payload.get("verifier"),
            "source": role,
            "ledger_result": result,
        }

    def record_observation(self, task_id, role, atom, observed_at=None, commit=True):
        """Record one bounded task-level evidence/audit observation.

        The atom is normalized through the persistent ledger, while this
        observation keeps the task-level audit trail without making the atom
        identity depend on task IDs or timestamps.
        """
        if not task_id or not atom:
            return {"inserted": 0, "confirmed": 0, "observations": 0}

        role = role or "unknown"
        now = observed_at or datetime.now(timezone.utc).isoformat()
        result = self.record(
            task_id,
            role,
            {str(atom)},
            observed_at=now,
            commit=False,
        )
        normalized_atom = str(atom).strip()
        kind, value = self.split_atom(normalized_atom)
        encoded = value.encode("utf-8")
        if len(encoded) > self.MAX_ATOM_VALUE_BYTES:
            value = encoded[: self.MAX_ATOM_VALUE_BYTES].decode(
                "utf-8", errors="ignore"
            )
            normalized_atom = f"{kind}:{value}"
        atom_id = self.atom_id(normalized_atom)
        case_id = None
        round_id = None
        round_spec_id = None
        try:
            queue_columns = {
                row[1] for row in self.db.execute("PRAGMA table_info(queue)")
            }
            if {"id", "research_case_id"}.issubset(queue_columns):
                selected = ["research_case_id"]
                for column in ("round_id", "round_spec_id"):
                    if column in queue_columns:
                        selected.append(column)
                case_row = self.db.execute(
                    f"SELECT {', '.join(selected)} FROM queue WHERE id = ?",
                    (task_id,),
                ).fetchone()
                if case_row:
                    case_id = case_row[0]
                    offsets = {name: index for index, name in enumerate(selected)}
                    round_id = case_row[offsets["round_id"]] if "round_id" in offsets else None
                    round_spec_id = case_row[offsets["round_spec_id"]] if "round_spec_id" in offsets else None
        except Exception:
            # Standalone/legacy databases may not contain a compatible queue.
            case_id = None
            round_id = None
            round_spec_id = None
        self.db.execute(
            """INSERT OR IGNORE INTO evidence_observations
               (atom_id, task_id, role, observed_at, case_id, round_id, round_spec_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (atom_id, task_id, role, now, case_id, round_id, round_spec_id),
        )
        self.db.execute(
            """DELETE FROM evidence_observations
               WHERE rowid IN (
                   SELECT rowid FROM evidence_observations
                   ORDER BY observed_at DESC, rowid DESC
                   LIMIT -1 OFFSET ?
               )""",
            (self.MAX_OBSERVATIONS,),
        )
        if commit:
            self.db.commit()
        result["observations"] = self.db.execute(
            "SELECT COUNT(*) FROM evidence_observations"
        ).fetchone()[0]
        return result

    @staticmethod
    def _finding_identity(finding):
        if not isinstance(finding, dict):
            return None
        identity = {}
        for key in ("repository", "file", "rule", "description", "contract", "address"):
            value = finding.get(key)
            if value is not None and str(value).strip():
                identity[key] = str(value).strip()
        return tuple(sorted(identity.items())) if identity else None

    @staticmethod
    def _finding_status(finding):
        if not isinstance(finding, dict):
            return None
        for key in ("status", "verdict", "result"):
            value = finding.get(key)
            if value is not None and str(value).strip():
                return str(value).strip().upper()
        return None

    def detect_contradictions(self, atoms):
        """Detect explicit contradictions without treating refinements as conflicts."""
        findings = []
        for atom in sorted(set(atoms or ())):
            kind, value = self.split_atom(atom)
            if kind != "finding":
                continue
            try:
                finding = json.loads(value)
            except Exception:
                continue
            identity = self._finding_identity(finding)
            status = self._finding_status(finding)
            if identity and status:
                findings.append((self.atom_id(atom), identity, status))

        if not findings:
            return []

        # Only compare against identities already present in the ledger.
        # Keep the lookup bounded by the identities in this observation so a
        # large historical ledger cannot turn each record into a full scan.
        identities = {identity for _, identity, _ in findings}
        existing = []
        for identity in identities:
            identity_map = dict(identity)
            predicates = []
            params = []
            for key in ("repository", "file", "rule", "contract", "address", "description"):
                value = identity_map.get(key)
                if value is None:
                    continue
                predicates.append("value LIKE ?")
                params.append(
                    f"%{json.dumps(key)}:{json.dumps(value, ensure_ascii=False)}%"
                )
            if not predicates:
                continue
            candidates = self.db.execute(
                "SELECT atom_id, value FROM evidence_ledger "
                "WHERE kind = 'finding' AND " + " AND ".join(predicates),
                tuple(params),
            ).fetchall()
            existing.extend(candidates)
        opposite = {
            "POTENTIAL_RISK": {"SAFE", "NOT_A_RISK", "FALSE_POSITIVE", "REJECTED"},
            "CONFIRMED": {"SAFE", "NOT_A_RISK", "FALSE_POSITIVE", "REJECTED"},
            "SAFE": {"POTENTIAL_RISK", "CONFIRMED"},
            "NOT_A_RISK": {"POTENTIAL_RISK", "CONFIRMED"},
            "FALSE_POSITIVE": {"POTENTIAL_RISK", "CONFIRMED"},
            "REJECTED": {"POTENTIAL_RISK", "CONFIRMED"},
        }
        conflicts = []
        for atom_id, identity, status in findings:
            for existing_id, value in existing:
                if existing_id == atom_id:
                    continue
                try:
                    old = json.loads(value)
                except Exception:
                    continue
                old_identity = self._finding_identity(old)
                old_status = self._finding_status(old)
                if old_identity == identity and old_status in opposite.get(status, set()):
                    pair = tuple(sorted((atom_id, existing_id)))
                    if pair not in {(c["atom_id"], c["other_atom_id"]) for c in conflicts}:
                        conflicts.append({
                            "atom_id": pair[0],
                            "other_atom_id": pair[1],
                            "reason": f"same finding identity with contradictory status: {status} vs {old_status}",
                        })
        return conflicts

    def record_contradictions(self, task_id, role, contradictions, observed_at=None, commit=True):
        if not contradictions:
            return 0
        now = observed_at or datetime.now(timezone.utc).isoformat()
        count = 0
        for item in contradictions:
            a, b = item["atom_id"], item["other_atom_id"]
            self.db.execute("""
                INSERT INTO evidence_contradictions
                (atom_id, other_atom_id, first_seen, last_seen, first_task_id, latest_task_id, latest_role, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(atom_id, other_atom_id) DO UPDATE SET
                    last_seen=excluded.last_seen, latest_task_id=excluded.latest_task_id,
                    latest_role=excluded.latest_role, reason=excluded.reason
            """, (a, b, now, now, task_id, task_id, role or "unknown", item["reason"]))
            count += 1
        if commit:
            self.db.commit()
        return count

    def contradiction_stats(self):
        row = self.db.execute(
            "SELECT COUNT(*) FROM evidence_contradictions"
        ).fetchone()
        return {"contradictions": row[0]}

    def evidence_quality(self, atom_id):
        """Return explainable evidence quality without pretending it is probability."""
        row = self.db.execute(
            """SELECT kind, value, confirmation_count, independent_role_count,
                      first_seen, last_seen, latest_task_id, latest_role
               FROM evidence_ledger WHERE atom_id = ?""",
            (atom_id,),
        ).fetchone()
        if row is None:
            return None

        contradiction_count = self.db.execute(
            """SELECT COUNT(*) FROM evidence_contradictions
               WHERE atom_id = ? OR other_atom_id = ?""",
            (atom_id, atom_id),
        ).fetchone()[0]

        independent_roles = row[3]
        if contradiction_count:
            state = "CONTESTED"
            quality_score = 15
        elif independent_roles >= 3:
            state = "MULTI_SOURCE"
            quality_score = 85
        elif independent_roles >= 2:
            state = "CORROBORATED"
            quality_score = 60
        else:
            state = "UNCONFIRMED"
            quality_score = 25

        return {
            "atom_id": atom_id,
            "kind": row[0],
            "value": row[1],
            "confirmation_count": row[2],
            "independent_role_count": independent_roles,
            "contradiction_count": contradiction_count,
            "state": state,
            # Ordinal evidence-strength index, not a probability.
            # It is derived only from independent-role corroboration and
            # contradiction state so planner behavior remains explainable.
            "quality_score": quality_score,
            "first_seen": row[4],
            "last_seen": row[5],
            "latest_task_id": row[6],
            "latest_role": row[7],
        }

    def stats(self):
        row = self.db.execute(
            "SELECT COUNT(*), COALESCE(SUM(confirmation_count), 0) "
            "FROM evidence_ledger"
        ).fetchone()
        return {"atoms": row[0], "confirmations": row[1]}

# Versioned, portable evidence records. ResearchCase remains the canonical
# domain contract in shared.research_case; TypeAdapter validates that contract
# instead of introducing a second ResearchCase class.
from dataclasses import asdict as _dataclass_asdict
from enum import Enum as _Enum
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError


EVIDENCE_SCHEMA_VERSION = "aegisforge-evidence-v1"


class _EvidenceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    schema_version: Literal["aegisforge-evidence-v1"]


class Hypothesis(_EvidenceRecord):
    """Falsifiable, scope-bound research hypothesis."""
    hypothesis_id: str
    claim: str
    affected_component: str
    source_revision: str
    source_locations: list[str]
    attacker_capability: str
    preconditions: list[str]
    expected_invariant: str
    reproduction_procedure: str
    counter_test: str
    impact_path: str
    scope_reference: str
    scope_status: Literal["IN_SCOPE", "OUT_OF_SCOPE", "UNVERIFIED"]
    conclusion: Literal["CONFIRMED", "REJECTED", "INCONCLUSIVE", "OUT_OF_SCOPE", "NOT_REPRODUCED"]
    evidence_refs: list[str]


class EvidenceArtifact(_EvidenceRecord):
    """Content-addressable artifact metadata; the manifest verifier checks bytes."""
    artifact_id: str
    case_id: str
    target_revision: str
    scope_reference: str
    hypothesis_id: str
    relative_path: str
    media_type: str
    sha256: str
    size_bytes: int


class VerificationCheck(_EvidenceRecord):
    check_id: str
    level: Literal[1, 2, 3, 4, 5]
    status: Literal["PASS", "FAIL", "SKIP", "INCONCLUSIVE"]
    detail: str
    artifact_refs: list[str]


class Finding(_EvidenceRecord):
    finding_id: str
    case_id: str
    hypothesis_id: str
    title: str
    claim: str
    impact: str
    severity_rationale: str
    conclusion: Literal["CONFIRMED", "REJECTED", "INCONCLUSIVE", "OUT_OF_SCOPE", "NOT_REPRODUCED"]
    evidence_refs: list[str]


def _plain(value: Any) -> Any:
    """Convert dataclasses/enums to stable JSON-compatible primitives."""
    if hasattr(value, "__dataclass_fields__"):
        value = _dataclass_asdict(value)
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, _Enum):
        return value.value
    return value


def serialize_research_case(case: Any) -> dict[str, Any]:
    """Serialize the existing ResearchCase domain type in a versioned envelope."""
    from shared.research_case import ResearchCase
    if not isinstance(case, ResearchCase):
        raise TypeError("case must be shared.research_case.ResearchCase")
    data = _plain(case)
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "record_type": "ResearchCase",
        "data": data,
    }


def deserialize_research_case(payload: dict[str, Any]):
    """Validate a versioned envelope against the canonical ResearchCase type."""
    from shared.research_case import ResearchCase
    if not isinstance(payload, dict):
        raise ValueError("ResearchCase envelope must be an object")
    if payload.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        raise ValueError("Unsupported or missing evidence schema_version")
    if payload.get("record_type") != "ResearchCase":
        raise ValueError("Unexpected record_type for ResearchCase envelope")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError("ResearchCase envelope data must be an object")
    # Pydantic validates the existing dataclass without defining a competing
    # ResearchCase model or weakening its own fail-closed __post_init__ checks.
    return TypeAdapter(ResearchCase).validate_python(data)


def serialize_record(record: _EvidenceRecord) -> dict[str, Any]:
    """Return a JSON-compatible, versioned record with strict model validation."""
    if not isinstance(record, _EvidenceRecord):
        raise TypeError("record must be a versioned evidence record")
    return record.model_dump(mode="json")


def deserialize_record(model: type[_EvidenceRecord], payload: dict[str, Any]) -> _EvidenceRecord:
    """Strictly deserialize one evidence record; unknown fields and omissions fail."""
    if not isinstance(model, type) or not issubclass(model, _EvidenceRecord):
        raise TypeError("model must be a supported versioned evidence model")
    return model.model_validate(payload)


# Case-bound file manifest for portable evidence bundles. This is separate from
# the existing in-memory Merkle manifest used for capability/receipt bindings.
CASE_ARTIFACT_MANIFEST_VERSION = "aegisforge-case-artifact-manifest-v1"
CASE_ARTIFACT_MANIFEST_FILENAME = "case-artifact-manifest.json"
MAX_CASE_ARTIFACTS = 10_000
MAX_CASE_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_CASE_ARTIFACT_TOTAL_BYTES = 1024 * 1024 * 1024


class CaseArtifactManifestError(ValueError):
    """A case-bound evidence manifest or artifact path is invalid."""


def _manifest_canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _safe_artifact_file(root, relative_path):
    from pathlib import Path, PurePosixPath

    if not isinstance(relative_path, str) or not relative_path or "\\" in relative_path:
        raise CaseArtifactManifestError("invalid_artifact_path")
    # Validate the raw spelling before PurePosixPath normalizes "." and repeated "/".
    if any(part in ("", ".", "..") for part in relative_path.split("/")):
        raise CaseArtifactManifestError("invalid_artifact_path")
    rel = PurePosixPath(relative_path)
    if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
        raise CaseArtifactManifestError("invalid_artifact_path")
    if rel.parts and ":" in rel.parts[0]:
        raise CaseArtifactManifestError("invalid_artifact_path")

    root_input = Path(root)
    if root_input.is_symlink():
        raise CaseArtifactManifestError("artifact_root_must_not_be_symlink")
    root_path = root_input.resolve(strict=True)
    if not root_path.is_dir():
        raise CaseArtifactManifestError("artifact_root_not_directory")
    candidate = root_path
    for part in rel.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise CaseArtifactManifestError("symlink_artifact_not_allowed")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root_path)
    except (OSError, ValueError) as exc:
        raise CaseArtifactManifestError("artifact_path_outside_root_or_missing") from exc
    if not resolved.is_file():
        raise CaseArtifactManifestError("artifact_not_regular_file")
    return resolved


def _file_sha256(path, *, max_bytes=None):
    if max_bytes is None:
        max_bytes = MAX_CASE_ARTIFACT_BYTES
    hasher = hashlib.sha256()
    size = 0
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            if size > max_bytes:
                raise CaseArtifactManifestError("artifact_size_limit_exceeded")
            hasher.update(chunk)
    return hasher.hexdigest(), size


def _case_manifest_payload(case_id, hypothesis_id, artifacts):
    return {
        "schema_version": CASE_ARTIFACT_MANIFEST_VERSION,
        "case_id": case_id,
        "hypothesis_id": hypothesis_id,
        "artifacts": artifacts,
    }


def build_case_artifact_manifest(root, *, case_id, hypothesis_id, artifact_paths):
    """Build a portable manifest linking each artifact's bytes to a case and hypothesis."""
    from pathlib import PurePosixPath

    for name, value in (("case_id", case_id), ("hypothesis_id", hypothesis_id)):
        if not isinstance(value, str) or not value.strip():
            raise CaseArtifactManifestError(f"invalid_{name}")
    if isinstance(artifact_paths, (str, bytes)) or not isinstance(artifact_paths, (list, tuple, set)):
        raise CaseArtifactManifestError("artifact_paths_must_be_a_collection")
    if not artifact_paths:
        raise CaseArtifactManifestError("artifact_paths_required")
    if len(artifact_paths) > MAX_CASE_ARTIFACTS:
        raise CaseArtifactManifestError("artifact_count_limit_exceeded")

    normalized = []
    seen = set()
    total_size = 0
    for relative_path in artifact_paths:
        if relative_path == CASE_ARTIFACT_MANIFEST_FILENAME:
            raise CaseArtifactManifestError("manifest_cannot_include_itself_as_artifact")
        path = _safe_artifact_file(root, relative_path)
        normalized_path = PurePosixPath(relative_path).as_posix()
        if normalized_path in seen:
            raise CaseArtifactManifestError("duplicate_artifact_path")
        seen.add(normalized_path)
        sha256, size_bytes = _file_sha256(path)
        total_size += size_bytes
        if total_size > MAX_CASE_ARTIFACT_TOTAL_BYTES:
            raise CaseArtifactManifestError("bundle_size_limit_exceeded")
        normalized.append({
            "path": normalized_path,
            "sha256": sha256,
            "size_bytes": size_bytes,
        })
    normalized.sort(key=lambda item: item["path"])
    payload = _case_manifest_payload(case_id.strip(), hypothesis_id.strip(), normalized)
    payload["manifest_sha256"] = hashlib.sha256(
        _manifest_canonical_json(payload).encode("utf-8")
    ).hexdigest()
    return payload



def write_case_artifact_manifest(root, *, case_id, hypothesis_id, artifact_paths):
    """Build and atomically write the portable case manifest into the bundle root."""
    from pathlib import Path

    root_path = Path(root)
    if root_path.is_symlink():
        raise CaseArtifactManifestError("artifact_root_must_not_be_symlink")
    try:
        root_path = root_path.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise CaseArtifactManifestError("artifact_root_missing_or_invalid") from exc
    if not root_path.is_dir():
        raise CaseArtifactManifestError("artifact_root_not_directory")
    if isinstance(artifact_paths, (str, bytes)) or not isinstance(artifact_paths, (list, tuple, set)):
        raise CaseArtifactManifestError("artifact_paths_must_be_a_collection")
    if any(path == CASE_ARTIFACT_MANIFEST_FILENAME for path in artifact_paths):
        raise CaseArtifactManifestError("manifest_cannot_include_itself_as_artifact")

    target = root_path / CASE_ARTIFACT_MANIFEST_FILENAME
    if target.is_symlink():
        raise CaseArtifactManifestError("manifest_file_must_not_be_symlink")
    manifest = build_case_artifact_manifest(
        root_path,
        case_id=case_id,
        hypothesis_id=hypothesis_id,
        artifact_paths=artifact_paths,
    )

    fd, temporary_name = tempfile.mkstemp(
        prefix=".case-artifact-manifest-", suffix=".tmp", dir=str(root_path)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(manifest, stream, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, target)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise
    return manifest


def verify_case_artifact_manifest(root, manifest):
    """Return explicit PASS/FAIL checks; never treat malformed or missing evidence as success."""
    if not isinstance(manifest, dict):
        return {"status": "FAIL", "errors": ["manifest_must_be_an_object"]}
    expected_keys = {
        "schema_version", "case_id", "hypothesis_id", "artifacts", "manifest_sha256"
    }
    if set(manifest) != expected_keys:
        return {"status": "FAIL", "errors": ["manifest_fields_invalid"]}
    if manifest.get("schema_version") != CASE_ARTIFACT_MANIFEST_VERSION:
        return {"status": "FAIL", "errors": ["unsupported_manifest_schema"]}
    for field in ("case_id", "hypothesis_id", "manifest_sha256"):
        value = manifest.get(field)
        if not isinstance(value, str) or not value.strip():
            return {"status": "FAIL", "errors": [f"invalid_{field}"]}
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return {"status": "FAIL", "errors": ["artifacts_required"]}
    if len(artifacts) > MAX_CASE_ARTIFACTS:
        return {"status": "FAIL", "errors": ["artifact_count_limit_exceeded"]}

    seen = set()
    total_size = 0
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256", "size_bytes"}:
            return {"status": "FAIL", "errors": ["artifact_entry_invalid"]}
        path = artifact.get("path")
        digest = artifact.get("sha256")
        size = artifact.get("size_bytes")
        if not isinstance(path, str) or not path:
            return {"status": "FAIL", "errors": ["artifact_path_invalid"]}
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            return {"status": "FAIL", "errors": [f"artifact_digest_invalid:{path}"]}
        if type(size) is not int or size < 0:
            return {"status": "FAIL", "errors": [f"artifact_size_invalid:{path}"]}
        if size > MAX_CASE_ARTIFACT_BYTES:
            return {"status": "FAIL", "errors": [f"artifact_size_limit_exceeded:{path}"]}
        total_size += size
        if total_size > MAX_CASE_ARTIFACT_TOTAL_BYTES:
            return {"status": "FAIL", "errors": ["bundle_size_limit_exceeded"]}
        if path in seen:
            return {"status": "FAIL", "errors": ["duplicate_artifact_path"]}
        seen.add(path)

    payload = _case_manifest_payload(
        manifest["case_id"], manifest["hypothesis_id"], artifacts
    )
    actual_manifest_digest = hashlib.sha256(
        _manifest_canonical_json(payload).encode("utf-8")
    ).hexdigest()
    if actual_manifest_digest != manifest["manifest_sha256"]:
        return {"status": "FAIL", "errors": ["manifest_digest_mismatch"]}

    for artifact in artifacts:
        try:
            path = _safe_artifact_file(root, artifact["path"])
            actual_digest, actual_size = _file_sha256(
                path, max_bytes=artifact["size_bytes"]
            )
        except (CaseArtifactManifestError, OSError, ValueError) as exc:
            return {"status": "FAIL", "errors": [f"artifact_unavailable:{artifact['path']}:{exc}"]}
        if actual_digest != artifact["sha256"]:
            return {"status": "FAIL", "errors": [f"artifact_digest_mismatch:{artifact['path']}"]}
        if actual_size != artifact["size_bytes"]:
            return {"status": "FAIL", "errors": [f"artifact_size_mismatch:{artifact['path']}"]}
    return {
        "status": "PASS",
        "case_id": manifest["case_id"],
        "hypothesis_id": manifest["hypothesis_id"],
        "checked_artifacts": len(artifacts),
        "manifest_sha256": manifest["manifest_sha256"],
        "errors": [],
    }

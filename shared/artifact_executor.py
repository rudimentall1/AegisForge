import hashlib
import os
from pathlib import Path


class ArtifactExecutorError(ValueError):
    pass


class SafeArtifactPublisher:
    """Publish one explicitly authorized artifact inside a staging root."""

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _resolve_target(self, intent):
        raw = str(intent.target or "")
        if not raw:
            raise ArtifactExecutorError("artifact_target_required")
        target = (self.root / raw).resolve()
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise ArtifactExecutorError("artifact_path_escape") from exc
        if target == self.root or target.is_dir():
            raise ArtifactExecutorError("artifact_target_invalid")
        return target

    def publish(self, intent):
        if intent.action != "publish":
            raise ArtifactExecutorError("unsupported_artifact_action")
        parameters = dict(intent.parameters or {})
        content = parameters.get("content")
        if not isinstance(content, str):
            raise ArtifactExecutorError("artifact_content_required")
        declared_sha256 = parameters.get("sha256")
        actual_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if declared_sha256 != actual_sha256:
            raise ArtifactExecutorError("artifact_content_hash_mismatch")

        target = self._resolve_target(intent)
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        try:
            temp.write_text(content, encoding="utf-8")
            os.replace(temp, target)
        finally:
            if temp.exists():
                temp.unlink()

        return {
            "published": str(target.relative_to(self.root)),
            "sha256": actual_sha256,
            "bytes": len(content.encode("utf-8")),
        }

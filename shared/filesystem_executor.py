from pathlib import Path


class FilesystemExecutorError(ValueError):
    pass


class SafeFilesystemExecutor:
    """Constrained filesystem executor for an explicitly configured root.

    It intentionally exposes only deletion for the first concrete adapter:
    the target path is part of ActionIntent and therefore covered by the grant.
    No arbitrary content is accepted outside the authorized intent.
    """

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _resolve_target(self, intent):
        raw = str(intent.target or "")
        if not raw:
            raise FilesystemExecutorError("filesystem_target_required")
        candidate = (self.root / raw).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise FilesystemExecutorError("filesystem_path_escape") from exc
        if candidate == self.root:
            raise FilesystemExecutorError("filesystem_root_protected")
        return candidate

    def delete(self, intent):
        if intent.action != "delete":
            raise FilesystemExecutorError("unsupported_filesystem_action")
        if not intent.irreversible:
            raise FilesystemExecutorError("delete_must_be_irreversible")
        target = self._resolve_target(intent)
        if not target.exists():
            raise FilesystemExecutorError("filesystem_target_missing")
        if target.is_dir():
            raise FilesystemExecutorError("directory_delete_not_supported")
        target.unlink()
        return {"deleted": str(target.relative_to(self.root))}

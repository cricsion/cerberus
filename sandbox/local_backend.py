"""Repo-confined read backend for scan agents (no sandbox, no shell).

Extends FilesystemBackend — never a sandbox-protocol backend — so
deepagents creates no `execute` tool. All reads stay inside `repo_path`.
"""
from __future__ import annotations

import uuid
from pathlib import Path

from deepagents.backends.filesystem import FilesystemBackend

from harness.paths import resolve_tool_path


class RepoLocalBackend(FilesystemBackend):
    def __init__(self, *, repo_path: str | Path) -> None:
        self.repo_path = Path(repo_path).resolve()
        if not self.repo_path.is_dir():
            raise ValueError(f"repo_path is not a directory: {repo_path}")
        # Denial target: never created, so denied reads return the base's
        # structured "not found" instead of raising (the base methods do not
        # catch ValueError).
        self._sentinel = self.repo_path / f".denied-{uuid.uuid4().hex[:16]}"
        super().__init__(root_dir=self.repo_path, virtual_mode=True)

    def _resolve_path(self, key: str) -> Path:
        # One contract for every accepted spelling: repo-relative, host-absolute
        # under the root, or a virtual leading-slash path whose repo-local
        # target exists. Anything that escapes resolves to the sentinel.
        resolved = resolve_tool_path(key, self.repo_path)
        return resolved if resolved is not None else self._sentinel

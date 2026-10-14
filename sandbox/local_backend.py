"""Repo-confined local backend for scan agents (no sandbox, no shell).

Extends :class:`FilesystemBackend` -- file operations only. It deliberately
does NOT extend ``LocalShellBackend``, so the backend never satisfies
``SandboxBackendProtocol`` and deepagents never creates an ``execute`` tool
for it. There is no shell to refuse; one simply does not exist.

All reads run in-process against the target repository with resolve-then-check
containment: symlinks pointing outside the repo are rejected, not followed.

Read-only by design: write/edit/delete raise.
"""
from __future__ import annotations

import os
from pathlib import Path

from deepagents.backends.filesystem import FilesystemBackend
from deepagents.backends.protocol import (
    FileDownloadResponse,
    FileUploadResponse,
    GrepResult,
)

from .credentials import (CREDENTIAL_GLOBS, find_credential_files,
                          is_credential_path)

_REFUSAL = "refused: the scan backend is read-only"


class RepoLocalBackend(FilesystemBackend):
    """Filesystem backend confined to a single repository directory."""

    def __init__(self, *, repo_path: str | Path,
                 denied_globs: tuple[str, ...] | list[str] | None = None) -> None:
        self.repo_path = Path(repo_path).resolve()
        if not self.repo_path.is_dir():
            raise ValueError(f"repo_path is not a directory: {repo_path}")
        # Credential files are readable-but-refused: egress is allowed, so a
        # live key inside the scanned tree must not be handed to the model
        # through the cheap in-process path.
        self.denied_globs = tuple(CREDENTIAL_GLOBS if denied_globs is None
                                  else denied_globs)
        # Protect the in-repo destination of a credential-named symlink too.
        # Otherwise `.env -> settings.txt` is refused by name while a direct
        # read of settings.txt still exposes the same bytes.
        self._credential_targets: set[Path] = set()
        if self.denied_globs:
            for rel in find_credential_files(self.repo_path, self.denied_globs):
                try:
                    target = (self.repo_path / rel).resolve()
                    target.relative_to(self.repo_path)
                except (OSError, RuntimeError, ValueError):
                    continue
                if target.is_file():
                    self._credential_targets.add(target)
        super().__init__(root_dir=self.repo_path, virtual_mode=True)

    def _is_credential_path(self, target: Path,
                            requested_path: str | None = None) -> bool:
        if not self.denied_globs:
            return False
        try:
            rel = str(target.relative_to(self.repo_path))
        except ValueError:
            return False
        if (target in self._credential_targets
                or is_credential_path(rel, self.denied_globs)):
            return True
        if requested_path is None:
            return False
        lexical = os.path.normpath(
            str(requested_path).strip().replace("\\", "/").lstrip("/"))
        return is_credential_path(lexical, self.denied_globs)

    @staticmethod
    def _credential_refusal(file_path: str) -> str:
        return (f"refused: {file_path!r} is a credential file; the scan "
                "sandbox will not hand it to the model")

    def _contained(self, key: str | None) -> Path:
        """Resolve an agent-supplied path and enforce repo containment.

        In virtual mode (always, for scan backends) paths are repo-relative
        and the middleware normalizes them to leading-slash form: the model
        asks for ``/app.py`` or ``app.py`` and both mean
        ``<repo>/app.py``. Absolute-looking paths therefore map INTO the repo;
        the containment check then still rejects anything that resolves
        outside it (e.g. via a symlink planted inside the repo).
        """
        p = (key or ".").strip() or "."
        # virtual_mode is always True for scan backends -- the constructor
        # forces it and nothing reassigns it -- so the non-virtual branches
        # are unreachable and paths are always repo-relative.
        candidate = (self.repo_path / p.lstrip("/")).resolve()
        try:
            candidate.relative_to(self.repo_path)
        except ValueError:
            raise ValueError(f"Access denied: {key!r} is outside the repo") from None
        return candidate

    # -- reads: validate, then delegate ---------------------------------

    def read(self, file_path: str, offset: int = 0, limit: int = 2000):  # type: ignore[override]
        try:
            target = self._contained(file_path)
        except ValueError as e:
            from deepagents.backends.protocol import ReadResult
            return ReadResult(error=str(e))
        if self._is_credential_path(target, file_path):
            from deepagents.backends.protocol import ReadResult
            return ReadResult(error=self._credential_refusal(file_path))
        rel = str(target.relative_to(self.repo_path))
        return super().read(rel, offset=offset, limit=limit)

    def grep(self, pattern: str, path: str | None = None, glob: str | None = None,
             *, max_count: int | None = None, context_lines: int = 0):  # type: ignore[override]
        """Search the repo without returning credential-file contents.

        The base filesystem backend searches recursively, so a directory
        search must filter matches as well as refusing a credential file when
        it is named directly. Filtering is done on resolved paths, which also
        closes aliases through in-repo symlinks.
        """
        search_path = path or "."
        try:
            target = self._contained(search_path)
        except ValueError as e:
            return GrepResult(error=str(e), matches=[])
        if target.is_file() and self._is_credential_path(target, search_path):
            return GrepResult(error=self._credential_refusal(search_path), matches=[])

        result = super().grep(pattern, search_path, glob, max_count=max_count,
                              context_lines=context_lines)
        if not result.matches:
            return result

        safe_matches = []
        for match in result.matches:
            try:
                match_path = self._contained(match.get("path", ""))
            except (ValueError, OSError, RuntimeError):
                # The base backend already enforces containment, but fail
                # closed if a path changes between its search and this check.
                continue
            if not self._is_credential_path(match_path, match.get("path", "")):
                safe_matches.append(match)
        if len(safe_matches) == len(result.matches):
            return result
        return GrepResult(error=result.error, matches=safe_matches,
                          truncated=result.truncated)

    def ls(self, path: str = "."):  # type: ignore[override]
        try:
            target = self._contained(path)
        except ValueError as e:
            from deepagents.backends.protocol import LsResult
            return LsResult(error=str(e))
        rel = str(target.relative_to(self.repo_path))
        return super().ls(rel)

    def glob(self, pattern: str, path: str | None = None):  # type: ignore[override]
        try:
            target = self._contained(path or ".")
        except ValueError as e:
            from deepagents.backends.protocol import GlobResult
            return GlobResult(error=str(e))
        rel = str(target.relative_to(self.repo_path))
        return super().glob(pattern, rel)

    def upload_files(self, files: list[tuple[str, bytes]]) -> list[FileUploadResponse]:
        return [FileUploadResponse(path=dest, error=_REFUSAL) for dest, _ in files]

    def download_files(self, paths: list[str]) -> list[FileDownloadResponse]:
        out: list[FileDownloadResponse] = []
        for src in paths:
            try:
                target = self._contained(src)
            except ValueError as e:
                out.append(FileDownloadResponse(path=src, content=None, error=str(e)))
                continue
            if self._is_credential_path(target, src):
                out.append(FileDownloadResponse(
                    path=src, content=None,
                    error=self._credential_refusal(src)))
                continue
            try:
                out.append(FileDownloadResponse(
                    path=src, content=target.read_bytes(), error=None))
            except OSError as e:
                out.append(FileDownloadResponse(path=src, content=None, error=str(e)))
        return out

    # -- refused: no mutation --------------------------------------------
    # Denials return structured errors (not raises): a raise halts the agent
    # run, while an error result lets the model recover and continue.

    def write(self, file_path: str = "", *args, **kwargs):  # type: ignore[override]
        from deepagents.backends.protocol import WriteResult
        return WriteResult(error=_REFUSAL + " (write blocked).", path=file_path)

    def edit(self, file_path: str = "", *args, **kwargs):  # type: ignore[override]
        from deepagents.backends.protocol import EditResult
        return EditResult(error=_REFUSAL + " (edit blocked).", path=file_path)

    def delete(self, file_path: str = "", *args, **kwargs):  # type: ignore[override]
        from deepagents.backends.protocol import DeleteResult
        return DeleteResult(error=_REFUSAL + " (delete blocked).", path=file_path)

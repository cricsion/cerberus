"""Repo-confined local backend for scan agents (no sandbox, no shell).

Extends :class:`FilesystemBackend`, never ``LocalShellBackend``, so deepagents
creates no ``execute`` tool. Reads run in-process with resolve-then-check
containment (symlinks outside the repo are rejected, not followed);
write/edit/delete raise.
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
        # Credentials are readable-but-refused: egress is allowed, so a live
        # key must not reach the model by this cheap in-process path.
        self.denied_globs = tuple(CREDENTIAL_GLOBS if denied_globs is None
                                  else denied_globs)
        # Protect the in-repo destination of a credential-named symlink too:
        # `.env -> settings.txt` must not leak the same bytes by direct read.
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
        """Resolve an agent-supplied path and enforce repo containment: in
        virtual mode paths are repo-relative (``/app.py`` maps INTO the repo),
        and anything resolving outside it is rejected."""
        p = (key or ".").strip() or "."
        # Handle cases where agents provide absolute or relative paths referencing self.repo_path
        # e.g., /Users/.../repo/path/file.py or Real-Vuln-Benchmark/repos/realvuln-.../file.py
        repo_str = str(self.repo_path)
        repo_str_lstrip = repo_str.lstrip("/")
        stripped = p.lstrip("/")
        if p == repo_str or p.startswith(repo_str + "/"):
            p = p[len(repo_str):].lstrip("/")
        elif stripped == repo_str_lstrip or stripped.startswith(repo_str_lstrip + "/"):
            p = stripped[len(repo_str_lstrip):].lstrip("/")
        elif self.repo_path.name and (stripped == self.repo_path.name or stripped.startswith(self.repo_path.name + "/")):
            p = stripped[len(self.repo_path.name):].lstrip("/")
        else:
            # Check if stripped ends with repo_path's tail or relative path from workspace
            for ancestor in [self.repo_path] + list(self.repo_path.parents):
                try:
                    rel_to_ancestor = str(self.repo_path.relative_to(ancestor))
                    if rel_to_ancestor and rel_to_ancestor != ".":
                        if stripped == rel_to_ancestor or stripped.startswith(rel_to_ancestor + "/"):
                            p = stripped[len(rel_to_ancestor):].lstrip("/")
                            break
                except ValueError:
                    pass

        # virtual_mode is always True for scan backends (constructor forces it,
        # nothing reassigns it), so paths are always repo-relative.
        candidate = (self.repo_path / p.lstrip("/")).resolve()
        try:
            candidate.relative_to(self.repo_path)
        except ValueError:
            raise ValueError(f"Access denied: {key!r} is outside the repo") from None
        return candidate

    def _resolve_path(self, key: str) -> Path:
        """Containment-based resolver for the base backend's virtual mode.

        The base implementation rejects any path containing the substring
        ".." before resolving — a false positive on legitimate filenames like
        Next.js catch-alls (``pages/api/auth/[...nextauth].js``; the dots sit
        inside the brackets). Enforce the real invariant instead, same as
        every other entry point here: resolve, then require containment under
        ``repo_path`` (this still rejects real ``..`` escapes and symlinks
        that leave the repo).
        """
        return self._contained(key)

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
        """Search the repo without returning credential-file contents: a
        directory search filters matches as well as refusing a file named
        directly, and filtering on resolved paths closes symlink aliases."""
        search_path = path or "."
        try:
            target = self._contained(search_path)
        except ValueError as e:
            return GrepResult(error=str(e), matches=[])
        if target.is_file() and self._is_credential_path(target, search_path):
            return GrepResult(error=self._credential_refusal(search_path), matches=[])

        rel_search_path = str(target.relative_to(self.repo_path))
        result = super().grep(pattern, rel_search_path, glob, max_count=max_count,
                              context_lines=context_lines)
        if not result.matches:
            return result

        safe_matches = []
        for match in result.matches:
            try:
                match_path = self._contained(match.get("path", ""))
            except (ValueError, OSError, RuntimeError):
                # Base backend enforces containment; fail closed anyway if a
                # path changes between its search and this check.
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
    # Denials return structured errors, never raise: a raise halts the agent run.

    def write(self, file_path: str = "", *args, **kwargs):  # type: ignore[override]
        from deepagents.backends.protocol import WriteResult
        return WriteResult(error=_REFUSAL + " (write blocked).", path=file_path)

    def edit(self, file_path: str = "", *args, **kwargs):  # type: ignore[override]
        from deepagents.backends.protocol import EditResult
        return EditResult(error=_REFUSAL + " (edit blocked).", path=file_path)

    def delete(self, file_path: str = "", *args, **kwargs):  # type: ignore[override]
        from deepagents.backends.protocol import DeleteResult
        return DeleteResult(error=_REFUSAL + " (delete blocked).", path=file_path)

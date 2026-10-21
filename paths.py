"""One path contract for the scanner.

The canonical repo root is an absolute, resolved path computed once per scan.
File tools accept three spellings (repo-relative, host-absolute under the root,
and the legacy virtual leading-slash form), while model output is always a
repo-relative POSIX path.

Resolution order (see ``resolve_tool_path``):
1. absolute and inside the root;
2. absolute outside the root but shadowing a repo-local target that exists;
3. relative and inside the root;
4. denied.

Symlinks are followed before every containment check, so an in-repo link to
the host filesystem never becomes a read outside the root.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def canonical_repo(repo: str | Path) -> Path:
    """Resolve the repo root once: absolute, expanded, symlink-free."""
    return Path(repo).expanduser().resolve()


def _resolve(path: Path) -> Path | None:
    """Resolve without requiring existence; None when unaddressable."""
    try:
        return path.expanduser().resolve()
    except (OSError, ValueError):
        return None


def _exists(path: Path | None) -> bool:
    """Existence probe that treats an OS refusal as 'not addressable'."""
    if path is None:
        return False
    try:
        return path.exists()
    except (OSError, ValueError):
        return False


def is_within(path: Path, root: Path) -> bool:
    """True when ``path`` resolves to ``root`` or a descendant of it."""
    resolved = _resolve(path)
    base = _resolve(root)
    if resolved is None or base is None:
        return False
    return resolved == base or base in resolved.parents


def resolve_tool_path(path: str, repo: str | Path) -> Path | None:
    """Resolve a tool-supplied path under ``repo``; None when it escapes.

    Accepts repo-relative paths, host-absolute paths under the root, and the
    virtual leading-slash form (``/etc/passwd`` -> ``<repo>/etc/passwd``) when
    that repo-local target exists.
    """
    root = canonical_repo(repo)
    raw = str(path or "").strip().replace("\\", "/")
    if raw in ("", ".", "./"):
        return root

    if Path(raw).is_absolute():
        candidate = _resolve(Path(raw))
        if candidate is not None and is_within(candidate, root):
            return candidate
        # Virtual form: only an existing repo-local counterpart is acceptable
        # (this preserves confinement for /etc/passwd shadowing).
        virtual = _resolve(root / raw.lstrip("/"))
        if virtual is not None and is_within(virtual, root) and _exists(virtual):
            return virtual
        return None

    candidate = _resolve(root / raw)
    if candidate is not None and is_within(candidate, root):
        return candidate
    return None


def _strip_dot_prefix(path: str) -> str:
    """Drop leading ``./`` components only (never ``lstrip('./')``)."""
    while path.startswith("./"):
        path = path[2:]
    return path


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def to_repo_relative(path: str, repo: str | Path) -> str:
    """Canonical repo-relative POSIX spelling of a model-derived path.

    Returns the normalized input, and logs a warning, when containment cannot
    be proven. Never returns the host-absolute form for a contained path.
    """
    root = canonical_repo(repo)
    raw = str(path or "").strip().replace("\\", "/")
    if not raw:
        return ""
    if raw in (".", "./"):
        return "."

    if Path(raw).is_absolute():
        candidate = _resolve(Path(raw))
        if candidate is not None and is_within(candidate, root):
            return _relative(candidate, root)
        # Virtual leading-slash form: only trust it when the repo-local target
        # actually exists, so we cannot fabricate a path that was never there.
        virtual = _resolve(root / raw.lstrip("/"))
        if virtual is not None and is_within(virtual, root) and _exists(virtual):
            return _relative(virtual, root)
        logger.warning("cannot prove path is inside repo %s: %s", root, path)
        return raw

    rel = _strip_dot_prefix(raw)
    if not rel:
        return "."
    literal = _resolve(root / rel)
    literal_ok = literal is not None and is_within(literal, root)
    # Prefer a literal path that actually exists. The repo-name prefix is a
    # common model habit, but stripping it first can silently retarget a real
    # `repo/inner.py` to a sibling `inner.py`.
    if literal_ok and _exists(literal):
        return _relative(literal, root)
    first, sep, rest = rel.partition("/")
    if sep and first == root.name:
        candidate = _resolve(root / rest)
        if candidate is not None and is_within(candidate, root) and _exists(candidate):
            return _relative(candidate, root)
    if literal_ok:
        return os.path.normpath(rel).replace(os.sep, "/")
    logger.warning("cannot prove path is inside repo %s: %s", root, path)
    return rel or raw

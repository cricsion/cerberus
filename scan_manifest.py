"""Scan audit metadata: target-tree digests; bookkeeping only, not sandbox
lifecycle or confinement."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

# Excluded from the target-source digest: VCS, deps, build caches, scan outputs.
SKIP_PARTS = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    ".hg", ".svn", ".idea", ".vscode", ".codegraph", "tmp",
})

_MANIFESTS: dict[str, dict[str, Any]] = {}
_HASH_CHUNK = 1 << 20


def _digest_repo(repo: str | Path) -> dict[str, Any]:
    """Digest source paths and contents so same-size edits are detected."""
    manifest = hashlib.sha256()
    count = 0
    base = Path(repo)
    for path in sorted(base.rglob("*")):
        try:
            rel = path.relative_to(base)
        except ValueError:
            continue
        if any(part in SKIP_PARTS for part in rel.parts):
            continue
        try:
            if path.is_symlink() or not path.is_file():
                continue
            manifest.update(str(rel).encode("utf-8"))
            manifest.update(b"\0")
            manifest.update(str(path.stat().st_size).encode("utf-8"))
            manifest.update(b"\0")
            with path.open("rb") as fh:
                while chunk := fh.read(_HASH_CHUNK):
                    manifest.update(chunk)
                manifest.update(b"\0")
            count += 1
        except OSError:
            continue
    return {"manifest_hash": manifest.hexdigest(), "manifest_files": count}


def record_scan_manifest(repo_path: str | Path) -> dict[str, Any]:
    """Record the target tree at scan start."""
    key = str(Path(repo_path).resolve())
    try:
        record = {"repo": key, **_digest_repo(key)}
    except OSError:
        record = {"repo": key, "manifest_hash": "", "manifest_files": 0}
    _MANIFESTS[key] = record
    return dict(record)


def close_scan(repo_path: str | Path) -> dict[str, Any]:
    """Compare the target tree with its scan-start digest."""
    key = str(Path(repo_path).resolve())
    start = _MANIFESTS.get(key, {})
    try:
        end = _digest_repo(key)
    except OSError:
        end = {"manifest_hash": "", "manifest_files": 0}
    record = {
        "repo": key,
        "manifest_hash": end["manifest_hash"],
        "manifest_files": end["manifest_files"],
        "tree_changed_during_scan": bool(start.get("manifest_hash")) and (
            end.get("manifest_hash") != start.get("manifest_hash")
        ),
    }
    _MANIFESTS[key] = record
    return dict(record)

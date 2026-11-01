"""Code-reading primitives shared by the tool modules: ``_safe_path`` (repo
containment) and ``grep_files`` (capped shared engine). Read-only,
no exec, no network; agent reads come from FilesystemMiddleware."""
from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path

from harness.paths import canonical_repo, resolve_tool_path

from ._compat import env_int, tool


def _resolve_limit(explicit: int | None, env_key: str, default: int) -> int:
    """Explicit arg wins; otherwise env; 0 = unlimited."""
    if explicit is not None:
        # int already validated by the tool's schema; env_int covers env caps.
        v = int(explicit)
        return v if v >= 0 else default
    return env_int(env_key, default)

SKIP_DIRS = frozenset({
    ".angular", ".bloop", ".build", ".cache", ".codegraph", ".cxx",
    ".dart_tool", ".docusaurus", ".eggs", ".env", ".externalNativeBuild",
    ".git", ".gradle", ".harness", ".hg", ".hypothesis", ".ipynb_checkpoints",
    ".luarocks", ".metals", ".mypy_cache", ".netlify", ".next", ".nitro",
    ".nox", ".nuxt", ".nyc_output", ".output", ".parcel-cache",
    ".pdm-build", ".pixi", ".pnpm-store", ".pub-cache", ".pytest_cache",
    ".ruff_cache", ".serverless", ".svelte-kit", ".svn", ".swiftpm",
    ".terraform", ".tox", ".turbo", ".venv", ".vercel", ".vinxi", ".vite",
    ".worktrees", ".wrangler", ".yarn", "Carthage", "DerivedData", "Pods",
    "__history", "__pycache__", "__pypackages__", "__recovery",
    "__snapshots__", "bower_components", "build", "dist", "dist-protected",
    "jspm_packages", "lcov-report", "lib64", "lua_modules", "node_modules",
    "obj", "out-tsc", "site-packages", "storybook-static", "tmp",
    "vcpkg_installed", "vendor", "venv", "visual-test", "visual-tests",
    "web_modules",
})

SKIP_DIR_SUFFIXES = (".egg-info", "_venv")


def _has_venv_markers(directory: Path) -> bool:
    """True when an ``env``-named directory is actually a virtualenv."""
    try:
        if (directory / "pyvenv.cfg").is_file():
            return True
        if (directory / "bin" / "activate").is_file():
            return True
        if (directory / "Scripts" / "activate").is_file():
            return True
        if (directory / "Scripts" / "activate.bat").is_file():
            return True
        if any(p.is_dir() for p in directory.glob("lib/python*")):
            return True
        if (directory / "conda-meta").is_dir():
            return True
    except OSError:
        pass
    return False


def _is_build_target(directory: Path) -> bool:
    """True when ``target`` is Cargo/Maven output, not first-party source."""
    parent = directory.parent
    try:
        if (parent / "Cargo.toml").is_file() or (parent / "pom.xml").is_file():
            return True
        if (directory / "CACHEDIR.TAG").is_file():
            return True
        if (directory / "debug").is_dir() or (directory / "release").is_dir():
            return True
        if (directory / "classes").is_dir():
            return True
    except OSError:
        pass
    return False


def is_skipped_dir(directory: Path) -> bool:
    """True when *directory* should be pruned from inventory/grep walks.

    Name-based for unambiguous build/dependency/cache dirs. ``target`` and
    ``env``/``*_env`` are kept unless on-disk evidence says otherwise, so a
    Python app under ``target/`` and ``config/env`` survive.
    """
    name = directory.name
    if name in SKIP_DIRS:
        return True
    if name.endswith(SKIP_DIR_SUFFIXES):
        return True
    if name == "target":
        return _is_build_target(directory)
    if name == "env" or name.endswith("_env"):
        return _has_venv_markers(directory)
    return False


def is_skipped_relpath(base: Path, rel: Path) -> bool:
    """True when any parent directory of *rel* is pruned."""
    current = base
    for part in rel.parts[:-1]:
        current = current / part
        if is_skipped_dir(current):
            return True
    return False


def _safe_path(path: str, root: str = ".") -> Path:
    """Resolve path and enforce containment within root; symlinks are followed
    BEFORE the check, so an escape is refused, not followed. TARGET_REPO, when
    set, is the only root (absolute and virtual leading-slash forms under it
    are accepted by the shared path contract).
    """
    target = os.environ.get("TARGET_REPO")
    base = canonical_repo(target) if target else canonical_repo(root)
    resolved = resolve_tool_path(path, base)
    if resolved is None:
        raise ValueError(f"path escapes repo: {path}")
    return resolved


def grep_files(regex: str, include: str = "*.py", root: str = ".", limit: int | None = None, offset: int = 0) -> str:
    """Ripgrep-like search, the shared engine behind the deterministic passes.

    Not an agent tool (agents use the built-in grep). Capped, skip-policy-aware,
    containment-checked; paginated via limit/offset (0 = unlimited).
    """
    lim = _resolve_limit(limit, "GREP_LIMIT", 500)
    off = int(offset or 0)
    if off < 0:
        off = 0
    try:
        base = _safe_path(root)
    except ValueError as e:
        return f"ERROR: {e}"
    if not base.exists():
        return "(no matches)"
    try:
        pat = re.compile(regex)
    except re.error as e:
        return f"ERROR: bad regex: {e}"
    targets: list[Path] = []
    try:
        if base.is_file():
            targets = [base]
            base = base.parent
        else:
            targets = []
    except OSError:
        return "(no matches)"
    hits = []
    skipped_large = 0

    def _search_file(f: Path) -> None:
        nonlocal skipped_large
        try:
            if f.stat().st_size > 10_000_000:
                skipped_large += 1
                return
            raw = f.read_bytes()
        except OSError:
            return
        if b"\x00" in raw[:8192]:
            return
        text = raw.decode("utf-8", errors="replace")
        for n, line in enumerate(text.splitlines(), start=1):
            if pat.search(line):
                try:
                    rel = f.relative_to(base)
                except ValueError:
                    rel = f
                truncated = len(line) > 1000
                hits.append(f"{rel}:{n}: {line[:1000]}" + (" …[truncated]" if truncated else ""))

    if targets:
        f = targets[0]
        if fnmatch.fnmatch(f.name, include) or include == "*":
            _search_file(f)
    else:
        try:
            walker = sorted(base.rglob("*"))
        except OSError:
            return "(no matches)"
        for f in walker:
            try:
                if not f.is_file() or f.is_symlink():
                    continue
            except OSError:
                continue
            try:
                rel = f.relative_to(base)
                # rglob descends through symlink dirs; re-check each file.
                f.resolve().relative_to(base.resolve())
            except ValueError:
                continue
            if is_skipped_relpath(base, rel):
                continue
            if not fnmatch.fnmatch(f.name, include) and include != "*":
                # Also match rel path for patterns like *.html vs subdirs
                if not fnmatch.fnmatch(str(rel), include):
                    continue
            _search_file(f)
    total = len(hits)
    if lim <= 0:
        page = hits[off:]
    else:
        page = hits[off: off + lim]
    if not page and total == 0:
        extra = f" ({skipped_large} large files skipped)" if skipped_large else ""
        return f"(no matches){extra}"
    body = "\n".join(page)
    if total > len(page) or off > 0:
        body += f"\n… showing {off + 1}-{off + len(page)} of {total} (use offset={off + len(page)} to page)"
    if skipped_large:
        body += f"\n[{skipped_large} files >10MB skipped]"
    return body or "(no matches)"




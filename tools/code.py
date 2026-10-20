"""Code-reading primitives shared by the tool modules: ``_safe_path`` (repo
containment), ``grep_files`` (capped shared engine), ``ast_query``. Read-only,
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
    ".venv", "venv", ".env", "node_modules", ".git", "__pycache__",
    ".pytest_cache", ".tox", ".mypy_cache", "dist", "build", ".hg", ".svn",
    "graphify-out", ".graphify",
})


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

    Not an agent tool (agents use the built-in grep). Capped, SKIP_DIRS-aware,
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
            if any(part in SKIP_DIRS for part in rel.parts):
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


@tool(parse_docstring=True)
def ast_query(path: str, node: str = "Call", name_pattern: str = "", limit: int | None = None, offset: int = 0) -> str:
    """Structural query: Python AST for .py files (stdlib), grep fallback otherwise.

    node: FunctionDef|ClassDef|Call|Import|Assign. Paginated via limit/offset.

    Args:
        path: File path to parse, relative to the repo root.
        node: AST node kind to collect, e.g. "Call".
        name_pattern: Regex to filter node names / called funcs / imports.
        limit: Max nodes per page. 0 = unlimited.
        offset: Node index to start from, for paging.
    """
    import ast as _ast

    lim = _resolve_limit(limit, "AST_LIMIT", 500)
    off = int(offset or 0)
    if off < 0:
        off = 0
    try:
        p = _safe_path(path)
    except ValueError as e:
        return f"ERROR: {e}"
    if not p.is_file():
        return f"ERROR: not a file: {path}"
    if p.suffix.lower() != ".py":
        rx = re.escape(name_pattern) if name_pattern else r"\w+"
        return grep_files(regex=rf"\b{rx}\s*\(" if name_pattern else r"\b\w+\s*\(",
                          include=p.name, root=str(p.parent))
    try:
        tree = _ast.parse(p.read_text(errors="replace"))
    except (SyntaxError, OSError) as e:
        return f"ERROR: cannot parse {path}: {e}"
    try:
        npat = re.compile(name_pattern) if name_pattern else None
    except re.error as e:
        return f"ERROR: bad regex: {e}"
    hits: list[str] = []

    def _name_ok(n: str) -> bool:
        return bool(npat.search(n)) if npat else True

    for n in _ast.walk(tree):
        if node == "FunctionDef" and isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            if _name_ok(n.name):
                hits.append(f"{path}:{n.lineno}: def {n.name}(args={[a.arg for a in n.args.args][:8]})")
        elif node == "ClassDef" and isinstance(n, _ast.ClassDef):
            if _name_ok(n.name):
                hits.append(f"{path}:{n.lineno}: class {n.name}")
        elif node == "Call" and isinstance(n, _ast.Call):
            fn = n.func
            fname = ""
            if isinstance(fn, _ast.Name):
                fname = fn.id
            elif isinstance(fn, _ast.Attribute):
                fname = fn.attr
            if fname and _name_ok(fname):
                hits.append(f"{path}:{n.lineno}: call {fname}()")
        elif node == "Import" and isinstance(n, (_ast.Import, _ast.ImportFrom)):
            mods = [a.name for a in n.names] if isinstance(n, _ast.Import) else [n.module or ""]
            for m in mods:
                if _name_ok(m):
                    hits.append(f"{path}:{n.lineno}: import {m}")
        elif node == "Assign" and isinstance(n, _ast.Assign):
            targets = []
            for t in n.targets:
                if isinstance(t, _ast.Name):
                    targets.append(t.id)
            for t in targets:
                if _name_ok(t):
                    hits.append(f"{path}:{n.lineno}: assign {t} = ...")
    total = len(hits)
    page = hits[off:] if lim <= 0 else hits[off: off + lim]
    if not page and total == 0:
        return "(no matches)"
    body = "\n".join(page)
    if total > len(page) or off > 0:
        body += f"\n… showing {off + 1}-{off + len(page)} of {total} (use offset={off + len(page)} to page)"
    return body or "(no matches)"



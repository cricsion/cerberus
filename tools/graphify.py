from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from harness.config import get_default_config


DEFAULT_BUILD_TIMEOUT = int(get_default_config("graphify.build_timeout"))
DEFAULT_GRAPH_CHARS = int(get_default_config("graphify.chars"))

# Kept in sync with the scan inventory: excluded from Graphify's source graph.
GRAPHIFY_SKIP_DIRS = frozenset({
    ".venv", "venv", "node_modules", ".git", "__pycache__",
    "graphify-out", ".graphify", "dist", "build",
})


def _cmd() -> list[str] | None:
    try:
        import graphify  # noqa: F401
        return [sys.executable, "-m", "graphify"]
    except ImportError:
        pass
    import shutil
    if shutil.which("graphify"):
        return ["graphify"]
    return None


def graph_path_for(root: str) -> Path:
    from harness.tools.code import _safe_path
    base = _safe_path(root)
    if base.is_file():
        base = base.parent
    return base / "graphify-out" / "graph.json"


def _graph_chars() -> int:
    import os as _os
    try:
        raw = _os.environ.get("GRAPH_CHARS", str(DEFAULT_GRAPH_CHARS))
        v = int(raw or DEFAULT_GRAPH_CHARS)
        return v if v >= 0 else DEFAULT_GRAPH_CHARS
    except (TypeError, ValueError):
        return DEFAULT_GRAPH_CHARS


def _truncate(s: str) -> str:
    lim = _graph_chars()
    if lim <= 0 or len(s) <= lim:
        return s
    return s[:lim] + f"\n… +{len(s) - lim} more chars (total {len(s)})"


def _source_files(root: str) -> list[Path]:
    # No file-count cap: a capped staleness walk can miss newer files.
    from harness.tools.code import _safe_path as _sp
    base = _sp(root)
    if base.is_file():
        return [base]
    out: list[Path] = []
    resolved_base = base.resolve()
    for f in sorted(base.rglob("*")):
        if not f.is_file() or f.is_symlink():
            continue
        try:
            if any(p in GRAPHIFY_SKIP_DIRS for p in f.relative_to(base).parts):
                continue
            # rglob descends through symlink dirs; re-check each file.
            f.resolve().relative_to(resolved_base)
        except ValueError:
            continue
        out.append(f)
    return out


def needs_rebuild(root: str) -> bool:
    gp = graph_path_for(root)
    if not gp.is_file():
        return True
    try:
        gmt = gp.stat().st_mtime
    except OSError:
        return True
    # A filesystem error mid-walk would underreport staleness; fail toward
    # rebuilding (stale is never served as fresh).
    try:
        for f in _source_files(root):
            try:
                if f.stat().st_mtime > gmt:
                    return True
            except OSError:
                continue
    except OSError:
        return True
    return False


def graphify_build(root: str, timeout: int = DEFAULT_BUILD_TIMEOUT) -> str:
    from harness.tools._compat import scrubbed_env
    cmd = _cmd()
    if cmd is None:
        return ""
    from harness.tools.code import _safe_path as _sp
    root = str(_sp(root))
    if Path(root).is_file():
        return ""
    if not needs_rebuild(root):
        p = graph_path_for(root)
        return str(p) if p.is_file() else ""
    try:
        proc = subprocess.run(cmd + [root, "--code-only", "--no-viz"],
                              capture_output=True, text=True, timeout=timeout,
                              env=scrubbed_env())
    except (subprocess.TimeoutExpired, OSError):
        return ""
    p = graph_path_for(root)
    if p.is_file():
        return str(p)
    return ""


def graphify_summary(root: str) -> str:
    import json
    gp = graph_path_for(root)
    try:
        g = json.loads(gp.read_text())
    except Exception:
        return "(no graph)"
    try:
        nodes = g.get("nodes", [])
        links = g.get("links", [])
        deg: dict[str, int] = {}
        for l in links:
            for k in ("source", "target"):
                v = str(l.get(k, ""))
                if v:
                    deg[v] = deg.get(v, 0) + 1
        top = sorted(deg.items(), key=lambda kv: -kv[1])[:20]
        by_id = {str(n.get("id")): n for n in nodes if isinstance(n, dict)}
        hubs = []
        for nid, d in top:
            n = by_id.get(nid, {})
            hubs.append(f"{n.get('label', nid)}@{n.get('source_file', '?')}:{n.get('source_location', '?')}({d})")
        return _truncate(f"graph: {len(nodes)} nodes, {len(links)} edges. "
                f"Hubs: {'; '.join(hubs) if hubs else 'n/a'}")
    except Exception:
        return "(graph unreadable)"

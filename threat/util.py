"""Repo-root resolution, lenient config reads, indexer-signal derivation.
Leaf module: no intra-package imports, so every other submodule may depend on it.
"""
from __future__ import annotations

import datetime as _dt
import logging as _logging
from pathlib import Path

_logger = _logging.getLogger(__name__)


FILENAME = "THREAT_MODEL.md"
CACHE_DIRNAME = ".cerberus"  # machine-managed per-repo cache (see persist_threat)
CACHE_HEADER = "<!-- machine-managed by cerberus: safe to delete, regenerated+updated each scan -->"


def _now_iso() -> str:
    """Today's UTC date (ISO) for provenance stamps; every threat-stage stamp
    shares this helper so no site wraps its own datetime.now guard."""
    return _dt.datetime.now(_dt.UTC).date().isoformat()


def _repo_root(repo: str) -> Path | None:
    """Directory owning repo state (itself, or parent when repo is a file)."""
    try:
        if not str(repo or "").strip():
            return None  # nowhere: never fall back to the process CWD
        base = Path(repo)
        if base.is_dir():
            return base
        if base.is_file():
            return base.parent  # repo given as a file: its directory owns state
        return None
    except (TypeError, ValueError, OSError):
        return None


def find_repo_file(repo: str) -> Path | None:
    """Locate a threat model for future-run reuse, owner file first:
    `<repo>/THREAT_MODEL.md`, then `<repo>/.cerberus/THREAT_MODEL.md` (machine cache).
    """
    try:
        root = _repo_root(repo)
        if root is None:
            return None
        root_resolved = root.resolve()
        owner = root / FILENAME
        if owner.is_file() and not owner.is_symlink() and owner.resolve().is_relative_to(root_resolved):
            return owner
        cached = root / CACHE_DIRNAME / FILENAME
        if cached.is_file() and not cached.is_symlink() and cached.resolve().is_relative_to(root_resolved):
            return cached
        return None
    except (OSError, ValueError, TypeError):
        return None


_GIT_SAFE_OPTS = ("-c", "core.hooksPath=/dev/null", "-c", "diff.external=", "-c", "commit.gpgsign=false")


def _signal_text(signals: list[dict] | None, cid: str) -> str:
    """The full text of one signal entry. State only carries ``text`` for the
    signals whose consumers read it mid-scan (``prefilter``, ``routes``)."""
    for s in (signals or []):
        if isinstance(s, dict) and s.get("id") == cid:
            return str(s.get("text") or "")
    return ""


def _detector_signals(signals: list[dict]) -> list[str]:
    """Prefilter rule IDs from the ``prefilter`` signal's ``## `` headings. This is
    detector coverage, never scope: what our regex rules match, not what an
    attacker can do to this repository.
    """
    try:
        return [ln[3:] for ln in _signal_text(signals, "prefilter").splitlines()
                if ln.startswith("## ")]
    except AttributeError:
        return []


def _attack_surfaces(signals: list[dict], files: list[str]) -> list[str]:
    """Surfaces this repository actually exposes, from measured evidence: each
    entry is a place where a lower-trust actor hands input to the code, not a bug
    type.
    """
    surfaces: list[str] = []
    routes = [ln for ln in _signal_text(signals, "routes").splitlines()
              if ln.strip()]
    if routes:
        surfaces.append(f"HTTP request handlers ({len(routes)} routes detected)")
    if any(f.replace("\\", "/").startswith(".github/") for f in files or []):
        surfaces.append("CI workflow definitions")
    paths = [f.replace("\\", "/") for f in files or []]
    names = {p.rsplit("/", 1)[-1] for p in paths}
    # Manifest names compare case-insensitively (Cargo.toml is not cargo.toml);
    # the Dockerfile/IaC/template checks below stay exact-case.
    manifest_names = {n.lower() for n in names}
    _DEP_MANIFESTS = frozenset((
        "requirements.txt", "package.json", "package-lock.json",
        "pyproject.toml", "pom.xml", "build.gradle", "go.mod",
        "gemfile.lock", "composer.json", "cargo.toml"))
    if any(n in _DEP_MANIFESTS or n.startswith("requirements")
           for n in manifest_names):
        surfaces.append("declared dependencies")
    if any(n in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml")
           or n.endswith((".tf", ".tfvars"))
           for n in names):
        surfaces.append("container build and runtime configuration")
    tpl_exts = (".j2", ".jinja", ".jinja2", ".tpl", ".ejs", ".pug", ".hbs", ".mustache", ".erb")
    has_tpl_engine_file = any(n.endswith(tpl_exts) for n in names)
    has_tpl_dir_html = any(("/templates/" in p or p.startswith("templates/")
                            or "/views/" in p or p.startswith("views/"))
                           and p.endswith((".html", ".htm"))
                           for p in paths)
    has_tpl_signal = any(k in " ".join(_detector_signals(signals)).lower()
                         for k in ("jinja", "template", "tpl", "render"))
    if has_tpl_engine_file or has_tpl_dir_html or has_tpl_signal:
        surfaces.append("server-side template rendering")
    if any(f.endswith((".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"))
           for f in paths):
        surfaces.append("parsed configuration and data files")
    if not surfaces:
        surfaces.append("unclassified entry points — owner to confirm")
    return surfaces


def attach_signal_paths(md: str, signals: list[dict] | None) -> str:
    """Append the scan's stored-signal file paths to §7 Provenance.

    Paths are repo-relative (``.cerberus/<run_id>/signals/...``): openable by
    repo-rooted agents with the tools they already have, and both copies (the
    scan state doc and the persisted ``.cerberus/THREAT_MODEL.md`` cache) stay
    portable. Idempotent on a repeated application.
    """
    text = str(md or "")
    rows = [s for s in (signals or [])
            if isinstance(s, dict) and str(s.get("path") or "")]
    if not rows or not text.strip():
        return text
    marker = "stored scan signals:"
    if marker in text:
        return text
    lines = [f"- {marker}"]
    for s in rows:
        row = f"  - {s.get('id', '?')}: {s['path']}"
        if s.get("count"):
            row += f" ({s['count']} entries)"
        lines.append(row)
    block = "\n" + "\n".join(lines)
    heading_idx = text.find(_PROVENANCE_HEADING)
    if heading_idx < 0:
        return text.rstrip() + f"\n\n{_PROVENANCE_HEADING}{block}"
    nxt = text.find("\n## ", heading_idx + len(_PROVENANCE_HEADING))
    end = nxt if nxt >= 0 else len(text)
    return text[:end].rstrip() + block + text[end:]


_PROVENANCE_HEADING = "## 7. Provenance"


# Skeleton surfaces match threat rows by FAMILY, not name (the planner renames
# rows); code-owned names only, so threat-row prose cannot game the match.
_SURFACE_FAMILY = {
    "HTTP request handlers": ("http", "route", "endpoint"),
    "declared dependencies": ("depend", "package", "import", "supply",
                              "third-party", "lockfile"),
    "CI workflow definitions": ("ci", "workflow", "pipeline", "action"),
    "container build and runtime": ("container", "docker", "image", "build"),
    "server-side template rendering": ("template", "render", "html"),
    "parsed configuration and data files": ("config", "yaml", "json", "toml",
                                            "ini", "settings"),
}

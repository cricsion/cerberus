"""Repo-root resolution, lenient config reads, indexer-signal derivation.
Leaf module: no intra-package imports, so every other submodule may depend on it.
"""
from __future__ import annotations

import datetime as _dt
import logging as _logging
import os as _os
from pathlib import Path

_logger = _logging.getLogger(__name__)


FILENAME = "THREAT_MODEL.md"
CACHE_DIRNAME = ".harness"  # machine-managed per-repo cache (see persist_threat)
CACHE_HEADER = "<!-- machine-managed by vuln-harness: safe to delete, regenerated+updated each scan -->"


def _now_iso() -> str:
    """Today's UTC date (ISO) for provenance stamps; every threat-stage stamp
    shares this helper so no site wraps its own datetime.now guard."""
    return _dt.datetime.now(_dt.timezone.utc).date().isoformat()


def _coerce_timeout(value: object) -> int:
    """Resolved timeout -> int seconds, minimum 1; unparseable -> 60.
    Only the numeric coercion is guarded: callers must resolve model kwargs
    (operator config errors) outside this helper so those failures stay loud."""
    try:
        return max(int(value or 60), 1)
    except (TypeError, ValueError):
        return 60


def _as_bool(value: object, default: bool = True) -> bool:
    """Lenient bool: real bools, "1/true/yes" strings (env interpolation
    stringifies YAML), numbers. Unparseable -> default.
    """
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def threat_enabled(cfg: dict | None, key: str, default: bool = True) -> bool:
    """Read `threat.<key>` from config with lenient bool parsing. For
    ``llm_enrich`` an explicit ``HARNESS_THREAT_LLM`` value overrides config."""
    if key == "llm_enrich":
        env = _os.environ.get("HARNESS_THREAT_LLM")
        if env is not None and str(env).strip() != "":
            return _as_bool(env, default)
    try:
        return _as_bool((cfg or {}).get("threat", {}).get(key, default), default)
    except AttributeError:
        return default


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
    `<repo>/THREAT_MODEL.md`, then `<repo>/.harness/THREAT_MODEL.md` (machine cache).
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


_GIT_SAFE_OPTS = ("-c", "core.hooksPath=/dev/null", "-c", "diff.external=")


def _detector_signals(candidates: list[dict]) -> list[str]:
    """Prefilter rule IDs from the `prefilter` candidate's `## ` headings. This is
    detector coverage, never scope: what our regex rules match, not what an
    attacker can do to this repository.
    """
    try:
        pre = next((c.get("snippet", "") for c in (candidates or [])
                    if c.get("id") == "prefilter"), "")
        return [ln[3:] for ln in str(pre).splitlines() if ln.startswith("## ")]
    except AttributeError:
        return []


def _attack_surfaces(candidates: list[dict], files: list[str]) -> list[str]:
    """Surfaces this repository actually exposes, from measured evidence: each
    entry is a place where a lower-trust actor hands input to the code, not a bug
    type.
    """
    surfaces: list[str] = []
    cands = list(candidates or [])

    def _snippet(cid: str) -> str:
        return str(next((c.get("snippet", "") for c in cands
                         if c.get("id") == cid), ""))

    routes = [ln for ln in _snippet("routes").splitlines() if ln.strip()]
    if routes:
        surfaces.append(f"HTTP request handlers ({len(routes)} routes detected)")
    man = _snippet("manifest")
    if man.strip() and man.strip() != "(no manifests found)":
        surfaces.append("declared dependencies")
    if any(f.replace("\\", "/").startswith(".github/") for f in files or []):
        surfaces.append("CI workflow definitions")
    paths = [f.replace("\\", "/") for f in files or []]
    names = {p.rsplit("/", 1)[-1] for p in paths}
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
    has_tpl_signal = any(k in " ".join(_detector_signals(candidates)).lower()
                         for k in ("jinja", "template", "tpl", "render"))
    if has_tpl_engine_file or has_tpl_dir_html or has_tpl_signal:
        surfaces.append("server-side template rendering")
    if any(f.endswith((".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"))
           for f in paths):
        surfaces.append("parsed configuration and data files")
    if not surfaces:
        surfaces.append("unclassified entry points — owner to confirm")
    return surfaces


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

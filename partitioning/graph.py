"""Partitioning edge coupling: connects files that belong in the same hunter unit.

When a CodeGraph index exists, coupling edges are read via the
native CodeGraph SDK (calls, references, imports).
When unindexed, returns input edges without inventing connections.
"""
from __future__ import annotations

from pathlib import PurePosixPath

_TEMPLATE_EXTENSIONS = frozenset({
    ".html", ".htm", ".j2", ".jinja", ".jinja2", ".ejs", ".erb", ".twig",
    ".hbs", ".handlebars", ".mustache", ".njk", ".liquid", ".pug", ".jade",
})
_CONFIG_EXTENSIONS = frozenset({
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties",
})
_CONFIG_BASENAMES = frozenset({
    "package.json", "tsconfig.json", "jsconfig.json", "angular.json",
    "composer.json", "pyproject.toml", "setup.cfg", "tox.ini", "cargo.toml",
    "pom.xml", "application.properties", "application.yml", "application.yaml",
    "config.py", "configuration.py", "settings.py", "webpack.config.js",
    "webpack.config.ts", "vite.config.js", "vite.config.ts", "jest.config.js",
    "jest.config.ts", "babel.config.js", "postcss.config.js", "config.js",
    "config.ts", "configuration.js", "configuration.ts", "settings.js",
    "settings.ts", "config.php", "configuration.php", "settings.php",
})


def support_file_kind(path: str) -> str | None:
    normalized = str(path or "").replace("\\", "/")
    if not normalized:
        return None
    pure = PurePosixPath(normalized)
    name = pure.name.lower()
    suffix = pure.suffix.lower()
    parts = {part.lower() for part in pure.parts[:-1]}
    if suffix in _TEMPLATE_EXTENSIONS:
        return "template"
    if (name.startswith(".env") or suffix in _CONFIG_EXTENSIONS
            or name in _CONFIG_BASENAMES
            or (suffix in {".json", ".xml", ".py", ".js", ".ts", ".php"}
                and ("config" in parts or "configs" in parts
                     or "settings" in parts or "configuration" in parts))):
        return "config"
    if suffix in {".md", ".rst", ".txt", ".adoc", ".pdf"}:
        return "docs"
    if suffix in {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
        ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".webm",
    }:
        return "asset"
    return None


def augment_edges(repo: str, files: list[str],
                  edges: dict[tuple[str, str], int]) -> dict[tuple[str, str], int]:
    """Augment file coupling edges for unit partitioning.

    Native CodeGraph SDK: extracts actual inter-file dependency edges
    (calls, references, imports) without querying the database directly.
    """
    out = dict(edges or {})
    file_list = sorted(set(files or []))
    fs = set(file_list)

    def put(a: str, b: str, w: int) -> None:
        k = (a, b)
        if out.get(k, 0) < w:
            out[k] = w

    try:
        from cerberus.codegraph import native
        pairs = native.file_dependency_pairs(repo)
        for pair in pairs:
            src, dst = pair.get("source"), pair.get("target")
            if src and dst and src != dst and src in fs and dst in fs:
                put(src, dst, 1)
    except Exception:
        pass

    return out


__all__ = ["augment_edges", "support_file_kind"]

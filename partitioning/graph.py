from __future__ import annotations

import posixpath
import re
from pathlib import Path, PurePosixPath

from harness.partitioning.config import (edge_max_file_bytes, edge_read_cap_bytes,
                                         same_dir_soft_edges)

_TEMPLATE_EXTENSIONS = frozenset({
    ".html", ".htm", ".j2", ".jinja", ".jinja2", ".ejs", ".erb", ".twig",
    ".vue", ".jsx", ".tsx", ".hbs", ".handlebars", ".mustache", ".njk",
    ".liquid", ".pug", ".jade",
})
_SUPPORT_TEMPLATE_EXTENSIONS = _TEMPLATE_EXTENSIONS - {".vue", ".jsx", ".tsx"}
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
_CONFIG_IMPORT_SUFFIXES = (
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".xml", ".py", ".js", ".ts", ".php",
)
_CONFIG_PATH_LITERAL = re.compile(
    r"""(?P<quote>["'`])(?P<path>(?:(?:\.{1,2}[\\/]|/)[\w.@-]+(?:[\\/][\w.@-]+)*(?:\.(?:json|ya?ml|toml|ini|cfg|conf|properties|xml|py|js|ts|php))?|[\w.@-]+(?:[\\/][\w.@-]+)*\.(?:json|ya?ml|toml|ini|cfg|conf|properties|xml|py|js|ts|php)|\.env(?:\.[\w-]+)?))(?P=quote)""",
    re.IGNORECASE,
)
_CONFIG_MODULE_IMPORT = re.compile(
    r"(?m)^\s*(?:from\s+(?P<from>[.A-Za-z_][\w.]*)\s+import\b|"
    r"import\s+(?P<import>[A-Za-z_][\w.]*))"
)
_ENV_KEY_ASSIGNMENT = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*="
)
_ENV_REFERENCE_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"\b(?:process\s*\.\s*env|import\s*\.\s*meta\s*\.\s*env)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)",
    r"\b(?:process\s*\.\s*env|import\s*\.\s*meta\s*\.\s*env)\s*\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",
    r"\b(?:os\s*\.\s*)?(?:getenv|env)\s*\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",
    r"\b(?:os\s*\.\s*)?environ(?:ment)?\s*(?:\.\s*(?:get|setdefault)\s*\(\s*|\[\s*)['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",
    r"\bENV\s*\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",
    r"\b(?:config|env)\s*\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]",
    r"\$\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}",
))

_RENDER_PATTERNS = tuple(re.compile(p) for p in (
    r"""render_template\(\s*["']([^"']+)["']""",
    r"""render_template_to_response\(\s*["']([^"']+)["']""",
    r"""render_to_string\(\s*["']([^"']+)["']""",
    r"""(?:get_template|select_template)\(\s*["']([^"']+)["']""",
    r"""render\(\s*request\s*,\s*["']([^"']+)["']""",
    r"""TemplateResponse\(\s*request\s*,\s*["']([^"']+)["']""",
    r"""@template\(\s*["']([^"']+)["']""",
    r"""load_template\(\s*["']([^"']+)["']""",
    r"""res\.render\(\s*["']([^"']+)["']""",
    r"""\.render\(\s*["']([^"']+)["']""",
    r"""\brender\s*\(\s*partial\s*:\s*["']([^"']+)["']""",
    r"""\binclude\s*\(\s*["']([^"']+)["']""",
    r"""\{%\s*include\s+["']([^"']+)["']""",
    r"""\{%\s*extends\s+["']([^"']+)["']""",
    r"""templateUrl\s*:\s*["']([^"']+)["']""",
))

_BARREL_BASENAMES = frozenset({
    "__init__.py", "__init__.js", "index.js", "mod.rs"})

_LOADER_MARKERS = (
    "readdirSync(__dirname)",
    "readdirSync(__dirname",
    "os.listdir(",
    "os.scandir(",
    "pkgutil.iter_modules",
    "walk_packages",
)

_SAME_DIR_MAX_FILES = 40
_RENDER_TARGET_MAX = 5


def support_file_kind(path: str) -> str | None:
    normalized = str(path or "").replace("\\", "/")
    if not normalized:
        return None
    pure = PurePosixPath(normalized)
    name = pure.name.lower()
    suffix = pure.suffix.lower()
    parts = {part.lower() for part in pure.parts[:-1]}
    if suffix in _SUPPORT_TEMPLATE_EXTENSIONS:
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


def _resolve_render_targets(name: str, fs: set[str],
                            file_list: list[str],
                            source: str | None = None) -> list[str]:
    name = name.strip().replace("\\", "/")
    if not name:
        return []
    if name in fs:
        return [name]
    normalized = {str(f).replace("\\", "/"): f for f in file_list}
    if source and name.startswith(("./", "../")):
        parent = str(PurePosixPath(source.replace("\\", "/")).parent)
        relative = posixpath.normpath(posixpath.join(parent, name))
        if relative in normalized:
            return [normalized[relative]]
        if PurePosixPath(relative).suffix.lower() not in _TEMPLATE_EXTENSIONS:
            for ext in sorted(_TEMPLATE_EXTENSIONS):
                if relative + ext in normalized:
                    return [normalized[relative + ext]]
        name = relative
    while name.startswith("./"):
        name = name[2:]
    if name in normalized:
        return [normalized[name]]
    variants = [name]
    if PurePosixPath(name).suffix.lower() not in _TEMPLATE_EXTENSIONS:
        variants.extend(name + ext for ext in sorted(_TEMPLATE_EXTENSIONS))
    suffix = sorted({
        original for path, original in normalized.items()
        if any(path == variant or path.endswith("/" + variant)
               for variant in variants)
    })
    if suffix:
        return suffix[:_RENDER_TARGET_MAX]
    stem = sorted(f for f in file_list
                  if PurePosixPath(str(f).replace("\\", "/")).stem == name
                  and PurePosixPath(str(f).replace("\\", "/")).suffix.lower() in _TEMPLATE_EXTENSIONS)
    return stem[:_RENDER_TARGET_MAX]


def _resolve_config_targets(name: str, source: str,
                            config_paths: set[str]) -> list[str]:
    raw = str(name or "").strip().replace("\\", "/")
    if not raw:
        return []
    source_parent = str(PurePosixPath(source.replace("\\", "/")).parent)
    candidates = [raw.lstrip("/")]
    if not raw.startswith("/"):
        candidates.insert(0, posixpath.normpath(posixpath.join(source_parent, raw)))
    for candidate in candidates:
        candidate = candidate.removeprefix("./")
        if candidate in config_paths:
            return [candidate]
    expanded = []
    for candidate in candidates:
        candidate = candidate.removeprefix("./")
        if not PurePosixPath(candidate).suffix:
            expanded.extend(candidate + suffix
                            for suffix in _CONFIG_IMPORT_SUFFIXES)
    for candidate in expanded:
        if candidate in config_paths:
            return [candidate]
    for candidate in candidates:
        candidate = candidate.removeprefix("./")
        matches = sorted(path for path in config_paths
                         if path.endswith("/" + candidate))
        if len(matches) == 1:
            return matches
    for candidate in expanded:
        matches = sorted(path for path in config_paths
                         if path.endswith("/" + candidate))
        if len(matches) == 1:
            return matches
    return []


def _resolve_config_module(module: str, source: str,
                           config_paths: set[str]) -> list[str]:
    raw = str(module or "").strip()
    if not raw:
        return []
    dots = len(raw) - len(raw.lstrip("."))
    name = raw[dots:].replace(".", "/")
    if dots:
        raw = ("../" * (dots - 1)) + name
        if dots == 1:
            raw = "./" + name
    else:
        raw = name
    return _resolve_config_targets(raw, source, config_paths)


def _environment_keys(path: str, text: str) -> set[str]:
    if not PurePosixPath(path).name.lower().startswith(".env"):
        return set()
    return {m.group(1) for line in text.splitlines()
            if (m := _ENV_KEY_ASSIGNMENT.match(line))}


def _environment_references(text: str) -> set[str]:
    return {m.group(1) for pattern in _ENV_REFERENCE_PATTERNS
            for m in pattern.finditer(text)}


def _read_local_texts(repo: str, file_list: list[str]) -> dict[str, str]:
    base = Path(repo).resolve()
    max_file = edge_max_file_bytes()
    read_cap = edge_read_cap_bytes()
    texts: dict[str, str] = {}
    total = 0
    for rel in file_list:
        try:
            p = (base / rel).resolve()
            if not p.is_relative_to(base):
                continue
            size = p.stat().st_size
        except OSError:
            continue
        if size <= 0 or size > max_file:
            continue
        if total + size > read_cap:
            continue
        try:
            texts[rel] = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        total += size
    return texts


def augment_edges(repo: str, files: list[str],
                  edges: dict[tuple[str, str], int]) -> dict[tuple[str, str], int]:
    out = dict(edges)
    file_list = sorted(set(files))
    fs = set(file_list)
    def put(a: str, b: str, w: int) -> None:
        k = (a, b)
        if out.get(k, 0) < w:
            out[k] = w
    texts = _read_local_texts(repo, file_list)
    config_paths = {f for f in file_list if support_file_kind(f) == "config"}
    # (a) renderer -> template, including extensionless framework names.
    for f in sorted(texts):
        for pat in _RENDER_PATTERNS:
            for m in pat.finditer(texts[f]):
                for target in _resolve_render_targets(m.group(1), fs,
                                                      file_list, f):
                    if target != f:
                        put(f, target, 2)
    # (b) component -> explicitly loaded config file.
    for f in sorted(texts):
        for m in _CONFIG_PATH_LITERAL.finditer(texts[f]):
            for target in _resolve_config_targets(m.group("path"), f,
                                                  config_paths):
                if target != f:
                    put(f, target, 2)
        for m in _CONFIG_MODULE_IMPORT.finditer(texts[f]):
            module = m.group("from") or m.group("import")
            for target in _resolve_config_module(module, f, config_paths):
                if target != f:
                    put(f, target, 2)
    # .env links need explicit env-access expressions, not just variable names.
    env_by_key: dict[str, list[str]] = {}
    for f in sorted(config_paths):
        for key in sorted(_environment_keys(f, texts.get(f, ""))):
            env_by_key.setdefault(key, []).append(f)
    if env_by_key:
        for f in sorted(texts):
            if f in config_paths:
                continue
            used = _environment_references(texts[f])
            for key in sorted(used & env_by_key.keys()):
                source_dirs = PurePosixPath(f).parent.parts
                targets = env_by_key[key]
                def depth(target: str) -> int:
                    count = 0
                    for a, b in zip(source_dirs,
                                    PurePosixPath(target).parent.parts):
                        if a != b:
                            break
                        count += 1
                    return count
                closest = max(depth(target) for target in targets)
                targets = [target for target in targets
                           if depth(target) == closest]
                if any(PurePosixPath(target).name == ".env"
                       for target in targets):
                    targets = [target for target in targets
                               if PurePosixPath(target).name == ".env"]
                for target in sorted(targets):
                    if target != f:
                        put(f, target, 2)
    by_dir: dict[str, list[str]] = {}
    for f in file_list:
        norm_parent = str(PurePosixPath(str(f).replace("\\", "/")).parent)
        by_dir.setdefault(norm_parent, []).append(f)
    # (c) barrel file -> every same-dir sibling, both directions.
    for d in sorted(by_dir):
        for f in by_dir[d]:
            if PurePosixPath(str(f).replace("\\", "/")).name in _BARREL_BASENAMES:
                for other in by_dir[d]:
                    if other != f:
                        put(f, other, 2)
                        put(other, f, 2)
    # (d) dynamic-loader file -> every same-dir sibling, both directions.
    for f in sorted(texts):
        if any(marker in texts[f] for marker in _LOADER_MARKERS):
            loader_parent = str(PurePosixPath(str(f).replace("\\", "/")).parent)
            for other in by_dir.get(loader_parent, []):
                if other != f:
                    put(f, other, 1)
                    put(other, f, 1)
    # (e) soft edges between same-dir pairs in dirs of <= 40 files.
    if same_dir_soft_edges():
        for d in sorted(by_dir):
            members = by_dir[d]
            if len(members) <= _SAME_DIR_MAX_FILES:
                for a in members:
                    for b in members:
                        if a != b:
                            put(a, b, 1)
    return out


__all__ = ["augment_edges", "support_file_kind"]

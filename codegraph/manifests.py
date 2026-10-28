"""Manifest-vs-import reconciliation for CodeGraph.

``reconcile_manifest_imports`` bridges the two ends of supply-chain review:
which components the manifests PIN versus which components the indexed source
actually IMPORTS. Unimported pinned components are the reachable surface of
IDE-based typosquatting / dependency-confusion hunting (the
``offensive-dependency-confusion`` skill's first triage step); undeclared
imports find undeclared/lazily-vendored components.

LAWS
- A reconciliation gap is a lead, never proof: unimported packages can be
  CLI-only, build-only, or optional; undeclared imports can be first-party
  tree members the manifest does not name.
- Parsing is bounded and read-only: manifest and import-cap both clamp, the
  walk prunes dependency trees, every failure is a success-shaped string.

FORMAT LAW: section titles, verdict descriptors and truncation tails follow
the package's pinned shapes. No network, subprocess, or writes occur.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tomllib

from harness.codegraph import _common
from harness.tools._compat import tool

# ---------------------------------------------------------------------------
# caps — the package-wide env idiom; values frozen
# ---------------------------------------------------------------------------

ENV_FILES = "CODEGRAPH_MANIFEST_FILES_LIMIT"

DEFAULT_FILES = 400         # files inspected per reconciliation run
MAX_ROW = 120               # per-row text truncation

_SKIP_DIRS = frozenset({
    ".git", ".codegraph", ".venv", "venv", "env", "node_modules", "vendor",
    "__pycache__", "dist", "build", "target", "out", ".idea",
    "testdata", "fixtures",
})

_NODE_BUILTINS = frozenset({
    "assert", "buffer", "child_process", "cluster", "console", "crypto",
    "dgram", "dns", "domain", "events", "fs", "http", "https", "http2",
    "inspector", "module", "net", "os", "path", "perf_hooks", "process",
    "querystring", "readline", "repl", "stream", "string_decoder", "tls",
    "tty", "url", "util", "v8", "vm", "worker_threads", "zlib",
    "test", "node:test", "punycode", "async_hooks", "trace_events",
    "diagnostics_channel", "wasi", "sqlite", "sea",
})

# ---------------------------------------------------------------------------
# bounded walk shared by manifests and import scans
# ---------------------------------------------------------------------------

def _walk_files(root: str, cap: int) -> list[str]:
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in _SKIP_DIRS and not _is_test_dir(d))
        for name in sorted(filenames):
            if len(out) >= cap:
                return out
            out.append(os.path.join(dirpath, name))
    return out


def _is_test_dir(name: str) -> bool:
    low = name.lower()
    return low == "tests" or low.startswith("test_") or low.endswith("_tests")

# ---------------------------------------------------------------------------
# manifest parsing — name sets per ecosystem
# ---------------------------------------------------------------------------

_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:[<>=!~\[;]|$)")
_GO_REQUIRE_RE = re.compile(r"^\s*(?:-\s*)?([A-Za-z0-9][\w./\-.]*)(?:\s+v[\w.\-+]+)?\s*$")
_IMPORT_PY_RE = re.compile(r"^\s*(?:import|from)\s+([A-Za-z_][\w.]*)")
_IMPORT_JS_RE = re.compile(
    r"(?:from\s+|import\s*\(?\s*|require\(\s*|import\()\s*[\"']([^\"'./][^\"']*)[\"']")
_IMPORT_GO_RE = re.compile(r"\"([A-Za-z0-9][\w./\-.]*)\"")


def _parse_manifest(path: str) -> tuple[str, list[str], str]:
    """``(ecosystem, dep names, display root)``; unparsable => empty set."""
    name = os.path.basename(path).lower()
    try:
        if name == "pyproject.toml":
            deps: list[str] = []
            data = tomllib.loads(_read_text(path))
            proj = (data.get("project") or {})
            raw = proj.get("dependencies") or []
            for entry in raw:
                match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)", str(entry))
                if match:
                    deps.append(match.group(1))
            poetry = ((data.get("tool") or {}).get("poetry") or {}).get(
                "dependencies") or {}
            deps.extend(k for k in poetry if k != "python")
            optional = proj.get("optional-dependencies") or {}
            for entries in optional.values():
                for entry in entries or []:
                    match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)",
                                     str(entry))
                    if match:
                        deps.append(match.group(1))
            own = str(proj.get("name") or "")
            return "python", deps, own
        if name.startswith("requirements"):
            deps = []
            for line in _read_text(path).splitlines():
                match = _REQ_LINE_RE.match(line)
                if match and not line.lstrip().startswith(("-", "#")):
                    deps.append(match.group(1))
            return "python", deps, ""
        if name == "package.json":
            data = json.loads(_read_text(path))
            deps = list((data.get("dependencies") or {}).keys())
            deps += list((data.get("devDependencies") or {}).keys())
            return "javascript", deps, str(data.get("name") or "")
        if name == "go.mod":
            deps = []
            in_block = False
            for line in _read_text(path).splitlines():
                low = line.strip()
                if low.startswith("require ("):
                    in_block = True
                    continue
                if in_block and low == ")":
                    in_block = False
                    continue
                match = _GO_REQUIRE_RE.match(low)
                if match and not low.startswith(("module", "go ", "toolchain",
                                                 "exclude", "replace", "//",
                                                 "require (")):
                    deps.append(match.group(1))
                elif low.startswith("require ") and low.endswith(")"):
                    parts = low[len("require "):].split()
                    if parts:
                        deps.append(parts[0])
            return "go", deps, ""
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError, OSError):
        return "", [], ""
    return "", [], ""


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(1_000_000)
    except OSError:
        return ""

# ---------------------------------------------------------------------------
# import-root scanning — top-level import names per ecosystem
# ---------------------------------------------------------------------------

def _python_import_root(module: str) -> str:
    return module.split(".", 1)[0]


def _js_import_root(spec: str) -> str:
    if spec.startswith("@"):
        return "/".join(spec.split("/", 2)[:2])
    return spec.split("/", 1)[0]


def _scan_imports(path: str, language: str) -> set[str]:
    """Import roots of one file's head region (bounded read)."""
    text = _read_text(path)
    if not text:
        return set()
    if language == "python":
        roots = set()
        for match in _IMPORT_PY_RE.finditer(text):
            roots.add(_python_import_root(match.group(1)))
        # ``from __future__``-shaped stdlib names are never manifest-declared;
        # the same for the Python stdlib since 3.10 keeps this noise out.
        return {r for r in roots if r not in sys.stdlib_module_names}
    if language in ("javascript", "typescript"):
        roots = set()
        for match in _IMPORT_JS_RE.finditer(text):
            root = _js_import_root(match.group(1))
            if root not in _NODE_BUILTINS:
                roots.add(root)
        return roots
    if language == "go":
        roots = set()
        for match in _IMPORT_GO_RE.finditer(text):
            roots.add(match.group(1))
        return roots
    return set()


_EXT_LANGUAGE: dict = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go",
}

# ---------------------------------------------------------------------------
# 1. reconcile_manifest_imports
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def reconcile_manifest_imports(root: str = ".",
                               limit: int | None = None) -> str:
    """
    Compare pinned manifest components with what the source actually imports.

    Unimported dependencies are the first dependency-confusion triage surface
    (a package name that resolves in a public registry while nothing imports
    it is an attacker-shaped hole); undeclared imports find vendored/left-out
    components. Leads, never proof — CLI-only and build-only packages stay
    legitimately unimported.

    Args:
        root: Repo root to inspect (no index required).
        limit: Files inspected; 0 means unlimited up to the hard cap.

    Returns:
        A bounded per-ecosystem reconciliation (unimported pinned, undeclared
        imports), with dependency-confusion candidates called out.
    """
    try:
        root = _common._safe_path(root)
    except ValueError as e:
        return f"ERROR: {e}"
    file_cap = _common._cap_rows(limit, ENV_FILES, DEFAULT_FILES)
    files = _walk_files(root, file_cap)

    manifests: dict[str, dict] = {}     # ecosystem -> {"names": set, "own": str}
    imports: dict[str, dict] = {}       # ecosystem -> {root: count}
    walked = 0
    for path in files:
        if walked >= file_cap:
            break
        walked += 1
        base = os.path.basename(path).lower()
        is_manifest = (base == "pyproject.toml"
                       or base.startswith("requirements")
                       or base == "package.json" or base == "go.mod")
        language = _EXT_LANGUAGE.get(os.path.splitext(path)[1].lower(), "")
        if is_manifest:
            ecosystem, names, own = _parse_manifest(path)
            if ecosystem:
                bucket = manifests.setdefault(ecosystem,
                                              {"names": set(), "own": "",
                                               "paths": []})
                bucket["names"].update(n.lower() for n in names)
                if own:
                    bucket["own"] = own
                bucket["paths"].append(os.path.relpath(path, root))
        elif language:
            roots = _scan_imports(path, language)
            if roots:
                bucket = imports.setdefault(language, {})
                for r in roots:
                    bucket[r] = bucket.get(r, 0) + 1
                    # go tree-sitter imports appear with full specs; also
                    # offer module tails for "github.com/org/repo/pkg"
                    if "/" in r:
                        parts = r.strip("/").split("/")
                        bucket.setdefault("/".join(parts[:3]), 0)

    out: list[str] = ["# reconcile manifest imports",
                      f"root: {root}",
                      f"files inspected: {walked} (cap {file_cap})"]
    if not manifests:
        out += ["", "no manifests recognized: requirements*, pyproject.toml, "
                    "package.json, go.mod — nothing to reconcile"]
        return _common._cap_chars("\n".join(out))

    findings: list[dict] = []
    for ecosystem in sorted(set(manifests) | set(imports)):
        m = manifests.get(ecosystem, {"names": set(), "own": "", "paths": []})
        i = imports.get(ecosystem, {})
        imported = {k.lower() for k in i}
        own = {old.strip().lower() for old in [m["own"]] if old}
        unimported = sorted(n for n in m["names"] - imported - own)
        undeclared = sorted(n for n in imported - m["names"] - own)
        out += ["", f"--- ecosystem {ecosystem}",
                f"manifests: {', '.join(m['paths']) or '(none)' }"
                f"   pinned: {len(m['names'])}   import roots: {len(i)}"]
        out += ["", f"--- pinned but unimported ({len(unimported)})"]
        if not unimported:
            out.append("none: every pinned package shows at least one import")

        for name in unimported:
            internal_shape = ("-" in name
                              or name.endswith(("internal", "core", "lib",
                                                "sdk", "private", "common")))
            out.append(f"  {name}"
                       + ("   [internal-shaped name — dependency-confusion "
                          "candidate]" if internal_shape else ""))
            if internal_shape:
                findings.append(_confusion_finding(
                    name, ecosystem, list(m["paths"])[:2]))
        out += ["", f"--- imported but undeclared ({len(undeclared)})"]
        if not undeclared:
            out.append("none: every imported root is pinned "
                       "(vendoring/bundling aside)")
        else:
            for name in undeclared[:_common.HARD_MAX_SECTION]:
                out.append(f"  {name}"
                           + ("  (first-party? check setup before reading "
                              "as a real gap)"))

    out += ["", f"--- dependency-confusion candidates ({len(findings)})"]
    if not findings:
        out.append("none: no internal-shaped unimported pinned name in "
                   "these manifests")
    for index, finding in enumerate(
            findings[:_common._section_cap("CODEGRAPH_FINDINGS_LIMIT", 10)],
            start=1):
        out += [f"{index}. {finding['header']}",
                json.dumps(finding["finding"], indent=2, sort_keys=False)]
    return _common._cap_chars("\n".join(out))


def _confusion_finding(name: str, ecosystem: str, manifests: list) -> dict:
    """One dependency-confusion candidate in the hunter schema."""
    finding = _common._candidate_finding(
        title=f"unimported internal-shaped {ecosystem} package {name!r}",
        path=(manifests[0] if manifests else ""),
        start_line=1, end_line=1,
        cwe="CWE-1357", severity="medium",
        confidence=_common._confidence(0.45, 0.10),
        taint_source="public registry resolution of a private-looking name",
        taint_sink=f"manifest pin {name!r} with zero imports",
        taint_path=[(manifests[0] if manifests else "manifest")],
        evidence=(f"{name!r} is pinned in {manifests or 'a manifest'} but "
                  "never imported in the inspected source tree; if the "
                  "public registry serves that name, an attacker can claim "
                  "the build's dependency"),
        rationale=("dependency confusion: zero imports means nobody can "
                   "vouch the pin resolves through a private index or "
                   "proxy; verify the private-index config before "
                   "treating as exploitable"),
        note=("closest CWE: 1357 (Reliance on Uncontrolled Component); "
              "verify against CI/proxy config (private index reaches the "
              "resolver first?)"),
    )
    return {"header": (f"## candidate finding (CWE-1357, severity medium, "
                       f"confidence {finding['confidence']})"),
            "finding": finding}


__all__ = ["reconcile_manifest_imports"]

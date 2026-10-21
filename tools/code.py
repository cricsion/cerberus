"""Code-reading primitives shared by the tool modules: ``_safe_path`` (repo
containment), ``grep_files`` (capped shared engine), ``ast_query``. Read-only,
no exec, no network; agent reads come from FilesystemMiddleware."""
from __future__ import annotations

import fnmatch
import os
import re
import stat
import subprocess
import unicodedata
from pathlib import Path
from typing import Callable

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


# =============================================================================
# Scan-ignore primitives (P4 / retirement precursor)
# -----------------------------------------------------------------------------
# Verbatim port of the vendored graphify tree's file-discovery ignore machinery.
#   source: graphify/graphify/detect.py @ graphify 0.9.90 -- the repo-local
#   vendored tree, the active import target per plan section 5 item 3. NOT the
#   pip graphifyy 0.9.73 in the venv (detect.py 2793 lines vs the vendored
#   2981 -- 0.9.73 predates rules such as the #4057 install-file set).
#
# This is the order-critical first half of plan P4 (section 7): it lets
# harness/pipeline.py stop importing `graphify.detect` and lets tools/graphify.py
# be deleted WITHOUT changing the inventory walk's ignore decisions. No existing
# function in this module is modified.
#
# Public entry points:
#   * INVENTORY_SKIP_DIRS    byte-for-byte port of tools/graphify.py's
#                            GRAPHIFY_SKIP_DIRS (the walk's hard dir skip set).
#   * ignored_predicate(...)  the vendored factory, contract preserved as-is:
#                            reproduces (a) gitignore-style excludes and
#                            (b) the noise-dirs list.
#
# Deliberately NOT included in ignored_predicate: the sensitive-file heuristic
# (vendored detect.py:1789 "#2495" -- a heuristic match is not user intent). The
# secret-skip regexes (detect.py:135,138) are ported separately as the opt-in
# `secret_skip_predicate` below. Today's walk does NOT secret-skip; that default
# is preserved here.
# =============================================================================

INVENTORY_SKIP_DIRS = frozenset({
    ".venv", "venv", "node_modules", ".git", "__pycache__",
    "graphify-out", ".graphify", "dist", "build",
})


def _is_regular_file(path: Path) -> bool:
    """True only for regular files (symlinks followed).

    Named pipes, sockets and device nodes must never reach a reader:
    ``open()`` on a FIFO with no writer blocks forever and never raises, so a
    single ``pipe.py`` in a scanned repository hangs the run with no output.
    A symlink is resolved deliberately — a link pointing at a FIFO blocks
    exactly like the FIFO itself. A path that cannot be stat'ed is treated as
    not readable rather than raising.
    """
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        return False


# Directory names to always skip - venvs, caches, build artifacts, deps
_SKIP_DIRS = {
    "venv", ".venv",  # "env"/".env"/"*_env" are gated on venv markers below (#2058)
    "node_modules", "__pycache__", ".git",
    "dist", "build", "target",  # bare "out" is gated on build-output evidence below (#3347)
    "site-packages", "lib64",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", ".nox", ".eggs", "*.egg-info",  # nox is tox's successor, same .nox/ venv shape (#1804)
    "graphify-out",  # never treat the default output as source input (#524)
    # Coverage/test-artefact dirs — generated, never architecturally meaningful
    "lcov-report",                          # Vitest/Istanbul/nyc HTML reports (#870);
                                            # bare "coverage" is gated on report
                                            # artefacts below (#2339)
    "visual-tests", "visual-test",          # Playwright/visual-regression bundles (#869)
    "__snapshots__",                        # Jest/Vitest snapshot dir (unambiguous)
    "storybook-static",                     # Storybook production build output
    "dist-protected",                       # Protected dist variants (same noise as dist)
    # Framework cache/build dirs — generated, never architecturally meaningful (#873)
    ".next", ".nuxt", ".turbo", ".angular",
    ".idea", ".cache", ".parcel-cache", ".svelte-kit", ".terraform", ".serverless",
    ".graphify",  # graphify's own extraction cache — never index self-generated data
    ".obsidian", ".smart-env",  # Obsidian vault metadata and plugin caches (#2493)
    ".worktrees",  # git worktree convention (#947) — sibling checkouts, always redundant
}


# Large generated files that are never useful to extract
_SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Cargo.lock", "poetry.lock", "Gemfile.lock",
    "composer.lock", "go.sum", "go.work.sum",
    # Removed allowlist config (#2112) — no longer consumed, so keep a leftover
    # file out of the unclassified list instead of surfacing it as scan input.
    ".graphifyinclude",
}


# A bare "snapshots" dir is a Jest/Vitest artifact only when it actually holds
# snapshot files or lives directly under a JS test root. Elsewhere it is often a
# real code namespace (e.g. Rails app/services/snapshots/), so pruning it by name
# silently dropped legitimate source from the graph (#1666). "__snapshots__" stays
# unconditionally pruned above; only the ambiguous bare name is gated here.
_JS_SNAPSHOT_TEST_ROOTS = frozenset({"__tests__", "__test__"})


# Platforms whose project-scope skills dir is one level below the hidden dir
# (install.py: pi -> .pi/agent/skills, kilo -> .config/kilo/skills).
_NESTED_SKILL_HOLDERS = frozenset({(".pi", "agent"), (".config", "kilo")})


# Single files `graphify install` writes whole into a project (#4057): the
# always-on rules/steering/workflow files and the opencode/kilo hook plugins.
# Matched on the hidden holder dir plus the exact relative path, never on the
# bare file name, so e.g. docs/graphify.md or src/plugins/graphify.js stay.
# Files graphify only adds a section or entry to (AGENTS.md, CLAUDE.md,
# settings.json, ...) belong to the user and are not listed here.
_GRAPHIFY_INSTALLED_FILES = frozenset({
    (".agents", "rules", "graphify.md"),      # antigravity
    (".agents", "workflows", "graphify.md"),  # antigravity
    (".cursor", "rules", "graphify.mdc"),     # cursor
    (".kilo", "plugins", "graphify.js"),      # kilo
    (".kiro", "steering", "graphify.md"),     # kiro
    (".opencode", "plugins", "graphify.js"),  # opencode
    (".windsurf", "rules", "graphify.md"),    # devin
})


def _is_installed_graphify_file(path: "Path") -> bool:
    """True for a single file `graphify install` wrote into the project (#4057)."""
    return path.parts[-3:] in _GRAPHIFY_INSTALLED_FILES


# Files a coverage tool writes into its own output dir. Any one of them is proof
# the directory is generated: lcov (lcov.info), nyc/Istanbul (coverage-final.json,
# clover.xml, the lcov-report/ subtree), coverage.py (coverage.xml, .coverage),
# JaCoCo/Cobertura (jacoco.xml, cobertura-coverage.xml).
_COVERAGE_ARTIFACT_FILES = frozenset({
    "lcov.info", "coverage-final.json", "coverage-summary.json",
    "clover.xml", "coverage.xml", "cobertura-coverage.xml", "jacoco.xml",
    ".coverage", "index.html",
})
_COVERAGE_ARTIFACT_DIRS = frozenset({"lcov-report", "html-report"})


def _has_coverage_artifacts(d: "Path") -> bool:
    """True only when *d* holds files a coverage tool actually generated.

    ``coverage`` is a legitimate package name (a Python package, a Go/Rust module,
    a domain namespace), so pruning it by name alone silently drops real source —
    an entire 5-module package in #2339, with its dependents left in the graph so
    queries still returned plausible neighbours. Prune it only on real evidence,
    mirroring the ``snapshots``/``env`` gating (#1666/#2058): a coverage report
    file, or an Istanbul/lcov HTML report subtree.
    """
    try:
        for name in _COVERAGE_ARTIFACT_FILES:
            if (d / name).is_file():
                return True
        for name in _COVERAGE_ARTIFACT_DIRS:
            if (d / name).is_dir():
                return True
    except OSError:
        pass
    return False


# Files only a compiler/bundler writes. Any one of them inside an ``out/``
# tree is proof the directory is generated output rather than source.
_BUILD_OUTPUT_SUFFIXES = (
    ".class", ".jar", ".o", ".obj", ".exe", ".dll", ".pyc",
    ".js.map", ".css.map", ".d.ts",
)


def _has_build_output_markers(d: "Path") -> bool:
    """True only when *d* holds evidence a build tool generated it.

    ``out`` is a mainstream SOURCE convention in hexagonal / ports-and-adapters
    codebases — ``adapter/out/`` and ``port/out/`` hold the entire outbound
    layer (persistence adapters, entities, outbound ports) — so pruning it by
    name alone silently drops an architectural layer from the graph: 196 of
    655 .java files on the #3347 corpus, exit code 0, no warning. Prune only
    on real generated-output evidence, mirroring the ``env``/``coverage``/
    ``snapshots`` gating (#1666/#2058/#2339): the IntelliJ ``out/production``
    layout, a Next.js static-export ``_next/`` tree, or compiled artifacts in
    the top two directory levels. An ``out`` that cannot be verified is kept —
    the same keep-on-doubt bias every other gated name has.
    """
    try:
        if (d / "production").is_dir():  # IntelliJ IDEA compile output layout
            return True
        if (d / "_next").is_dir():      # `next export` static-site output
            return True
        subdirs: list = []
        with os.scandir(d) as it:
            for entry in it:
                if entry.is_file() and entry.name.lower().endswith(_BUILD_OUTPUT_SUFFIXES):
                    return True
                if entry.is_dir():
                    subdirs.append(entry.path)
        # Probe one more level across EVERY subdirectory (a wide TS outDir may
        # keep its compiled files only under later-sorted module dirs), bounded
        # by total entries scanned rather than by subdirectory count so a
        # pathological tree still costs O(1)-ish.
        budget = 4000
        for sub in subdirs:
            if budget <= 0:
                break
            with os.scandir(sub) as it:
                for entry in it:
                    budget -= 1
                    if entry.is_file() and entry.name.lower().endswith(_BUILD_OUTPUT_SUFFIXES):
                        return True
                    if budget <= 0:
                        break
    except OSError:
        pass
    return False


def _has_venv_markers(d: "Path") -> bool:
    """True only when *d* has actual virtualenv/conda structure on disk.

    ``env``/``.env``/``*_env`` is a real source-directory convention (UVM/ASIC
    verification trees, and others), so pruning it by name alone silently drops
    legitimate source with no trace (#2058). Prune it only on real evidence: a
    ``pyvenv.cfg``, an ``activate`` script, a ``lib/python*`` tree, or conda's
    ``conda-meta/`` (``conda create -p ./env`` writes no pyvenv.cfg).
    """
    try:
        if (d / "pyvenv.cfg").is_file():
            return True
        if (d / "bin" / "activate").is_file() or (d / "Scripts" / "activate").is_file():
            return True
        if next(d.glob("lib/python*"), None) is not None:
            return True
        if (d / "conda-meta").is_dir():
            return True
    except OSError:
        pass
    return False


def _is_noise_dir(part: str, parent: "Path | None" = None) -> bool:
    """Return True if this directory name looks like a venv, cache, or dep dir."""
    if part in _SKIP_DIRS:
        return True
    if part in ("env", ".env") or part.endswith("_env"):
        # Ambiguous: a real venv OR a real source dir. Prune only on actual venv
        # evidence, mirroring the "snapshots" gating (#1666/#2058).
        if parent is None:
            return False  # cannot verify; keep a possibly-real code dir
        return _has_venv_markers(parent / part)
    if part == "coverage":
        # Ambiguous: a generated report dir OR a real package named coverage.
        # Prune only on actual coverage-artefact evidence (#2339).
        if parent is None:
            return False  # cannot verify; keep a possibly-real code dir
        return _has_coverage_artifacts(parent / part)
    if part == "out":
        # Ambiguous: compiler/bundler output (IntelliJ, `next export`, a TS
        # outDir) OR the outbound layer of a hexagonal codebase
        # (adapter/out/, port/out/). Prune only on actual build-output
        # evidence (#3347).
        if parent is None:
            return False  # cannot verify; keep a possibly-real code dir
        return _has_build_output_markers(parent / part)
    if part == "snapshots":
        # Prune only when it looks like an actual JS/Vitest snapshot dir.
        if parent is None:
            return False  # cannot verify; keep a possibly-real code dir
        snap_dir = parent / part
        if parent.name in _JS_SNAPSHOT_TEST_ROOTS:
            return True
        try:
            if next(snap_dir.glob("*.snap"), None) is not None:
                return True
        except OSError:
            pass
        return False
    # Catch *_venv (unambiguous — "venv" is always a virtualenv signal). "*_env"
    # is gated on markers above (#2058), not pruned by name.
    if part.endswith("_venv"):
        return True
    if part.endswith(".egg-info"):
        return True
    # worktrees/ nested inside a dotted dir (e.g. .claude/worktrees/, .git/worktrees/)
    if part == "worktrees" and parent is not None and parent.name.startswith("."):
        return True
    # graphify's own skill folder, as `graphify install --project` writes it
    # (#4057): <hidden dir>/skills/graphify/ (.claude, .codex, .agents, ...),
    # .pi/agent/skills/graphify/, .config/kilo/skills/graphify/ and
    # .aider/graphify/. Matched on the whole path shape rather than the bare
    # names "skills"/"graphify" (#2479), so graphify's own source tree
    # (graphify/skills/<host>/), a top-level skills/graphify/ and the user's
    # other skills under .claude/skills/ are still indexed.
    if part == "graphify" and parent is not None:
        if parent.name == ".aider":
            return True
        if parent.name == "skills":
            holder = parent.parent
            if holder.name.startswith(".") and holder.name != "..":
                return True
            return (holder.parent.name, holder.name) in _NESTED_SKILL_HOLDERS
    return False


_VCS_MARKERS = (".git", ".hg", ".svn", "_darcs", ".fossil")


def _nfc(text: str) -> str:
    """Normalize text to NFC so ignore matching survives Unicode form drift.

    macOS (APFS/HFS+) returns filenames in NFD: "ç" comes back as "c" +
    U+0327 COMBINING CEDILLA. Editors write ignore files in NFC, where the
    same "ç" is the single codepoint U+00E7. The two render identically and
    compare unequal, so a pattern like `Orçamento/` silently fails to exclude
    the directory it names — the files are scanned and, for docs/PDFs, sent
    to an LLM despite an explicit rule against it.

    Both sides are normalized to NFC before any fnmatch call. NFC is the form
    Linux and Windows already use, so this is a no-op there and only repairs
    the macOS mismatch.
    """
    return unicodedata.normalize("NFC", text)


def _parse_gitignore_line(raw: str) -> str:
    """Parse one raw line from a .graphifyignore file per gitignore spec.

    - Strip newline chars
    - Strip inline comments (whitespace + # suffix), but only when # is
      preceded by whitespace — so path#with#hash.py is preserved
    - Unescape \\# to literal #
    - Remove trailing spaces unless escaped with backslash
    - Strip leading whitespace
    - Return empty string for blank lines and full-line comments
    """
    line = raw.rstrip("\n\r")
    line = line.lstrip()
    if not line or line.startswith("#"):
        return ""
    # Strip inline comments: require whitespace before # (gitignore extension)
    line = re.sub(r"\s+#+[^\\].*$", "", line)
    # Unescape \# → literal #
    line = line.replace("\\#", "#")
    # Remove unescaped trailing spaces (per gitignore spec)
    line = re.sub(r"(?<!\\) +$", "", line)
    return _nfc(line)


def _find_vcs_root(start: Path) -> Path | None:
    """Walk upward from start; return the first directory containing a VCS marker."""
    current = start.resolve()
    home = Path.home()
    while True:
        if any((current / m).exists() for m in _VCS_MARKERS):
            return current
        parent = current.parent
        if parent == current or current == home:
            return None
        current = parent


def _path_identity(path: Path) -> str:
    """Portable comparison key for an existing filesystem path."""
    return _nfc(os.path.normcase(os.path.abspath(os.fspath(path))))


def _git_tracked_path_keys(root: Path) -> tuple[set[str], set[str]]:
    """Return tracked-file keys and their ancestor-directory keys under *root*.

    Gitignore rules do not apply to paths already present in Git's index. Ask
    Git once per scan/predicate construction with NUL-delimited output so every
    valid filename is preserved. Missing Git, a non-Git VCS marker, command
    failure, and malformed output all fail closed to the historical ignore
    behavior rather than making discovery fail (#2759).
    """
    root = root.resolve()
    vcs_root = _find_vcs_root(root)
    if vcs_root is None or not (vcs_root / ".git").exists():
        return set(), set()
    try:
        proc = subprocess.run(
            ["git", "-C", str(vcs_root), "ls-files", "-z", "--cached"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        )
    except (OSError, subprocess.SubprocessError):
        return set(), set()
    if proc.returncode != 0:
        return set(), set()

    tracked_files: set[str] = set()
    tracked_dirs: set[str] = set()
    for raw in proc.stdout.split(b"\0"):
        if not raw:
            continue
        path = Path(os.path.abspath(vcs_root / os.fsdecode(raw)))
        try:
            path.relative_to(root)
        except ValueError:
            continue
        # Deleted index entries and submodule gitlinks are not discoverable
        # files. Symlinks to regular files remain eligible; the existing
        # in-root target guard still decides whether they may enter the corpus.
        if not _is_regular_file(path):
            continue
        tracked_files.add(_path_identity(path))
        parent = path.parent
        while parent != root:
            parent_key = _path_identity(parent)
            if parent_key in tracked_dirs:
                break  # its ancestors were added with the first file below it
            tracked_dirs.add(parent_key)
            parent = parent.parent
    return tracked_files, tracked_dirs


def _git_info_exclude(vcs_root: Path) -> Path | None:
    """Resolve ``$GIT_DIR/info/exclude`` for the repo rooted at ``vcs_root``.

    ``info/exclude`` is where git records local-only, uncommitted excludes — and
    where ``git worktree add`` writes nested worktree paths — so a repo can ignore
    a directory without any ``.gitignore`` entry. graphify only read
    ``.gitignore``/``.graphifyignore``, so it walked into those worktree copies and
    the graph exploded (#1810). Handles the linked-worktree/submodule case where
    ``.git`` is a file (``gitdir: <path>``) and the real excludes live in the
    shared common git dir. Returns None when there is no readable exclude file.
    """
    dot_git = vcs_root / ".git"
    git_dir: Path | None = None
    if dot_git.is_dir():
        git_dir = dot_git
    elif dot_git.is_file():
        try:
            content = dot_git.read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            content = ""
        if content.startswith("gitdir:"):
            gd = Path(content[len("gitdir:"):].strip())
            if not gd.is_absolute():
                gd = (vcs_root / gd).resolve()
            git_dir = gd
            # A linked worktree's gitdir holds a `commondir` file pointing at the
            # shared git dir, where info/exclude actually lives.
            commondir = gd / "commondir"
            if commondir.exists():
                try:
                    cd_raw = commondir.read_text(encoding="utf-8", errors="ignore").strip()
                except OSError:
                    cd_raw = ""
                if cd_raw:
                    cd = Path(cd_raw)
                    git_dir = cd if cd.is_absolute() else (gd / cd).resolve()
    if git_dir is None:
        return None
    exclude = git_dir / "info" / "exclude"
    return exclude if exclude.is_file() else None


def _git_global_excludes(vcs_root: Path) -> Path | None:
    """Resolve git's user-wide excludes file (``core.excludesFile``).

    This is where people keep machine-wide rules for local settings and secret
    files so they don't repeat them in every repo; git ignores those files but
    graphify read them (#4335). Asks git for the configured path (``--path``
    expands ``~``) and falls back to git's default,
    ``$XDG_CONFIG_HOME/git/ignore`` or ``~/.config/git/ignore``, when the key
    is unset or git is unavailable. Only applies inside a git repo, like git.
    Returns None when there is no readable file.
    """
    if not (vcs_root / ".git").exists():
        return None
    configured = ""
    try:
        proc = subprocess.run(
            ["git", "-C", str(vcs_root), "config", "--path", "--get", "core.excludesFile"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        )
        if proc.returncode == 0:
            configured = proc.stdout.decode("utf-8", errors="replace").strip()
    except (OSError, subprocess.SubprocessError):
        pass
    if configured:
        path = Path(configured).expanduser()
        if not path.is_absolute():
            path = vcs_root / path
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg) if xdg and Path(xdg).is_absolute() else Path.home() / ".config"
        path = base / "git" / "ignore"
    return path if path.is_file() else None


_warned_ignore_encodings: set[str] = set()


def _read_ignore_text(path: Path) -> str:
    """Read an ignore file, preferring UTF-8 but never silently dropping a rule.

    These files were read with ``errors="ignore"``, which turns a mis-encoded
    byte into *no* byte. An ignore file saved in the host's ANSI codepage — the
    historical Notepad default on Windows, and still what ``Set-Content`` writes
    without ``-Encoding`` — is not valid UTF-8, so ``Or\xe7amento/`` decoded to
    the pattern ``Oramento/``. That matches nothing, and nothing said so: the
    directory was scanned despite an explicit exclusion, which for a rule
    covering documents or PDFs means they reach the semantic pass anyway.

    So: UTF-8 (BOM-tolerant) first, since that is what the format should be and
    what every other reader here assumes. Only if that fails do we fall back to
    the host encoding, then to latin-1, which cannot fail and maps every byte to
    a codepoint — a rule spelled in some third encoding still comes out wrong,
    but it comes out *whole*, and the warning names the file so it is fixable.
    Decoding never raises, matching the previous contract.
    """
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    # A BOM'd UTF-16 file (common from PowerShell `Set-Content` / Notepad "Unicode")
    # is not valid UTF-8, and latin-1 would map its interleaved NUL bytes to a
    # wall of \x00, garbling every rule. Decode it as UTF-16 by its BOM first.
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            pass
    import locale
    import sys as _sys
    fallback = locale.getpreferredencoding(False) or "latin-1"
    for enc in (fallback, "latin-1"):
        try:
            text = raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        key = str(path)
        if key not in _warned_ignore_encodings:
            _warned_ignore_encodings.add(key)
            print(
                f"[graphify] WARNING: {path} is not valid UTF-8; read it as "
                f"{enc} instead. Re-save it as UTF-8 — patterns with non-ASCII "
                "characters may not match as written.",
                file=_sys.stderr,
            )
        return text
    return raw.decode("utf-8", errors="ignore")


def _load_dir_own_ignore(d: Path, *, gitignore: bool = True) -> list[tuple[Path, str]]:
    """Read .gitignore/.graphifyignore directly inside *d* (not its ancestors).

    Merges .gitignore and .graphifyignore for this one directory (#1363):
    .gitignore is read first and .graphifyignore last, so .graphifyignore
    patterns (including `!` negations) win on conflict via last-match-wins;
    adding a .graphifyignore can only ever exclude MORE, never re-include a
    .gitignore-excluded file (#945 kept: a dir with only a .gitignore still
    gets sensible defaults).

    Shared by `_load_graphifyignore` (ancestor chain, loaded once before the
    scan) and the live os.walk loop in `detect()` (called per-directory as
    each descendant is visited), so nested ignore files *below* the scan
    root are honored too — previously only the scan root and its ancestors
    were read, so e.g. `vendor/sub/.gitignore` was silently ignored (#1206).
    """
    patterns: list[tuple[Path, str]] = []
    for fname in ((".gitignore", ".graphifyignore") if gitignore else (".graphifyignore",)):
        ignore_file = d / fname
        if ignore_file.exists():
            for raw in _read_ignore_text(ignore_file).splitlines():
                line = _parse_gitignore_line(raw)
                if line:
                    patterns.append((d, line))
    return patterns


def _load_graphifyignore(root: Path, *, gitignore: bool = True) -> list[tuple[Path, str]]:
    """Read .graphifyignore files and return (anchor_dir, pattern) pairs.

    Patterns are returned outer-first so that inner (closer) rules are
    appended last and win via last-match-wins semantics — matching gitignore
    behavior exactly.

    Walk ceiling: the nearest VCS root if inside a repo, otherwise the scan
    root itself (hermetic — no leakage across unrelated sibling projects).

    Covers the scan root and its ancestors only — directories *below* the
    scan root are picked up live during the os.walk in `detect()` instead,
    since they aren't known until the walk reaches them (#1206).
    """
    root = root.resolve()
    ceiling = _find_vcs_root(root) or root

    # Collect ancestor dirs from ceiling down to root (outer → inner)
    dirs: list[Path] = []
    current = root
    while True:
        dirs.append(current)
        if current == ceiling:
            break
        current = current.parent
    dirs.reverse()  # ceiling first, scan root last

    patterns: list[tuple[Path, str]] = []

    # git's user-wide excludes file ranks below info/exclude, so it goes first
    # of all, anchored at the VCS root like info/exclude (#4335).
    global_excludes = _git_global_excludes(ceiling) if gitignore else None
    if global_excludes is not None:
        for raw in _read_ignore_text(global_excludes).splitlines():
            line = _parse_gitignore_line(raw)
            if line:
                patterns.append((ceiling, line))

    # $GIT_DIR/info/exclude is repo-root-scoped and, per git, ranks below every
    # per-directory .gitignore/.graphifyignore — so load it first (lowest priority
    # under last-match-wins) anchored at the VCS root, letting a nearer `!`
    # re-include still override it (#1810).
    info_exclude = _git_info_exclude(ceiling) if gitignore else None
    if info_exclude is not None:
        for raw in _read_ignore_text(info_exclude).splitlines():
            line = _parse_gitignore_line(raw)
            if line:
                patterns.append((ceiling, line))

    for d in dirs:
        patterns.extend(_load_dir_own_ignore(d, gitignore=gitignore))
    return patterns


# Parsed-pattern cache: raw pattern string -> (negated, directory_only,
# path_relative, stripped_pattern). Ignore patterns are re-evaluated for every
# walked entry; parsing the same strings per entry per scan was pure waste.
# Plain dict (no LRU): the universe of keys is the distinct pattern lines in
# the corpus's ignore files, which is small and bounded per scan. A long-lived
# `graphify watch` process spanning many repos could still accumulate keys over
# time, so cap it and clear wholesale on overflow (parsing is cheap, so a rare
# full re-fill costs nothing that matters).
_PARSED_PATTERN_CACHE: dict[str, tuple[bool, bool, bool, str]] = {}
_PARSED_PATTERN_CACHE_MAX = 100_000


def _parse_ignore_pattern(pattern: str) -> tuple[bool, bool, bool, str]:
    """Split one gitignore-style pattern into its matching flags, cached.

    Returns (negated, directory_only, path_relative, stripped). ``stripped``
    is empty for patterns that match nothing (bare "!", bare "/").
    """
    got = _PARSED_PATTERN_CACHE.get(pattern)
    if got is None:
        negated = pattern.startswith("!")
        raw = pattern[1:] if negated else pattern
        directory_only = raw.endswith("/")
        path_relative = "/" in raw.rstrip("/")
        got = (negated, directory_only, path_relative, raw.strip("/"))
        if len(_PARSED_PATTERN_CACHE) >= _PARSED_PATTERN_CACHE_MAX:
            _PARSED_PATTERN_CACHE.clear()
        _PARSED_PATTERN_CACHE[pattern] = got
    return got


# PurePath.relative_to compares casefolded parts on Windows only; mirror that
# exactly, but skip the normcase pass entirely where it is a no-op (POSIX).
_CASEFOLD_PATHS = os.path.normcase("Aa") != "Aa"


def _lexical_relative(
    target: Path, target_parts: tuple[str, ...], anchor: Path
) -> str | None:
    """String-space equivalent of ``_nfc(str(target.relative_to(anchor)).replace(os.sep, "/"))``.

    Returns None where ``relative_to`` raises ValueError (target not under
    anchor). ``relative_to`` is purely lexical — a parts-prefix check — so this
    performs the same comparison on the already-parsed ``parts`` tuples instead
    of constructing a Path object (and, on 3.12+, walking ``parents``
    quadratically) per pattern per scanned entry. That construction was the
    dominant cost of large scans (see CHANGELOG: 76k-file vault, 50+ min).
    """
    anchor_parts = anchor.parts
    if not anchor_parts:
        # Anchor without parts (Path(".")): defer to pathlib for its exact
        # "." / ValueError semantics. Real anchors are directories with parts,
        # so the hot path never lands here.
        try:
            return _nfc(str(target.relative_to(anchor)).replace(os.sep, "/"))
        except ValueError:
            return None
    n = len(anchor_parts)
    if len(target_parts) < n:
        return None
    head = target_parts[:n]
    if head != anchor_parts and (
        not _CASEFOLD_PATHS
        or tuple(map(os.path.normcase, head))
        != tuple(map(os.path.normcase, anchor_parts))
    ):
        return None
    tail = target_parts[n:]
    if not tail:
        return "."
    return _nfc("/".join(tail))


def _match_globstar_parts(
    path_parts: tuple[str, ...],
    pattern_parts: tuple[str, ...],
    path_idx: int,
    pattern_idx: int,
    memo: dict[tuple[int, int], bool],
) -> bool:
    """Recursive ``**``-aware segment match, memoized via an explicit dict.

    Lifted out of ``_match_anchored_ignore_pattern`` (was a per-call
    ``@lru_cache`` closure): the decorated inner closure referenced itself, so
    every call leaked a reference cycle for the GC to reclaim on this hot path.
    A plain dict passed in avoids both the cycle and the per-call cache setup.
    """
    key = (path_idx, pattern_idx)
    cached = memo.get(key)
    if cached is not None:
        return cached

    if pattern_idx == len(pattern_parts):
        result = path_idx == len(path_parts)
    else:
        part = pattern_parts[pattern_idx]
        if part == "**":
            if pattern_idx == len(pattern_parts) - 1:
                result = path_idx < len(path_parts)
            else:
                result = _match_globstar_parts(
                    path_parts, pattern_parts, path_idx, pattern_idx + 1, memo
                ) or (
                    path_idx < len(path_parts)
                    and _match_globstar_parts(
                        path_parts, pattern_parts, path_idx + 1, pattern_idx, memo
                    )
                )
        else:
            result = (
                path_idx < len(path_parts)
                and fnmatch.fnmatchcase(path_parts[path_idx], part)
                and _match_globstar_parts(
                    path_parts, pattern_parts, path_idx + 1, pattern_idx + 1, memo
                )
            )
    memo[key] = result
    return result


def _match_anchored_ignore_pattern(path: str, pattern: str) -> bool:
    """Match an anchored gitignore pattern without letting ``*`` cross ``/``."""
    path_parts = tuple(path.split("/"))
    pattern_parts = tuple(pattern.split("/"))
    # Fast path: with no ``**`` the match is a straight segment-wise fnmatch of
    # equal-length paths, so skip the recursive matcher and its memo entirely.
    if "**" not in pattern_parts:
        if len(path_parts) != len(pattern_parts):
            return False
        return all(
            fnmatch.fnmatchcase(pp, qp) for pp, qp in zip(path_parts, pattern_parts)
        )
    return _match_globstar_parts(path_parts, pattern_parts, 0, 0, {})


def _is_ignored(
    path: Path,
    root: Path,
    patterns: list[tuple[Path, str]],
    *,
    _cache: dict[Path, bool] | None = None,
) -> bool:
    """Return True if the path should be ignored per .graphifyignore patterns.

    Uses gitignore last-match-wins semantics: all patterns are evaluated in
    order; the final matching pattern determines the result. Negation patterns
    (starting with !) un-ignore a previously ignored path.

    Enforces gitignore's parent-exclusion rule: a ! pattern cannot re-include
    a file whose ancestor directory is already excluded.

    _cache: optional dict shared across calls within the same scan. Ancestor
    directory results are memoised so files under the same subtree don't
    re-evaluate the same patterns repeatedly.
    """
    if not patterns:
        return False

    def _eval(target: Path) -> bool:
        """Apply last-match-wins to a single target path.

        Everything derivable from ``target`` alone — its parts, its relative
        path per anchor, the NFC name, the is_dir() stat — is computed at most
        ONCE per call, no matter how many patterns are evaluated. The previous
        shape rebuilt pathlib objects (``relative_to``) and re-split strings
        per PATTERN per entry, which pinned real scans for tens of minutes
        (see CHANGELOG).
        """
        if _cache is not None and target in _cache:
            return _cache[target]

        target_parts = target.parts
        target_name_nfc: str | None = None
        target_is_dir: bool | None = None
        # rel string (or None = outside anchor) per distinct anchor; patterns
        # overwhelmingly share a handful of anchors.
        rel_by_anchor: dict[Path, str | None] = {}

        def _matches(rel: str, p: str, path_relative: bool) -> bool:
            nonlocal target_name_nfc
            if path_relative:
                return _match_anchored_ignore_pattern(rel, p)
            # A pattern without a slash names one path component, so it is
            # compared with the target's own name only. Ancestors are tested
            # one by one by _is_ignored's parent-exclusion walk; matching them
            # again here let `*` cross "/" and left a directory re-included
            # with `!dir/` without its files.
            if target_name_nfc is None:
                target_name_nfc = _nfc(target.name)
            return fnmatch.fnmatch(target_name_nfc, p)

        result = False
        for anchor, pattern in patterns:
            negated, directory_only, path_relative, p = _parse_ignore_pattern(pattern)
            if not p:
                continue

            # gitignore semantics: patterns from A/.gitignore apply ONLY to paths
            # under A. Matching non-anchored patterns against root-relative paths
            # let e.g. .hypothesis/.gitignore's bare "*" ignore the ENTIRE repo
            # (detect() returned 0 files). The anchor dir itself is exempt — an
            # ignore file governs its directory's contents, not the directory.
            if anchor not in rel_by_anchor:
                rel_by_anchor[anchor] = _lexical_relative(target, target_parts, anchor)
            rel_anchor = rel_by_anchor[anchor]
            if rel_anchor is None:
                continue  # target outside this pattern's anchor: cannot match
            matched = False
            if rel_anchor != ".":
                matched = _matches(rel_anchor, p, path_relative=path_relative)
                if matched and directory_only:
                    if target_is_dir is None:
                        target_is_dir = target.is_dir()
                    if not target_is_dir:
                        matched = False

            if matched:
                result = not negated  # last match wins; ! flips to un-ignore
        if _cache is not None:
            _cache[target] = result
        return result

    # Gitignore parent-exclusion rule: a ! re-include cannot rescue a file
    # whose ancestor directory is already excluded. Walk ancestors top-down;
    # if any ancestor is excluded, the file is excluded regardless of later
    # ! patterns targeting the file or a sub-path.
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        return _eval(path)

    ancestor = root
    for part in rel_parts[:-1]:
        ancestor = ancestor / part
        if _eval(ancestor):
            return True
    return _eval(path)


def _is_scan_ignored(
    path: Path,
    root: Path,
    patterns: list[tuple[Path, str]],
    explicit_patterns: list[tuple[Path, str]],
    tracked_files: set[str],
    tracked_dirs: set[str],
    *,
    cache: dict[Path, bool],
    explicit_cache: dict[Path, bool],
) -> bool:
    """Apply ignore rules while preserving Git-tracked paths.

    ``patterns`` combines Git and graph-specific rules. ``explicit_patterns``
    contains only .graphifyignore/--exclude rules, which remain authoritative
    even for tracked files. A tracked file's ancestor directories are preserved
    from Git-only pruning so the walk can reach the file (#2759).
    """
    if not _is_ignored(path, root, patterns, _cache=cache):
        return False
    if _is_ignored(path, root, explicit_patterns, _cache=explicit_cache):
        return True
    identity = _path_identity(path)
    return identity not in tracked_files and identity not in tracked_dirs


def ignored_predicate(
    root: Path,
    *,
    extra_excludes: list[str] | None = None,
    gitignore: bool = True,
) -> Callable[[Path], bool]:
    """Build a per-path predicate answering "would detect() exclude this path?".

    Mirrors detect()'s ignore decisions for a single existing path WITHOUT
    re-walking the corpus, from the same machinery detect() uses: the ancestor
    .graphifyignore/.gitignore chain (_load_graphifyignore), CLI/persisted
    ``--exclude`` patterns appended last at the root anchor (#947), nested
    per-directory ignore files along the path's own lineage (#1206), the
    _is_noise_dir directory pruning, and _SKIP_FILES. The sensitive-file
    heuristic (_is_sensitive) is deliberately NOT included: callers use this
    predicate as positive evidence of a live ignore RULE (#2495), and a
    heuristic match is not user intent.

    Nested patterns are loaded lazily, once per directory, into one shared
    pattern list. That accumulation cannot cross-contaminate results — a
    pattern only ever matches paths under its anchor directory, so patterns
    from a sibling subtree are inert — which is the same invariant detect()'s
    live os.walk relies on, and it keeps the shared _is_ignored cache valid.
    """
    root = root.resolve()
    patterns = _load_graphifyignore(root, gitignore=gitignore)
    explicit_patterns = _load_graphifyignore(root, gitignore=False)
    # Only shell out to git when .gitignore actually contributes patterns beyond
    # the explicit (.graphifyignore/--exclude) set: with no .gitignore in play,
    # nothing is dropped by gitignore and the tracked-file exemption is moot, so a
    # non-.gitignore corpus pays no `git ls-files` cost.
    tracked_files, tracked_dirs = (
        _git_tracked_path_keys(root)
        if gitignore and len(patterns) > len(explicit_patterns)
        else (set(), set())
    )
    if extra_excludes:
        for pat in extra_excludes:
            line = _parse_gitignore_line(pat)
            if line:
                patterns.append((root, line))
                explicit_patterns.append((root, line))
    cache: dict[Path, bool] = {}
    explicit_cache: dict[Path, bool] = {}
    # root's own ignore file is the last entry of _load_graphifyignore's chain.
    loaded_dirs: set[Path] = {root}

    def _ignored(path: Path) -> bool:
        path = Path(os.path.abspath(path))
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            return False  # outside the scan root: detect() never considered it
        if path.name in _SKIP_FILES or _is_installed_graphify_file(path):
            return True
        # Noise-dir pruning: os.walk never descends these, so anything beneath
        # one is excluded from the corpus regardless of ignore patterns.
        parent = root
        for part in rel_parts[:-1]:
            if _is_noise_dir(part, parent):
                return True
            parent = parent / part
        # Load ignore files along this path's own lineage — detect()'s walk
        # would have loaded exactly these before reaching the file (#1206).
        ancestor = root
        for part in rel_parts[:-1]:
            ancestor = ancestor / part
            if ancestor not in loaded_dirs:
                loaded_dirs.add(ancestor)
                patterns.extend(_load_dir_own_ignore(ancestor, gitignore=gitignore))
                explicit_patterns.extend(
                    _load_dir_own_ignore(ancestor, gitignore=False)
                )
        return _is_scan_ignored(
            path,
            root,
            patterns,
            explicit_patterns,
            tracked_files,
            tracked_dirs,
            cache=cache,
            explicit_cache=explicit_cache,
        )

    return _ignored


# --- opt-in secret-file guard (ported separately; NOT part of the predicate) --
# Verbatim from vendored detect.py:135 (_SENSITIVE_PATTERNS[1]) and :138 ([2]).
# The full vendored list also covers .env*/credential dotfiles, but plan P4 pins
# exactly these two "secret-skip regexes"; the predicate leaves ALL of them to the
# caller. Kept as a *distinct, optional* guard so the walk can opt in later
# without changing today's default.
_SECRET_SKIP_PATTERNS = [
    re.compile(r'\.(pem|key|p12|pfx|cert|crt|der|p8)$', re.IGNORECASE),
    re.compile(r'(^|[^A-Za-z0-9])(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\.pub)?$', re.IGNORECASE),
]


def secret_skip_predicate(path: Path) -> bool:
    """True for a file whose name matches the vendored secret-skip regexes.

    OPT-IN ONLY. `ignored_predicate` never calls this (vendored "#2495"), and the
    harness inventory walk does not use it today -- enabling it changes which
    files reach the partition and is a deliberate, separately-reviewed behavior
    change. Composes as: ``ignored(p) or secret_skip_predicate(p)``.
    """
    name = path.name
    return any(p.search(name) for p in _SECRET_SKIP_PATTERNS)

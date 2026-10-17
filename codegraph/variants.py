"""Variant hunting and triage memory — the Verifier/Remediation agent's edge.

Two tools, both answering questions a SAST agent asks after a finding is
already proven:

- **"Where else does this happen?"** (:func:`synthesize_and_sweep_variant_rule`)
  takes one proven vulnerability and sweeps the whole repo for the same
  callee, at zero extra exploration cost. This is the tool that turns one
  analyst-verified path into a repo-wide answer: the same sink reached from
  a service nobody audited yet, a copy-pasted handler in a second language,
  a test double that proves the pattern was known. The pattern is either a
  **bare callee name** (grammar-agnostic, one generic AST walk — works across
  every grammar pack installed) or a **tree-sitter S-expression query**
  (grammar-specific: compiled per language, and a language that cannot
  compile it is skipped and reported rather than silently ignored).
- **"What did we already decide?"** (:func:`query_historical_triage_memory`)
  injects institutional knowledge before an agent re-litigates a known
  finding: the triage sidecar's verdict for the (CWE, sink) pair, plus the
  in-repo suppression comments (``# nosemgrep``, ``# sast-ignore``,
  ``# codegraph-ignore`` …) that are the comment-level half of the same
  memory.

What this gives that a raw tree-sitter walk does not:

- **Bounded, contained, everything reported.** The sweep is one
  SKIP_DIRS-aware walk of the repo (the same containment rules
  ``harness.tools.code`` applies), capped by file count and match count, with
  the caps and the totals in the output. Generated files (the index's
  ``files.generated`` flag) are skipped; test files are marked, never skipped —
  a match under ``tests/`` is usually noise, but "usually" is not "always" and
  a suppressed test case is evidence about the pattern.
- **Graph join.** Every match carries the enclosing CodeGraph node id, so a
  sweep result drops straight into a finding that cites a symbol rather than a
  line. A match outside the index says ``(outside index)`` instead of guessing.
- **Memory.** The rule that produced a sweep is persisted through
  :func:`summaries.record_variant_rule`, so the next agent can rediscover it
  (and the pattern that earned a FALSE_POSITIVE last time is in the triage
  memory when the next agent gets there).

Degradation contract, same as the rest of the package: no tool here raises.
A missing index, an unwritable sidecar, a grammar that is not installed and a
pattern that does not compile are all strings — either a success-shaped
guidance note (the index is optional for a sweep: it only adds node ids and
the generated-file cross-check) or an ``ERROR: ...`` line naming what to fix.
"""
from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path

try:
    from langchain_core.tools import tool
except ImportError:  # pragma: no cover
    def tool(*dargs, **dkwargs):  # type: ignore
        def deco(fn):
            return fn
        if dargs and callable(dargs[0]):
            return dargs[0]
        return deco

try:  # pragma: no cover - the query API is version-dependent
    from tree_sitter import Query, QueryCursor
except ImportError:  # pragma: no cover
    Query = None  # type: ignore
    QueryCursor = None  # type: ignore

from harness.codegraph import _db, _ts, summaries
from harness.tools.code import SKIP_DIRS, _safe_path

# ---------------------------------------------------------------------------
# caps (env override, 0 = unlimited where a cap is optional)
# ---------------------------------------------------------------------------

ENV_MATCH_LIMIT = "CODEGRAPH_VARIANTS_LIMIT"
ENV_FILES = "CODEGRAPH_SWEEP_FILES"
ENV_CHARS = "CODEGRAPH_CHARS"
ENV_TRIAGE_LIMIT = "CODEGRAPH_TRIAGE_LIMIT"
ENV_SITES = "CODEGRAPH_TRIAGE_SITES"

DEFAULT_MATCH_LIMIT = 200
DEFAULT_FILES = 2000
DEFAULT_TRIAGE_LIMIT = 100
DEFAULT_SITES = 50

# The package's single row ceiling, imported from the foundation rather than
# restated: a module-private 2000 here would break the promise every other
# module keeps ("hard-clamped at _db.HARD_MAX_ROWS"). The DEFAULT_* values
# below are the env defaults and are unchanged — only the ceiling moved.
HARD_MAX = _db.HARD_MAX_ROWS   # matches / rows / sites: limit <= 0 clamps to this
CHAR_CAP = 20000         # overall output cap, same as every other tool here
TEXT_CAP = 160           # per-match / per-comment text truncation
MAX_PATTERN = 20000      # mirrors summaries.record_variant_rule's own limit
MAX_SCAN_BYTES = 10_000_000  # same "large file" threshold grep_files uses

# The sidecar's own directory is not source. ``code.py``'s SKIP_DIRS is frozen
# and does not list it, so the walk excludes it locally: counting the index DB
# the sweep just read as a "file examined" would inflate the one number an
# agent uses to judge how much of the repo was actually swept.
_WALK_SKIP_DIRS = SKIP_DIRS | {".codegraph"}

# Field names a grammar uses for the callee of a call-ish node, in the order
# they are consulted. Probed against every grammar pack in this environment:
# python/typescript/javascript/go/rust/scala/c/cpp use ``function``, csharp
# uses ``function``, ruby uses ``method``, java's ``method_invocation`` uses
# ``name`` (with the receiver as the first *named* child), and kotlin/swift
# ``call_expression`` carries no field at all — the first named child is the
# callee, which is why that fallback is last-resort and mandatory.
_CALLEE_FIELDS = ("function", "callee", "method", "name")

# Separator between a receiver chain and the called name: `a.b`, `a->b`,
# `a?.b`, `a!.b`, `A::b`.
_CHAIN_SEP = re.compile(r"(?:\?\.|!\.|->|::|\.)")

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*$")

# Comment-level suppression markers. `# noqa` only counts WITH a code, so a
# stray "# noqa" in prose never reads as a suppression.
_SUPPRESSION_RE = re.compile(
    r"nosemgrep|sast-ignore|codegraph-ignore|false[-_ ]?positive|suppress"
    r"|allow[-_ ]?list|noqa\s*[:=]\s*\S",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# small helpers (house style: env caps never raise)
# ---------------------------------------------------------------------------

def _safe_root(root: str) -> Path:
    """Resolve a tool-supplied root against the repo boundary.

    Delegates to :func:`harness.tools.code._safe_path`, which confines to
    TARGET_REPO when set and raises ``ValueError`` on escape. Callers convert
    that to an agent-facing error string. ``_safe_path`` can also raise
    ``OSError`` (an unaddressable path — ENAMETOOLONG, NUL), so it is
    re-raised as ``ValueError`` here: the same shape every caller already
    converts, and no traceback ever escapes a tool.
    """
    try:
        return _safe_path(str(root) if root is not None else ".")
    except OSError as e:
        raise ValueError(f"cannot resolve root {root!r}: {e}") from e


def _cap_int(env_key: str, default: int) -> int:
    """Env override for a cap. 0 means "unlimited" where that is allowed."""
    try:
        v = os.environ.get(env_key)
        if v is None or v == "":
            return default
        return int(v)
    except (TypeError, ValueError):
        return default


def _resolve_limit(value, env_key: str, default: int, hard_max: int = HARD_MAX) -> int:
    """Explicit arg wins, then env, then default. <=0 = unlimited, hard-capped."""
    if value is None:
        n = _cap_int(env_key, default)
    else:
        try:
            n = int(value)
        except (TypeError, ValueError):
            n = default
    if n <= 0:
        return hard_max
    return min(n, hard_max)


def _char_cap(text: str) -> str:
    """The overall 20000-char cap every agent-facing string passes through."""
    lim = _cap_int(ENV_CHARS, CHAR_CAP)
    if lim <= 0 or len(text) <= lim:
        return text
    return text[:lim] + f"\n… +{len(text) - lim} more chars (total {len(text)})"


def _one_line(text: str) -> str:
    """Flatten a matched expression / comment onto one output line."""
    return " ".join(str(text or "").split())


def _clip(text: str, cap: int = TEXT_CAP) -> str:
    flat = _one_line(text)
    return flat if len(flat) <= cap else flat[:cap] + "…"


def _stamp(ms) -> str:
    """A sidecar ``updated_at`` (epoch ms) as a compact UTC stamp, or ''."""
    try:
        import datetime
        return datetime.datetime.fromtimestamp(int(ms) / 1000.0,
                                               datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


# ---------------------------------------------------------------------------
# the contained walk (shared by both tools)
# ---------------------------------------------------------------------------

def _candidate_files(base: Path) -> list[Path]:
    """Every file under ``base``, contained and SKIP_DIRS-aware.

    Mirrors the walk in ``harness.tools.code`` / ``graphify.py``: symlinked
    files are skipped, ``rglob`` results that resolve outside the root are
    re-checked (a symlinked directory must not smuggle a path in), and any
    path component in :data:`SKIP_DIRS` (plus ``.codegraph`` — see
    :data:`_WALK_SKIP_DIRS`) is dropped. Never raises.
    """
    try:
        if base.is_file():
            return [base]
    except OSError:
        return []
    out: list[Path] = []
    try:
        resolved_base = base.resolve()
        for f in sorted(base.rglob("*")):
            try:
                if not f.is_file() or f.is_symlink():
                    continue
                rel = f.relative_to(base)
            except (OSError, ValueError):
                continue
            if any(part in _WALK_SKIP_DIRS for part in rel.parts):
                continue
            try:
                f.resolve().relative_to(resolved_base)
            except (OSError, ValueError):
                continue
            out.append(f)
    except OSError:
        return out
    return out


def _rel(base: Path, path: Path) -> str:
    """Repo-relative POSIX path — the spelling ``nodes.file_path`` uses."""
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.name


def _repo_anchor(base: Path) -> Path:
    """The repo root a sweep's paths and index lookups are spelled against.

    ``root`` may be the repo root OR a subdirectory of it (the docstring says
    so), while ``files.path`` / ``nodes.file_path`` / ``files.generated`` are
    stored relative to the repo root. Resolving the anchor once means a
    subdirectory sweep still joins the index — and still gets
    ``(outside index)`` when the swept base genuinely is outside the
    containment root (an absolute path in another tree), rather than quietly
    mis-joining.
    """
    try:
        anchor = _safe_path(".")
        base.relative_to(anchor)
        return anchor
    except (ValueError, OSError):
        return base


def _walk_nodes(node):
    """Depth-first, parent before children (a tree-sitter node tree walk)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        try:
            children = list(current.children)
        except Exception:
            children = []
        stack.extend(reversed(children))


def _is_callish(node_type: str) -> bool:
    """Is this node a call? Grammar-agnostic on purpose.

    ``_ts.CALL_NODE_TYPES`` holds the exact spellings the foundation already
    knew about; the substring test adds the ones it did not enumerate
    (``function_call_expression``, ``nullsafe_member_call_expression``,
    ``scoped_call_expression``, ``call_suffix``) so a grammar pack added
    later still sweeps instead of silently matching nothing.
    """
    t = (node_type or "").lower()
    if not t:
        return False
    if t in _ts.CALL_NODE_TYPES:
        return True
    return "call" in t or "invocation" in t


def _callee_tail(expr: str) -> str:
    """``db.run_query(...)`` -> ``run_query``; '' when not a plain callee."""
    text = str(expr or "").strip()
    if "(" in text:            # drop the argument list
        text = text.split("(", 1)[0].strip()
    if not text:
        return ""
    text = _CHAIN_SEP.split(text)[-1].strip().lstrip("$&*~@").strip()
    return text if _IDENTIFIER.fullmatch(text) else ""


def _callee_candidates(node, src: bytes) -> list[str]:
    """Every reading of "what is being called" for one call-ish node.

    Field first (a grammar's own notion of the callee), the first named child
    second (kotlin/swift ``call_expression``, rust ``macro_invocation``), and
    the whole node text last (so a receiver chain with no callee field still
    resolves its tail). Order only matters for which text gets displayed.
    """
    out: list[str] = []
    try:
        for field in _CALLEE_FIELDS:
            try:
                child = node.child_by_field_name(field)
            except Exception:
                child = None
            if child is None:
                continue
            text = _ts.node_text(child, src)
            if text:
                out.append(text)
        named = [c for c in node.children if getattr(c, "is_named", False)]
    except Exception:
        named = []
    if named:
        text = _ts.node_text(named[0], src)
        if text:
            out.append(text)
    return out


# ---------------------------------------------------------------------------
# per-language tree-sitter query compilation
# ---------------------------------------------------------------------------

def _language_key_for_query(language: str) -> str:
    """The :data:`_ts.LANG_BY_EXT` key that resolves to ``language``'s grammar.

    The per-file cache key is derived from the file's extension (``.cs`` ->
    ``c_sharp``), so a pre-flight compile for a restricted sweep has to use
    the same spelling or it would compile the same grammar twice under two
    keys. Falls back to the normalised language name, which
    :func:`_ts.parser_for_language` still resolves through its aliases.
    """
    wanted = _ts.parser_for_language(language)
    if wanted is None:
        return (language or "").strip().lower().replace("-", "_")
    key = (language or "").strip().lower().replace("-", "_")
    if key in set(_ts.LANG_BY_EXT.values()):
        return key  # the common case: no grammar load needed to resolve it
    for _ext, ext_key in sorted(_ts.LANG_BY_EXT.items()):
        try:
            if _ts.parser_for_language(ext_key) is wanted:
                return ext_key
        except Exception:
            continue
    return key


def _query_for_language(lang_key: str, pattern: str, cache: dict):
    """(QueryCursor, error_string) for one grammar, compiled once and cached.

    A grammar that cannot compile the pattern is not an error — it is a
    skipped language the caller reports, because a query written for python
    is simply meaningless against ``call_expression``.
    """
    if lang_key in cache:
        return cache[lang_key]
    entry: tuple = (None, "")
    try:
        parser = _ts.parser_for_language(lang_key)
        lang = getattr(parser, "language", None) if parser is not None else None
        if lang is None:
            entry = (None, "grammar not installed")
        elif Query is None or QueryCursor is None:  # pragma: no cover
            entry = (None, "tree_sitter query API unavailable")
        else:
            entry = (QueryCursor(Query(lang, pattern)), "")
    except Exception as e:  # QueryError, QueryCompileError, ...
        entry = (None, str(e) or e.__class__.__name__)
    cache[lang_key] = entry
    return entry


# ---------------------------------------------------------------------------
# the graph join: which symbol encloses a match
# ---------------------------------------------------------------------------

def _nodes_for_file(conn, rel: str, cache: dict) -> list[tuple]:
    """(start_line, end_line, node_id, kind, name) for one file, cached.

    One direct span query rather than a :func:`_db.find_nodes` page: a sweep
    asks "which symbol contains line N" thousands of times, and the node page
    is capped at 500 rows — on a god-file repo the containing symbol would
    silently be past the cap. Falls back to the public helper if the direct
    query is unavailable, so a schema change degrades instead of breaking.
    """
    if rel in cache:
        return cache[rel]
    rows: list[tuple] = []
    if conn is not None:
        try:
            cur = conn.execute(
                "SELECT id, kind, name, start_line, end_line FROM nodes "
                "WHERE file_path = ? ORDER BY start_line, id LIMIT ?",
                (rel, HARD_MAX * 10),
            )
            rows = [(int(r[3] or 0), int(r[4] or 0), str(r[0] or ""),
                     str(r[1] or ""), str(r[2] or "")) for r in cur.fetchall()]
        except sqlite3.Error:
            rows = []
        if not rows:
            try:
                rows = [(int(n.get("start_line") or 0), int(n.get("end_line") or 0),
                         str(n.get("id") or ""), str(n.get("kind") or ""),
                         str(n.get("name") or ""))
                        for n in _db.find_nodes(conn, file_path=rel, limit=0)]
            except Exception:
                rows = []
    cache[rel] = rows
    return rows


def _enclosing_node_id(rows, line: int) -> str:
    """The innermost symbol whose span contains ``line``.

    A file node's span contains every line, so a non-``file`` node wins and
    the file node is the last resort — a match in an indexed file with no
    extracted symbol still gets the file's node id, not a blank.
    """
    best = None
    best_key = None
    for start, end, node_id, kind, _name in rows:
        if start and end and start <= line <= end:
            key = (1 if kind == "file" else 0, end - start)
            if best is None or key < best_key:
                best, best_key = node_id, key
    return best or "(outside index)"


# ---------------------------------------------------------------------------
# pattern matching
# ---------------------------------------------------------------------------

def _bare_name_matches(tree, src: bytes, pattern: str) -> list[dict]:
    """Grammar-agnostic calls whose callee tail equals ``pattern``.

    No query compilation, so it works on every grammar pack (including ones
    with no published node-type documentation) at the cost of precision: it
    answers "is this name called anywhere", never "is it called with these
    arguments".

    The comparison is on the callee's TAIL, so a pattern written as a receiver
    chain (``cursor.execute``) still finds the same sink written through
    another receiver (``cur.execute()``, ``stmt.execute()``,
    ``$conn->execute()``): the receiver is what changes between call chains,
    the sink name is what does not. A plain name is its own tail, so
    ``execute`` behaves exactly as strictly as the chain spelling does.
    """
    out: list[dict] = []
    if tree is None:
        return out
    try:
        root_node = tree.root_node
    except Exception:
        return out
    wanted_tail = _callee_tail(pattern) or pattern
    for node in _walk_nodes(root_node):
        if not _is_callish(getattr(node, "type", "")):
            continue
        whole = _ts.node_text(node, src)
        candidates = _callee_candidates(node, src)
        if whole:
            candidates.append(whole)
        if not any(_callee_tail(c) == wanted_tail or _one_line(c) == pattern
                   for c in candidates):
            continue
        try:
            line = node.start_point[0] + 1
            col = node.start_point[1] + 1
        except Exception:
            continue
        out.append({"line": line, "col": col, "text": whole, "captures": []})
    out.sort(key=lambda m: (m["line"], m["col"]))
    return out


def _query_matches(cursor, tree, src: bytes) -> list[dict]:
    """Captures of a compiled query, one entry per matched node."""
    out: list[dict] = []
    if tree is None or cursor is None:
        return out
    try:
        caps = cursor.captures(tree.root_node)
    except Exception:
        return out
    grouped: dict[tuple, dict] = {}
    for name, nodes in (caps or {}).items():
        for node in nodes or []:
            try:
                key = (node.start_byte, node.end_byte)
                line = node.start_point[0] + 1
                col = node.start_point[1] + 1
            except Exception:
                continue
            entry = grouped.get(key)
            if entry is None:
                entry = {"line": line, "col": col,
                         "text": _ts.node_text(node, src), "captures": []}
                grouped[key] = entry
            if name not in entry["captures"]:
                entry["captures"].append(name)
    for entry in grouped.values():
        entry["captures"].sort()
        out.append(entry)
    out.sort(key=lambda m: (m["line"], m["col"], m["text"]))
    return out


def _auto_rule_name(pattern: str, cwe_id: str) -> str:
    """A stable rule name when the analyst did not supply one."""
    if "(" in pattern:  # a query: name it after its first node type
        m = re.search(r"\(\s*([\w.]+)", pattern)
        core = m.group(1) if m else "query"
    else:
        core = pattern.strip()
    core = re.sub(r"[^A-Za-z0-9_.-]+", "-", core).strip("-.")
    name = f"variant-{core}" if core else "variant-rule"
    if cwe_id:
        name += "-" + re.sub(r"[^A-Za-z0-9_.-]+", "-", cwe_id).strip("-.")
    return name[:200]


def _format_match(match: dict) -> str:
    """``rel:line:col [TEST] [node=id] [caps=@f] <expr>`` — one match, one line."""
    parts = [f"{match['rel']}:{match['line']}:{match['col']}"]
    if match.get("is_test"):
        parts.append("[TEST]")
    parts.append(f"[node={match['node_id']}]")
    if match.get("captures"):
        parts.append("[caps=" + ",".join(match["captures"]) + "]")
    parts.append(_clip(match.get("text")))
    return " ".join(parts)


# ---------------------------------------------------------------------------
# tool 1: the variant sweep
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def synthesize_and_sweep_variant_rule(pattern: str, name: str = "", cwe_id: str = "",
                                      language: str = "", root: str = ".",
                                      limit: int | None = None) -> str:
    """Sweep the repo for every occurrence of a proven vulnerability pattern.

    Use this the moment one path is confirmed: a variant is the same sink
    reached from another call chain, and finding it costs one call instead of
    a re-investigation per candidate file. Two pattern modes:

    - **Bare callee name** — ``pattern`` holds no ``(``. Grammar-agnostic:
      one AST walk per file matches any call-ish node whose callee tail
      equals the name, so ``cursor.execute`` finds ``cur.execute()``
      (python), ``stmt.execute()`` (java), ``db.execute()`` (go) and
      ``$conn->execute()`` (php) in one sweep — the receiver is what varies
      between call chains, the sink name is what does not.
    - **Tree-sitter query** — ``pattern`` contains ``(``, so it is an
      S-expression compiled per grammar. Queries are grammar-specific: with
      ``language`` set the sweep is restricted to that one grammar and a
      pattern that does not compile for it is an ERROR; with ``language``
      empty every file's grammar gets a compile attempt and languages that
      cannot compile the pattern are skipped and reported.

    Use it NOT for argument-level dataflow (a sweep proves occurrence, not
    taint), not for a name that is also a common library helper
    (``open``/``print``/``get`` will over-match — narrow with a query), and
    not when the repo is un-indexed AND you need node ids: the sweep still
    runs, but every match reads ``(outside index)``.

    Output: a header with mode/caps/totals, the skipped languages, then the
    matches grouped by file as ``file:line:col [TEST] [node=<id>]
    [caps=<names>] <matched text>``, then ``… +N more`` when the match cap
    was hit. Generated files are skipped, test files are marked ``[TEST]``,
    and the rule is persisted so it is rediscoverable later.

    Args:
        pattern: A bare callee name (``cursor.execute``) or a tree-sitter
            S-expression query (any pattern containing ``(``, e.g.
            ``(call function: (identifier) @f) @c``).
        name: Rule name to persist. Empty derives ``variant-<pattern>``.
        cwe_id: CWE recorded with the rule, e.g. ``89`` or ``CWE-89``.
        language: For query mode only: restrict the sweep to one grammar
            (python, typescript, tsx, javascript, go, java, ruby, php,
            csharp, kotlin, swift, scala, c, cpp, rust). Ignored in bare
            callee name mode, where the walk is grammar-agnostic on purpose.
        root: Repo root to sweep (or a subdirectory of it).
        limit: Max matches returned. 0 = unlimited.
    """
    try:
        base = _safe_root(root)
    except ValueError as e:
        return f"ERROR: {e}"
    pattern = (pattern or "").strip()
    if not pattern:
        return ("ERROR: pattern is required — a bare callee name such as "
                "'cursor.execute', or a tree-sitter query containing '('")
    if len(pattern) > MAX_PATTERN:
        return f"ERROR: pattern too long ({len(pattern)} chars, max {MAX_PATTERN})"
    try:
        if not base.exists():
            return "(no matches)"
    except OSError:
        return "(no matches)"

    query_mode = "(" in pattern
    language = (language or "").strip()
    # Paths and index lookups are spelled against the repo root, so a
    # subdirectory root still joins the index (see _repo_anchor).
    anchor = _repo_anchor(base)
    conn = _db.connect(str(anchor))  # once per call; read-only, never closed
    match_cap = _resolve_limit(limit, ENV_MATCH_LIMIT, DEFAULT_MATCH_LIMIT, HARD_MAX)
    file_cap = _cap_int(ENV_FILES, DEFAULT_FILES)

    if query_mode and language and _ts.parser_for_language(language) is None:
        supported = ", ".join(sorted(set(_ts.LANG_BY_EXT.values())))
        return (f"ERROR: no tree-sitter grammar for {language!r} "
                f"(supported languages: {supported})")

    skipped_langs: dict[str, str] = {}
    query_cache: dict[str, tuple] = {}
    if query_mode and language:
        # Fail fast: a restricted sweep that cannot compile the pattern is an
        # error naming the grammar, not a silent zero-match run.
        cursor, error = _query_for_language(_language_key_for_query(language),
                                            pattern, query_cache)
        if cursor is None:
            return (f"ERROR: pattern does not compile for {language}: {error}\n"
                    "hint: tree-sitter queries are grammar-specific — write the "
                    "pattern for that language's node types, or drop `language` "
                    "to let the sweep skip (and report) the languages that "
                    "cannot compile it")

    files = _candidate_files(base)
    matches: list[dict] = []
    total = 0
    capped = False
    considered = 0
    parsed_files = 0
    unparseable = 0
    generated_skipped = 0
    test_files = 0
    files_past_cap = 0
    capped_file = ""
    node_cache: dict[str, list[tuple]] = {}
    wanted_parser = (_ts.parser_for_language(language)
                     if query_mode and language else None)

    for index, path in enumerate(files):
        if file_cap > 0 and considered >= file_cap:
            files_past_cap = len(files) - index
            break
        if wanted_parser is not None and _ts.parser_for_file(path) is not wanted_parser:
            continue  # outside the restricted grammar: never examined at all
        considered += 1
        rel = _rel(anchor, path)
        if conn is not None and _db.is_generated_file(conn, rel):
            generated_skipped += 1
            continue
        if _ts.parser_for_file(path) is None:
            continue  # not a language we can parse: not a sweep candidate
        parsed = _ts.parse_file(path)
        if parsed is None:
            unparseable += 1
            continue
        tree, src = parsed
        parsed_files += 1
        is_test = _db.is_test_file(rel)
        if is_test:
            test_files += 1
        if query_mode:
            lang_key = _ts.LANG_BY_EXT.get(path.suffix.lower(), "")
            cursor, error = _query_for_language(lang_key, pattern, query_cache)
            if cursor is None:
                if language:
                    # Defensive: the pre-flight compile above already caught
                    # this for the restricted grammar.
                    return (f"ERROR: pattern does not compile for {language}: "
                            f"{error}")
                skipped_langs[lang_key or path.suffix or "?"] = error
                continue
            found = _query_matches(cursor, tree, src)
        else:
            found = _bare_name_matches(tree, src, pattern)
        if not found:
            continue
        rows = _nodes_for_file(conn, rel, node_cache)
        for item in found:
            total += 1
            if len(matches) < match_cap:
                matches.append({"rel": rel, "is_test": is_test,
                                "node_id": _enclosing_node_id(rows, item["line"]),
                                **item})
            else:
                # Keep counting THIS file's matches so the reported total is a
                # real count of it, then stop: the sweep is bounded by design.
                capped = True
                capped_file = rel
        if capped:
            files_past_cap = len(files) - index - 1
            break

    rule_name = (name or "").strip() or _auto_rule_name(pattern, cwe_id)
    recorded = summaries.record_variant_rule(str(anchor), rule_name, pattern,
                                             cwe_id or "")

    out: list[str] = [
        f"## variant sweep: {_clip(pattern, 120)}",
        "mode: " + ("tree-sitter query" if query_mode else "bare callee name")
        + (f" (restricted to {language})" if query_mode and language else ""),
        f"rule: {rule_name} — {recorded}",
        (f"files examined: {considered} (cap {file_cap if file_cap > 0 else 'unlimited'})"
         + (f", {files_past_cap} more not examined"
            + (" (stopped at the match limit)" if capped else "")
            if files_past_cap else "")),
        f"parsed: {parsed_files} ({unparseable} unreadable or over the 1MB index cap)",
        f"generated skipped: {generated_skipped}   test files scanned: {test_files}",
        f"matches: {total}{'+' if capped else ''} (limit {match_cap})",
    ]
    if not query_mode and language:
        out.append(f"note: language={language!r} is ignored in bare callee name "
                   "mode — the walk is grammar-agnostic on purpose; use a "
                   "tree-sitter query to restrict the sweep to one grammar")
    if skipped_langs:
        out.append("skipped languages: " + "; ".join(
            f"{lang} ({reason[:80]})" for lang, reason in sorted(skipped_langs.items())))
    if conn is None:
        out.append("note: " + _db.guidance_no_db(str(anchor))
                   + " — the sweep still runs, but node ids and the "
                     "generated-file cross-check need the index")
    out.append("")
    if matches:
        current = None
        for match in matches:
            if match["rel"] != current:
                current = match["rel"]
                out.append(current)
            out.append("  " + _format_match(match))
        if capped:
            out.append(f"… +{total - len(matches)} more matches in "
                       f"{capped_file}, and possibly more beyond it "
                       f"(sweep stopped at the limit; re-run with a narrower "
                       f"pattern or a higher limit)")
    else:
        out.append("(no variant matches)")
    return _char_cap("\n".join(out))


# ---------------------------------------------------------------------------
# tool 2: triage memory
# ---------------------------------------------------------------------------

def _signature_tail(signature: str) -> str:
    """``cursor.execute`` -> ``execute`` — the name a comment would cite."""
    tokens = [t for t in re.split(r"[^\w$]+", signature or "") if t]
    return tokens[-1] if tokens else ""


def _suppression_sites(base: Path, conn, signature: str, cap: int,
                       anchor: Path | None = None) -> tuple:
    """(sites, files_scanned) for in-repo suppression comments.

    A site is a line that carries a suppression marker AND names the sink —
    either the full signature or its tail segment, so both
    ``# nosemgrep: cursor.execute is parameterised`` and
    ``# codegraph-ignore CWE-89 (execute)`` are found. Both halves on the SAME
    line are the strict reading; the line-above spelling
    (``# nosemgrep`` on its own line immediately above the sink call) is the
    common real form and is accepted too, bounded to 1-2 lines above.

    ``anchor`` is the repo root the displayed paths (and the index's
    ``files.generated`` cross-check) are spelled against; it defaults to
    ``base`` so the helper stays callable on its own.
    """
    tail = _signature_tail(signature)
    file_cap = _cap_int(ENV_FILES, DEFAULT_FILES)
    anchor = anchor if anchor is not None else base
    sites: list[dict] = []
    seen: set[tuple[str, int]] = set()
    considered = 0
    for path in _candidate_files(base):
        if file_cap > 0 and considered >= file_cap:
            break
        considered += 1
        rel = _rel(anchor, path)
        if conn is not None and _db.is_generated_file(conn, rel):
            continue
        try:
            if path.stat().st_size > MAX_SCAN_BYTES:
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:8192]:  # binary, like grep_files
            continue
        lines = raw.decode("utf-8", errors="replace").splitlines()
        for index, line in enumerate(lines):
            site = None
            if _SUPPRESSION_RE.search(line):
                # the strict reading: marker AND sink on one line
                if _line_names_sink(line, signature, tail):
                    site = (index, line)
            elif _line_names_sink(line, signature, tail):
                # the line-above spelling: a bare marker comment on the line
                # above the sink call is what suppresses it
                above = _bare_marker_above(lines, index)
                if above >= 0:
                    site = (above, lines[above])
            if site is None:
                continue
            key = (rel, site[0] + 1)
            if key in seen:
                continue  # the marker line named the sink itself: one site
            seen.add(key)
            sites.append({"rel": rel, "line": key[1], "text": site[1]})
            if len(sites) >= cap:
                return sites, considered
    return sites, considered


# How far above a sink call a bare marker comment may sit: the line
# immediately above, or one more when nothing but a blank separates them.
_MAX_MARKER_LINES = 2


def _bare_marker_above(lines: list[str], index: int) -> int:
    """The index of a marker-only line 1-2 lines above ``index``, or ``-1``.

    ``# nosemgrep`` on its own line above the call is the spelling most
    suppression tooling emits, so a marker that names no sink still counts
    when it sits directly on the sink. The two-line window is deliberately
    not a sliding window over the whole file: a marker two lines up with a
    ``def`` (or any other code) in between is module-level documentation, and
    a marker alone is documentation, not a suppression of that sink.
    """
    for candidate in range(index - 1, max(-1, index - 1 - _MAX_MARKER_LINES), -1):
        if candidate < 0 or candidate >= len(lines):
            continue
        if candidate == index - 2 and lines[index - 1].strip():
            continue  # the line between them is code, not a blank
        if _SUPPRESSION_RE.search(lines[candidate]):
            return candidate
    return -1


def _line_names_sink(line: str, signature: str, tail: str) -> bool:
    """Does this line name the sink — the full signature or its tail?"""
    if signature and signature in line:
        return True
    if tail and len(tail) >= 3:
        return re.search(rf"(?<![\w$]){re.escape(tail)}(?![\w$])", line) is not None
    return False


@tool(parse_docstring=True)
def query_historical_triage_memory(cwe_id: str = "", sink_signature: str = "",
                                   root: str = ".", limit: int | None = None) -> str:
    """What did we already decide about this CWE and sink before I re-litigate it?

    Use this BEFORE reasoning about a candidate finding: an agent that
    re-derives a verdict the team already recorded costs a review cycle and,
    worse, can contradict it. It reads the triage sidecar (per-(CWE, sink)
    TRUE_POSITIVE / FALSE_POSITIVE / SUPPRESSED / NEEDS_REVIEW rows with the
    analyst's notes) and, when a sink signature is given, sweeps the repo for
    comment-level suppression markers (``# nosemgrep``, ``# sast-ignore``,
    ``# codegraph-ignore``, ``false-positive``, ``suppress``, ``allowlist``,
    ``# noqa: CODE``) that sit on the same sink.

    Use it NOT as a substitute for verification: this is memory, not proof, so
    a stale row is exactly as wrong as no row. A single input is fine — CWE
    alone answers "how has this weakness class gone for us", sink alone
    answers "what did we decide about exactly this sink".

    Output: a header naming the query, a one-line verdict
    (``PRIOR FALSE_POSITIVE: <notes>`` / ``PRIOR SUPPRESSION at <sites>`` /
    ``no triage history for CWE-89 on cursor.execute``), the memory rows
    newest-first with notes and timestamps, and the suppression comment sites
    as ``file:line: <comment text>``.

    Args:
        cwe_id: CWE to filter on, e.g. ``89`` or ``CWE-89``. Empty = any CWE.
        sink_signature: Sink signature to filter on, e.g. ``cursor.execute``.
            Empty = any sink, and disables the suppression-comment scan.
        root: Repo root the sidecar and suppression comments live under.
        limit: Max triage rows (and suppression sites) returned. 0 = unlimited.
    """
    cwe = (cwe_id or "").strip()
    signature = (sink_signature or "").strip()
    if not cwe and not signature:
        return ("ERROR: provide cwe_id and/or sink_signature "
                "(e.g. cwe_id='89', sink_signature='cursor.execute')")
    try:
        base = _safe_root(root)
    except ValueError as e:
        return f"ERROR: {e}"
    try:
        base_exists = base.exists()
    except OSError:
        base_exists = False  # an unaddressable path has no triage history
    if not base_exists:
        return "(no triage history)"

    # The sidecar is per-repo, and the comment scan's displayed paths (and the
    # generated-file cross-check) are spelled against the repo root, so a
    # subdirectory root reads the same memory as the repo itself.
    anchor = _repo_anchor(base)
    conn = _db.connect(str(anchor))  # read-only, once per call
    # ... and the memory query uses the SAME anchor. `summaries.store_path`
    # resolves `<root>/.codegraph/sast_summaries.db`, so passing the swept
    # `root` would look for a second sidecar inside the subdirectory — one
    # that was never written to — and the recorded FALSE_POSITIVE would be
    # missed exactly when an agent is working inside a subpackage.
    rows = summaries.query_triage(str(anchor), cwe, signature)
    cap = _resolve_limit(limit, ENV_TRIAGE_LIMIT, DEFAULT_TRIAGE_LIMIT, HARD_MAX)
    page = rows[:cap]
    # The explicit `limit` caps every list in this answer (rows AND sites), so
    # one knob bounds the whole output; the env override only fills in when the
    # agent did not pass one.
    site_cap = _resolve_limit(limit, ENV_SITES, DEFAULT_SITES, HARD_MAX)
    sites, files_scanned = (([], 0) if not signature else
                            _suppression_sites(base, conn, signature, site_cap,
                                               anchor))

    # the one-line verdict an agent can act on without reading further
    if rows:
        newest = rows[0]
        decision = str(newest.get("decision") or "").upper()
        notes = _clip(newest.get("notes"), 200) or "no notes recorded"
        if decision == "FALSE_POSITIVE":
            verdict = f"PRIOR FALSE_POSITIVE: {notes}"
        elif decision == "SUPPRESSED":
            verdict = f"PRIOR SUPPRESSION: {notes}"
            if sites:
                verdict += f" (also {len(sites)} in-repo suppression comment(s))"
        elif decision == "TRUE_POSITIVE":
            verdict = (f"PRIOR TRUE_POSITIVE: {notes} — re-verify rather than "
                       f"rediscover")
        else:
            verdict = f"PRIOR NEEDS_REVIEW: {notes}"
    elif sites:
        where = ", ".join(f"{s['rel']}:{s['line']}" for s in sites[:3])
        if len(sites) > 3:
            where += f" (+{len(sites) - 3} more)"
        verdict = f"PRIOR SUPPRESSION at {where} (no triage-memory row recorded)"
    else:
        verdict = f"no triage history for {cwe or 'any CWE'} on {signature or 'any sink'}"

    out: list[str] = [
        f"## historical triage: {cwe or 'any CWE'} @ {signature or 'any sink'}",
        f"verdict: {verdict}",
    ]
    if rows:
        out.append(f"triage memory ({len(page)} of {len(rows)} rows, newest first):")
        for row in page:
            stamp = _stamp(row.get("updated_at"))
            out.append("  {} @ {} = {}{}{}".format(
                row.get("cwe_id", ""), row.get("sink_signature", ""),
                row.get("decision", ""),
                f" — {_clip(row.get('notes'), 200)}" if row.get("notes") else "",
                f"  ({stamp})" if stamp else ""))
        if len(rows) > len(page):
            out.append(f"… +{len(rows) - len(page)} more rows "
                       f"(re-run with a narrower cwe_id/sink_signature)")
    else:
        out.append("triage memory: (no rows recorded)")
    if signature:
        if sites:
            out.append(f"suppression comments ({len(sites)} site(s), "
                       f"{files_scanned} files scanned):")
            for site in sites:
                out.append(f"  {site['rel']}:{site['line']}: {_clip(site['text'])}")
        else:
            out.append("suppression comments: none found "
                       f"({files_scanned} files scanned)")
    if conn is None:
        out.append("note: " + _db.guidance_no_db(str(anchor))
                   + " — the sidecar and comment scan still run; only the "
                     "generated-file cross-check is unavailable")
    return _char_cap("\n".join(out))

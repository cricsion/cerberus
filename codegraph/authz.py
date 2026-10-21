"""AuthZ & business-logic tools for the AuthZ/Business-Logic micro-agent.

Three questions the graph can answer and a taint tracer cannot, because they are
about *what a sibling does*, *who touches shared state*, and *which state
transition is legal* — not about how a value flows:

- :func:`compare_sibling_route_security` — **BOLA / IDOR / missing
  function-level access control by consensus.** One endpoint that omits the
  decorator or the ownership check its siblings all carry is the single most
  common shape of CWE-639, and it is invisible to a tracer: the vulnerable
  handler looks perfectly ordinary in isolation. This tool builds the consensus
  (same controller file, same URL prefix), computes what the target is missing,
  and emits a candidate finding when the gap is an authorisation-shaped one.
- :func:`find_shared_state_readers_writers` — **TOCTOU / double-spend / race.**
  Readers and writers of one state carrier (a balance, a quota, a nonce) found
  through ``references`` edges, each site classified reader-vs-writer by parsing
  the statement that touches it, and each enclosing function checked for a
  transaction/lock wrapper. A read and a write with nothing between them is the
  bug: across an ``await`` (CWE-367) or in two different unsynchronised
  functions (CWE-362).
- :func:`trace_state_machine_transitions` — **business-logic bypass.** Every
  assignment that SETS a status field, with the prior-state guard that (does not)
  precede it, mapped to the endpoint that reaches it. An unguarded
  ``status = "shipped"`` is a skip-the-workflow bug (CWE-840) whether or not any
  taint path exists.

Everything here is read-only against the target repo: the index is opened
``mode=ro`` by :func:`harness.codegraph._db.connect`, source is read through the
same containment check every harness tool uses, and the only sidecar touched is
the summary store's *read* path (:func:`summaries.cache_hint`), which is how a
call an analyst already labelled ``AUTH_GUARD`` joins the consensus. No LLM, no
network, no writes, and no tool here raises: a missing index, an unreadable file,
a grammar that is not installed and a symbol the index never saw are all strings.

The confidence numbers are heuristics and are documented as such in each
docstring — they rank candidates for an analyst, they do not settle anything.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from harness.codegraph import _db, _ts, summaries
from harness.config import get_default_config
from harness.tools.code import _safe_path

try:
    from langchain_core.tools import tool
except ImportError:  # pragma: no cover - langchain absent
    def tool(*dargs, **dkwargs):  # type: ignore
        def deco(fn):
            return fn
        if dargs and callable(dargs[0]):
            return dargs[0]
        return deco


# ---------------------------------------------------------------------------
# caps — the same shape as _db's and navigation.py's, one env idiom package-wide
# ---------------------------------------------------------------------------

HARD_MAX_SECTION = 200   # per-section ceiling before _db.HARD_MAX_ROWS applies
CHAR_CAP = int(get_default_config("codegraph.chars"))  # CODEGRAPH_CHARS, 0 = unlimited
ENV_CHARS = "CODEGRAPH_CHARS"

ENV_SIBLINGS = "CODEGRAPH_SIBLINGS_LIMIT"
ENV_SITES = "CODEGRAPH_STATE_SITES_LIMIT"
ENV_TRANSITIONS = "CODEGRAPH_TRANSITIONS_LIMIT"
ENV_GUARDS = "CODEGRAPH_GUARD_CALLS_LIMIT"

DEFAULT_SIBLINGS = 40      # sibling routes per comparison
DEFAULT_SITES = 60         # reference sites per state carrier
DEFAULT_TRANSITIONS = 60   # transitions per status field
DEFAULT_GUARDS = 12        # guard calls reported per handler
DEFAULT_FINDINGS = 10      # candidate findings per tool call
DEFAULT_CARRIERS = 10      # state carriers / status fields per tool call
MAX_EVIDENCE = 160         # per-row evidence truncation
MAX_SPAN_TEXT = 20000      # wrapper-syntax walk is bounded, like every read here


def _env_int(key: str, default: int) -> int:
    try:
        v = os_environ(key)
        if v is None or v == "":
            return default
        return int(v)
    except (TypeError, ValueError):
        return default


def os_environ(key: str):
    """``os.environ.get`` behind one seam, so a test could stub it if needed."""
    import os
    return os.environ.get(key)


def _cap_rows(limit, env_key: str, default: int) -> int:
    """Explicit arg wins, then env, ``<=0`` means unlimited, hard-clamped.

    Mirrors ``_db._resolve_rows`` (private to the foundation module on purpose)
    so authz.py does not reach into it; the clamp is still
    :data:`_db.HARD_MAX_ROWS`, the one ceiling the whole package shares.
    """
    if limit is None:
        n = _env_int(env_key, default)
    else:
        try:
            n = int(limit)
        except (TypeError, ValueError):
            n = default
    if n <= 0:
        return _db.HARD_MAX_ROWS
    return min(n, _db.HARD_MAX_ROWS)


def _section_cap(env_key: str, default: int) -> int:
    """A per-section cap that never outgrows the row ceiling."""
    return min(_env_int(env_key, default), HARD_MAX_SECTION)


def _cap_chars(text: str) -> str:
    """The overall character budget. ``CODEGRAPH_CHARS``, 0 = unlimited."""
    lim = _env_int(ENV_CHARS, CHAR_CAP)
    if lim <= 0 or len(text) <= lim:
        return text
    return text[:lim] + f"\n… +{len(text) - lim} more chars (total {len(text)})"


# ---------------------------------------------------------------------------
# source access
# ---------------------------------------------------------------------------

def _contained_file(root: str, file_path: str) -> Path | None:
    """Resolve a repo-relative ``nodes.file_path`` under ``root``.

    Returns ``None`` — never raises — when the path escapes the repo boundary,
    does not exist, is unreadable, or is above the 1 MB per-file cap the
    indexer applies (a file CodeGraph skipped has no symbols here either, so
    parsing one would invent spans the graph disagrees with).
    """
    rel = str(file_path or "").strip().replace("\\", "/")
    if not rel:
        return None
    try:
        base = _safe_path(str(root) if root is not None else ".")
        if base.is_file():
            base = base.parent  # a tool may point at one file, not a tree
    except (ValueError, OSError):
        # ValueError: the path escapes the repo / carries a NUL byte. OSError:
        # ENAMETOOLONG, ELOOP — a hostile file_path must degrade to a miss.
        return None
    try:
        candidates = [(base / rel).resolve()]
    except (ValueError, OSError):
        return None
    if rel.startswith("/"):
        # A leading slash may be the repo's own virtual path ("/app.py").
        try:
            candidates.append(_safe_path(rel))
        except (ValueError, OSError):
            pass
    for cand in candidates:
        try:
            cand.relative_to(base)  # re-check after resolving symlinks
        except ValueError:
            continue
        try:
            if not cand.is_file():
                continue
            if cand.stat().st_size > _ts.MAX_FILE_BYTES:
                continue
            cand.read_bytes()
        except (ValueError, OSError):
            # A 400-byte component or an embedded NUL raises out of
            # is_file()/stat(); an unreadable candidate is a miss, not a raise.
            continue
        return cand
    return None


def _parsed_file(root: str, file_path: str, cache: dict):
    """``(tree, source_bytes)`` for a file, parsed at most once per tool call.

    ``_ts.parse_file`` owns the parser choice and the CodeGraph 1 MB cap, so a
    file the indexer skipped stays unparsed here and every span this module
    reports agrees with the graph. ``(None, None)`` when unreadable.
    """
    key = str(file_path or "")
    if key in cache:
        return cache[key]
    entry = (None, None)
    path = _contained_file(root, key)
    if path is not None:
        parsed = _ts.parse_file(path)
        if parsed is not None:
            entry = (parsed[0], parsed[1])
    cache[key] = entry
    return entry


# ---------------------------------------------------------------------------
# tree-sitter walk helpers (same pre-order contract as _ts._walk)
# ---------------------------------------------------------------------------

def _walk(node):
    """Depth-first, parent before children."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        try:
            children = list(current.children)
        except Exception:
            continue
        stack.extend(reversed(children))


def _line_of(node) -> int:
    try:
        return int(node.start_point[0]) + 1
    except Exception:
        return 0


def _end_line_of(node) -> int:
    try:
        return int(node.end_point[0]) + 1
    except Exception:
        return 0


def _truncate_line(text: str, cap: int = MAX_EVIDENCE) -> str:
    flat = " ".join(str(text or "").split())
    if len(flat) <= cap:
        return flat
    return flat[:cap] + " …"


# ---------------------------------------------------------------------------
# graph vocabulary
# ---------------------------------------------------------------------------

# Handler kinds getRoutingManifest accepts — mirrors queries.ts:1258. Kept local
# so this module never reaches into the foundation's private table.
_HANDLER_KINDS = ("function", "method", "class", "constant", "variable",
                  "component")

# The kinds that can carry shared state: a field, a property, a module-level
# variable, a constant. CodeGraph models no table nodes, so a bare table name
# only resolves here when the index spells it as one of these.
_STATE_KINDS = ("variable", "field", "property", "constant")

# Languages spell "this binding introduces a name" many ways; the suffix rule
# catches the rest (``variable_declarator`` / ``init_declarator``) while the
# function/class exclusion keeps a nested ``def`` out of the list. Identical to
# navigation.py's set on purpose — one codebase, one reading of "assignment".
_DECLARATION_TYPES = frozenset({
    "assignment", "augmented_assignment", "named_expression",
    "assignment_expression", "augmented_assignment_expression",
    "assignment_statement", "local_variable_declaration", "field_declaration",
    "init_declarator", "short_var_declaration", "var_declaration",
    "const_declaration", "variable_declaration", "lexical_declaration",
})
_DECLARATION_SUFFIXES = ("_declaration", "_declarator")

# Conditionals only — the shape that can name a prior state. Deliberately
# narrower than navigation.py's _GUARD_TYPES (which also counts try/catch as
# control flow): a ``try:`` is not a prior-state check, and calling it one would
# mark unguarded transitions as guarded.
_CONDITIONAL_TYPES = frozenset({
    "if_statement", "elif_clause", "if_expression", "switch_statement",
    "switch_expression", "conditional_expression", "ternary_expression",
    "match_statement", "guard_statement",
})

# Depth-1 callees that read like an access-control check. The spec's pattern,
# with IGNORECASE added: without it the C#/JVM spellings (``Authorize``,
# ``RequireRole``, ``HasPermission``) all miss, because they are PascalCase.
_GUARD_NAME_RE = re.compile(
    r"^(assert|check|require|authoriz|authoris|ensure|verify|validate|guard|"
    r"policy|permission|ownership|enforce|protect|can[A-Z]|has[A-Z]|is[A-Z])",
    re.IGNORECASE)

# A decorator that is about WHO may call, not about routing or caching. Used
# only to decide high-vs-medium severity; it is a heuristic and says so.
_AUTH_DECORATOR_RE = re.compile(
    r"auth|login|logged|role|permission|tenant|admin|secure|jwt|token|session|"
    r"acl|policy|scope|owner|ownership|member|privileged|protected|api[-_]?key",
    re.IGNORECASE)

# Update-style verbs on the receiver of a state carrier: `account.save()`,
# `ledger.deduct(amount)`. Prefix-matched, so saveAsync/increment!/UpdateOne all
# land. `set` is broad and stays because the spec names it.
_WRITE_CALL_RE = re.compile(r"^(?:save|update|incr|decr|deduct|set|del|delete|"
                            r"push|append)", re.IGNORECASE)

# The wrapper vocabulary — matched against a wrapper's SYNTAX (the context
# expression of a `with`, a decorator name, a callee name), NEVER against
# prose. `update` and `begin` are deliberately absent: the word "update"
# inside a mutation is not a transaction, and counting it is what made every
# `db.execute("UPDATE …")` read as synchronised and silently suppressed the
# TOCTOU/race findings this tool exists to emit. See :func:`_has_wrapper`.
_WRAPPER_WORD_RE = re.compile(
    r"\b(?:with_lock|with_for_update|for_update|locks?|lock(?:ed|ing)?|"
    r"mutex(?:es)?|transactions?|transactional|atomic|synchroni[sz]e(?:d)?|"
    r"sessions?|unit_of_work|pessimistic)\b",
    re.IGNORECASE)

# A node type that IS the lock shape (Java's `synchronized(this) { … }`),
# which needs no context expression to qualify.
_SYNCHRONIZED_NODE_RE = re.compile(r"synchroni[sz]", re.IGNORECASE)

# `with`/`using` statement shapes across the grammars here (Python's
# `with_statement`, C#'s `using_statement`, Java's `try_with_resources…`).
_WITH_NODE_RE = re.compile(r"^(?:.*with.*|.*using.*)(?:statement|expression)$",
                           re.IGNORECASE)

# The body of a with/using statement, which is not a context expression.
_BODY_NODE_RE = re.compile(r"block|statement_list|suite|body|statements",
                           re.IGNORECASE)

# A callee that takes the row lock explicitly: `select_for_update()`,
# `with_for_update()`. Matched on the callee, never on the whole statement.
_WRAPPER_CALL_RE = re.compile(r"for[\s_]update", re.IGNORECASE)

# A string LITERAL that locks rows — the SQL spelling. A docstring or comment
# saying "use SELECT … FOR UPDATE" is prose, so only string nodes are matched.
_SELECT_FOR_UPDATE_RE = re.compile(r"\bselect\b[\s\S]{0,400}?\bfor\s+update\b",
                                   re.IGNORECASE)

# The raw-SQL write shape: a call on a db/cursor/session/connection-shaped
# receiver whose first string argument carries DML. `self.db.execute("UPDATE
# wallets SET balance = …")` writes `balance` with no assignment node behind
# it, and reading such a site as a *reader* is the false all-clear.
_DB_RECEIVER_RE = re.compile(
    r"(?:^|[.\s(\[])(?:db|database|cursor|conn|connection|session|transaction|"
    r"tx|engine)\b",
    re.IGNORECASE)

_DML_VERB_RE = re.compile(
    r"\b(?:INSERT|UPDATE|DELETE|REPLACE|UPSERT|MERGE)\b", re.IGNORECASE)

# The row-lock clause, which is NOT a mutation: `SELECT … FOR UPDATE` locks
# rows, and the UPDATE inside it must never read as a DML verb.
_FOR_UPDATE_RE = re.compile(r"\bfor\s+update\b", re.IGNORECASE)

# `SET <carrier> = …` is DML even with no verb in front of it — the shape a
# status write uses in `UPDATE orders SET status = 'cancelled'`.
_SQL_METHOD_RE = re.compile(
    r"^(?:execute|executemany|executescript|exec|raw|raw_sql|execute_sql|sql|"
    r"query)$", re.IGNORECASE)

# A WHERE clause that constrains the row by status: the SQL spelling of a
# prior-state guard, which no `if_statement` node will ever show.
_WHERE_STATUS_RE = re.compile(
    r"\bwhere\b[^\n;]{0,160}?\b(?:status|state)\b[^\n;]{0,160}", re.IGNORECASE)

# `POST /api/orders/:id` -> `/api/orders/:id`. Route names carry the method.
_METHOD_TOKEN_RE = re.compile(
    r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY|ALL|ROUTE)\s+", re.IGNORECASE)

# Edge kinds a route uses to reach its handler (framework resolver dependent:
# Spring/Rails/Laravel emit `references`, Express emits `calls`).
_ROUTE_EDGE_KINDS = ("references", "calls")

# The getCallers edge set, for the backward BFS in the transition table.
_CALLER_EDGE_KINDS = ("calls", "references", "instantiates", "navigates")

_CALLER_BFS_DEPTH = 3

_CONF_BASE = 0.45
_CONF_EVIDENCE = 0.20
_CONF_GAP = 0.10
_CONF_STRENGTH = 0.10
_CONF_NOGUARD = 0.05
_CONF_MIN = 0.30
_CONF_MAX = 0.85


def _truthy(value) -> bool:
    """A SQLite flag column (``nodes.is_async``) as a bool, never a surprise."""
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in ("1", "true", "yes", "y", "t")


def _is_declaration(node) -> bool:
    """A binding-introducing node: assignment, declaration or declarator."""
    if node.type in _ts.FUNCTION_NODE_TYPES or node.type in _ts.CLASS_NODE_TYPES:
        return False
    return node.type in _DECLARATION_TYPES or node.type.endswith(_DECLARATION_SUFFIXES)


def _mentions(text: str, keys, ignore_case: bool = False) -> bool:
    """Does ``text`` name one of ``keys`` as a whole word?

    Word boundaries matter: ``balance`` must not match ``balanceSheet``, and
    ``self.balance`` must match ``balance`` (the ``.`` is a boundary).
    """
    for key in keys:
        if not key:
            continue
        pattern = rf"(?<![\w$]){re.escape(str(key))}(?![\w$])"
        if re.search(pattern, str(text or ""),
                     re.IGNORECASE if ignore_case else 0):
            return True
    return False


def _assign_target(node, src: bytes) -> str:
    """The left-hand side of an assignment-ish node, whatever the grammar calls it."""
    for field in ("left", "name", "pattern", "target"):
        child = node.child_by_field_name(field)
        if child is not None:
            return _ts.node_text(child, src)
    text = _ts.node_text(node, src)
    return text.split("=", 1)[0] if "=" in text else ""


def _assign_value(node, src: bytes) -> str:
    """The right-hand side of an assignment-ish node."""
    for field in ("right", "value"):
        child = node.child_by_field_name(field)
        if child is not None:
            return _ts.node_text(child, src)
    text = _ts.node_text(node, src)
    return text.split("=", 1)[1] if "=" in text else ""


def _callee_tail(text: str) -> str:
    """``db.run_query`` -> ``run_query`` — the segment a name match uses."""
    tail = str(text or "").strip()
    if "(" in tail:
        tail = tail.split("(", 1)[0].strip()
    tail = tail.rsplit(".", 1)[-1]
    return tail.lstrip("?!").strip()


def _guard_condition(node, src: bytes) -> str:
    """The conditional's test, not its body."""
    for field in ("condition", "value", "subject"):
        child = node.child_by_field_name(field)
        if child is not None:
            return _truncate_line(_ts.node_text(child, src), 200)
    text = _ts.node_text(node, src)
    return _truncate_line(text.splitlines()[0] if text else "")


def _normalise_decorator(text) -> str:
    """``@PreAuthorize("hasRole('ADMIN')")`` -> ``@PreAuthorize``.

    Argument lists, trailing punctuation and a missing ``@`` are all folded, so
    a Python ``@login_required``, a C# ``[Authorize]`` and a Java
    ``@RequireRole("admin")`` compare as the same bare name.
    """
    flat = " ".join(str(text or "").split())
    if not flat:
        return ""
    flat = flat.split("(", 1)[0].strip()
    flat = flat.rstrip(":;,.").strip()
    if not flat:
        return ""
    if not flat.startswith("@"):
        flat = "@" + flat
    return flat


def _confidence(base: float, *bonuses: float) -> float:
    """Bounded, documented confidence: a heuristic never claims certainty."""
    return round(max(_CONF_MIN, min(_CONF_MAX, base + sum(bonuses))), 2)


def _site(file_path, line) -> str:
    return f"{file_path}:{line}"


def _node_label(node: dict, with_span: bool = True) -> str:
    """``file:line (kind name)`` — the one-line citation every row shares."""
    if not node:
        return "(unknown node)"
    file_path = str(node.get("file_path") or "")
    name = str(node.get("name") or "")
    kind = str(node.get("kind") or "node")
    try:
        start = int(node.get("start_line") or 0)
    except (TypeError, ValueError):
        start = 0
    if with_span:
        try:
            end = int(node.get("end_line") or start)
        except (TypeError, ValueError):
            end = start
        span = f"{start}-{end}" if end and end != start else str(start)
        return f"{_site(file_path, start)} ({kind} {name}, {span})"
    return f"{_site(file_path, start)} ({kind} {name})"


def _node_span(node) -> tuple[int, int]:
    """``(start_line, end_line)`` of a node dict — the span a finding cites."""
    try:
        start = int(node.get("start_line") or 0)
    except (TypeError, ValueError, AttributeError):
        return (0, 0)
    if not start:
        return (0, 0)
    try:
        end = int(node.get("end_line") or start)
    except (TypeError, ValueError):
        end = start
    return (start, end if end >= start else start)


def _is_low_value(file_path: str, conn) -> bool:
    """The routing manifest's hygiene filter, applied to the sibling population.

    A handler in a generated file (``api_pb2.py``) or a test file is not a
    sibling whose decorators say anything about production policy, and
    ``getRoutingManifest`` drops exactly those rows.
    """
    path = str(file_path or "")
    if not path:
        return False
    if _db.is_test_file(path):
        return True
    return _db.is_generated_file(conn, path)


def _handler_for_route(conn, route_id: str) -> dict | None:
    """The route's handler: outgoing ``references``/``calls`` to a handler kind.

    Mirrors ``getRoutingManifest``'s join (queries.ts:1258) so this tool and the
    manifest can never disagree about which symbol serves a URL.
    """
    if conn is None:
        return None
    for kind in _ROUTE_EDGE_KINDS:
        for edge in _db.get_edges(conn, source=route_id, kind=kind,
                                  limit=HARD_MAX_SECTION):
            node = _db.get_node(conn, edge.get("target"))
            if node is not None and str(node.get("kind") or "") in _HANDLER_KINDS:
                return node
    return None


def _url_path(url: str) -> str:
    """``POST /api/orders/:id`` -> ``/api/orders/:id`` (the method token dropped)."""
    text = str(url or "").strip()
    stripped = _METHOD_TOKEN_RE.sub("", text, count=1).strip()
    return stripped or text


def _url_prefix(url: str) -> str:
    """The static segments before the first ``:param`` — the 'same controller' reading.

    ``/api/orders/:id``, ``/api/orders/:id/refund`` and ``/api/orders`` all
    prefix to ``api/orders``, so a route added later under the same resource
    still lands in the comparison.
    """
    path = _url_path(url).split("?", 1)[0]
    out: list[str] = []
    for segment in path.split("/"):
        if not segment:
            continue
        if segment.startswith(":") or segment.startswith("{") or segment.startswith("*"):
            break
        out.append(segment)
    return "/".join(out)


# ---------------------------------------------------------------------------
# candidate findings — the harness finding schema (hunters._normalize_finding)
# ---------------------------------------------------------------------------

def _candidate_finding(*, title: str, path: str, start_line: int, end_line: int,
                       cwe: str, severity: str, confidence: float,
                       taint_source: str, taint_sink: str, taint_path,
                       evidence: str, rationale: str = "", note: str = "") -> dict:
    """One candidate finding in the schema a hunter emits, no more, no less.

    ``_normalize_finding`` coerces id/title/status/snippet on top of these
    fields; the ones here are the ones a human reads, so every tool in this
    module fills exactly the same keys in the same order.
    """
    return {
        "title": title,
        "path": str(path or ""),
        "start_line": int(start_line or 0),
        "end_line": int(end_line or 0),
        "cwe": cwe,
        "severity": severity,
        "confidence": confidence,
        "taint": {
            "source": taint_source,
            "sink": taint_sink,
            "path": [str(p) for p in (taint_path or [])][:20],
        },
        "evidence": _truncate_line(evidence, 400),
        "rationale": _truncate_line(rationale, 400),
        "note": note,
    }


def _finding_lines(finding: dict, header: str) -> list[str]:
    """``## candidate finding …`` plus the JSON block, ready to append."""
    return [header, json.dumps(finding, indent=2, sort_keys=False)]


# ---------------------------------------------------------------------------
# 1. compare_sibling_route_security
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def compare_sibling_route_security(route_node_id: str, root: str = ".",
                                   limit: int | None = None) -> str:
    """Does this endpoint enforce what every sibling endpoint enforces?

    Builds the consensus of the routes that share this one's controller file or
    URL prefix, then reports the decorators and guard calls that consensus
    carries and the target does not. That gap is the BOLA/IDOR shape: the
    handler is ordinary in isolation, and only its siblings say a check was
    forgotten.

    Use this on a route node before claiming a missing access control, on any
    endpoint that takes an object id, and whenever a handler looks
    under-guarded. Do NOT use it as proof: a sibling consensus is a *vote*, so a
    repo where every sibling is also wrong produces no signal, and a
    deliberately public endpoint (a health check, a login) is flagged for the
    same reason. Treat the candidate finding as the first thing to verify, not
    the last word.

    Severity: ``high`` when a missing consensus decorator reads like
    authentication/authorisation (``@Authorize``, ``@RequireRole``,
    ``@login_required`` …), ``medium`` otherwise. Confidence is
    ``0.45 + 0.20`` for that auth-shaped decorator gap, ``+0.10`` for a missing
    consensus guard call, ``+0.10`` when at least three siblings agree and
    ``+0.05`` when the target has no guard-shaped call at all — clamped to
    [0.30, 0.85], because a consensus is evidence, never a verdict. When the
    target DOES carry a guard-shaped call (or a callee an analyst labelled
    ``AUTH_GUARD``) the gap is a NAME mismatch, not a proven omission, so the
    finding is downgraded to an informational note (severity ``info``,
    confidence 0.30) that says which names could not be compared.

    Args:
        route_node_id: The route node id (a routing manifest ``route_id``), e.g.
            ``"controllers.py:DELETE /api/orders/<id>"``.
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Max sibling routes compared. 0 = unlimited.

    Returns:
        A bounded report: the target's url/handler/decorators/guard calls, the
        sibling consensus with majority rule, what is missing on the target, a
        compact per-sibling table, and a candidate finding block (CWE-639, with
        a CWE-284 note) when an auth-shaped gap exists.
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return _cap_chars(_db.guidance_no_db(root))

    route = _db.get_node(conn, route_node_id)
    if route is None:
        return _cap_chars(f"ERROR: node not found: {route_node_id}")
    if str(route.get("kind") or "") != "route":
        return _cap_chars(
            f"ERROR: node {route_node_id} is kind "
            f"{route.get('kind')!r}, not 'route' — pass the route node id "
            f"(a routing manifest route_id), not its handler")

    handler = _handler_for_route(conn, route_node_id)
    url = str(route.get("name") or "")
    route_file = str(route.get("file_path") or "")
    target = _route_security(conn, handler, route)
    target["url"] = url

    sibling_cap = _cap_rows(limit, ENV_SIBLINGS, DEFAULT_SIBLINGS)
    guard_cap = _section_cap(ENV_GUARDS, DEFAULT_GUARDS)
    handler_file = str((handler or {}).get("file_path") or "") or route_file
    prefix = _url_prefix(url)

    found = _sibling_routes(conn, route_node_id, handler_file, prefix)
    siblings = found[:sibling_cap]
    profiles = []
    for sib, sib_handler in siblings:
        profile = _route_security(conn, sib_handler, sib)
        profile["url"] = str(sib.get("name") or "")
        profiles.append((profile, sib, sib_handler))

    out: list[str] = [
        f"# route security consensus: {url or route_node_id}",
        f"target: route {_node_label(route)}"
        + (f" -> handler {_node_label(handler)}" if handler else ""),
        f"url: {url or '(unnamed route)'}",
        f"handler: {_node_label(handler) if handler else '(no handler resolvable)'}",
        "decorators: " + (", ".join(target["decorators"]) or "(none)"),
        "guard_calls: " + (_guard_summary(target["guard_calls"], guard_cap) or "(none)"),
    ]
    hint = summaries.cache_hint(conn, route_node_id)
    if hint:
        out.append("cached summary: " + hint)

    if handler is None:
        out.append("")
        out.append("no handler resolvable: no outgoing references/calls edge from "
                   "the route node to a node of kind "
                   f"{'|'.join(_HANDLER_KINDS)}")
        out.append("hint: compare a route whose handler the index did resolve — "
                   "check the routing manifest first (codegraph_explore) or "
                   "resolve_blind_spot on the route node")
        return _cap_chars("\n".join(out))

    if not profiles:
        out.append("")
        out.append(f"sibling_count: 0 — no route shares the handler file "
                   f"({handler_file}) or the URL prefix ({prefix or '(none)'})")
        out.append("nothing is compared and no candidate finding is emitted: a "
                   "consensus needs at least one sibling")
        out.append("hint: a lone endpoint is either the only one of its kind "
                   "(nothing to compare) or the index missed the controller "
                   "(its references may sit in unresolved_refs)")
        return _cap_chars("\n".join(out))

    common_decorators = _consensus(p["decorators"] for p, _s, _h in profiles)
    common_guards = _consensus([g["name"] for g in p["guard_calls"]]
                               for p, _s, _h in profiles)
    missing_decorators = [d for d in common_decorators if d not in target["decorators"]]
    missing_guards = [g for g in common_guards
                      if g not in {x["name"] for x in target["guard_calls"]}]

    out.append("")
    out.append(f"## sibling consensus ({len(profiles)} sibling(s), majority rule: "
               f"held by more than half)")
    out.append(f"sibling_count: {len(profiles)}"
               + (f" (+{len(found) - len(siblings)} more routes found, capped at "
                  f"{sibling_cap})" if len(found) > len(siblings) else ""))
    out.append("common_decorators: "
               + (", ".join(f"{d} ({_count_holders(d, profiles, 'decorators')}/"
                            f"{len(profiles)})" for d in common_decorators) or "(none)"))
    out.append("common_guard_calls: "
               + (", ".join(f"{g} ({_count_holders(g, profiles, 'guards')}/"
                            f"{len(profiles)})" for g in common_guards) or "(none)"))
    out.append("missing_on_target: decorators "
               + (", ".join(missing_decorators) or "(none)")
               + "; guard_calls " + (", ".join(missing_guards) or "(none)"))

    out.append("")
    out.append(f"## siblings ({len(profiles)} of {len(found)})")
    for index, (profile, sib, sib_handler) in enumerate(profiles, start=1):
        out.append(f"{index}. {profile['url']}  route {_node_label(sib, with_span=False)}"
                   + (f"  ->  {_node_label(sib_handler)}" if sib_handler
                      else "  ->  (no handler resolvable)"))
        out.append("   decorators: " + (", ".join(profile["decorators"]) or "(none)"))
        out.append("   guard_calls: "
                   + (_guard_summary(profile["guard_calls"], guard_cap) or "(none)"))

    if missing_decorators or missing_guards:
        finding, header = _consensus_finding(
            target, profiles, missing_decorators, missing_guards)
        out.append("")
        out.extend(_finding_lines(finding, header))
        if finding["severity"] == "info":
            # The finding is a name mismatch, not a proven gap: say so in the
            # report body too, where an analyst reads first.
            out.append("")
            out.append("note: " + finding["note"])
    else:
        out.append("")
        out.append("no candidate finding: every consensus item is present on the "
                   "target route")
    return _cap_chars("\n".join(out))


def _route_security(conn, handler: dict | None, route: dict | None = None) -> dict:
    """Decorators + guard calls for one handler (the consensus's unit of vote).

    Decorators come from both places CodeGraph records them: the handler's own
    ``nodes.decorators`` JSON and the route node's, normalised to bare names so
    a Python ``@login_required`` and a C# ``[Authorize]`` compare as equals.
    """
    decorators: list[str] = []
    guards: list[dict] = []
    seen_dec: set[str] = set()
    for source in (handler, route):
        if not source:
            continue
        raw = source.get("decorators") or []
        if not isinstance(raw, (list, tuple)):
            continue
        for item in raw:
            name = _normalise_decorator(item)
            if name and name not in seen_dec:
                seen_dec.add(name)
                decorators.append(name)
    if handler is not None:
        guards = _guard_calls(conn, str(handler.get("id") or ""))
    return {"decorators": decorators, "guard_calls": guards, "handler": handler}


def _guard_calls(conn, handler_id: str) -> list[dict]:
    """Depth-1 callees that read like an access-control check.

    Two independent signals: a guard-shaped callee NAME, and a cached
    ``AUTH_GUARD`` summary recorded by an analyst against the callee node. The
    summary probe is the expensive one (it opens the sidecar), so it only runs
    for callees the name pattern did not already settle.
    """
    if conn is None or not handler_id:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for kind in ("calls", "references"):
        for edge in _db.get_edges(conn, source=handler_id, kind=kind,
                                  limit=HARD_MAX_SECTION):
            target = _db.get_node(conn, edge.get("target"))
            if target is None:
                continue
            target_id = str(target.get("id") or "")
            if not target_id or target_id in seen:
                continue
            name = str(target.get("name") or "")
            named = bool(_GUARD_NAME_RE.match(name))
            hint = ""
            if not named:
                hint = summaries.cache_hint(conn, target_id)
                if "AUTH_GUARD" not in hint:
                    continue
            seen.add(target_id)
            out.append({
                "name": name,
                "node_id": target_id,
                "reason": "guard-shaped name" if named else "cached AUTH_GUARD summary",
                "hint": hint,
                "site": _site(target.get("file_path"), target.get("start_line")),
                "edge_line": edge.get("line"),
            })
    out.sort(key=lambda g: (g["edge_line"] or 0, g["name"]))
    return out


def _sibling_routes(conn, route_id: str, handler_file: str, prefix: str):
    """(route, handler) pairs sharing the controller file or the URL prefix.

    Same-file first (a controller is the strongest sibling signal), then
    prefix-only siblings; the target itself and low-value handler files are
    excluded, and the same route can only appear once even when both rules
    match it.
    """
    same_file: list[tuple] = []
    same_prefix: list[tuple] = []
    seen = {route_id}
    for row in _db.find_nodes(conn, kind="route", limit=0):
        row_id = str(row.get("id") or "")
        if not row_id or row_id in seen:
            continue
        handler = _handler_for_route(conn, row_id)
        row_file = str(row.get("file_path") or "")
        sib_handler_file = str((handler or {}).get("file_path") or "") or row_file
        if handler is not None and _is_low_value(sib_handler_file, conn):
            continue
        if handler_file and sib_handler_file == handler_file:
            seen.add(row_id)
            same_file.append((row, handler))
        elif prefix and _url_prefix(row.get("name")) == prefix:
            seen.add(row_id)
            same_prefix.append((row, handler))
    return same_file + same_prefix


def _consensus(value_lists) -> list[str]:
    """Items held by a strict majority of the sibling population."""
    counts: dict[str, int] = {}
    total = 0
    for values in value_lists:
        total += 1
        for value in set(values):
            counts[value] = counts.get(value, 0) + 1
    if not total:
        return []
    return sorted(name for name, count in counts.items() if count * 2 > total)


def _count_holders(item: str, profiles, field: str) -> int:
    holders = 0
    for profile, _sib, _handler in profiles:
        values = (profile["decorators"] if field == "decorators"
                  else [g["name"] for g in profile["guard_calls"]])
        if item in values:
            holders += 1
    return holders


def _guard_summary(guards: list[dict], cap: int) -> str:
    """``assert_tenant_owner (guard-shaped name)``, … — compact and capped."""
    shown = guards[:cap]
    parts = [f"{g['name']} ({g['reason']})" for g in shown]
    extra = len(guards) - len(shown)
    if extra > 0:
        parts.append(f"… +{extra} more")
    return ", ".join(parts)


def _consensus_finding(target: dict, profiles, missing_decorators,
                       missing_guards) -> tuple[dict, str]:
    """The candidate finding for a consensus gap, with the severity heuristic.

    A target that carries ANY guard-shaped guard call (or a callee an analyst
    labelled ``AUTH_GUARD``) is not omitting a check: the set difference is
    then a NAME mismatch, and name-based matching cannot prove that
    ``assert_tenant_owner`` and ``check_permission`` differ — or that they
    agree. Emitting the "this handler omits" wording, or escalating severity
    off a cached summary, for that shape is what the audit found, so the gap is
    reported honestly instead: an informational finding at the lowest
    documented confidence, with the set-difference data kept as evidence.
    """
    handler = target["handler"] or {}
    auth_gap = [d for d in missing_decorators if _AUTH_DECORATOR_RE.search(d)]
    target_guards = [g["name"] for g in target["guard_calls"]]
    if target_guards:
        return _consensus_name_mismatch(target, profiles, missing_decorators,
                                        missing_guards, target_guards)
    # No guard-shaped call on the target at all, so the gap is real evidence of
    # a missing check — and guard_hint cannot be set here (it is drawn from
    # target["guard_calls"]), so it can never escalate this severity.
    severity = "high" if auth_gap else "medium"
    confidence = _confidence(
        _CONF_BASE,
        _CONF_EVIDENCE if auth_gap else 0.0,
        _CONF_GAP if missing_guards else 0.0,
        _CONF_STRENGTH if len(profiles) >= 3 else 0.0,
        _CONF_NOGUARD if not target["guard_calls"] else 0.0,
    )
    taint_path = [f"{p['url']} @ {_node_label(p['handler'] or h, with_span=False)}"
                  for p, _s, h in profiles[:5]]
    taint_path.append(f"{target['url']} @ "
                      f"{_node_label(handler, with_span=False)}")
    evidence = (f"target {target['url']} handler "
                f"{_node_label(handler, with_span=False)} carries "
                f"{', '.join(target['decorators']) or 'no decorators'} and "
                f"{', '.join(target_guards) or 'no guard calls'}"
                f"; {len(profiles)} sibling route(s) carry "
                f"{', '.join(missing_decorators) or 'no extra decorators'}"
                + (f" and {', '.join(missing_guards)}" if missing_guards else ""))
    finding = _candidate_finding(
        title=(f"missing function-level access control on {target['url']} "
               f"(siblings enforce {', '.join(missing_decorators or missing_guards)})"),
        path=str(handler.get("file_path") or ""),
        start_line=int(handler.get("start_line") or 0),
        end_line=int(handler.get("end_line") or 0),
        cwe="CWE-639",
        severity=severity,
        confidence=confidence,
        taint_source="sibling consensus: " + ", ".join(
            missing_decorators + missing_guards),
        taint_sink=f"{target['url']} handler {handler.get('name') or '?'}",
        taint_path=taint_path,
        evidence=evidence,
        rationale=(f"{len(profiles)} sibling route(s) in the same controller file "
                   f"or URL prefix enforce the check this handler omits; an "
                   f"authorised user of one endpoint reaches another's objects"),
        note=("CWE-284 (Improper Access Control) is the parent class; CWE-639 "
              "(Authorization Bypass Through User-Controlled Key) is the "
              "specific weakness this consensus gap indicates"),
    )
    header = (f"## candidate finding (CWE-639, severity {severity}, "
              f"confidence {confidence})")
    return finding, header


def _consensus_name_mismatch(target: dict, profiles, missing_decorators,
                             missing_guards, target_guards) -> tuple[dict, str]:
    """The honest shape of a consensus gap on a target that already has guards.

    The set difference stays (it is informative: the consensus spells the check
    one way and the target another), but the claim is downgraded to a note —
    severity ``info`` at the lowest documented confidence — because a name that
    differs from the consensus does not prove a missing access control.
    """
    handler = target["handler"] or {}
    missing = missing_decorators + missing_guards
    confidence = _CONF_MIN  # informational: name matching proves nothing here
    taint_path = [f"{p['url']} @ {_node_label(p['handler'] or h, with_span=False)}"
                  for p, _s, h in profiles[:5]]
    taint_path.append(f"{target['url']} @ "
                      f"{_node_label(handler, with_span=False)}")
    evidence = (f"target {target['url']} handler "
                f"{_node_label(handler, with_span=False)} carries "
                f"{', '.join(target['decorators']) or 'no decorators'} and "
                f"{', '.join(target_guards)}"
                f"; {len(profiles)} sibling route(s) carry "
                f"{', '.join(missing) or 'no extra items'}")
    finding = _candidate_finding(
        title=(f"consensus check not matched by name on {target['url']}: target "
               f"enforces {', '.join(target_guards)} "
               f"(siblings: {', '.join(missing) or 'none'})"),
        path=str(handler.get("file_path") or ""),
        start_line=int(handler.get("start_line") or 0),
        end_line=int(handler.get("end_line") or 0),
        cwe="CWE-639",
        severity="info",
        confidence=confidence,
        taint_source="sibling consensus (name mismatch): " + ", ".join(missing),
        taint_sink=f"{target['url']} handler {handler.get('name') or '?'}",
        taint_path=taint_path,
        evidence=evidence,
        rationale=(f"target enforces {', '.join(target_guards)}, so the access "
                   f"check is not verifiably absent; consensus item(s) "
                   f"{', '.join(missing) or 'none'} are not matched by name — "
                   f"name-based matching cannot prove equivalence"),
        note=(f"target enforces {', '.join(target_guards)}; consensus check "
              f"{', '.join(missing_guards or missing_decorators) or 'none'} not "
              f"matched by name — name-based matching cannot prove equivalence. "
              f"CWE-284 (Improper Access Control) is the parent class; CWE-639 "
              f"(Authorization Bypass Through User-Controlled Key) is the "
              f"specific weakness a real consensus gap would indicate"),
    )
    header = (f"## candidate finding (CWE-639, severity info, confidence "
              f"{confidence}) — name mismatch, not a proven gap")
    return finding, header


# ---------------------------------------------------------------------------
# 2. find_shared_state_readers_writers
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def find_shared_state_readers_writers(state_symbol_or_table: str, root: str = ".",
                                      limit: int | None = None) -> str:
    """Who reads and who writes this shared state, and is any of it unguarded?

    Resolves the state carrier (a field, property, variable or constant —
    CodeGraph models no table nodes), then classifies every ``references`` site
    as a reader or a writer by parsing the statement that touches it, and checks
    each enclosing function for a transaction/lock wrapper. Two shapes get
    flagged: a read-then-write across an ``await`` inside one unsynchronised
    function (CWE-367, TOCTOU / double-spend) and a read in one function and a
    write in another with no wrapper on either (CWE-362, race).

    Use this on balance/quota/nonce/ownership state before reasoning about a
    double-spend, and on any field two functions touch. Do NOT use it as proof:
    a wrapper is detected by a bounded SYNTAX scan — a ``with`` on a
    lock/transaction/session-shaped expression, a lock-shaped decorator,
    ``select_for_update()``, a ``SELECT … FOR UPDATE`` string LITERAL — so an
    unusual spelling can hide, prose is never mistaken for a lock, and two
    functions that never actually run concurrently still produce a CWE-362
    candidate. A raw-SQL mutation (``self.db.execute("UPDATE wallets SET
    balance = …")``) is classified a writer of the carrier it names, and one
    whose target cannot be attributed to this carrier is reported
    unclassified rather than silently as a reader. Severity is ``high`` for the
    TOCTOU pair (an ``await`` between the check and the mutation is what an
    attacker needs) and ``medium`` for the
    cross-function race. Confidence is ``0.45 + 0.20`` for an ``await`` between
    the two lines + ``0.10`` because neither site carries a wrapper for the
    TOCTOU pair, and ``0.40 + 0.10`` (no wrapper on either side) for the race,
    plus ``0.05`` when the carrier has two or more writer functions — clamped to
    [0.30, 0.85].

    Args:
        state_symbol_or_table: The state carrier. A bare name (``balance``), a
            dotted ``Class.field`` (``Account.balance``) or ``user.balance``,
            or a table name (which resolves only when the index spells it as a
            constant/variable/field).
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Max reference sites reported per state carrier. 0 = unlimited.

    Returns:
        A bounded report: the resolved carriers, every reference site with
        file:line, reader/writer/unclassified, enclosing function and wrapper
        status, then one candidate finding block per racy pair (CWE-367 or
        CWE-362) with taint source "state check" and sink "state mutation".
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return _cap_chars(_db.guidance_no_db(root))

    symbol = str(state_symbol_or_table or "").strip()
    if not symbol:
        return _cap_chars(
            "ERROR: state_symbol_or_table is required (e.g. 'balance', 'Account.balance')")

    carriers, head = _state_carriers(conn, symbol)
    if not carriers:
        return _cap_chars(_no_carrier_message(symbol))

    site_cap = _cap_rows(limit, ENV_SITES, DEFAULT_SITES)
    finding_cap = _section_cap("CODEGRAPH_STATE_FINDINGS", DEFAULT_FINDINGS)
    cache: dict[str, tuple] = {}
    out: list[str] = [f"# shared state readers/writers: {symbol}"]

    all_sites: list[dict] = []
    for carrier in carriers:
        sites = _state_sites(conn, root, carrier, head, site_cap, cache)
        all_sites.extend(sites)
        out.append("")
        out.append(f"## carrier {_node_label(carrier)}  [node {carrier.get('id')}]")
        parent = _db.node_parent(conn, str(carrier.get("id") or ""))
        if parent:
            out.append(f"   owner: {_node_label(parent)}")
        hint = summaries.cache_hint(conn, str(carrier.get("id") or ""))
        if hint:
            out.append("   cached summary: " + hint)
        readers = [s for s in sites if s["access"] == "reader"]
        writers = [s for s in sites if s["access"] == "writer"]
        unclassified = [s for s in sites
                        if s["access"] not in ("reader", "writer")]
        out.append(f"   reference sites: {len(sites)} "
                   f"({len(readers)} reader, {len(writers)} writer"
                   + (f", {len(unclassified)} unclassified" if unclassified else "")
                   + ")")
        for site in sites:
            out.append(_site_row(site))

    pairs = _racy_pairs(all_sites)
    out.append("")
    out.append(f"## racy pairs ({len(pairs)})")
    if not pairs:
        out.append("none: every read/write pair is either inside one "
                   "non-async function, separated by no await, or covered by a "
                   "transaction/lock wrapper")
    for index, pair in enumerate(pairs[:finding_cap], start=1):
        out.append(f"{index}. {pair['kind']} (CWE-{pair['cwe']}) — "
                   f"{pair['evidence']}")
        out.extend(_finding_lines(pair["finding"],
                                  f"   candidate finding (CWE-{pair['cwe']}, "
                                  f"severity {pair['finding']['severity']}, "
                                  f"confidence {pair['finding']['confidence']}):"))
    if len(pairs) > finding_cap:
        out.append(f"… +{len(pairs) - finding_cap} more racy pairs (total "
                   f"{len(pairs)}); re-run with a narrower state symbol or a "
                   f"higher limit")
    return _cap_chars("\n".join(out))


def _no_carrier_message(symbol: str) -> str:
    """The guidance string when no state carrier resolves.

    The symbol is echoed twice in the original shape, so an agent-supplied
    200 KB one produced a 400 KB answer; the echo is bounded here and the
    message itself is capped by the caller.
    """
    shown = _truncate_line(symbol, 200) or "(empty)"
    return "\n".join([
        f"# no state carrier for {shown!r}",
        f"no node named (or matching) {shown!r} of kind "
        f"{'|'.join(_STATE_KINDS)} — CodeGraph models no table nodes, so a bare "
        f"table name only resolves when the index spells it as a constant, "
        f"variable, field or property",
        "hint: pass the FIELD or VARIABLE that carries the state, e.g. "
        "'Account.balance', 'user.balance', 'ledger.nonce'",
    ])


def _state_carriers(conn, symbol: str) -> tuple[list[dict], str]:
    """Nodes that carry the state, plus the head of a dotted symbol.

    Exact name in the state kinds first, then the dotted
    ``Class.field`` / ``user.balance`` tail matching (a node whose parent is
    named like the head wins outright). ``head`` comes back so a statement that
    writes through the owner (``user.save()`` for ``user.balance``) can still be
    read as a write.
    """
    cap = _section_cap("CODEGRAPH_STATE_CARRIERS", DEFAULT_CARRIERS)
    head, _, tail = symbol.rpartition(".")
    wanted = tail if tail else symbol
    carriers: list[dict] = []
    seen: set[str] = set()

    def add(nodes) -> None:
        for node in nodes:
            if str(node.get("kind") or "") not in _STATE_KINDS:
                continue
            node_id = str(node.get("id") or "")
            if not node_id or node_id in seen:
                continue
            seen.add(node_id)
            carriers.append(node)

    add(_db.find_nodes(conn, name=wanted, limit=cap))
    if not carriers:
        add(_db.find_nodes(conn, name_like=f"%{wanted}%", limit=cap))
    if head and len(carriers) > 1:
        owned = [c for c in carriers
                 if _parent_name(conn, str(c.get("id") or "")).lower() == head.lower()]
        if owned:
            carriers = owned
    return carriers[:cap], head


def _parent_name(conn, node_id: str) -> str:
    parent = _db.node_parent(conn, node_id)
    return str((parent or {}).get("name") or "")


def _state_sites(conn, root: str, carrier: dict, head: str, cap: int,
                 cache: dict) -> list[dict]:
    """Every ``references`` site of the carrier, classified reader/writer."""
    keys = _carrier_keys(carrier)
    if head and head not in keys:
        keys = keys + [head]
    carrier_id = str(carrier.get("id") or "")
    edges = _db.incoming_edges(conn, carrier_id, kinds=["references"], limit=0)
    sites: list[dict] = []
    for edge in edges:
        source = _db.get_node(conn, edge.get("source"))
        if source is None:
            continue
        try:
            line = int(edge.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        if not line:
            continue
        file_path = str(source.get("file_path") or "")
        tree, src = _parsed_file(root, file_path, cache)
        site = {
            "file": file_path,
            "line": line,
            "function": str(source.get("name") or ""),
            "function_id": str(source.get("id") or ""),
            "function_kind": str(source.get("kind") or ""),
            "carrier_id": carrier_id,
            "access": "reader",
            "evidence": "",
            "wrapper": False,
            "is_async": _truthy(source.get("is_async")),
            "await_lines": set(),
            "span": (line, line),
            "reason": "no assignment or update-style call names the state here",
        }
        if tree is None:
            # The graph still says WHERE the access is; only the reader/writer
            # split needs the source, so the site is kept and labelled honestly.
            site["reason"] = ("source not parseable — reader/writer undecided "
                              "(classified by graph metadata only)")
            sites.append(site)
            if len(sites) >= cap:
                break
            continue
        _classify_site(tree, src, site, keys, source.get("decorators"))
        sites.append(site)
        if len(sites) >= cap:
            break
    sites.sort(key=lambda s: (s["file"], s["line"]))
    return sites


def _carrier_keys(carrier: dict) -> list[str]:
    """The names a statement may use for this carrier: name, tail and owner."""
    keys: list[str] = []
    for raw in (carrier.get("name"), carrier.get("qualified_name")):
        text = str(raw or "").strip()
        if not text:
            continue
        if text not in keys:
            keys.append(text)
        tail = text.rsplit(".", 1)[-1]
        if tail and tail not in keys:
            keys.append(tail)
    return keys


def _classify_site(tree, src: bytes, site: dict, keys, decorators=None) -> None:
    """Reader or writer? Parse the enclosing function, then the statement."""
    fn = _ts.enclosing_function(tree, site["line"])
    if fn is None:
        fn = _ts.enclosing_node(tree, site["line"])
    start, end = _line_of(fn), _end_line_of(fn)
    if not start or not end or end < start:
        start, end = site["line"], site["line"]
    site["span"] = (start, end)
    if fn is not None:
        site["is_async"] = site["is_async"] or _ts_node_is_async(fn, src)
        site["await_lines"] = _await_lines(tree, start, end)
        site["wrapper"] = _has_wrapper(fn, src, decorators)

    statement = _enclosing_declaration(tree, site["line"], start, end)
    if statement is not None:
        stmt_start, stmt_end = _line_of(statement), _end_line_of(statement)
    else:
        stmt_start = stmt_end = site["line"]
    if statement is not None:
        target = _assign_target(statement, src)
        if _mentions(target, keys):
            site["access"] = "writer"
            site["reason"] = f"assignment to {_truncate_line(target, 60)}"
            site["evidence"] = _truncate_line(_ts.node_text(statement, src))
            return
    calls = _ts.calls_in_span(tree, stmt_start, stmt_end, src)
    for call in calls:
        tail = _callee_tail(call["text"])
        if not _WRITE_CALL_RE.match(tail):
            continue
        # The whole call, not just the callee: `ledger.save(self.total + amount)`
        # writes `total` even though the callee itself is only `save`.
        whole = _ts.node_text(call["node"], src)
        if not _mentions(whole, keys):
            continue
        site["access"] = "writer"
        site["reason"] = f"update-style call {_truncate_line(tail, 40)}"
        site["evidence"] = _truncate_line(whole)
        return
    # A raw-SQL mutation: `self.db.execute("UPDATE wallets SET balance = …")`
    # writes the carrier with no assignment and no update-style call behind
    # it. Calling that a reader is the false all-clear, so it is classified
    # here — and a DML statement whose target cannot be attributed to this
    # carrier is reported unclassified rather than silently a reader.
    raw = _raw_sql_access(calls, keys, src)
    if raw is not None:
        access, reason, evidence = raw
        site["access"] = access
        site["reason"] = reason
        site["evidence"] = evidence
        return
    site["evidence"] = _truncate_line(
        _ts.line_text(src, site["line"]) if src else "")


def _call_receiver(callee_text: str) -> str:
    """``self.db.execute`` -> ``self.db``; a bare ``execute`` -> ``""``."""
    text = str(callee_text or "").strip()
    if "." not in text:
        return ""
    return text.rsplit(".", 1)[0]


def _first_string_argument(arguments, src: bytes) -> str:
    """The string literals in a call's FIRST argument, or ``""``.

    The first argument is not always a plain literal: ``"UPDATE … WHERE id IN
    (%s)" % ids`` and ``f"SET {field} = 1"`` build the SQL around the literal,
    so every string inside that one argument is read. A dynamic argument
    (``db.execute(sql)``) yields ``""`` on purpose: an invisible statement
    cannot be classified from its text.
    """
    if arguments is None:
        return ""
    try:
        children = list(arguments.children)
    except Exception:
        return ""
    first = None
    for child in children:
        try:
            if not bool(getattr(child, "is_named", True)):
                continue
        except Exception:
            pass
        first = child
        break
    if first is None:
        return ""
    first_type = str(getattr(first, "type", "") or "").lower()
    if "string" in first_type:
        return _ts.node_text(first, src)
    parts: list[str] = []
    for node in _walk(first):
        node_type = str(getattr(node, "type", "") or "").lower()
        if "string" in node_type:
            parts.append(_ts.node_text(node, src))
    return " ".join(part for part in parts if part)


def _dml_body(sql: str) -> str:
    """The SQL text with the row-lock clause removed.

    ``FOR UPDATE`` locks rows, it does not mutate them, so the ``UPDATE``
    inside it must not read as a DML verb.
    """
    return _FOR_UPDATE_RE.sub(" ", str(sql or ""))


def _is_dml_sql(sql: str, keys) -> bool:
    """Does this SQL text mutate? A DML verb, or ``SET <carrier>`` on its own."""
    if not sql:
        return False
    if _DML_VERB_RE.search(_dml_body(sql)):
        return True
    for key in keys:
        if not key:
            continue
        pattern = rf"\bset\s+(?:[A-Za-z_$][\w$]*\.)?{re.escape(str(key))}\b"
        if re.search(pattern, sql, re.IGNORECASE):
            return True
    return False


def _raw_sql_access(calls, keys, src: bytes):
    """``(access, reason, evidence)`` for a raw-SQL statement, or ``None``.

    A call on a db/cursor/session/connection-shaped receiver whose first string
    argument carries DML is a state mutation:

    * it names the carrier  -> ``writer`` of that carrier;
    * it does not (or the statement is not a visible literal at all) ->
      ``unclassified``: the mutation is real but its target is unknown, and
      guessing "reader" here is the false all-clear the audit found.

    Anything else (a SELECT, a call on a non-db receiver) returns ``None`` and
    keeps the ordinary reader/writer path.
    """
    for call in calls:
        if not _DB_RECEIVER_RE.search(_call_receiver(call["text"])):
            continue
        try:
            arguments = call["node"].child_by_field_name("arguments")
        except Exception:
            arguments = None
        sql = _first_string_argument(arguments, src)
        if sql and _is_dml_sql(sql, keys):
            if _mentions(sql, keys, ignore_case=True):
                return ("writer",
                        f"raw SQL DML names the carrier: "
                        f"{_truncate_line(sql, 120)}",
                        _truncate_line(sql))
            return ("unclassified",
                    "raw SQL DML does not name this carrier",
                    _truncate_line(sql))
        if not sql and _SQL_METHOD_RE.match(_callee_tail(call["text"])):
            return ("unclassified",
                    "raw SQL on a db handle with no visible statement",
                    _truncate_line(_ts.node_text(call["node"], src)))
    return None


def _enclosing_declaration(tree, line: int, start: int, end: int):
    """The innermost assignment-ish node whose span contains ``line``.

    Scoped to the enclosing function when there is one, so a same-line
    assignment inside a nested closure cannot answer for the outer one.
    """
    scope = _ts.enclosing_function(tree, line) or _ts.enclosing_node(tree, line)
    root = scope if scope is not None else tree.root_node
    best = None
    best_key = None
    for node in _walk(root):
        if not _is_declaration(node):
            continue
        n_start, n_end = _line_of(node), _end_line_of(node)
        if not n_start or n_start > line or n_end < line:
            continue
        if start and end and (n_start < start or n_end > end):
            continue
        key = (n_end - n_start, node.end_byte - node.start_byte)
        if best is None or key < best_key:
            best, best_key = node, key
    return best


def _ts_node_is_async(node, src: bytes) -> bool:
    """An ``await``/``async`` inside the span, the textual fallback for is_async."""
    text = _ts.node_text(node, src)
    return bool(re.search(r"\basync\b|\bawait\b", text or ""))


def _await_lines(tree, start: int, end: int) -> set:
    """Line numbers of ``await`` expressions inside a span, grammar-agnostic."""
    lines: set = set()
    for node in _walk(tree.root_node):
        node_type = str(getattr(node, "type", "") or "").lower()
        if "await" not in node_type:
            continue
        line = _line_of(node)
        if start <= line <= end:
            lines.add(line)
    return lines


def _wrapper_scope(fn):
    """Where the wrapper scan starts: the function, plus its decorators.

    Python keeps decorators OUTSIDE the ``function_definition`` node (they sit
    on the wrapping ``decorated_definition``), so the scan has to start one
    level up to see them — or fall back on the index's decorator list.
    """
    scope = fn
    try:
        parent = getattr(fn, "parent", None)
    except Exception:
        parent = None
    if parent is not None:
        if "decorat" in str(getattr(parent, "type", "") or ""):
            scope = parent
    return scope


def _with_context_text(node, src: bytes) -> str:
    """The context expressions of a with/using statement — not its body."""
    parts: list[str] = []
    try:
        children = list(node.children)
    except Exception:
        return ""
    for child in children:
        ctype = str(getattr(child, "type", "") or "")
        if not ctype:
            continue
        try:
            named = bool(child.is_named)
        except Exception:
            named = True
        if not named or _BODY_NODE_RE.search(ctype):
            continue  # a keyword, a colon, or the block the `with` guards
        parts.append(_ts.node_text(child, src))
    return " ".join(parts)


def _has_wrapper(node, src: bytes, decorators=None) -> bool:
    """Is this function synchronised — a lock-looking SYNTAX, not a keyword?

    Four shapes count, all read off the parse tree (or the index's decorator
    column), so a comment or a docstring can never supply one:

    * a ``with`` statement whose context expression is
      lock/transaction/session-shaped — ``with self.lock:``,
      ``with transaction.atomic():``, ``with db.session.begin():``;
    * a decorator on the function — ``@transactional``, ``@with_lock``,
      ``@Synchronized``;
    * a ``select_for_update()`` / ``with_for_update()`` call;
    * a string LITERAL holding a ``SELECT … FOR UPDATE``.

    Everything else is NOT a wrapper: the word "update" in a mutation, a
    ``# TODO: add a lock here`` comment, a docstring mentioning a lock. An
    unsynchronised function must read as unsynchronised, or the race the tool
    exists to flag is suppressed by prose. The walk is bounded like every
    other read here (:data:`MAX_SPAN_TEXT` nodes).
    """
    for raw in (decorators or ()):
        name = _normalise_decorator(raw)
        if name and _WRAPPER_WORD_RE.search(name):
            return True
    if node is None:
        return False
    budget = MAX_SPAN_TEXT
    for child in _walk(_wrapper_scope(node)):
        if budget <= 0:
            break
        budget -= 1
        node_type = str(getattr(child, "type", "") or "")
        if not node_type:
            continue
        low = node_type.lower()
        if low == "comment":
            continue  # prose is never a lock, in any grammar
        if "string" in low:
            # A literal, not prose: the SQL spelling of a row lock.
            if _SELECT_FOR_UPDATE_RE.search(_ts.node_text(child, src)):
                return True
            continue
        if "decorator" in low or "annotation" in low or low == "modifiers":
            if _WRAPPER_WORD_RE.search(_ts.node_text(child, src)):
                return True
            continue
        if _SYNCHRONIZED_NODE_RE.search(low):
            return True
        if _WITH_NODE_RE.match(low):
            context = _with_context_text(child, src)
            if context and _WRAPPER_WORD_RE.search(context):
                return True
            continue
        try:
            callee = child.child_by_field_name("function")
            if callee is None:
                callee = child.child_by_field_name("callee")
        except Exception:
            callee = None
        if callee is not None and low in _ts.CALL_NODE_TYPES:
            if _WRAPPER_CALL_RE.search(_ts.node_text(callee, src)):
                return True
    return False


def _site_row(site: dict) -> str:
    evidence = f"  — {site['evidence']}" if site["evidence"] else ""
    return (f"   {_site(site['file'], site['line'])}  {site['access']:<6} "
            f"{site['function']}({site['function_kind']})  "
            f"span {site['span'][0]}-{site['span'][1]}  "
            f"async: {'yes' if site['is_async'] else 'no'}  "
            f"wrapper: {'yes' if site['wrapper'] else 'no'}"
            f"{evidence}  [{site['reason']}]")


def _racy_pairs(sites: list[dict]) -> list[dict]:
    """The two racy shapes, each as one candidate finding.

    (a) TOCTOU: one async function reads then writes with an ``await`` between
        the two lines and no wrapper — the value can change while the function
        is suspended.
    (b) Race: a read and a write in DIFFERENT functions with no wrapper on
        either — nothing orders them.

    A wrapper on either side suppresses the flag, because that is exactly the
    mitigation; and a same-function pair with no await between is a plain
    read-modify-write, which is atomic within the function.
    """
    pairs: list[dict] = []
    seen: set[tuple] = set()
    writers = [s for s in sites if s["access"] == "writer"]
    readers = [s for s in sites if s["access"] == "reader"]
    for writer in writers:
        for reader in readers:
            # A pair is about ONE carrier: a read of `balance` and a write of
            # `status` are two different bugs, not a race on shared state.
            if writer["carrier_id"] != reader["carrier_id"]:
                continue
            if writer["file"] == reader["file"] and writer["line"] == reader["line"]:
                continue
            key = (reader["file"], reader["line"], writer["file"], writer["line"])
            if key in seen:
                continue
            same_function = reader["function_id"] == writer["function_id"]
            carrier_writers = [w for w in writers
                               if w["carrier_id"] == reader["carrier_id"]]
            multi_writer = len({w["function_id"] for w in carrier_writers}) >= 2
            if same_function:
                if reader["line"] >= writer["line"]:
                    continue  # not check-then-act
                if not (reader["is_async"] or writer["is_async"]):
                    continue
                between = {line for line in reader["await_lines"]
                           if reader["line"] < line < writer["line"]}
                if not between:
                    continue
                if reader["wrapper"] or writer["wrapper"]:
                    continue
                kind, cwe, severity = "TOCTOU", "367", "high"
                confidence = _confidence(
                    _CONF_BASE, _CONF_EVIDENCE,
                    _CONF_GAP if not (reader["wrapper"] or writer["wrapper"]) else 0.0,
                    _CONF_NOGUARD if multi_writer else 0.0)
                detail = (f"read {_site(reader['file'], reader['line'])} in "
                          f"{reader['function']}() then write "
                          f"{_site(writer['file'], writer['line'])} in the SAME "
                          f"function, with await at line "
                          f"{min(between)} between them and no transaction/lock "
                          f"wrapper")
            else:
                if reader["wrapper"] or writer["wrapper"]:
                    continue
                kind, cwe, severity = "race", "362", "medium"
                confidence = _confidence(
                    _CONF_BASE - 0.05, _CONF_GAP,
                    _CONF_NOGUARD if multi_writer else 0.0)
                detail = (f"read {_site(reader['file'], reader['line'])} in "
                          f"{reader['function']}() and write "
                          f"{_site(writer['file'], writer['line'])} in "
                          f"{writer['function']}() — different functions, no "
                          f"transaction/lock wrapper on either")
            seen.add(key)
            evidence = (f"{detail}; reader evidence: {reader['evidence']}; "
                        f"writer evidence: {writer['evidence']}")
            finding = _candidate_finding(
                title=(f"{kind} on shared state: "
                       f"{reader['file']}:{reader['line']} read, "
                       f"{writer['file']}:{writer['line']} write"),
                path=writer["file"],
                start_line=writer["span"][0],
                end_line=writer["span"][1],
                cwe=f"CWE-{cwe}",
                severity=severity,
                confidence=confidence,
                taint_source="state check",
                taint_sink="state mutation",
                taint_path=[_site(reader["file"], reader["line"]),
                            _site(writer["file"], writer["line"])],
                evidence=evidence,
                rationale=(f"{detail}. The state can be observed stale or "
                           f"mutated twice because nothing orders the two "
                           f"sites."),
                note=("CWE-367 (TOCTOU) is the same-function read-across-await "
                      "shape; CWE-362 is the concurrent read/write shape"),
            )
            pairs.append({"kind": kind, "cwe": cwe, "finding": finding,
                          "evidence": detail})
    pairs.sort(key=lambda p: (p["finding"]["path"], p["finding"]["start_line"]))
    return pairs


# ---------------------------------------------------------------------------
# 3. trace_state_machine_transitions
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def trace_state_machine_transitions(entity_name: str, status_field: str = "status",
                                    root: str = ".", limit: int | None = None) -> str:
    """Which state transitions does this entity allow, and which skip the workflow?

    Finds every assignment that SETS the status field, extracts the prior-state
    guard that precedes it (an ``if`` mentioning the entity or the field, or a
    WHERE clause constraining the row), and maps the mutating function to the
    endpoint that reaches it. A transition with no prior-state guard is a
    business-logic bypass (CWE-840): the workflow can be entered at any step.

    Use this on any status/state field of an order, payment, approval or ticket
    flow, and before claiming an endpoint is unreachable. Do NOT use it as
    proof: a guard written as a call (``self.can_ship()``) is only detected
    when the condition names the entity or the field, the WHERE-clause reading
    is a regex over the function text, and an unguarded transition is sometimes
    the legitimate first step of the flow. A raw-SQL write
    (``db.execute("UPDATE orders SET status = 'cancelled' …")``) is a transition
    too; one whose target state is not a literal is counted in an explicit
    ``skipped (N unclassified status writes)`` line instead of being dropped, so
    the table never reads as exhaustive when it is not. Severity is ``medium``
    and confidence is ``0.45 + 0.15`` when the mutation is reachable from a route
    and ``+0.10`` when the entity has two or more transitions (so one skip is a
    real fork, not the only edge) — clamped to [0.30, 0.85].

    Args:
        entity_name: Owning symbol of the status field (``Order``, ``Payment``).
        status_field: The field that carries the state (``status``, ``state``).
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Max transitions reported per status field. 0 = unlimited.

    Returns:
        A bounded report: the resolved status fields, a transition table
        (FROM_STATE -> TO_STATE, file:line, endpoint url or "(not
        route-reachable)", guard_present, evidence line), and one candidate
        finding block (CWE-840, severity medium) per unguarded transition.
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return _cap_chars(_db.guidance_no_db(root))

    entity = str(entity_name or "").strip()
    field = str(status_field or "").strip() or "status"
    if not entity:
        return _cap_chars("ERROR: entity_name is required (e.g. 'Order')")

    fields = _status_fields(conn, entity, field)
    if not fields:
        return _cap_chars("\n".join([
            f"# no status field for {_truncate_line(entity, 120)}.{_truncate_line(field, 120)}",
            f"no node named {_truncate_line(field, 120)!r} owned by "
            f"{_truncate_line(entity, 120)!r} (falling back to any "
            f"such field found none)",
            "hint: check the owning symbol's name and the field's spelling "
            "('status' vs 'orderStatus' vs 'state')",
        ]))

    route_map = _route_map(conn)
    transition_cap = _cap_rows(limit, ENV_TRANSITIONS, DEFAULT_TRANSITIONS)
    finding_cap = _section_cap("CODEGRAPH_TRANSITION_FINDINGS", DEFAULT_FINDINGS)
    cache: dict[str, tuple] = {}
    endpoints: dict[str, str] = {}
    out: list[str] = [f"# state machine: {entity}.{field}"]
    all_transitions: list[dict] = []
    all_unclassified = 0

    for carrier, parent in fields:
        transitions, skipped, unclassified = _transitions(
            conn, root, carrier, entity, field, route_map, transition_cap, cache,
            endpoints)
        all_transitions.extend(transitions)
        all_unclassified += unclassified
        out.append("")
        out.append(f"## status field {_node_label(carrier)}  [node {carrier.get('id')}]")
        if parent:
            out.append(f"   owner: {_node_label(parent)}")
        readers = len([t for t in transitions if t["guard_present"]])
        out.append(f"   transitions: {len(transitions)} ({readers} guarded, "
                   f"{len(transitions) - readers} unguarded)")
        if skipped:
            out.append(f"   note: {skipped} reference(s) skipped — the source is "
                       f"not parseable through this root, so those sites are "
                       f"absent from the table (under-approximation)")
        if unclassified:
            out.append(f"   skipped ({unclassified} unclassified status writes) "
                       f"— a raw-SQL statement names {field} but no transition "
                       f"could be read from it (a bind parameter, a DELETE), so "
                       f"those writes are absent from the table "
                       f"(under-approximation)")
        for row in transitions:
            out.append(_transition_row(row))

    unguarded = [t for t in all_transitions if not t["guard_present"]]
    out.append("")
    out.append(f"## unguarded transitions ({len(unguarded)} of "
               f"{len(all_transitions)} transitions)")
    if not unguarded:
        out.append("none: every status assignment is preceded by a prior-state "
                   "guard or a WHERE clause")
    if all_unclassified:
        # The table is not exhaustive unless this is said out loud.
        out.append(f"note: skipped ({all_unclassified} unclassified status "
                   f"writes) — raw SQL names {field} without a readable target "
                   f"state, so the table above is not exhaustive")
    strength = _CONF_STRENGTH if len(all_transitions) >= 2 else 0.0
    for index, row in enumerate(unguarded[:finding_cap], start=1):
        confidence = _confidence(_CONF_BASE,
                                 _CONF_EVIDENCE - 0.05 if row["endpoint"] else 0.0,
                                 strength)
        finding = _candidate_finding(
            title=(f"unguarded {field} transition on {entity}: "
                   f"{row['to_state']} at {row['file']}:{row['line']}"),
            path=row["file"],
            start_line=row["span"][0],
            end_line=row["span"][1],
            cwe="CWE-840",
            severity="medium",
            confidence=confidence,
            taint_source=f"current {field}",
            taint_sink=f"{field} = {row['to_state']}",
            taint_path=[row["endpoint"] or "(not route-reachable)",
                        f"{row['file']}:{row['line']}"],
            evidence=(f"{row['file']}:{row['line']} sets {field} to "
                      f"{row['to_state']!r} in {row['function']}() with no "
                      f"prior-state guard; evidence: {row['evidence']}"),
            rationale=(f"the function sets {field} without checking its current "
                       f"value, so the workflow can be entered at any step"
                       + (f" (reachable at {row['endpoint']})"
                          if row["endpoint"] != "(not route-reachable)" else
                          " (no route reaches this function in the index)")),
            note=("CWE-840 (Business Logic Errors); the missing prior-state "
                  "check is the specific bypass"),
        )
        out.append(f"{index}. {_transition_row(row)}")
        out.extend(_finding_lines(
            finding,
            f"   candidate finding (CWE-840, severity medium, "
            f"confidence {confidence}):"))
    if len(unguarded) > finding_cap:
        out.append(f"… +{len(unguarded) - finding_cap} more unguarded transitions "
                   f"(total {len(unguarded)}); re-run with a narrower entity or a "
                   f"higher limit")
    return _cap_chars("\n".join(out))


def _status_fields(conn, entity: str, field: str) -> list[tuple]:
    """(field_node, parent) for the status field, preferring the right owner.

    Exact name first; a node whose parent (``contains``) is named like the
    entity wins outright, and only when none matches do we fall back to any
    node with that name, then to a substring match (``orderStatus``).
    """
    cap = _section_cap("CODEGRAPH_STATUS_FIELDS", DEFAULT_CARRIERS)
    exact = _db.find_nodes(conn, name=field, limit=cap)
    owned: list[tuple] = []
    others: list[tuple] = []
    for node in exact:
        parent = _db.node_parent(conn, str(node.get("id") or ""))
        parent_name = str((parent or {}).get("name") or "")
        parent_qualified = str((parent or {}).get("qualified_name") or "")
        if parent_name.lower() == entity.lower() or \
                parent_qualified.rsplit(".", 1)[-1].lower() == entity.lower():
            owned.append((node, parent))
        else:
            others.append((node, parent))
    if owned:
        return owned[:cap]
    if others:
        return others[:cap]
    loose = _db.find_nodes(conn, name_like=f"%{field}%", limit=cap)
    return [(node, _db.node_parent(conn, str(node.get("id") or "")))
            for node in loose][:cap]


def _route_map(conn) -> dict:
    """Handler -> url, from the routing manifest plus an exact route->handler join.

    ``getRoutingManifest`` applies the test/generated hygiene filter and a row
    cap but does not expose the handler's node id, so the id-based join runs as
    well: a manifest row is matched by (handler_file, handler_line), and a route
    the manifest's cap dropped is still found by its own edge.
    """
    by_id: dict[str, str] = {}
    by_site: dict[tuple, str] = {}
    for row in _db.routing_manifest(conn, limit=0):
        url = str(row.get("url") or "")
        key = (str(row.get("handler_file") or ""), int(row.get("handler_line") or 0))
        by_site.setdefault(key, url)
    for route in _db.find_nodes(conn, kind="route", limit=0):
        handler = _handler_for_route(conn, str(route.get("id") or ""))
        if handler is None:
            continue
        by_id.setdefault(str(handler.get("id") or ""),
                         str(route.get("name") or ""))
    return {"by_id": by_id, "by_site": by_site}


def _endpoint_for_function(conn, node: dict, route_map: dict, cache: dict):
    """The endpoint serving this function: manifest, id join, then callers' BFS.

    The backward BFS walks incoming ``calls``/``references``/``instantiates``/
    ``navigates`` up to three hops, so a service method reached from a
    controller still resolves to the URL — and a function nobody routes to says
    so honestly instead of guessing.
    """
    node_id = str(node.get("id") or "")
    if node_id in cache:
        return cache[node_id]
    file_path = str(node.get("file_path") or "")
    try:
        start_line = int(node.get("start_line") or 0)
    except (TypeError, ValueError):
        start_line = 0
    answer = (route_map["by_id"].get(node_id)
              or route_map["by_site"].get((file_path, start_line)))
    if answer is None:
        answer = _endpoint_by_callers(conn, node_id, route_map)
    cache[node_id] = answer
    return answer


def _endpoint_by_callers(conn, node_id: str, route_map: dict):
    """Backward BFS over the getCallers edge set, depth capped at 3."""
    if not node_id:
        return None
    seen = {node_id}
    frontier = [node_id]
    for _hop in range(_CALLER_BFS_DEPTH):
        nxt: list[str] = []
        for current in frontier:
            edges = _db.incoming_edges(conn, current, kinds=_CALLER_EDGE_KINDS,
                                       limit=HARD_MAX_SECTION)
            for edge in edges:
                source = str(edge.get("source") or "")
                if not source or source in seen:
                    continue
                seen.add(source)
                caller = _db.get_node(conn, source)
                if caller is None:
                    continue
                answer = (route_map["by_id"].get(source)
                          or route_map["by_site"].get(
                              (str(caller.get("file_path") or ""),
                               int(caller.get("start_line") or 0))))
                if answer:
                    return answer
                nxt.append(source)
        frontier = nxt
        if not frontier:
            break
    return None


def _transitions(conn, root: str, carrier: dict, entity: str, field: str,
                 route_map: dict, cap: int, cache: dict,
                 endpoints: dict) -> tuple[list[dict], int, int]:
    """Every reference that SETS the status field, with its guard and endpoint.

    The second value counts ``references`` the tool could not read a statement
    for (an unparseable file) and the third counts raw-SQL status writes whose
    target state could not be read, so the caller can say the table is
    incomplete rather than presenting an exhaustive-looking answer.
    """
    keys = _carrier_keys(carrier)
    assign_keys = [k for k in keys if k.lower() != entity.lower()]
    guard_keys = list(dict.fromkeys(keys + [entity, field]))
    carrier_id = str(carrier.get("id") or "")
    rows: list[dict] = []
    skipped = 0
    unclassified = 0
    seen_raw: set[tuple] = set()
    for edge in _db.incoming_edges(conn, carrier_id, kinds=["references"], limit=0):
        source = _db.get_node(conn, edge.get("source"))
        if source is None:
            continue
        try:
            line = int(edge.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        if not line:
            continue
        file_path = str(source.get("file_path") or "")
        tree, src = _parsed_file(root, file_path, cache)
        if tree is None:
            skipped += 1
            continue
        assignment = _status_assignment(tree, src, line, assign_keys)
        if assignment is not None:
            value = _truncate_line(_assign_value(assignment, src), 80)
            to_state = _state_literal(value)
        else:
            # No `status = …` assignment on this reference. A raw-SQL write
            # (`db.execute("UPDATE orders SET status = 'cancelled' …")`) sets
            # the field too, and dropping the reference here is what let the
            # table read as exhaustive while a transition was missing.
            raw = _raw_status_write(tree, src, line, field, assign_keys)
            if raw is None:
                continue  # this reference reads the field, it does not set it
            statement, to_state = raw
            seen_key = (file_path, _line_of(statement))
            if seen_key in seen_raw:
                continue  # one statement, one row — other references saw it
            seen_raw.add(seen_key)
            if to_state is None:
                # A DML naming the field with no readable target state (a bind
                # parameter, a DELETE): counted, not silently dropped.
                unclassified += 1
                continue
            assignment = statement
        guards = _prior_guards(tree, src, line, guard_keys)
        endpoint = _endpoint_for_function(conn, source, route_map, endpoints)
        rows.append({
            "from_state": _guard_states(guards),
            "to_state": to_state,
            "file": file_path,
            "line": _line_of(assignment) or line,
            "span": _node_span(source),
            "function": str(source.get("name") or ""),
            "endpoint": endpoint or "(not route-reachable)",
            "guard_present": bool(guards),
            "guards": guards,
            "evidence": _truncate_line(_ts.node_text(assignment, src)),
        })
        if len(rows) >= cap:
            break
    rows.sort(key=lambda r: (r["file"], r["line"]))
    return rows, skipped, unclassified


def _dml_calls(tree, start: int, end: int, src: bytes, keys) -> list[dict]:
    """The raw-SQL calls in a span whose statement carries DML naming ``keys``."""
    out: list[dict] = []
    for call in _ts.calls_in_span(tree, start, end, src):
        if not _DB_RECEIVER_RE.search(_call_receiver(call["text"])):
            continue
        try:
            arguments = call["node"].child_by_field_name("arguments")
        except Exception:
            arguments = None
        sql = _first_string_argument(arguments, src)
        if not sql or not _DML_VERB_RE.search(_dml_body(sql)):
            continue
        if not _mentions(sql, keys, ignore_case=True):
            continue
        out.append(call)
    return out


def _raw_status_write(tree, src: bytes, line: int, field: str, keys):
    """The raw-SQL statement on ``line`` that SETs the status field.

    Returns ``(statement_node, to_state)`` — ``to_state`` being the quoted
    literal the SQL writes — or ``(statement_node, None)`` for a DML that names
    the field without a readable target (a bind parameter, a DELETE), or
    ``None`` when the statement is not a raw-SQL mutation at all.
    """
    scope = _ts.enclosing_function(tree, line) or _ts.enclosing_node(tree, line)
    if scope is None:
        return None
    start, end = _line_of(scope), _end_line_of(scope)
    if not start or not end:
        start = end = line
    statement = _enclosing_statement(tree, line, start, end)
    span_start, span_end = start, end
    if statement is not None:
        span_start, span_end = _line_of(statement), _end_line_of(statement)
        if not span_start:
            span_start, span_end = line, line
    candidates = _dml_calls(tree, span_start, span_end, src, keys)
    if not candidates:
        # The graph records the reference by its own line, which need not sit
        # inside the statement that writes — so the enclosing function is
        # scanned too rather than dropping the write.
        candidates = _dml_calls(tree, start, end, src, keys)
    if not candidates:
        return None
    candidates.sort(key=lambda c: (abs(c["line"] - line), c["line"]))
    call = candidates[0]
    try:
        arguments = call["node"].child_by_field_name("arguments")
    except Exception:
        arguments = None
    return (call["node"],
            _sql_status_value(_first_string_argument(arguments, src), field))


def _enclosing_statement(tree, line: int, start: int, end: int):
    """The innermost statement-ish node whose span contains ``line``."""
    scope = _ts.enclosing_function(tree, line) or _ts.enclosing_node(tree, line)
    root = scope if scope is not None else tree.root_node
    best = None
    best_key = None
    for node in _walk(root):
        node_type = str(getattr(node, "type", "") or "")
        if "statement" not in node_type and "declaration" not in node_type \
                and node_type not in _DECLARATION_TYPES:
            continue
        n_start, n_end = _line_of(node), _end_line_of(node)
        if not n_start or n_start > line or n_end < line:
            continue
        if start and end and (n_start < start or n_end > end):
            continue
        key = (n_end - n_start, node.end_byte - node.start_byte)
        if best is None or key < best_key:
            best, best_key = node, key
    return best


def _sql_status_value(sql: str, field: str) -> str | None:
    """``UPDATE orders SET status = 'cancelled' …`` -> ``cancelled``.

    ``None`` when the SQL sets the field to something no state can be named
    from (a bind parameter, a variable) — the caller counts that honestly
    rather than inventing a transition.
    """
    match = re.search(
        rf"\bset\s+(?:[A-Za-z_$][\w$]*\.)?{re.escape(str(field or ''))}\s*=\s*"
        rf"(['\"])([^'\"]{{1,80}})\1",
        str(sql or ""), re.IGNORECASE)
    if match:
        return match.group(2).strip()
    return None


def _status_assignment(tree, src: bytes, line: int, keys):
    """The assignment on ``line`` whose left side names the status field."""
    scope = _ts.enclosing_function(tree, line) or _ts.enclosing_node(tree, line)
    root = scope if scope is not None else tree.root_node
    best = None
    best_key = None
    for node in _walk(root):
        if not _is_declaration(node):
            continue
        n_start, n_end = _line_of(node), _end_line_of(node)
        if not n_start or n_start > line or n_end < line:
            continue
        target = _assign_target(node, src)
        if not _mentions(target, keys):
            continue
        key = (n_end - n_start, node.end_byte - node.start_byte)
        if best is None or key < best_key:
            best, best_key = node, key
    return best


def _prior_guards(tree, src: bytes, line: int, keys) -> list[dict]:
    """Guards that precede the assignment and name the entity or the field.

    Conditionals first (``if self.status == "pending"``), then the SQL spelling:
    a WHERE clause constraining the row by status, matched over the function
    text because no ``if_statement`` node will ever show it.
    """
    guards: list[dict] = []
    fn = _ts.enclosing_function(tree, line) or _ts.enclosing_node(tree, line)
    scope = fn if fn is not None else tree.root_node
    for node in _walk(scope):
        if node.type not in _CONDITIONAL_TYPES:
            continue
        guard_line = _line_of(node)
        if not guard_line or guard_line >= line:
            continue
        condition = _guard_condition(node, src)
        if not _mentions(condition, keys, ignore_case=True):
            continue
        guards.append({
            "line": guard_line,
            "condition": condition,
            "kind": "conditional",
            "states": _state_literals(condition),
        })
    text = _ts.node_text(scope, src)
    match = _WHERE_STATUS_RE.search(text or "")
    if match:
        where_line = text[:match.start()].count("\n") + _line_of(scope)
        if where_line < line:
            # A WHERE clause that follows the assignment constrains nothing:
            # only the ones before it read as a prior-state check. The trailing
            # `")` of the enclosing call is trimmed, it is not part of the clause.
            clause = match.group(0).rstrip(')" ')
            guards.append({
                "line": where_line,
                "condition": _truncate_line(clause, 200),
                "kind": "where-clause",
                "states": _state_literals(clause),
            })
    guards.sort(key=lambda g: g["line"])
    return guards


def _state_literals(text: str) -> list[str]:
    """The compared values in a guard text: quoted literals, else the tokens
    that follow a comparison operator."""
    out: list[str] = []
    for match in re.finditer(r"""['"]([^'"]{1,60})['"]""", str(text or "")):
        value = match.group(1).strip()
        if value and value not in out:
            out.append(value)
    if not out:
        for match in re.finditer(
                r"(?:==|!=|>=|<=|>|<|\bis\b|\bin\b)\s*([A-Za-z_][\w.]*)",
                str(text or "")):
            token = match.group(1).rsplit(".", 1)[-1].strip()
            if token and token not in out and token.lower() not in ("none", "null"):
                out.append(token)
    return out[:4]


def _state_literal(value: str) -> str:
    """``"shipped"`` -> ``shipped``; ``Status.SHIPPED`` -> ``SHIPPED``; else the
    truncated expression that makes it dynamic."""
    text = str(value or "").strip()
    match = re.fullmatch(r"""['"]([^'"]{1,80})['"]""", text)
    if match:
        return match.group(1)
    if re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", text):
        return text.rsplit(".", 1)[-1]
    return _truncate_line(text, 80) or "(dynamic)"


def _guard_states(guards: list[dict]) -> str:
    states: list[str] = []
    for guard in guards:
        for state in guard["states"]:
            if state not in states:
                states.append(state)
    return ", ".join(states) if states else "(unguarded)"


def _transition_row(row: dict) -> str:
    guards = "; ".join(f"{g['kind']}@{g['line']}: {g['condition']}"
                       for g in row["guards"][:2])
    if len(row["guards"]) > 2:
        guards += f" … +{len(row['guards']) - 2} more"
    return (f"   {row['from_state']} -> {row['to_state']}  "
            f"{_site(row['file'], row['line'])}  "
            f"{row['endpoint']}  guard: {'yes' if row['guard_present'] else 'NO'}  "
            f"fn {row['function']}()  evidence: {row['evidence']}"
            + (f"  [{guards}]" if guards else ""))

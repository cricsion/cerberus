"""AuthZ & business-logic tools — consensus, shared state, transition legality.

Three questions a taint tracer cannot answer, because they are about *what a
sibling does*, *who touches shared state* and *which transition is legal*:

- :func:`compare_sibling_route_security` — BOLA/IDOR by **consensus**: one
  endpoint omitting the decorator or ownership check its siblings all carry is
  CWE-639, and it looks ordinary in isolation.
- :func:`find_shared_state_readers_writers` — TOCTOU/double-spend/race:
  classify every reference to one carrier reader-vs-writer, then pair reads with
  writes (CWE-367 across an ``await``, CWE-362 across functions).
- :func:`trace_state_machine_transitions` — business-logic bypass: a status
  assignment with no prior-state guard is CWE-840.

Laws: (1) **consensus, not taint** — every finding is a difference between
reads and writes. (2) **confidence bands are the currency**: ``.45 base / .20
evidence / .10 gap / .10 strength / .05 no-guard``, clamped ``[.30, .85]`` and
rendered as ``(confidence: …)``. (3) **bounded output**: ``HARD_MAX_SECTION``
per section, ``limit <= 0`` = the DB row ceiling, the pinned ``+N more`` shapes,
``CODEGRAPH_CHARS`` applied once. (4) **guard detection is SYNTAX, not
vocabulary** (:func:`_has_wrapper`) — an ``async``/``await`` span, a ``with``
context, a lock decorator or a ``SELECT … FOR UPDATE`` literal; prose never
suppresses a finding. (5) **write classification**: assignment, update-style
call, or raw-SQL DML naming the carrier; one that cannot be attributed is
``unclassified``, never a silent reader. (6) **read-only, never-raise**: the
index opens ``mode=ro``, source passes the shared containment check, the only
sidecar touch is the summary *read*, and every failure is a string.

``_CALLER_EDGE_KINDS`` includes ``navigates`` (D-EDG2, FROZEN): the caller BFS
may traverse navigates hops to a sibling handler; contracts excludes it —
aligning them is a user decision. Format laws (pinned): ``## carrier …``,
``## racy pairs (n)``, ``## status field …``, ``   file:line  access
fn(kind)  span a-b  async: …  wrapper: …``, ``(confidence: …)``, and the
absence shape of :func:`_no_carrier_message`.
"""
from __future__ import annotations

import re
from collections import Counter

from harness.codegraph import _db, _ts, summaries
from harness.codegraph._common import (
    HARD_MAX_SECTION, Report, _CONF_MAX, _CONF_MIN,
    _HANDLER_KINDS, _ROUTE_EDGE_KINDS, _assign_value, _callee_tail_full,
    _candidate_finding, _cap_chars, _cap_rows, _confidence, _contained_file,
    _end_line_of, _env_int, _finding_lines, _guard_condition, _is_low_value,
    _line_of, _node_label, _node_span, _parsed_file, _route_handler, _route_map,
    _section_cap, _site, _truncate_line, _walk, tool_gate)

try:
    from langchain_core.tools import tool
except ImportError:  # pragma: no cover - langchain absent
    def tool(*dargs, **dkwargs):  # type: ignore
        def deco(fn):
            return fn
        if dargs and callable(dargs[0]):
            return dargs[0]
        return deco

# Kept module-level aliases (the shared bodies live in ``_common``).
_callee_tail = _callee_tail_full
_handler_for_route = _route_handler

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
MAX_SPAN_TEXT = 20000      # wrapper-syntax walk bound

# Graph kinds that may carry state; tables are not nodes.
_STATE_KINDS = ("variable", "field", "property", "constant")
# Binding node types; suffixes cover language variants, not nested defs/classes.
_DECLARATION_TYPES = frozenset({
    "assignment", "augmented_assignment", "named_expression",
    "assignment_expression", "augmented_assignment_expression",
    "assignment_statement", "local_variable_declaration", "field_declaration",
    "init_declarator", "short_var_declaration", "var_declaration",
    "const_declaration", "variable_declaration", "lexical_declaration"})
_DECLARATION_SUFFIXES = ("_declaration", "_declarator")
# Only conditionals can prove prior state; ``try`` is not a guard.
_CONDITIONAL_TYPES = frozenset({
    "if_statement", "elif_clause", "if_expression", "switch_statement",
    "switch_expression", "conditional_expression", "ternary_expression",
    "match_statement", "guard_statement"})
# Depth-1 guard names; case-insensitive for PascalCase C#/JVM spellings.
_GUARD_NAME_RE = re.compile(
    r"^(assert|check|require|authoriz|authoris|ensure|verify|validate|guard|"
    r"policy|permission|ownership|enforce|protect|can[A-Z]|has[A-Z]|is[A-Z])",
    re.IGNORECASE)
# Auth decorators affect only high-vs-medium severity.
_AUTH_DECORATOR_RE = re.compile(
    r"auth|login|logged|role|permission|tenant|admin|secure|jwt|token|session|"
    r"acl|policy|scope|owner|ownership|member|privileged|protected|api[-_]?key",
    re.IGNORECASE)
# Update-style verbs on a carrier receiver (for example, ``account.save()``).
_WRITE_CALL_RE = re.compile(r"^(?:save|update|incr|decr|deduct|set|del|delete|"
                            r"push|append)", re.IGNORECASE)
# Wrapper vocabulary matches syntax, never prose; ``update`` and ``begin`` are
# excluded so mutation words alone cannot suppress a race finding.
_WRAPPER_WORD_RE = re.compile(
    r"\b(?:with_lock|with_for_update|for_update|locks?|lock(?:ed|ing)?|"
    r"mutex(?:es)?|transactions?|transactional|atomic|synchroni[sz]e(?:d)?|"
    r"sessions?|unit_of_work|pessimistic)\b", re.IGNORECASE)
_SYNCHRONIZED_NODE_RE = re.compile(r"synchroni[sz]", re.IGNORECASE)
_WITH_NODE_RE = re.compile(r"^(?:.*with.*|.*using.*)(?:statement|expression)$",
                           re.IGNORECASE)
_BODY_NODE_RE = re.compile(r"block|statement_list|suite|body|statements",
                           re.IGNORECASE)
_WRAPPER_CALL_RE = re.compile(r"for[\s_]update", re.IGNORECASE)
# Match SQL string literals only; prose mentioning ``SELECT … FOR UPDATE`` is not a lock.
_SELECT_FOR_UPDATE_RE = re.compile(r"\bselect\b[\s\S]{0,400}?\bfor\s+update\b",
                                   re.IGNORECASE)
_DB_RECEIVER_RE = re.compile(
    r"(?:^|[.\s(\[])(?:db|database|cursor|conn|connection|session|transaction|"
    r"tx|engine)\b", re.IGNORECASE)
_DML_VERB_RE = re.compile(r"\b(?:INSERT|UPDATE|DELETE|REPLACE|UPSERT|MERGE)\b",
                          re.IGNORECASE)
_FOR_UPDATE_RE = re.compile(r"\bfor\s+update\b", re.IGNORECASE)
_SQL_METHOD_RE = re.compile(
    r"^(?:execute|executemany|executescript|exec|raw|raw_sql|execute_sql|sql|"
    r"query)$", re.IGNORECASE)
# A WHERE status/state predicate is the SQL spelling of a prior-state guard.
_WHERE_STATUS_RE = re.compile(
    r"\bwhere\b[^\n;]{0,160}?\b(?:status|state)\b[^\n;]{0,160}", re.IGNORECASE)
_METHOD_TOKEN_RE = re.compile(
    r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY|ALL|ROUTE)\s+", re.IGNORECASE)

# D-EDG2: authz and supply traverse `navigates`; contracts intentionally does not.
_CALLER_EDGE_KINDS = ("calls", "references", "instantiates", "navigates")
_CALLER_BFS_DEPTH = 3
_CONF_BASE = 0.45
_CONF_EVIDENCE = 0.20
_CONF_GAP = 0.10
_CONF_STRENGTH = 0.10
_CONF_NOGUARD = 0.05


class _Sections(Report):
    """``Report`` plus raw-line ``add()``: every row here is pre-rendered."""

    def add(self, *lines: str) -> "_Sections":
        """Append already-formatted lines and return self (chainable)."""
        self.lines.extend(lines)
        return self


def _truthy(value) -> bool:
    """A SQLite flag column (``nodes.is_async``) as a bool, never a surprise."""
    if value is None or isinstance(value, bool):
        return bool(value)
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in ("1", "true", "yes", "y", "t")


def _is_declaration(node) -> bool:
    """A binding-introducing node: assignment, declaration or declarator."""
    if node.type in _ts.FUNCTION_NODE_TYPES or node.type in _ts.CLASS_NODE_TYPES:
        return False
    return node.type in _DECLARATION_TYPES or node.type.endswith(_DECLARATION_SUFFIXES)


def _mentions(text: str, keys, ignore_case: bool = False) -> bool:
    """Does ``text`` name one of ``keys`` as a whole word? (``.`` is a boundary.)"""
    for key in keys:
        if key and re.search(rf"(?<![\w$]){re.escape(str(key))}(?![\w$])",
                             str(text or ""), re.IGNORECASE if ignore_case else 0):
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


def _normalise_decorator(text) -> str:
    """``@PreAuthorize("…")`` -> ``@PreAuthorize``; one bare name per spelling."""
    flat = " ".join(str(text or "").split()).split("(", 1)[0].strip().rstrip(":;,.")
    return "" if not flat else (flat if flat.startswith("@") else "@" + flat)


def _url_path(url: str) -> str:
    """``POST /api/orders/:id`` -> ``/api/orders/:id`` (method token dropped)."""
    text = str(url or "").strip()
    return _METHOD_TOKEN_RE.sub("", text, count=1).strip() or text


def _url_prefix(url: str) -> str:
    """Static segments before the first ``:param`` — the "same controller" read."""
    out: list[str] = []
    for segment in _url_path(url).split("?", 1)[0].split("/"):
        if segment and segment.startswith((":", "{", "*")):
            break
        if segment:
            out.append(segment)
    return "/".join(out)


# 1. Route security consensus

@tool(parse_docstring=True)
def compare_sibling_route_security(route_node_id: str, root: str = ".",
                                   limit: int | None = None) -> str:
    """Compare a route's decorators and guards against sibling-route consensus.

    Auth-shaped gaps are high, other gaps medium; differently named guards are informational.

    Args:
        route_node_id: The route node id (a routing manifest ``route_id``).
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Max sibling routes compared. 0 = unlimited.

    Returns:
        The target profile, sibling consensus, missing checks, per-sibling table
        and a candidate finding (CWE-639, CWE-284 note).
    """
    conn, route, error = tool_gate(
        root, kind="route", node_id=route_node_id,
        hint="pass the route node id (a routing manifest route_id), not its handler")
    if error:
        return error
    handler = _handler_for_route(conn, route_node_id)
    url = str(route.get("name") or "")
    target = _route_security(conn, handler, route)
    target["url"] = url
    sibling_cap = _cap_rows(limit, ENV_SIBLINGS, DEFAULT_SIBLINGS)
    guard_cap = _section_cap(ENV_GUARDS, DEFAULT_GUARDS)
    handler_file = str((handler or {}).get("file_path") or "") \
        or str(route.get("file_path") or "")
    prefix = _url_prefix(url)

    found = _sibling_routes(conn, route_node_id, handler_file, prefix)
    siblings = found[:sibling_cap]
    profiles = []
    for sib, sib_handler in siblings:
        profile = _route_security(conn, sib_handler, sib)
        profile["url"] = str(sib.get("name") or "")
        profiles.append((profile, sib, sib_handler))

    report = _Sections([
        f"# route security consensus: {url or route_node_id}",
        f"target: route {_node_label(route)}"
        + (f" -> handler {_node_label(handler)}" if handler else ""),
        f"url: {url or '(unnamed route)'}",
        f"handler: {_node_label(handler) if handler else '(no handler resolvable)'}",
        "decorators: " + (", ".join(target["decorators"]) or "(none)"),
        "guard_calls: " + (_guard_summary(target["guard_calls"], guard_cap) or "(none)")])
    hint = summaries.cache_hint(conn, route_node_id)
    if hint:
        report.add("cached summary: " + hint)

    if handler is None:
        report.blank().add(
            "no handler resolvable: no outgoing references/calls edge from the "
            "route node to a node of kind " + "|".join(_HANDLER_KINDS),
            "hint: compare a route whose handler the index did resolve — check "
            "the routing manifest first (codegraph_explore) or resolve_blind_spot "
            "on the route node")
        return report.text()
    if not profiles:
        report.blank().add(
            f"sibling_count: 0 — no route shares the handler file ({handler_file}) "
            f"or the URL prefix ({prefix or '(none)'})",
            "nothing is compared and no candidate finding is emitted: a consensus "
            "needs at least one sibling",
            "hint: a lone endpoint is either the only one of its kind (nothing to "
            "compare) or the index missed the controller (its references may sit "
            "in unresolved_refs)")
        return report.text()

    common_decorators = _consensus(p["decorators"] for p, _s, _h in profiles)
    common_guards = _consensus([g["name"] for g in p["guard_calls"]]
                               for p, _s, _h in profiles)
    missing_decorators = [d for d in common_decorators if d not in target["decorators"]]
    target_guard_names = {x["name"] for x in target["guard_calls"]}
    missing_guards = [g for g in common_guards if g not in target_guard_names]
    capped = report.capped(len(found) - len(siblings), "routes found", sibling_cap) \
        if len(found) > len(siblings) else ""
    report.blank().add(
        f"## sibling consensus ({len(profiles)} sibling(s), majority rule: held "
        f"by more than half)",
        f"sibling_count: {len(profiles)}{capped}",
        "common_decorators: " + (", ".join(
            f"{d} ({_count_holders(d, profiles, 'decorators')}/{len(profiles)})"
            for d in common_decorators) or "(none)"),
        "common_guard_calls: " + (", ".join(
            f"{g} ({_count_holders(g, profiles, 'guards')}/{len(profiles)})"
            for g in common_guards) or "(none)"),
        "missing_on_target: decorators " + (", ".join(missing_decorators) or "(none)")
        + "; guard_calls " + (", ".join(missing_guards) or "(none)"))

    report.blank().add(f"## siblings ({len(profiles)} of {len(found)})")
    for index, (profile, sib, sib_handler) in enumerate(profiles, start=1):
        report.add(
            f"{index}. {profile['url']}  route {_node_label(sib, with_span=False)}"
            + (f"  ->  {_node_label(sib_handler)}" if sib_handler
               else "  ->  (no handler resolvable)"),
            "   decorators: " + (", ".join(profile["decorators"]) or "(none)"),
            "   guard_calls: "
            + (_guard_summary(profile["guard_calls"], guard_cap) or "(none)"))

    if missing_decorators or missing_guards:
        finding, header = _consensus_finding(
            target, profiles, missing_decorators, missing_guards)
        report.blank().add(*_finding_lines(finding, header))
        if finding["severity"] == "info":
            report.blank().add("note: " + finding["note"])
    else:
        report.blank().add(
            "no candidate finding: every consensus item is present on the target route")
    return report.text()


def _route_security(conn, handler: dict | None, route: dict | None = None) -> dict:
    """Decorators + guard calls for one handler — the consensus's unit of vote."""
    decorators = list(dict.fromkeys(
        name for source in (handler, route)
        for raw in [(source or {}).get("decorators") or []]
        if isinstance(raw, (list, tuple))
        for item in raw if (name := _normalise_decorator(item))))
    guards = _guard_calls(conn, str(handler.get("id") or "")) if handler else []
    return {"decorators": decorators, "guard_calls": guards, "handler": handler}


def _guard_calls(conn, handler_id: str) -> list[dict]:
    """Depth-1 guard-name calls, with cached ``AUTH_GUARD`` summary fallback."""
    if conn is None or not handler_id:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for kind in ("calls", "references"):
        for edge in _db.get_edges(conn, source=handler_id, kind=kind,
                                  limit=HARD_MAX_SECTION):
            target = _db.get_node(conn, edge.get("target"))
            target_id = str((target or {}).get("id") or "")
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
            out.append({"name": name, "node_id": target_id,
                        "reason": "guard-shaped name" if named
                        else "cached AUTH_GUARD summary",
                        "hint": hint,
                        "site": _site(target.get("file_path"), target.get("start_line")),
                        "edge_line": edge.get("line")})
    out.sort(key=lambda g: (g["edge_line"] or 0, g["name"]))
    return out


def _sibling_routes(conn, route_id: str, handler_file: str, prefix: str):
    """Return same-file routes first, then same-prefix routes; exclude low-value files."""
    same_file: list[tuple] = []
    same_prefix: list[tuple] = []
    seen = {route_id}
    for row in _db.find_nodes(conn, kind="route", limit=0):
        row_id = str(row.get("id") or "")
        if not row_id or row_id in seen:
            continue
        handler = _handler_for_route(conn, row_id)
        sib_file = str((handler or {}).get("file_path") or "") \
            or str(row.get("file_path") or "")
        if handler is not None and _is_low_value(sib_file, conn):
            continue
        if handler_file and sib_file == handler_file:
            seen.add(row_id)
            same_file.append((row, handler))
        elif prefix and _url_prefix(row.get("name")) == prefix:
            seen.add(row_id)
            same_prefix.append((row, handler))
    return same_file + same_prefix


def _consensus(value_lists) -> list[str]:
    """Items held by a strict majority of the sibling population."""
    values = list(value_lists)
    counts = Counter(value for row in values for value in set(row))
    return sorted(name for name, count in counts.items() if count * 2 > len(values))


def _count_holders(item: str, profiles, field: str) -> int:
    """How many sibling profiles carry ``item`` in ``decorators``/``guards``."""
    return sum(1 for profile, _s, _h in profiles
               if item in (profile["decorators"] if field == "decorators"
                           else [g["name"] for g in profile["guard_calls"]]))


def _guard_summary(guards: list[dict], cap: int) -> str:
    """``assert_tenant_owner (guard-shaped name)``, … — compact and capped."""
    parts = [f"{g['name']} ({g['reason']})" for g in guards[:cap]]
    extra = len(guards) - len(guards[:cap])
    return ", ".join(parts + [f"… +{extra} more"] if extra > 0 else parts)


def _consensus_blocks(target: dict, profiles, carried: str) -> tuple:
    """``(handler, taint_path, evidence)`` shared by the two consensus findings."""
    handler = target["handler"] or {}
    taint_path = [f"{p['url']} @ {_node_label(p['handler'] or h, with_span=False)}"
                  for p, _s, h in profiles[:5]]
    taint_path.append(f"{target['url']} @ {_node_label(handler, with_span=False)}")
    evidence = (f"target {target['url']} handler "
                f"{_node_label(handler, with_span=False)} carries "
                f"{', '.join(target['decorators']) or 'no decorators'} and "
                f"{', '.join(g['name'] for g in target['guard_calls']) or 'no guard calls'}"
                f"; {len(profiles)} sibling route(s) carry {carried}")
    return handler, taint_path, evidence


def _consensus_finding(target: dict, profiles, missing_decorators,
                       missing_guards) -> tuple[dict, str]:
    """Build a gap finding, or delegate to the info-level name-mismatch case."""
    target_guards = [g["name"] for g in target["guard_calls"]]
    if target_guards:
        return _consensus_name_mismatch(target, profiles, missing_decorators,
                                        missing_guards, target_guards)
    auth_gap = [d for d in missing_decorators if _AUTH_DECORATOR_RE.search(d)]
    severity = "high" if auth_gap else "medium"
    confidence = _confidence(
        _CONF_BASE, _CONF_EVIDENCE if auth_gap else 0.0,
        _CONF_GAP if missing_guards else 0.0,
        _CONF_STRENGTH if len(profiles) >= 3 else 0.0, _CONF_NOGUARD)
    carried = ", ".join(missing_decorators) or "no extra decorators"
    if missing_guards:
        carried += f" and {', '.join(missing_guards)}"
    handler, taint_path, evidence = _consensus_blocks(target, profiles, carried)
    finding = _candidate_finding(
        title=(f"missing function-level access control on {target['url']} (siblings "
               f"enforce {', '.join(missing_decorators or missing_guards)})"),
        path=str(handler.get("file_path") or ""),
        start_line=int(handler.get("start_line") or 0),
        end_line=int(handler.get("end_line") or 0), cwe="CWE-639",
        severity=severity, confidence=confidence,
        taint_source="sibling consensus: " + ", ".join(missing_decorators + missing_guards),
        taint_sink=f"{target['url']} handler {handler.get('name') or '?'}",
        taint_path=taint_path, evidence=evidence,
        rationale=(f"{len(profiles)} sibling route(s) in the same controller file or "
                   f"URL prefix enforce the check this handler omits; an authorised "
                   f"user of one endpoint reaches another's objects"),
        note=("CWE-284 (Improper Access Control) is the parent class; CWE-639 "
              "(Authorization Bypass Through User-Controlled Key) is the specific "
              "weakness this consensus gap indicates"))
    return finding, (f"## candidate finding (CWE-639, severity {severity}, "
                     f"confidence {confidence})")


def _consensus_name_mismatch(target: dict, profiles, missing_decorators,
                             missing_guards, target_guards) -> tuple[dict, str]:
    """Build an info finding when an existing guard does not match by name."""
    handler = target["handler"] or {}
    missing = missing_decorators + missing_guards
    handler, taint_path, evidence = _consensus_blocks(
        target, profiles, ", ".join(missing) or "no extra items")
    confidence = _CONF_MIN
    finding = _candidate_finding(
        title=(f"consensus check not matched by name on {target['url']}: target "
               f"enforces {', '.join(target_guards)} "
               f"(siblings: {', '.join(missing) or 'none'})"),
        path=str(handler.get("file_path") or ""),
        start_line=int(handler.get("start_line") or 0),
        end_line=int(handler.get("end_line") or 0), cwe="CWE-639",
        severity="info", confidence=confidence,
        taint_source="sibling consensus (name mismatch): " + ", ".join(missing),
        taint_sink=f"{target['url']} handler {handler.get('name') or '?'}",
        taint_path=taint_path, evidence=evidence,
        rationale=(f"target enforces {', '.join(target_guards)}, so the access check "
                   f"is not verifiably absent; consensus item(s) "
                   f"{', '.join(missing) or 'none'} are not matched by name — "
                   f"name-based matching cannot prove equivalence"),
        note=(f"target enforces {', '.join(target_guards)}; consensus check "
              f"{', '.join(missing_guards or missing_decorators) or 'none'} not "
              f"matched by name — name-based matching cannot prove equivalence. "
              f"CWE-284 (Improper Access Control) is the parent class; CWE-639 "
              f"(Authorization Bypass Through User-Controlled Key) is the specific "
              f"weakness a real consensus gap would indicate"))
    return finding, (f"## candidate finding (CWE-639, severity info, confidence "
                     f"{confidence}) — name mismatch, not a proven gap")


# 2. Shared-state access

@tool(parse_docstring=True)
def find_shared_state_readers_writers(state_symbol_or_table: str, root: str = ".",
                                      limit: int | None = None) -> str:
    """Classify carrier references and find unguarded read/write pairs.

    Flags read/await/write TOCTOU (CWE-367) and unwrapped cross-function races (CWE-362).
    Syntax heuristics can miss forms; raw SQL without attribution is ``unclassified``.
    TOCTOU is high, races medium.

    Args:
        state_symbol_or_table: Bare/dotted symbol or table indexed as a state kind.
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Max reference sites per state carrier. 0 = unlimited.

    Returns:
        Carriers, per-site verdicts with wrapper status, then one finding per pair.
    """
    conn, _node, error = tool_gate(root)
    if error:
        return error
    symbol = str(state_symbol_or_table or "").strip()
    if not symbol:
        return _cap_chars("ERROR: state_symbol_or_table is required "
                          "(e.g. 'balance', 'Account.balance')")
    carriers, head = _state_carriers(conn, symbol)
    if not carriers:
        return _cap_chars(_no_carrier_message(symbol))

    site_cap = _cap_rows(limit, ENV_SITES, DEFAULT_SITES)
    finding_cap = _section_cap("CODEGRAPH_STATE_FINDINGS", DEFAULT_FINDINGS)
    cache: dict[str, tuple] = {}
    report = _Sections([f"# shared state readers/writers: {symbol}"])
    all_sites: list[dict] = []
    for carrier in carriers:
        sites = _state_sites(conn, root, carrier, head, site_cap, cache)
        all_sites.extend(sites)
        report.blank().add(f"## carrier {_node_label(carrier)}  "
                           f"[node {carrier.get('id')}]")
        parent = _db.node_parent(conn, str(carrier.get("id") or ""))
        if parent:
            report.add(f"   owner: {_node_label(parent)}")
        hint = summaries.cache_hint(conn, str(carrier.get("id") or ""))
        if hint:
            report.add("   cached summary: " + hint)
        readers = [s for s in sites if s["access"] == "reader"]
        writers = [s for s in sites if s["access"] == "writer"]
        unclassified = [s for s in sites if s["access"] not in ("reader", "writer")]
        report.add(f"   reference sites: {len(sites)} ({len(readers)} reader, "
                   f"{len(writers)} writer"
                   + (f", {len(unclassified)} unclassified" if unclassified else "")
                   + ")")
        for site in sites:
            report.add(_site_row(site))

    pairs = _racy_pairs(all_sites)
    report.blank().add(f"## racy pairs ({len(pairs)})")
    if not pairs:
        report.add("none: every read/write pair is either inside one non-async "
                   "function, separated by no await, or covered by a "
                   "transaction/lock wrapper")
    for index, pair in enumerate(pairs[:finding_cap], start=1):
        report.add(f"{index}. {pair['kind']} (CWE-{pair['cwe']}) — {pair['evidence']}")
        report.add(*_finding_lines(
            pair["finding"], f"   candidate finding (CWE-{pair['cwe']}, severity "
            f"{pair['finding']['severity']}, confidence "
            f"{pair['finding']['confidence']}):"))
    if len(pairs) > finding_cap:
        report.add(f"… +{len(pairs) - finding_cap} more racy pairs (total "
                   f"{len(pairs)}); re-run with a narrower state symbol or a "
                   f"higher limit")
    return report.text()


def _no_carrier_message(symbol: str) -> str:
    """The guidance when no state carrier resolves (bounded symbol echo twice)."""
    shown = _truncate_line(symbol, 200) or "(empty)"
    return "\n".join([
        f"# no state carrier for {shown!r}",
        f"no node named (or matching) {shown!r} of kind {'|'.join(_STATE_KINDS)} "
        f"— CodeGraph models no table nodes, so a bare table name only resolves "
        f"when the index spells it as a constant, variable, field or property",
        "hint: pass the FIELD or VARIABLE that carries the state, e.g. "
        "'Account.balance', 'user.balance', 'ledger.nonce'"])


def _state_carriers(conn, symbol: str) -> tuple[list[dict], str]:
    """Resolve exact then substring carriers, favoring a dotted symbol's owner."""
    cap = _section_cap("CODEGRAPH_STATE_CARRIERS", DEFAULT_CARRIERS)
    head, _, tail = symbol.rpartition(".")
    wanted = tail if tail else symbol
    carriers: list[dict] = []
    seen: set[str] = set()

    def add(nodes) -> None:
        for node in nodes:
            node_id = str(node.get("id") or "")
            if str(node.get("kind") or "") in _STATE_KINDS and node_id \
                    and node_id not in seen:
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
    """The ``contains`` parent's name, or ``""``."""
    return str(((_db.node_parent(conn, node_id) or {}).get("name")) or "")


def _reference_sites(conn, root: str, carrier_id: str, cache: dict):
    """Yield parseable incoming reference sites in graph order."""
    for edge in _db.incoming_edges(conn, carrier_id, kinds=["references"], limit=0):
        source = _db.get_node(conn, edge.get("source"))
        if source is None:
            continue
        try:
            line = int(edge.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        if line:
            file_path = str(source.get("file_path") or "")
            tree, src = _parsed_file(root, file_path, cache)
            yield source, line, file_path, tree, src


def _state_sites(conn, root: str, carrier: dict, head: str, cap: int,
                 cache: dict) -> list[dict]:
    """Every ``references`` site of the carrier, classified reader/writer."""
    keys = _carrier_keys(carrier)
    if head and head not in keys:
        keys = keys + [head]
    carrier_id = str(carrier.get("id") or "")
    sites: list[dict] = []
    for source, line, file_path, tree, src in _reference_sites(
            conn, root, carrier_id, cache):
        site = {
            "file": file_path, "line": line,
            "function": str(source.get("name") or ""),
            "function_id": str(source.get("id") or ""),
            "function_kind": str(source.get("kind") or ""),
            "carrier_id": carrier_id, "access": "reader", "evidence": "",
            "wrapper": False, "is_async": _truthy(source.get("is_async")),
            "await_lines": set(), "span": (line, line),
            "reason": "no assignment or update-style call names the state here"}
        if tree is None:
            # Retain graph-only sites when source parsing fails.
            site["reason"] = ("source not parseable — reader/writer undecided "
                              "(classified by graph metadata only)")
        else:
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
        if text and text not in keys:
            keys.append(text)
        tail = text.rsplit(".", 1)[-1]
        if tail and tail not in keys:
            keys.append(tail)
    return keys


def _classify_site(tree, src: bytes, site: dict, keys, decorators=None) -> None:
    """Try assignment, update-call, then raw-SQL rules; otherwise retain reader evidence."""
    fn = _ts.enclosing_function(tree, site["line"]) or _ts.enclosing_node(tree, site["line"])
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
    calls = _ts.calls_in_span(tree, stmt_start, stmt_end, src)
    verdict = (_assignment_access(src, statement, keys)
               or _update_call_access(src, calls, keys)
               or _raw_sql_access(calls, keys, src))
    if verdict is not None:
        site["access"], site["reason"], site["evidence"] = verdict
        return
    site["evidence"] = _truncate_line(
        _ts.line_text(src, site["line"]) if src else "", MAX_EVIDENCE)


def _assignment_access(src: bytes, statement, keys):
    """``writer`` when the statement assigns to a carrier name, else ``None``."""
    if statement is None:
        return None
    target = _assign_target(statement, src)
    if not _mentions(target, keys):
        return None
    return ("writer", f"assignment to {_truncate_line(target, 60)}",
            _truncate_line(_ts.node_text(statement, src), MAX_EVIDENCE))


def _update_call_access(src: bytes, calls, keys):
    """Detect carrier writes anywhere in an update-style call expression."""
    for call in calls:
        tail = _callee_tail(call["text"])
        if _WRITE_CALL_RE.match(tail):
            whole = _ts.node_text(call["node"], src)
            if _mentions(whole, keys):
                return ("writer", f"update-style call {_truncate_line(tail, 40)}",
                        _truncate_line(whole, MAX_EVIDENCE))
    return None


def _call_receiver(callee_text: str) -> str:
    """``self.db.execute`` -> ``self.db``; a bare ``execute`` -> ``""``."""
    text = str(callee_text or "").strip()
    return text.rsplit(".", 1)[0] if "." in text else ""


def _call_arguments(call):
    """The call's bracketed argument node, or ``None`` (never raises)."""
    try:
        return call["node"].child_by_field_name("arguments")
    except Exception:
        return None


def _first_string_argument(arguments, src: bytes) -> str:
    """Return SQL literals, including those nested in formatted strings."""
    if arguments is None:
        return ""
    try:
        children = [c for c in arguments.children if bool(getattr(c, "is_named", True))]
    except Exception:
        return ""
    if not children:
        return ""
    first = children[0]
    if "string" in str(getattr(first, "type", "") or "").lower():
        return _ts.node_text(first, src)
    return " ".join(_ts.node_text(node, src) for node in _walk(first)
                    if "string" in str(getattr(node, "type", "") or "").lower())


def _dml_body(sql: str) -> str:
    """The SQL text with the row-lock clause removed (``FOR UPDATE`` mutates nothing)."""
    return _FOR_UPDATE_RE.sub(" ", str(sql or ""))


def _is_dml_sql(sql: str, keys) -> bool:
    """Does this SQL text mutate? A DML verb, or ``SET <carrier>`` on its own."""
    if not sql:
        return False
    return bool(_DML_VERB_RE.search(_dml_body(sql))) or any(
        re.search(rf"\bset\s+(?:[A-Za-z_$][\w$]*\.)?{re.escape(str(key))}\b",
                  sql, re.IGNORECASE) for key in keys if key)


def _sql_calls(calls, src: bytes):
    """Yield recognized database calls with their first-argument SQL text."""
    for call in calls:
        if _DB_RECEIVER_RE.search(_call_receiver(call["text"])):
            yield call, _first_string_argument(_call_arguments(call), src)


def _raw_sql_access(calls, keys, src: bytes):
    """Classify raw DML as writer or unclassified; never guess an unknown target is a reader."""
    for call, sql in _sql_calls(calls, src):
        if sql and _is_dml_sql(sql, keys):
            if _mentions(sql, keys, ignore_case=True):
                return ("writer",
                        f"raw SQL DML names the carrier: {_truncate_line(sql, 120)}",
                        _truncate_line(sql, MAX_EVIDENCE))
            return ("unclassified", "raw SQL DML does not name this carrier",
                    _truncate_line(sql, MAX_EVIDENCE))
        if not sql and _SQL_METHOD_RE.match(_callee_tail(call["text"])):
            return ("unclassified", "raw SQL on a db handle with no visible statement",
                    _truncate_line(_ts.node_text(call["node"], src), MAX_EVIDENCE))
    return None


def _innermost_spanning(tree, line: int, start: int, end: int, accept):
    """Choose the narrowest accepted node spanning ``line`` within its function."""
    scope = _ts.enclosing_function(tree, line) or _ts.enclosing_node(tree, line)
    best = best_key = None
    for node in _walk(scope if scope is not None else tree.root_node):
        if not accept(node):
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


def _enclosing_declaration(tree, line: int, start: int, end: int):
    """The innermost assignment-ish node whose span contains ``line``."""
    return _innermost_spanning(tree, line, start, end, _is_declaration)


def _ts_node_is_async(node, src: bytes) -> bool:
    """An ``async``/``await`` inside the span — the textual is_async fallback."""
    return bool(re.search(r"\basync\b|\bawait\b", _ts.node_text(node, src) or ""))


def _await_lines(tree, start: int, end: int) -> set:
    """Line numbers of ``await`` expressions inside a span, grammar-agnostic."""
    lines: set = set()
    for node in _walk(tree.root_node):
        if "await" in str(getattr(node, "type", "") or "").lower():
            line = _line_of(node)
            if start <= line <= end:
                lines.add(line)
    return lines


def _wrapper_scope(fn):
    """The function plus its ``decorated_definition`` parent (Python decorators)."""
    try:
        parent = getattr(fn, "parent", None)
    except Exception:
        parent = None
    return parent if parent is not None and "decorat" in str(
        getattr(parent, "type", "") or "") else fn


def _with_context_text(node, src: bytes) -> str:
    """The context expressions of a with/using statement — not its body."""
    try:
        children = list(node.children)
    except Exception:
        return ""
    parts: list[str] = []
    for child in children:
        ctype = str(getattr(child, "type", "") or "")
        if not ctype:
            continue
        try:
            named = bool(child.is_named)
        except Exception:
            named = True
        if named and not _BODY_NODE_RE.search(ctype):
            parts.append(_ts.node_text(child, src))
    return " ".join(parts)


def _has_wrapper(node, src: bytes, decorators=None) -> bool:
    """Detect bounded lock syntax (decorators, synchronized nodes, lock-shaped
    ``with``/calls, SQL row locks); prose never counts.
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
        low = str(getattr(child, "type", "") or "").lower()
        if not low or low == "comment":
            continue  # prose is never a lock, in any grammar
        if "string" in low:
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
            callee = child.child_by_field_name("function") \
                or child.child_by_field_name("callee")
        except Exception:
            callee = None
        if callee is not None and low in _ts.CALL_NODE_TYPES:
            if _WRAPPER_CALL_RE.search(_ts.node_text(callee, src)):
                return True
    return False


def _site_row(site: dict) -> str:
    """One pinned site row: ``file:line  access fn(kind)  span …  async/wrapper``."""
    evidence = f"  — {site['evidence']}" if site["evidence"] else ""
    return (f"   {_site(site['file'], site['line'])}  {site['access']:<6} "
            f"{site['function']}({site['function_kind']})  "
            f"span {site['span'][0]}-{site['span'][1]}  "
            f"async: {'yes' if site['is_async'] else 'no'}  "
            f"wrapper: {'yes' if site['wrapper'] else 'no'}{evidence}  [{site['reason']}]")


def _racy_pairs(sites: list[dict]) -> list[dict]:
    """Pair same-carrier reads/writes; wrappers and duplicate site pairs are suppressed."""
    pairs: list[dict] = []
    seen: set[tuple] = set()
    writers = [s for s in sites if s["access"] == "writer"]
    readers = [s for s in sites if s["access"] == "reader"]
    for writer in writers:
        for reader in readers:
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
                    continue
                if not (reader["is_async"] or writer["is_async"]):
                    continue
                between = {line for line in reader["await_lines"]
                           if reader["line"] < line < writer["line"]}
                if not between or reader["wrapper"] or writer["wrapper"]:
                    continue
                kind, cwe, severity = "TOCTOU", "367", "high"
                confidence = _confidence(_CONF_BASE, _CONF_EVIDENCE, _CONF_GAP,
                                         _CONF_NOGUARD if multi_writer else 0.0)
                detail = (f"read {_site(reader['file'], reader['line'])} in "
                          f"{reader['function']}() then write "
                          f"{_site(writer['file'], writer['line'])} in the SAME "
                          f"function, with await at line {min(between)} between "
                          f"them and no transaction/lock wrapper")
            else:
                if reader["wrapper"] or writer["wrapper"]:
                    continue
                kind, cwe, severity = "race", "362", "medium"
                confidence = _confidence(_CONF_BASE - 0.05, _CONF_GAP,
                                         _CONF_NOGUARD if multi_writer else 0.0)
                detail = (f"read {_site(reader['file'], reader['line'])} in "
                          f"{reader['function']}() and write "
                          f"{_site(writer['file'], writer['line'])} in "
                          f"{writer['function']}() — different functions, no "
                          f"transaction/lock wrapper on either")
            seen.add(key)
            finding = _candidate_finding(
                title=(f"{kind} on shared state: {reader['file']}:{reader['line']} "
                       f"read, {writer['file']}:{writer['line']} write"),
                path=writer["file"], start_line=writer["span"][0],
                end_line=writer["span"][1], cwe=f"CWE-{cwe}", severity=severity,
                confidence=confidence, taint_source="state check",
                taint_sink="state mutation",
                taint_path=[_site(reader["file"], reader["line"]),
                            _site(writer["file"], writer["line"])],
                evidence=(f"{detail}; reader evidence: {reader['evidence']}; "
                          f"writer evidence: {writer['evidence']}"),
                rationale=(f"{detail}. The state can be observed stale or mutated "
                           f"twice because nothing orders the two sites."),
                note=("CWE-367 (TOCTOU) is the same-function read-across-await "
                      "shape; CWE-362 is the concurrent read/write shape"))
            pairs.append({"kind": kind, "cwe": cwe, "finding": finding,
                          "evidence": detail})
    pairs.sort(key=lambda p: (p["finding"]["path"], p["finding"]["start_line"]))
    return pairs


# 3. State transitions

@tool(parse_docstring=True)
def trace_state_machine_transitions(entity_name: str, status_field: str = "status",
                                    root: str = ".", limit: int | None = None) -> str:
    """List status transitions and flag writes lacking a prior-state guard.

    Guards name the entity/field in conditionals or earlier WHERE clauses.
    Unreadable SQL is counted separately; discovery is shape-limited; unguarded
    first steps may be legitimate. Findings are medium severity.

    Args:
        entity_name: Owning symbol of the status field (``Order``, ``Payment``).
        status_field: The field that carries the state (``status``, ``state``).
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Max transitions reported per status field. 0 = unlimited.

    Returns:
        Resolved fields, transitions and CWE-840 findings for unguarded writes.
    """
    conn, _node, error = tool_gate(root)
    if error:
        return error
    entity = str(entity_name or "").strip()
    field = str(status_field or "").strip() or "status"
    if not entity:
        return _cap_chars("ERROR: entity_name is required (e.g. 'Order')")
    fields = _status_fields(conn, entity, field)
    if not fields:
        return _cap_chars("\n".join([
            f"# no status field for {_truncate_line(entity, 120)}."
            f"{_truncate_line(field, 120)}",
            f"no node named {_truncate_line(field, 120)!r} owned by "
            f"{_truncate_line(entity, 120)!r} (falling back to any such field "
            f"found none)",
            "hint: check the owning symbol's name and the field's spelling "
            "('status' vs 'orderStatus' vs 'state')"]))

    route_map = _route_map(conn, low_value_filter=False)
    transition_cap = _cap_rows(limit, ENV_TRANSITIONS, DEFAULT_TRANSITIONS)
    finding_cap = _section_cap("CODEGRAPH_TRANSITION_FINDINGS", DEFAULT_FINDINGS)
    cache: dict[str, tuple] = {}
    endpoints: dict[str, str] = {}
    report = _Sections([f"# state machine: {entity}.{field}"])
    all_transitions: list[dict] = []
    all_unclassified = 0
    for carrier, parent in fields:
        transitions, skipped, unclassified = _transitions(
            conn, root, carrier, entity, field, route_map, transition_cap, cache,
            endpoints)
        all_transitions.extend(transitions)
        all_unclassified += unclassified
        report.blank().add(f"## status field {_node_label(carrier)}  "
                           f"[node {carrier.get('id')}]")
        if parent:
            report.add(f"   owner: {_node_label(parent)}")
        guarded = len([t for t in transitions if t["guard_present"]])
        report.add(f"   transitions: {len(transitions)} ({guarded} guarded, "
                   f"{len(transitions) - guarded} unguarded)")
        if skipped:
            report.add(f"   note: {skipped} reference(s) skipped — the source is "
                       f"not parseable through this root, so those sites are "
                       f"absent from the table (under-approximation)")
        if unclassified:
            report.add(f"   skipped ({unclassified} unclassified status writes) — "
                       f"a raw-SQL statement names {field} but no transition "
                       f"could be read from it (a bind parameter, a DELETE), so "
                       f"those writes are absent from the table "
                       f"(under-approximation)")
        for row in transitions:
            report.add(_transition_row(row))

    unguarded = [t for t in all_transitions if not t["guard_present"]]
    report.blank().add(f"## unguarded transitions ({len(unguarded)} of "
                       f"{len(all_transitions)} transitions)")
    if not unguarded:
        report.add("none: every status assignment is preceded by a prior-state "
                   "guard or a WHERE clause")
    if all_unclassified:
        report.add(f"note: skipped ({all_unclassified} unclassified status "
                   f"writes) — raw SQL names {field} without a readable target "
                   f"state, so the table above is not exhaustive")
    strength = _CONF_STRENGTH if len(all_transitions) >= 2 else 0.0
    for index, row in enumerate(unguarded[:finding_cap], start=1):
        confidence = _confidence(_CONF_BASE, _CONF_EVIDENCE - 0.05
                                 if row["endpoint"] else 0.0, strength)
        finding = _candidate_finding(
            title=(f"unguarded {field} transition on {entity}: {row['to_state']} "
                   f"at {row['file']}:{row['line']}"),
            path=row["file"], start_line=row["span"][0],
            end_line=row["span"][1], cwe="CWE-840", severity="medium",
            confidence=confidence, taint_source=f"current {field}",
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
                  "check is the specific bypass"))
        report.add(f"{index}. {_transition_row(row)}")
        report.add(*_finding_lines(
            finding, f"   candidate finding (CWE-840, severity medium, "
            f"confidence {confidence}):"))
    if len(unguarded) > finding_cap:
        report.add(f"… +{len(unguarded) - finding_cap} more unguarded transitions "
                   f"(total {len(unguarded)}); re-run with a narrower entity or "
                   f"a higher limit")
    return report.text()


def _status_fields(conn, entity: str, field: str) -> list[tuple]:
    """(field_node, parent) for the status field, preferring the entity-owned node."""
    cap = _section_cap("CODEGRAPH_STATUS_FIELDS", DEFAULT_CARRIERS)
    nodes = [(node, _db.node_parent(conn, str(node.get("id") or "")))
             for node in _db.find_nodes(conn, name=field, limit=cap)]
    owner = entity.lower()
    owned = [(node, parent) for node, parent in nodes
             if str((parent or {}).get("name") or "").lower() == owner
             or str((parent or {}).get("qualified_name") or "").rsplit(".", 1)[-1].lower() == owner]
    if nodes:
        return (owned or nodes)[:cap]
    return [(node, _db.node_parent(conn, str(node.get("id") or "")))
            for node in _db.find_nodes(conn, name_like=f"%{field}%", limit=cap)][:cap]


def _endpoint_for_function(conn, node: dict, route_map: dict, cache: dict):
    """Resolve a function's endpoint by route map, then bounded caller BFS."""
    node_id = str(node.get("id") or "")
    if node_id in cache:
        return cache[node_id]
    try:
        start_line = int(node.get("start_line") or 0)
    except (TypeError, ValueError):
        start_line = 0
    answer = (route_map["by_id"].get(node_id)
              or route_map["by_site"].get((str(node.get("file_path") or ""),
                                           start_line)))
    if answer is None:
        answer = _endpoint_by_callers(conn, node_id, route_map)
    cache[node_id] = answer
    return answer


def _endpoint_by_callers(conn, node_id: str, route_map: dict):
    """Backward BFS over the getCallers edge set, depth capped at 3."""
    if not node_id:
        return None
    seen, frontier = {node_id}, [node_id]
    for _hop in range(_CALLER_BFS_DEPTH):
        nxt: list[str] = []
        for current in frontier:
            for edge in _db.incoming_edges(conn, current,
                                           kinds=_CALLER_EDGE_KINDS,
                                           limit=HARD_MAX_SECTION):
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
    """Collect status writes with guards/endpoints and skipped/unclassified counts."""
    keys = _carrier_keys(carrier)
    assign_keys = [k for k in keys if k.lower() != entity.lower()]
    guard_keys = list(dict.fromkeys(keys + [entity, field]))
    carrier_id = str(carrier.get("id") or "")
    rows: list[dict] = []
    skipped = unclassified = 0
    seen_raw: set[tuple] = set()
    for source, line, file_path, tree, src in _reference_sites(
            conn, root, carrier_id, cache):
        if tree is None:
            skipped += 1
            continue
        assignment = _status_assignment(tree, src, line, assign_keys)
        if assignment is not None:
            value = _truncate_line(
                _assign_value(assignment, src, normalize_ws=False), 80)
            to_state = _state_literal(value)
        else:
            raw = _raw_status_write(tree, src, line, field, assign_keys)
            if raw is None:
                continue
            statement, to_state = raw
            seen_key = (file_path, _line_of(statement))
            if seen_key in seen_raw:
                continue  # one statement, one row — other references saw it
            seen_raw.add(seen_key)
            if to_state is None:
                unclassified += 1
                continue
            assignment = statement
        guards = _prior_guards(tree, src, line, guard_keys)
        endpoint = _endpoint_for_function(conn, source, route_map, endpoints)
        rows.append({
            "from_state": _guard_states(guards), "to_state": to_state,
            "file": file_path, "line": _line_of(assignment) or line,
            "span": _node_span(source), "function": str(source.get("name") or ""),
            "endpoint": endpoint or "(not route-reachable)",
            "guard_present": bool(guards), "guards": guards,
            "evidence": _truncate_line(_ts.node_text(assignment, src), MAX_EVIDENCE)})
        if len(rows) >= cap:
            break
    rows.sort(key=lambda r: (r["file"], r["line"]))
    return rows, skipped, unclassified


def _dml_calls(tree, start: int, end: int, src: bytes, keys) -> list[dict]:
    """The raw-SQL calls in a span whose statement carries DML naming ``keys``."""
    return [call for call, sql in _sql_calls(
        _ts.calls_in_span(tree, start, end, src), src)
        if sql and _DML_VERB_RE.search(_dml_body(sql))
        and _mentions(sql, keys, ignore_case=True)]


def _raw_status_write(tree, src: bytes, line: int, field: str, keys):
    """Find raw SQL that sets the field; return its statement and literal target, if any."""
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
        # The graph reference line may be outside the writing statement.
        candidates = _dml_calls(tree, start, end, src, keys)
    if not candidates:
        return None
    candidates.sort(key=lambda c: (abs(c["line"] - line), c["line"]))
    call = candidates[0]
    return (call["node"], _sql_status_value(
        _first_string_argument(_call_arguments(call), src), field))


def _is_statement(node) -> bool:
    """A statement/declaration node type, whatever the grammar spells it."""
    kind = str(getattr(node, "type", "") or "")
    return ("statement" in kind or "declaration" in kind
            or kind in _DECLARATION_TYPES)


def _enclosing_statement(tree, line: int, start: int, end: int):
    """The innermost statement-ish node whose span contains ``line``."""
    return _innermost_spanning(tree, line, start, end, _is_statement)


def _sql_status_value(sql: str, field: str) -> str | None:
    """``UPDATE orders SET status = 'cancelled' …`` -> ``cancelled`` (``None`` if dynamic)."""
    match = re.search(
        rf"\bset\s+(?:[A-Za-z_$][\w$]*\.)?{re.escape(str(field or ''))}\s*=\s*"
        rf"(['\"])([^'\"]{{1,80}})\1", str(sql or ""), re.IGNORECASE)
    return match.group(2).strip() if match else None


def _status_assignment(tree, src: bytes, line: int, keys):
    """The assignment on ``line`` whose left side names the status field."""
    return _innermost_spanning(tree, line, 0, 0, lambda node: (
        _is_declaration(node) and _mentions(_assign_target(node, src), keys)))


def _prior_guards(tree, src: bytes, line: int, keys) -> list[dict]:
    """Find earlier conditionals or status-bearing WHERE clauses naming the field."""
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
        if _mentions(condition, keys, ignore_case=True):
            guards.append({"line": guard_line, "condition": condition,
                           "kind": "conditional",
                           "states": _state_literals(condition)})
    text = _ts.node_text(scope, src)
    match = _WHERE_STATUS_RE.search(text or "")
    if match:
        where_line = text[:match.start()].count("\n") + _line_of(scope)
        # Ignore WHERE clauses after the assignment and trim trailing call syntax.
        clause = match.group(0).rstrip(')" ')
        if where_line < line:
            guards.append({"line": where_line,
                           "condition": _truncate_line(clause, 200),
                           "kind": "where-clause",
                           "states": _state_literals(clause)})
    guards.sort(key=lambda g: g["line"])
    return guards


def _state_literals(text: str) -> list[str]:
    """The compared values in a guard: quoted literals, else comparison tokens."""
    text = str(text or "")
    if quoted := list(dict.fromkeys(v.strip() for v in re.findall(
            r"""['"]([^'"]{1,60})['"]""", text) if v.strip())):
        return quoted[:4]
    tokens = (m.rsplit(".", 1)[-1].strip() for m in re.findall(
        r"(?:==|!=|>=|<=|>|<|\bis\b|\bin\b)\s*([A-Za-z_][\w.]*)", text))
    return list(dict.fromkeys(t for t in tokens
                              if t and t.lower() not in ("none", "null")))[:4]


def _state_literal(value: str) -> str:
    """``"shipped"`` -> ``shipped``; ``Status.SHIPPED`` -> ``SHIPPED``; else text."""
    text = str(value or "").strip()
    if match := re.fullmatch(r"""['"]([^'"]{1,80})['"]""", text):
        return match.group(1)
    if re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", text):
        return text.rsplit(".", 1)[-1]
    return _truncate_line(text, 80) or "(dynamic)"


def _guard_states(guards: list[dict]) -> str:
    """The distinct prior states a guard list names, or ``(unguarded)``."""
    states = dict.fromkeys(state for guard in guards for state in guard["states"])
    return ", ".join(states) or "(unguarded)"


def _transition_row(row: dict) -> str:
    """One pinned transition row: ``FROM -> TO  file:line  endpoint  guard: …``."""
    guards = "; ".join(f"{g['kind']}@{g['line']}: {g['condition']}"
                       for g in row["guards"][:2])
    if len(row["guards"]) > 2:
        guards += f" … +{len(row['guards']) - 2} more"
    return (f"   {row['from_state']} -> {row['to_state']}  "
            f"{_site(row['file'], row['line'])}  {row['endpoint']}  "
            f"guard: {'yes' if row['guard_present'] else 'NO'}  "
            f"fn {row['function']}()  evidence: {row['evidence']}"
            + (f"  [{guards}]" if guards else ""))

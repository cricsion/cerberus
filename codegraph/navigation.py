"""Navigation tools: bounded source slices, one-hop argument maps, blind spots.

The graph answers WHO is connected to WHOM; these tools answer what the code
around a hop looks like and what an argument became once it crossed.

Laws (pinned by ``tests/test_codgraph_navigation.py``):

- LAW-1 — graph is coordinates, source is content: every answer is a token view
  over an index-located span, sectioned above ``_SMALL_SPAN_LINES``.
- LAW-2 — three slice modes, a closed set (``_SLICE_MODES``): an unknown mode is
  ``ERROR: unknown mode``; a malformed focus line degrades to a note.
- LAW-3 — a hop is one edge plus the argument map the index does not model; a
  synthesized edge reports its wiring site, and a coordinate nobody owns is
  labelled ``SUSPECT_LINE_BASIS``.
- LAW-4 — a blind spot is a ranked list of unresolved refs (six ``_SCORE_*``
  weights, the ``1. score 8  app.py:13  function unsafe_query`` render,
  implementer counts, ``## n.`` blocks capped with totals).
- LAW-5 — containment and never-raise: hostile input is capped and echoes
  nothing private; every failure is an ``ERROR:``/guidance string.
- LAW-6 — cached summaries are read-only here: ``[CACHED SUMMARY: …]`` is
  injected when the sidecar has one, and the sidecar is never written.

Format laws are byte-frozen: ``# file:start-end (kind name)``, ``n: text``
bodies, ``--- def header`` / ``--- title (k of n)`` sections, the ``sliced:``
footer, the hop JSON key order, and ``## n. reference @ file:line`` blocks.
"""
from __future__ import annotations

import json
import re

from harness.codegraph import _common, _db, _ts, summaries
from harness.codegraph._common import (
    HARD_MAX_SECTION, Report, _as_int, _cap_chars, _cap_rows, _contained_file,
    _end_line_of, _env_int, _line_of, _walk,
)
from harness.config import get_default_config
from harness.tools._compat import tool

# Shared bodies stay module-level names: the pin suite reaches some directly.
_args_node = _common._args_node
_call_args = _common._call_arg_texts
_callee_tail = _common._callee_tail_tail
_DEF_TYPES = _ts.FUNCTION_NODE_TYPES | _ts.CLASS_NODE_TYPES
_COMMENT_TYPES = ("comment", "line_comment", "block_comment")


def _truncate_line(text: str, cap: int = 160) -> str:
    """Flatten whitespace and truncate at ``cap`` with the package ``" …"`` tail."""
    return _common._truncate_line(text, cap)


def _read_source(root: str, file_path: str):
    """``(source_bytes, path)`` for a node's file, or ``(None, None)``."""
    path = _contained_file(root, file_path)
    if path is None:
        return None, None
    try:
        return path.read_bytes(), path
    except OSError:
        return None, None
# ---------------------------------------------------------------------------
# node-kind groupings used by the slice
# ---------------------------------------------------------------------------

# The suffix rule catches the rest; the function/class exclusion keeps nested defs out.
_DECLARATION_TYPES = frozenset({
    "assignment", "augmented_assignment", "named_expression", "assignment_expression",
    "augmented_assignment_expression", "assignment_statement", "local_variable_declaration",
    "field_declaration", "init_declarator", "short_var_declaration", "var_declaration",
    "const_declaration", "variable_declaration", "lexical_declaration"})
_DECLARATION_SUFFIXES = ("_declaration", "_declarator")

# The condition text a taint check cares about: if / switch / try / ternary.
_GUARD_TYPES = frozenset({
    "if_statement", "elif_clause", "else_clause", "if_expression",
    "switch_statement", "switch_expression",
    "try_statement", "catch_clause", "finally_clause",
    "conditional_expression", "ternary_expression", "match_statement"})
_ID_LEAF_TYPES = _common._ID_LEAF_TYPES
_NAME_LAST_PARAM_TYPES = _common._NAME_LAST_PARAM_TYPES

_PY_KEYWORDS = frozenset({
    "False", "None", "True", "and", "as", "assert", "async", "await", "break",
    "class", "continue", "def", "del", "elif", "else", "except", "finally",
    "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal",
    "not", "or", "pass", "raise", "return", "try", "while", "with", "yield"})
_SLICE_MODES = ("full_or_window", "body", "def_use_slice")
_SMALL_SPAN_LINES = 60          # <= this many lines comes back verbatim
# Wide enough that the guard answering "is this caller authorized" is not dropped.
_SECTION_LINES = 24
_POLYMORPHIC_AT = 8             # CodeGraph's type-hierarchy threshold
_MAX_DECORATORS = 12            # a node with 40 decorators is not an answer
_MAX_RENDERED_REFS = 20         # blind-spot blocks per call, rest is marked

# What a call_site_basis reads when a synthesized edge carries no registeredAt.
SUSPECT_LINE_BASIS = (
    "edge line/col (suspect — synthesized edge with no registeredAt, so the "
    "coordinate is a placeholder, not a resolved call site)"
)

# Names that make a guard SECURITY-relevant rather than merely structural.
_GUARD_NAME_MARKERS = (
    "authorize", "auth", "permission", "ownership", "is_", "has_", "can_",
    "assert", "check", "validate", "allow", "deny", "role", "login", "admin",
    "owner",
)

# A guard clause: the test's FIRST statement leaves the function (not break/continue).
_EARLY_EXIT_TYPES = frozenset({
    "return_statement", "raise_statement", "throw_statement", "return",
    "throw", "return_expression", "yield_statement"})
_BLOCK_TYPES = frozenset({
    "block", "statement_block", "suite", "_suite", "statements", "compound_statement"})


def _is_declaration(node) -> bool:
    """True when a node introduces a name (a nested def/class never does)."""
    if node.type in _DEF_TYPES:
        return False
    return node.type in _DECLARATION_TYPES or node.type.endswith(_DECLARATION_SUFFIXES)


def _def_node(tree, start: int, end: int):
    """The innermost function/class whose span covers ``[start, end]``."""
    try:
        root = tree.root_node
    except Exception:
        return None
    best, best_key = None, None
    for node in _walk(root):
        if node.type not in _DEF_TYPES:
            continue
        s, e = _line_of(node), _end_line_of(node)
        if not s or e < end or s > start:
            continue
        key = (e - s, node.end_byte - node.start_byte)
        if best is None or key < best_key:
            best, best_key = node, key
    return best


def _def_header(node, src: bytes) -> str:
    """``def f(a, b):`` / ``function f(a) {`` — the signature, not the body."""
    if node is None:
        return ""
    body = (node.child_by_field_name("body")
            or node.child_by_field_name("statement_block")
            or node.child_by_field_name("block"))
    if body is not None:
        try:
            raw = src[node.start_byte:body.start_byte]
        except Exception:
            raw = b""
        text = raw.decode("utf-8", errors="replace").strip().rstrip("{").strip()
        if text:
            return _truncate_line(text, 800)
    text = _ts.node_text(node, src)
    return _truncate_line(text.splitlines()[0] if text else "")


def _block_leaves_early(block) -> bool:
    """True when ``block``'s first statement returns or raises."""
    if block is None:
        return False
    if block.type in _EARLY_EXIT_TYPES:
        return True
    if block.type not in _BLOCK_TYPES:
        return False
    for child in block.named_children:
        if child.type in _COMMENT_TYPES:
            continue
        return child.type in _EARLY_EXIT_TYPES
    return False


def _guard_is_security_shaped(node, src: bytes) -> bool:
    """Relevance, not syntax: auth/validation names and guard clauses that exit early."""
    try:
        condition = _common._guard_condition(node, src).lower()
    except Exception:
        condition = ""
    if any(marker in condition for marker in _GUARD_NAME_MARKERS):
        return True
    for field in ("consequence", "body", "statement_block", "block"):
        if _block_leaves_early(node.child_by_field_name(field)):
            return True
    # Grammars that do not name the consequence: the last named child is the body.
    if node.type.endswith(("_clause", "_statement")):
        named = [c for c in node.children
                 if c.is_named and c.type not in _COMMENT_TYPES]
        if named and _block_leaves_early(named[-1]):
            return True
    return False


def _identifiers_on_line(def_node, line: int, src: bytes, line_text: str) -> list[str]:
    """The names written on ``line`` — the def-use keys for the focus section."""
    names: list[str] = []
    seen: set[str] = set()
    if def_node is not None:
        for node in _walk(def_node):
            if _line_of(node) != line or node.type not in _ID_LEAF_TYPES:
                continue
            text = _ts.node_text(node, src).strip()
            if text and text not in seen:
                seen.add(text)
                names.append(text)
    if not names:
        # No parse (or the line is outside the def): a word-boundary fallback.
        for token in re.findall(r"[A-Za-z_$][\w$]*", line_text or ""):
            if token not in _PY_KEYWORDS and token not in seen:
                seen.add(token)
                names.append(token)
    return [n for n in names if len(n) >= 2]
# ---------------------------------------------------------------------------
# 1. get_ast_slice
# ---------------------------------------------------------------------------


@tool(parse_docstring=True)
def get_ast_slice(node_id: str, focus_line: int | None = None,
                  mode: str = "full_or_window", root: str = ".",
                  limit: int | None = None) -> str:
    """What is the source of this CodeGraph node, without flooding the context?
    A small node comes back verbatim with its numbered span, decorators,
    signature and cached summary; a long one comes back sliced — signature,
    declarations, guards and, for ``focus_line``, only the statements that
    reference that line's identifiers. A capped guard section keeps the
    guard-shaped rows first and names the lines it withheld. Do NOT dump a whole
    file through it, and do NOT use ``mode='body'`` on a 1,000-line handler.

    Args:
        node_id: CodeGraph node id (a content hash) to read.
        focus_line: Line whose identifiers the def-use slice keys on.
        mode: ``full_or_window`` (verbatim <= 60 lines, else sliced), ``body``
            (always verbatim), or ``def_use_slice`` (slices a long span).
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Per-section cap for declarations/guards/focus rows. 0 = unlimited.

    Returns:
        A bounded, numbered source view, or an ``ERROR:``/guidance string.
    """
    conn, node, error = _common.tool_gate(root, node_id=node_id)
    if error:
        return error
    chosen = str(mode or "").strip().lower() or "full_or_window"
    if chosen not in _SLICE_MODES:
        return _cap_chars(f"ERROR: unknown mode {mode!r} "
                          f"(use one of {', '.join(_SLICE_MODES)})")
    # A direct call can hand over anything; a malformed focus degrades to no focus.
    focus: int | None = None
    if focus_line is not None:
        try:
            focus = int(focus_line)
        except (TypeError, ValueError):
            focus = None
    file_path = str(node.get("file_path") or "")
    kind = str(node.get("kind") or "node")
    name = str(node.get("name") or node_id)
    try:
        start, end = int(node.get("start_line")), int(node.get("end_line"))
    except (TypeError, ValueError):
        return _cap_chars(f"ERROR: node has no usable line span: {node_id}")
    if end < start:
        start, end = end, start
    span_lines = (end - start + 1) if end >= start else 0
    meta: list[str] = [f"# {file_path}:{start}-{end} ({kind} {name})"]
    hint = summaries.cache_hint(conn, node_id)
    if hint:
        meta.append(hint)
    decorators = node.get("decorators") or []
    signature = str(node.get("signature") or "")
    if decorators:
        shown_dec = list(decorators)[:_MAX_DECORATORS]
        meta.append("decorators: " + ", ".join(str(d) for d in shown_dec)
                    + (f", … +{len(decorators) - len(shown_dec)} more"
                       if len(decorators) > len(shown_dec) else ""))
    if signature:
        meta.append("signature: " + _truncate_line(signature, 800))
    if focus_line is not None and focus is None:
        meta.append(f"note: focus_line {focus_line!r} is not a line number — ignored")
    src, _path = _read_source(root, file_path)
    if src is None:
        meta.append("(source file not readable through this root — showing graph "
                    "metadata only; node_modules/vendor are never indexed)")
        return _cap_chars("\n".join(meta))
    text = src.decode("utf-8", errors="replace")
    text_lines = text.splitlines()
    tree = _ts.parse_source(text, str(node.get("language") or ""))
    if span_lines <= _SMALL_SPAN_LINES or chosen == "body":
        return _full_span(meta, text_lines, start, end, span_lines, focus)
    return _slice_span(meta, src, text_lines, tree, signature, start, end,
                       span_lines, focus, chosen, limit)


def _full_span(meta, text_lines, start, end, span_lines, focus) -> str:
    """The verbatim numbered span, with the focus note that shape earns."""
    if focus is not None and span_lines > _SMALL_SPAN_LINES:
        meta.append(f"note: focus_line {focus} ignored — full span shown")
    elif focus is not None and not (start <= focus <= end):
        meta.append(f"note: focus_line {focus} is outside node span "
                    f"{start}-{end} — full span shown")
    body = "\n".join(f"{n}: {text_lines[n - 1]}"
                     for n in range(start, min(end, len(text_lines)) + 1))
    return _cap_chars("\n".join(meta + ([body] if body else [])))


def _slice_span(meta, src, text_lines, tree, signature, start, end, span_lines,
                focus, chosen, limit) -> str:
    """The sectioned view: def header, declarations, guards and focus rows."""
    cap = min(_cap_rows(limit, "CODEGRAPH_SLICE_LIMIT", _SECTION_LINES),
              HARD_MAX_SECTION)
    def_node = _def_node(tree, start, end)
    header_text = _def_header(def_node, src) or signature
    if header_text:
        meta.extend([f"--- def header", header_text])
    meta.append(f"note: span is {span_lines} lines — sliced (mode={chosen}); "
                f"pass mode='body' for the exact span")
    decls = _declaration_rows(def_node, src, start, end)
    decl_lines = sorted(decls)
    guard_lines, guards, shown_guards, guard_note = _guard_rows(
        def_node, src, start, end, cap)
    # focus: statements referencing the identifiers on focus_line
    focus_rows: list[str] = []
    focus_keys: list[str] = []
    if focus is not None:
        if 1 <= focus <= len(text_lines):
            focus_keys = _identifiers_on_line(def_node, focus, src,
                                              text_lines[focus - 1])
        if not (start <= focus <= end):
            meta.append(f"note: focus_line {focus} is outside node span {start}-{end}")
        if focus_keys:
            for n in range(start, min(end, len(text_lines)) + 1):
                if n == focus:
                    continue
                line_text = text_lines[n - 1]
                if any(re.search(rf"\b{re.escape(k)}\b", line_text) for k in focus_keys):
                    focus_rows.append(f"{n}: {_truncate_line(line_text)}")
        elif focus:
            meta.append(f"note: no identifiers parsed on focus_line {focus}")
    sections = [
        ("declarations", "declarations",
         [f"{line}: {decls[line]}" for line in decl_lines[:cap]],
         len(decl_lines), ""),
        ("guards", "guards", [f"{line}: {guards[line]}" for line in shown_guards],
         len(guard_lines), guard_note),
        (f"focus (line {focus}: {', '.join(focus_keys[:6])})", "focus",
         focus_rows[:cap], len(focus_rows), ""),
    ]
    shown = (2 if header_text else 0) + sum(len(rows) for *_h, rows, _t, _n in sections)
    report = Report(meta)
    for title, label, rows, total, note in sections:
        if not rows and not total:
            continue
        report.section(title, len(rows), total)
        report.lines.extend(rows)
        if total > len(rows):
            report.more(total - len(rows), label, total)
            if note:
                report.lines.append(note)
    report.lines.append(f"sliced: {span_lines} lines -> {shown} shown "
               f"(declarations {min(len(decl_lines), cap)}/{len(decl_lines)}, "
               f"guards {len(shown_guards)}/{len(guard_lines)}, "
               f"focus {min(len(focus_rows), cap)}/{len(focus_rows)})")
    return report.text()


def _declaration_rows(def_node, src, start, end) -> dict[int, str]:
    """Line -> flattened declaration text, first declaration per line wins."""
    rows: dict[int, str] = {}
    for node in (_walk(def_node) if def_node is not None else ()):
        line = _line_of(node)
        if _is_declaration(node) and start <= line <= end and line not in rows:
            rows[line] = _truncate_line(_ts.node_text(node, src))
    return rows


def _guard_rows(def_node, src, start, end, cap):
    """``(all_lines, texts, shown_lines, note)``, keeping security-shaped rows when capped."""
    guards: dict[int, str] = {}
    priority: dict[int, int] = {}
    for node in (_walk(def_node) if def_node is not None else ()):
        if node.type not in _GUARD_TYPES:
            continue
        line = _line_of(node)
        if not start <= line <= end or line in guards:
            continue
        guards[line] = _common._guard_condition(node, src)
        priority[line] = 2 if _guard_is_security_shaped(node, src) else 1
    lines = sorted(guards)
    kept = set(lines)
    if cap < len(lines):
        ranked = sorted(lines, key=lambda line: (-priority.get(line, 1), line))
        kept = set(ranked[:cap])
    shown = [line for line in lines if line in kept]
    dropped = [line for line in lines if line not in kept]
    note = ""
    if dropped:
        note = (
            f"note: the guard section is capped at {cap} row(s) of "
            f"{len(lines)} — guard-shaped conditions (authorization, "
            f"permission, ownership, validation and early-return guards) are "
            f"kept first, so the least security-relevant rows were dropped: "
            f"{', '.join(str(line) for line in dropped)}; pass limit=0 (or "
            f"mode='body') for the rest"
        )
    return lines, guards, shown, note
# ---------------------------------------------------------------------------
# 2. trace_interprocedural_hop
# ---------------------------------------------------------------------------


def _params_from_def(tree, line: int, src: bytes, language: str) -> list[dict]:
    """The callee's parameters from ITS OWN definition (leading ``self`` kept)."""
    node = (_ts.enclosing_function(tree, line)
            or _ts.enclosing_node(tree, line))
    if node is None:
        return []
    return _common._param_list(
        node, src, lambda child: child.type in _NAME_LAST_PARAM_TYPES)


def _find_call(tree, src: bytes, line: int, col: int | None, name: str,
               span=None):
    """``(call_node, basis, callee_text)`` — matching col, else the caller's span."""
    if tree is None:
        return None, "", ""
    candidates = _ts.calls_in_span(tree, line, line, src)
    exact = [c for c in candidates if _callee_tail(c["text"]) == name]
    if exact:
        if col:
            for call in exact:
                if call["col"] == col:
                    return call["node"], "edge line/col", _callee_text(call["node"], src)
        return exact[0]["node"], "edge line/col", _callee_text(exact[0]["node"], src)
    if span:
        lo, hi = span
        wider = [c for c in _ts.calls_in_span(tree, lo, hi, src)
                 if _callee_tail(c["text"]) == name]
        if wider:
            return (wider[0]["node"],
                    f"caller span (line {wider[0]['line']}, not the edge's line)",
                    _callee_text(wider[0]["node"], src))
    return None, "", ""


def _iter_candidate_params(node: dict, root: str, src_cache: dict):
    """Parameters for a callee: its own def, else ``nodes.signature``."""
    language = str(node.get("language") or "")
    file_path = str(node.get("file_path") or "")
    start = _as_int(node.get("start_line"), 0)
    if file_path not in src_cache:
        src_cache[file_path] = _read_source(root, file_path)
    src, _path = src_cache[file_path]
    tree = (_ts.parse_source(src.decode("utf-8", errors="replace"), language)
            if src is not None else None)
    if tree is not None and start:
        params = _params_from_def(tree, start, src, language)
        if params:
            return params, "tree-sitter def"
    return (_ts.parse_signature_params(str(node.get("signature") or ""), language),
            "nodes.signature")


def _callee_text(call_node, src: bytes) -> str:
    """The callee exactly as written: ``svc.handle`` for a member call."""
    if call_node is None:
        return ""
    for field in ("function", "callee", "method", "name"):
        child = call_node.child_by_field_name(field)
        if child is not None:
            text = _ts.node_text(child, src).strip()
            if text:
                return text
    named = [c for c in call_node.children if c.is_named]
    return _ts.node_text(named[0], src).strip() if named else ""
# A written-out receiver never passes ``self``, so index 0 is a real argument.
_RECEIVER_SEPARATORS = (".", "::", "->", "\\")


def _receiver_is_implicit(callee_text: str) -> bool:
    """True when the call site spells the receiver out (a bound/static call)."""
    return any(sep in str(callee_text or "") for sep in _RECEIVER_SEPARATORS)


def _arg_param_map(call_args: list[str], params: list[dict],
                   receiver_implicit: bool = False) -> list[dict]:
    """Positional/keyword alignment; ``receiver_implicit`` drops a leading self/cls."""
    if receiver_implicit and params and params[0]["name"] in ("self", "cls"):
        params = params[1:]
    by_name = {p["name"]: p for p in params}
    out: list[dict] = []
    for index, raw in enumerate(call_args):
        keyword = None
        target = params[index] if index < len(params) else None
        match = re.match(r"^([A-Za-z_$][\w$]*)\s*=(?!=)", raw)
        if match and match.group(1) in by_name:
            keyword = match.group(1)
            target = by_name[keyword]
        out.append({"call_arg_index": index,
                    "call_expr": raw if len(raw) <= 80 else raw[:80] + "…",
                    "callee_param": target["name"] if target else None,
                    "param_type": target.get("type") or "" if target else None,
                    "keyword": keyword})
    return out


@tool(parse_docstring=True)
def trace_interprocedural_hop(source_node_id: str, target_node_id: str,
                              root: str = ".") -> str:
    """Where exactly does one call hop happen, and what argument crossed it?
    Resolves the ``calls`` edge (falling back to any kind) between two node ids
    and reports the call site, provenance and wiring site, confidence, the
    argument-to-parameter map the graph does not model, and a numbered window
    around the call. A synthesized edge's own line/col are usually placeholders
    (``idx_edges_identity`` needs uniqueness), so its ``metadata.registeredAt``
    wiring site is what gets reported. Use it once per hop; for a path use the
    graph tools.

    Args:
        source_node_id: Caller node id.
        target_node_id: Callee node id.
        root: Repo root holding ``.codegraph/codegraph.db``.

    Returns:
        A JSON block with ``call_site``, ``provenance``, ``wiring_site``,
        ``confidence``, ``arg_to_param_map`` and ``caller_window``, or a
        guidance string naming ``resolve_blind_spot`` when no edge exists.
    """
    conn, source, error = _common.tool_gate(root, node_id=source_node_id)
    if error:
        return error
    target = _db.get_node(conn, target_node_id)
    if target is None:
        return _cap_chars(f"ERROR: node not found: {target_node_id}")
    edge = _pick_edge(conn, source_node_id, target_node_id)
    if edge is None:
        return _no_edge_guidance(conn, source, target)
    meta = edge.get("metadata") or {}
    kind = str(edge.get("kind") or "")
    provenance = edge.get("provenance")
    synthesized_by = meta.get("synthesizedBy")
    registered_at = meta.get("registeredAt")
    # SQLite column types are advisory: coerce once here rather than at each use.
    line, col = _as_int(edge.get("line"), 0), _as_int(edge.get("col"), 0)
    source_file = str(source.get("file_path") or "")
    target_name = str(target.get("name") or "")
    notes: list[str] = []
    # A synthesizer's edge carries coordinates it does not own: the identity index
    # forces a placeholder, and the provenance itself marks a heuristic hop.
    suspect = (bool(synthesized_by)
               or str(provenance or "").strip().lower()
               in ("heuristic", "synthesized", "inferred")
               or not line)
    call_site, basis = _call_site(source_file, line, suspect, registered_at, notes)
    confidence = meta.get("confidence")
    try:
        confidence = float(confidence)
        if confidence < 0.6:
            notes.append("confidence is below CodeGraph's UNCERTAIN_BELOW=0.6: "
                         "a name-only guess, not a call")
    except (TypeError, ValueError):
        confidence = "not recorded"
    if synthesized_by:
        notes.append(f"synthesized edge ({synthesized_by}); provenance is "
                     f"{provenance!r}, not a resolved call")
    if kind != "calls":
        notes.append(f"no calls edge for this pair; falling back to kind={kind!r}")
    # --- the call site, parsed locally ---------------------------------
    src, _path = _read_source(root, source_file)
    tree = (_ts.parse_source(src.decode("utf-8", errors="replace"),
                             str(source.get("language") or ""))
            if src is not None else None)
    call_node, found_by, callee_text = (None, "", "")
    if tree is not None and line:
        call_node, found_by, callee_text = _find_call(
            tree, src, line, col or None, target_name)
        if call_node is None:
            span = (_as_int(source.get("start_line"), 1) or 1,
                    _as_int(source.get("end_line"), 1) or 1)
            call_node, found_by, callee_text = _find_call(
                tree, src, 0, None, target_name, span=span)
    if call_node is not None:
        arg_map = _arg_binding(target, root, call_node, callee_text, src,
                               found_by, notes)
    else:
        arg_map = []
        notes.append(
            "no textual call to this target in the caller: the connection is a "
            "synthesizer's, so the argument that crosses it is not visible at "
            "the call site" if suspect else
            "no matching call parsed at the edge's call site; "
            "arg_to_param_map is empty")
    caller_window = ""
    if src is not None and line:
        caller_window = _ts.window(src, line, 3)
        if suspect and registered_at:
            notes.append(f"caller_window is centred on the edge's own (suspect) "
                         f"line {line} in {source_file}, not on the wiring site")
    elif registered_at:
        caller_window = (f"(caller window unavailable: {call_site} is a wiring "
                         f"site, not a line in {source_file})")
    payload = {
        "source": source_node_id,
        "target": target_node_id,
        "edge_kind": kind,
        "call_site": call_site,
        "call_site_basis": basis,
        "edge_line_col": {"line": line, "col": col} if line or col else None,
        "provenance": provenance,
        "synthesized_by": synthesized_by,
        "wiring_site": registered_at if synthesized_by else None,
        "confidence": confidence,
        "arg_to_param_map": arg_map,
        "caller_window": caller_window,
        "notes": notes,
    }
    return _cap_chars(json.dumps(payload, indent=2, sort_keys=False))


def _pick_edge(conn, source_id: str, target_id: str):
    """The edge between the pair, preferring ``calls`` over other kinds."""
    edges = _db.get_edges(conn, source=source_id, target=target_id)
    for preferred in ("calls", "instantiates", "references", "navigates"):
        edge = next((e for e in edges if e.get("kind") == preferred), None)
        if edge is not None:
            return edge
    return edges[0] if edges else None


def _call_site(source_file, line, suspect, registered_at, notes):
    """``(call_site, basis)`` — the wiring site, the edge line, or nothing."""
    if suspect and registered_at:
        return str(registered_at), (
            "metadata.registeredAt — the edge is synthesized, so its own line/col "
            "are suspect (idx_edges_identity uniqueness often forces a "
            "placeholder); this is the synthesizer's wiring site")
    if line:
        return (f"{source_file}:{line}",
                SUSPECT_LINE_BASIS if suspect else "edge line/col")
    notes.append("the edge carries no line/col at all and no wiring site: "
                 "no call site can be reported")
    return "", "unknown"


def _arg_binding(target, root, call_node, callee_text, src, found_by, notes):
    """The argument->parameter map for the parsed call, appending its notes."""
    call_exprs = _call_args(call_node, src)
    params, basis = _iter_candidate_params(target, root, {})
    bound = _receiver_is_implicit(callee_text)
    effective = params
    if bound and params and params[0]["name"] in ("self", "cls"):
        effective = params[1:]
        notes.append("receiver is implicit at this call site: the callee's "
                     "leading self/cls parameter is not an argument")
    if not effective and call_exprs:
        notes.append(f"callee parameters unavailable ({basis}); "
                     "arguments are listed without a parameter binding")
    arg_map = _arg_param_map(call_exprs, params, bound)
    if found_by.startswith("caller span"):
        notes.append(f"call located at {found_by}, not at the edge's line/col")
    if effective and len(call_exprs) != len(effective):
        notes.append(f"arity differs: call passes {len(call_exprs)} argument(s), "
                     f"callee declares {len(effective)} parameter(s) ({basis})")
    return arg_map


def _no_edge_guidance(conn, source: dict, target: dict) -> str:
    """No edge between the pair: is it a blind spot, or just unrelated?"""
    source_id = str(source.get("id") or "")
    target_name = str(target.get("name") or "")
    refs = _db.unresolved_refs(conn, node_id=source_id, limit=0)
    matches = [r for r in refs if str(r.get("name_tail") or "") == target_name
               or str(r.get("reference_name") or "") == target_name]
    lines = [f"# no edge from {source_id} to {target.get('id')} in the index"]
    if matches:
        for ref in matches[:5]:
            lines.append(
                f"unresolved ref: {ref.get('reference_name')} at "
                f"{ref.get('file_path')}:{ref.get('line')} "
                f"(kind {ref.get('reference_kind')}, status {ref.get('status')})")
        lines.append(f"the resolver saw this reference and failed on it "
                     f"({len(refs)} unresolved ref(s) for the caller)")
    else:
        lines.append(f"no unresolved ref matching {target_name!r} either "
                     f"({len(refs)} unresolved ref(s) for the caller) — the two "
                     "nodes are genuinely unconnected in this index")
    lines.append(f"hint: call resolve_blind_spot(node_id={source_id!r}) for "
                 "candidate targets of the caller's failed references")
    return _cap_chars("\n".join(lines))
# ---------------------------------------------------------------------------
# 3. resolve_blind_spot
# ---------------------------------------------------------------------------

_SCORE_EXACT_NAME = 3
_SCORE_TAIL = 2
_SCORE_SAME_FILE = 2
_SCORE_SAME_LANGUAGE = 1
_SCORE_ARITY = 2
_SCORE_ARITY_NEAR = 1
_SCORE_IMPLEMENTERS = 1
_TOP_CANDIDATES = 5

# ``nodes.kind`` values that own implementers — NOT tree-sitter node types.
_CLASS_KINDS = frozenset({
    "class", "interface", "trait", "protocol", "struct", "record", "enum",
    "object", "contract", "annotation", "mixin", "module", "namespace", "type"})
# Kinds whose implementers are reached through their ``contains`` parent.
_CALLABLE_KINDS = frozenset({
    "function", "method", "constructor", "component", "property", "field"})


def _candidate_pool(conn, ref: dict, cap: int) -> list[dict]:
    """Every node that could be the target of one unresolved reference."""
    reference_name = str(ref.get("reference_name") or "").strip()
    name_tail = str(ref.get("name_tail") or "").strip()
    if not name_tail:
        name_tail = reference_name.rsplit(".", 1)[-1]
    pool: dict[str, dict] = {}
    for name in (reference_name, name_tail):
        if name:
            for node in _db.find_nodes(conn, name=name, limit=cap):
                pool.setdefault(str(node.get("id")), node)
    if len(pool) < cap and name_tail:
        for node in _db.find_nodes(conn, name_like=f"%{name_tail}%", limit=cap):
            pool.setdefault(str(node.get("id")), node)
    return list(pool.values())
# The pinned ``why`` text is emitted by iterating this table in order; ``exact
# name`` and ``exact qualified name`` are mutually exclusive.
_SCORE_RULES = (
    ("exact name", _SCORE_EXACT_NAME,
     lambda cand, ref, ctx: ctx["exact"]),
    ("exact qualified name", _SCORE_EXACT_NAME,
     lambda cand, ref, ctx: not ctx["exact"] and ctx["qualified"]),
    ("name_tail", _SCORE_TAIL,
     lambda cand, ref, ctx: ctx["tail"]),
    ("same file", _SCORE_SAME_FILE,
     lambda cand, ref, ctx: bool(ref.get("file_path"))
     and cand.get("file_path") == ref.get("file_path")),
    ("same language", _SCORE_SAME_LANGUAGE,
     lambda cand, ref, ctx: bool(ref.get("language"))
     and cand.get("language") == ref.get("language")),
)


def _score_candidate(candidate: dict, ref: dict, call_arity, conn,
                     root: str, src_cache: dict) -> tuple[int, list[str]]:
    """Weight a candidate: name ladder, locality, arity fit, implementer fan-out."""
    reference_name = str(ref.get("reference_name") or "").strip()
    name_tail = str(ref.get("name_tail") or "").strip()
    if not name_tail:
        name_tail = reference_name.rsplit(".", 1)[-1]
    cand_name = str(candidate.get("name") or "")
    ctx = {
        "exact": bool(reference_name) and cand_name == reference_name,
        "qualified": bool(reference_name)
        and str(candidate.get("qualified_name") or "") == reference_name,
        "tail": bool(name_tail) and cand_name.rsplit(".", 1)[-1] == name_tail,
    }
    score = 0
    why: list[str] = []
    for reason, weight, applies in _SCORE_RULES:
        if applies(candidate, ref, ctx):
            score += weight
            why.append(reason)
    params, _basis = _iter_candidate_params(candidate, root, src_cache)
    if params and params[0]["name"] in ("self", "cls"):
        params = params[1:]  # a method's receiver is implicit at the call site
    variadic = any(p.get("variadic") for p in params)
    if call_arity is not None and params:
        if call_arity == len(params) or variadic:
            score += _SCORE_ARITY
            why.append(f"arity {call_arity}/{len(params)}")
        elif abs(call_arity - len(params)) <= 1:
            score += _SCORE_ARITY_NEAR
            why.append(f"arity {call_arity}~{len(params)}")
        else:
            why.append(f"arity {call_arity}!={len(params)}")
        if variadic:
            why.append("variadic")
    elif call_arity is not None:
        why.append(f"arity {call_arity}/? (callee params unparsed)")
    implementers = _implementer_count(conn, candidate)
    if implementers:
        score += _SCORE_IMPLEMENTERS
        note = f"{implementers} implementer(s)"
        if implementers >= _POLYMORPHIC_AT:
            note += " — polymorphic (dynamic dispatch decides)"
        why.append(note)
    return score, why


def _implementer_count(conn, candidate: dict) -> int:
    """Incoming ``implements`` edges to the candidate's class (0 for none)."""
    if conn is None:
        return 0
    kind = str(candidate.get("kind") or "")
    owner_id = candidate.get("id") if kind in _CLASS_KINDS else None
    if owner_id is None and kind in _CALLABLE_KINDS:
        parent = _db.node_parent(conn, str(candidate.get("id")))
        if parent and str(parent.get("kind") or "") in _CLASS_KINDS:
            owner_id = parent.get("id")
    if owner_id is None:
        return 0
    return len(_db.incoming_edges(conn, str(owner_id), kinds=["implements"], limit=0))


def _call_arity_at(tree, src: bytes, line: int, names: tuple[str, ...]):
    """Arguments in the call on ``line`` whose callee tail matches ``names``."""
    if tree is None or not line:
        return None
    for call in _ts.calls_in_span(tree, line, line, src):
        if _callee_tail(call["text"]) in names:
            return len(_call_args(call["node"], src))
    return None


@tool(parse_docstring=True)
def resolve_blind_spot(node_id: str, root: str = ".", limit: int | None = None) -> str:
    """Which repo symbol could an unresolved reference actually be pointing at?
    Every reference the resolver failed on becomes a ranked candidate list —
    exact name, name tail, same file, same language, arity fit, and implementer
    count with a ``polymorphic`` note at >= 8 — so dynamic dispatch, reflection
    and keyed registries can be recovered without guessing.

    Use it when a hop reports no edge, a sink call cannot be resolved, or before
    claiming code is unreachable. Do NOT use it to prove a call: candidates are
    ranked hypotheses, and polymorphic ones cannot be settled statically.

    Args:
        node_id: Node whose unresolved references to recover.
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Unresolved references to read (0 = unlimited). At most 20 blocks
            are rendered per call; the rest is marked.

    Returns:
        A bounded recovery list, one block per reference with up to five ranked
        candidates (node_id, kind, file:line, reason).
    """
    conn, node, error = _common.tool_gate(root, node_id=node_id)
    if error:
        return error
    node_file = str(node.get("file_path") or "")
    refs, file_fallback = _recovery_refs(conn, node_id, node_file, limit)
    if not refs:
        return _cap_chars(f"# no unresolved references for {node_id} "
                          f"({node_file or 'no file'}) — nothing to recover")
    src_cache: dict[str, tuple] = {}
    tree_cache: dict[tuple, tuple | None] = {}
    report = Report([f"# blind spot recovery: {node_id} ({node_file})"])
    if file_fallback:
        # A FILE-level scan: a sibling's reference must not be attributed to this node.
        report.lines.append("file-level fallback — references near this node, not "
                   "necessarily inside it (the node id matched no unresolved "
                   "reference of its own)")
    report.lines.append(f"{len(refs)} unresolved reference(s) for this node")
    # Blocks stop at _MAX_RENDERED_REFS, so "+N more" counts what is not shown.
    for position, ref in enumerate(refs[:_MAX_RENDERED_REFS], start=1):
        report.blank().lines.extend(_render_ref(conn, position, ref, root, src_cache,
                                        tree_cache))
    if len(refs) > _MAX_RENDERED_REFS:
        report.blank().more(len(refs) - _MAX_RENDERED_REFS, "references",
                            len(refs))
    report.blank().lines.append(
        "hint: pick a candidate node_id and call "
        "trace_interprocedural_hop(source_node_id=..., target_node_id=...) "
        "to confirm the hop and its argument binding")
    return report.text()


def _recovery_refs(conn, node_id: str, node_file: str, limit):
    """``(refs, file_fallback)`` — the node's rows, else its file's rows."""
    cap = _cap_rows(limit, "CODEGRAPH_REFS_LIMIT", 50)
    refs = _db.unresolved_refs(conn, node_id=node_id, limit=cap)
    seen = {(str(r.get("reference_name")), r.get("line")) for r in refs}
    if refs or not node_file:
        return refs, False
    # The node id may be stale after a re-index: the file's rows still count.
    for ref in _db.unresolved_refs(conn, file_path=node_file, limit=cap):
        key = (str(ref.get("reference_name")), ref.get("line"))
        if key not in seen:
            seen.add(key)
            refs.append(ref)
    return refs, True


def _render_ref(conn, position: int, ref: dict, root: str, src_cache: dict,
                tree_cache: dict) -> list[str]:
    """One reference block: what is unresolved, then its ranked candidates."""
    from_path = str(ref.get("file_path") or "")
    reference_name = str(ref.get("reference_name") or "")
    name_tail = str(ref.get("name_tail") or "") or reference_name.rsplit(".", 1)[-1]
    lines = [
        f"## {position}. {reference_name} @ {from_path}:{ref.get('line')}",
        f"   reference_name: {reference_name}  name_tail: {name_tail}  "
        f"kind: {ref.get('reference_kind')}  status: {ref.get('status')}",
    ]
    stored = ref.get("candidates") or []
    if stored:
        lines.append(f"   index candidates: {', '.join(str(c)[:40] for c in stored[:5])}")
    # call-site arity, when the line parses to a call to this name
    call_arity = None
    key = (from_path, str(ref.get("language") or ""))
    if key not in tree_cache:
        src, _path = _read_source(root, from_path)
        tree_cache[key] = ((_ts.parse_source(src.decode("utf-8", errors="replace"),
                                             key[1]), src)
                           if src is not None else None)
    if tree_cache[key] is not None:
        tree, src = tree_cache[key]
        call_arity = _call_arity_at(tree, src, _as_int(ref.get("line"), 0),
                                    (reference_name, name_tail))
    if call_arity is not None:
        lines.append(f"   call-site arity: {call_arity} (parsed from "
                     f"{from_path}:{ref.get('line')})")
    cap = min(_env_int("CODEGRAPH_CANDIDATES",
                       int(get_default_config("codegraph.candidates"))),
              _db.HARD_MAX_ROWS)
    pool = [c for c in _candidate_pool(conn, ref, cap)
            if str(c.get("id")) != str(ref.get("from_node_id"))]
    scored = [(score, index, str(candidate.get("id") or ""), candidate, why)
              for index, candidate in enumerate(pool)
              for score, why in (_score_candidate(candidate, ref, call_arity,
                                                  conn, root, src_cache),)]
    scored.sort(key=lambda row: (-row[0], str(row[3].get("file_path") or ""),
                                 _as_int(row[3].get("start_line"), 0), row[2]))
    top = scored[:_TOP_CANDIDATES]
    if not top:
        lines.append(f"   candidates: none found for {name_tail!r} "
                     "(vendor/node_modules are never indexed)")
        return lines
    lines.append(f"   candidates ({len(top)} of {len(scored)}):")
    for rank, (score, _idx, _cid, candidate, why) in enumerate(top, start=1):
        lines.append(f"   {rank}. score {score}  {candidate.get('file_path')}:"
                     f"{_as_int(candidate.get('start_line'), 0)}  "
                     f"{candidate.get('kind')} {candidate.get('name')}")
        lines.append(f"      node_id: {candidate.get('id')}")
        lines.append(f"      why: {'; '.join(why) if why else 'name match only'}")
    return lines

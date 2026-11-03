"""Shared helpers for the four CodeGraph feature modules.

The feature modules grew private copies of the same primitives (caps, tree
walking, node labels, finding dicts, route joins, render shapes). This module
is the single survivor; it imports only the foundation (``_db``), never a
feature module, so the dependency direction stays one-way.

Contract — consumers (the per-module detail lives in the Stage-3 specs):
``_contained_file`` all five source readers (P5-validated); ``_assign_value``
authz raw / supply ``normalize_ws=True``; ``_route_map`` authz
``low_value_filter=False`` / supply ``True``; ``_callee_tail_full``
authz+supply, ``_callee_tail_tail`` nav+contracts; ``_node_label`` the shared
None-tolerant label; ``_call_arg_texts`` nav, ``_call_arg_records`` supply
(two names, never merged); ``_param_list`` + tables the leaf core for the
nav/contracts wrappers; ``_split_top_level`` a one-line alias of
``_ts._split_top_level``; caps / ``_env_int`` (delegates to
``_compat.env_int``); tree+DB helpers; ``Report`` the pinned block formats;
``tool_gate`` the driver preamble. Local by ruling: the two ``_clip`` shapes,
the ``_params_from_def`` wrappers and classifiers.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from cerberus.codegraph import _db, _ts
from cerberus.config import get_config
from cerberus.tools._compat import env_int
from cerberus.tools.code import _safe_path

HARD_MAX_SECTION = 200
_CONF_MIN, _CONF_MAX = 0.30, 0.85
_MAX_VALUE_CHARS = 160
_HANDLER_KINDS = ("function", "method", "class", "constant", "variable", "component")
_ROUTE_EDGE_KINDS = ("references", "calls")
_ID_LEAF_TYPES = frozenset({
    "identifier", "field_identifier", "property_identifier", "type_identifier",
    "shorthand_property_identifier", "shorthand_property_identifier_pattern",
    "simple_identifier", "word"})
_NAME_LAST_PARAM_TYPES = frozenset({
    "formal_parameter", "parameter", "parameter_spec", "fixed_parameter",
    "typed_parameter", "required_parameter", "optional_parameter"})
_PARAM_SKIP_TYPES = frozenset({"comment", "line_comment", "block_comment"})
_VARIADIC_PARAM_TYPES = frozenset({
    "list_splat_pattern", "dictionary_splat_pattern", "rest_parameter",
    "spread_parameter", "variadic_parameter", "rest_pattern", "splat_pattern"})
# Splitting a signature is grammar work already solved in ``_ts``.
_split_top_level = _ts._split_top_level

def _env_int(key: str, default: int) -> int:
    """Read an int env override; ``default`` on empty/invalid input (never raises)."""
    return env_int(key, default)

def _cap_rows(limit, env_key: str, default: int) -> int:
    """Explicit arg wins, then env; ``<=0`` = unlimited, clamped to the DB ceiling."""
    n = _env_int(env_key, default) if limit is None else _as_int(limit, default)
    return _db.HARD_MAX_ROWS if n <= 0 else min(n, _db.HARD_MAX_ROWS)

def _section_cap(env_key: str, default: int) -> int:
    """A per-section cap that never outgrows :data:`HARD_MAX_SECTION`."""
    return min(_env_int(env_key, default), HARD_MAX_SECTION)

def _cap_chars(text: str) -> str:
    """Apply the ``codegraph.chars`` budget, preserving the pinned tail."""
    lim = int(get_config()["codegraph"]["chars"])
    if lim <= 0 or len(text) <= lim:
        return text
    return text[:lim] + f"\n… +{len(text) - lim} more chars (total {len(text)})"

def _truncate_line(text: str, cap: int) -> str:
    """Flatten whitespace and truncate at ``cap`` with the pinned ``" …"`` tail."""
    flat = " ".join(str(text or "").split())
    return flat if len(flat) <= cap else flat[:cap] + " …"

def _as_int(value, default: int = 0) -> int:
    """Coerce a possibly-advisory SQLite column to int without raising."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def _contained_file(root: str, file_path: str) -> Path | None:
    """Resolve a repo-relative ``nodes.file_path`` under ``root``, or ``None``.

    Never raises: escapes, missing/unreadable files, the indexer's 1 MB cap and
    unaddressable spellings (NUL -> ``ValueError``, long component -> ``OSError``)
    are all misses. Containment is re-checked after ``resolve()`` so a symlink
    out is refused; the leading-slash candidate keeps ``/app.py`` working.
    """
    rel = str(file_path or "").strip().replace("\\", "/")
    if not rel:
        return None
    try:
        base = _safe_path(str(root) if root is not None else ".")
        try:
            if base.is_file():
                base = base.parent  # a tool may point at one file, not a tree
        except (OSError, ValueError):
            return None
    except (OSError, ValueError):
        return None
    candidates: list[Path] = []
    try:
        candidates.append((base / rel).resolve())
    except (OSError, ValueError):
        pass  # unaddressable spelling: the virtual candidate is next
    if rel.startswith("/"):
        try:  # a leading slash may be the repo's own virtual path
            candidates.append(_safe_path(rel))
        except (OSError, ValueError):
            pass
    for cand in candidates:
        try:
            cand.relative_to(base)  # re-check after resolving symlinks
        except ValueError:
            continue
        try:
            if not cand.is_file():
                continue
        except (OSError, ValueError):
            continue
        try:
            if cand.stat().st_size > _ts.MAX_FILE_BYTES:
                continue
            cand.read_bytes()  # readability probe: unreadable is a miss
        except (OSError, ValueError):
            continue
        return cand
    return None

def _parsed_file(root: str, file_path: str, cache: dict):
    """``(tree, source_bytes)`` for a contained file, parsed once per call."""
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

def _walk(node):
    """Depth-first, parent before children (never raises on partial nodes)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        try:
            stack.extend(reversed(list(current.children)))
        except Exception:
            continue

def _line_of(node) -> int:
    """1-based start line, 0 when unavailable."""
    try:
        return int(node.start_point[0]) + 1
    except Exception:
        return 0

def _end_line_of(node) -> int:
    """1-based end line, 0 when unavailable."""
    try:
        return int(node.end_point[0]) + 1
    except Exception:
        return 0

def _node_span(node) -> tuple[int, int]:
    """``(start_line, end_line)`` of a node dict, clamped to a sane span."""
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

def _args_node(call_node):
    """The bracketed argument list of a call, whatever the grammar calls it."""
    for field in ("arguments", "argument_list", "arguments_list", "parameter_list"):
        child = call_node.child_by_field_name(field)
        if child is not None:
            return child
    for child in reversed(list(call_node.children)):
        if child.is_named and "argument" in child.type:
            return child
    return None

def _call_arg_texts(call_node, src: bytes) -> list[str]:
    """Top-level argument expressions as one-line text (navigation, ``list[str]``)."""
    args = _args_node(call_node)
    if args is None:
        return []
    out: list[str] = []
    for child in args.named_children:
        if child.type in _PARAM_SKIP_TYPES:
            continue
        text = _ts.node_text(child, src).strip()
        if text:
            out.append(" ".join(text.split()))
    return out

def _call_arg_records(call_node, src: bytes) -> list[dict]:
    """Top-level arguments as ``{index, text, keyword, node}`` (supply only)."""
    args = _args_node(call_node)
    if args is None:
        return []
    out: list[dict] = []
    for index, child in enumerate(args.named_children):
        if child.type in _PARAM_SKIP_TYPES:
            continue
        flat = " ".join(_ts.node_text(child, src).split())
        if not flat:
            continue
        match = re.match(r"^([A-Za-z_$][\w$]*)\s*=(?!=)", flat)
        out.append({"index": index, "text": _truncate_line(flat, _MAX_VALUE_CHARS),
                    "keyword": match.group(1) if match else "", "node": child})
    return out

def _param_list(def_node, src: bytes, name_first_last_selector) -> list[dict]:
    """Leaf-name core for the nav/contracts ``_params_from_def`` wrappers.

    Returns ``{name, type, index, variadic}`` rows. The selector says whether
    the NAME is the last identifier leaf (``_NAME_LAST_PARAM_TYPES``) or the
    first. Wrappers add grammar fields (contracts' ``default``) and skip rules
    (``self``/``cls``).
    """
    params = next((p for p in (def_node.child_by_field_name(f) for f in (
        "parameters", "formal_parameters", "parameter_list", "formal_parameter_list",
        "function_value_parameters", "arguments")) if p is not None), None)
    if params is None:
        params = next((c for c in def_node.children if c.type.endswith(
            ("parameters", "parameter_list"))), None)
    if params is None:
        return []
    out: list[dict] = []
    index = 0
    for child in params.named_children:
        if child.type in _PARAM_SKIP_TYPES:
            continue
        text = _ts.node_text(child, src).strip()
        if not text:
            continue
        leaves = [n for n in _walk(child) if n.type in _ID_LEAF_TYPES]
        if child.type in _ID_LEAF_TYPES:
            name = text
        elif leaves:
            wanted = leaves[-1] if name_first_last_selector(child) else leaves[0]
            name = _ts.node_text(wanted, src)
        else:
            name = ""
        name = re.sub(r"^[*.$\s]+", "", name).strip()
        type_node = child.child_by_field_name("type")
        type_text = (_ts.node_text(type_node, src).strip() if type_node is not None
                     else _ts.node_text(leaves[-1], src).strip()
                     if len(leaves) > 1 else "")
        if type_text == name:
            type_text = ""
        if not name and not type_text:
            continue
        out.append({"name": name, "type": type_text, "index": index,
                    "variadic": child.type in _VARIADIC_PARAM_TYPES})
        index += 1
    return out

def _assign_value(node, src: bytes, *, normalize_ws: bool = False) -> str:
    """The right-hand side of an assignment-ish node.

    ``normalize_ws`` is the old copies' only difference: authz kept the raw
    text, supply flattened whitespace. Callers state their choice.
    """
    for field in ("right", "value"):
        child = node.child_by_field_name(field)
        if child is not None:
            text = _ts.node_text(child, src)
            return " ".join(text.split()) if normalize_ws else text
    text = _ts.node_text(node, src)
    if "=" not in text:
        return ""
    tail = text.split("=", 1)[1]
    return " ".join(tail.split()) if normalize_ws else tail

def _callee_tail_full(text: str) -> str:
    """``db.run_query(...)`` -> ``run_query``, dropping the argument list (authz/supply)."""
    tail = str(text or "").strip()
    if "(" in tail:
        tail = tail.split("(", 1)[0].strip()
    return tail.rsplit(".", 1)[-1].lstrip("?!").strip()

def _callee_tail_tail(text: str) -> str:
    """``db.run_query`` -> ``run_query`` (nav/contracts; call list already stripped)."""
    return str(text or "").strip().rsplit(".", 1)[-1].lstrip("?!").strip()

def _site(file_path, line) -> str:
    """``path:line`` — the citation prefix shared by every module."""
    return f"{file_path}:{line}"

def _node_label(node: dict | None, with_span: bool = True) -> str:
    """``file:line (kind name[, span])`` — None-tolerant."""
    if not node:
        return "(unknown node)"
    file_path, name = str(node.get("file_path") or ""), str(node.get("name") or "")
    kind = str(node.get("kind") or "node")
    start = _as_int(node.get("start_line"), 0)
    if not with_span:
        return f"{_site(file_path, start)} ({kind} {name})"
    end = _as_int(node.get("end_line") or start, start)
    span = f"{start}-{end}" if end and end != start else str(start)
    return f"{_site(file_path, start)} ({kind} {name}, {span})"

def _guard_condition(node, src: bytes) -> str:
    """The guard's test expression (not its body), truncated to 200 chars."""
    for field in ("condition", "value", "subject"):
        child = node.child_by_field_name(field)
        if child is not None:
            return _truncate_line(_ts.node_text(child, src), 200)
    text = _ts.node_text(node, src)
    return text.splitlines()[0] if text else ""

def _confidence(base: float, *bonuses: float) -> float:
    """Bounded confidence: a heuristic never claims certainty."""
    return round(max(_CONF_MIN, min(_CONF_MAX, base + sum(bonuses))), 2)

def _candidate_finding(*, title: str, path: str, start_line: int, end_line: int,
                       cwe: str, severity: str, confidence: float,
                       taint_source: str, taint_sink: str, taint_path,
                       evidence: str, rationale: str = "", note: str = "") -> dict:
    """One candidate finding in the hunter schema, keys in pinned order."""
    return {
        "title": title, "path": str(path or ""),
        "start_line": int(start_line or 0), "end_line": int(end_line or 0),
        "cwe": cwe, "severity": severity, "confidence": confidence,
        "taint": {"source": taint_source, "sink": taint_sink,
                  "path": [str(p) for p in (taint_path or [])][:20]},
        "evidence": _truncate_line(evidence, 400),
        "rationale": _truncate_line(rationale, 400), "note": note}

def _finding_lines(finding: dict, header: str) -> list[str]:
    """``## candidate finding …`` plus its JSON block, ready to append."""
    return [header, json.dumps(finding, indent=2, sort_keys=False)]

def _is_low_value(file_path: str, conn) -> bool:
    """The routing manifest's hygiene filter: test/generated handlers are dropped."""
    path = str(file_path or "")
    if not path:
        return False
    if _db.is_test_file(path):
        return True
    return _db.is_generated_file(conn, path)

def _route_handler(conn, route_id: str) -> dict | None:
    """The route's handler: outgoing ``references``/``calls`` to a handler kind.

    Mirrors ``getRoutingManifest``'s join so tool and manifest agree.
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

def _route_map(conn, *, low_value_filter: bool) -> dict:
    """``{by_id, by_site}``: handler -> url, manifest rows plus the id join.

    ``low_value_filter`` is the one divergence: supply applied the manifest's
    test/generated filter to the id join; authz compares sibling routes
    including vendor-ish handlers, so it passes ``False``.
    """
    by_id: dict[str, str] = {}
    by_site: dict[tuple, str] = {}
    for row in _db.routing_manifest(conn, limit=0):
        url = str(row.get("url") or "")
        key = (str(row.get("handler_file") or ""), _as_int(row.get("handler_line")))
        by_site.setdefault(key, url)
    for route in _db.find_nodes(conn, kind="route", limit=0):
        handler = _route_handler(conn, str(route.get("id") or ""))
        if handler is None:
            continue
        if low_value_filter and _is_low_value(str(handler.get("file_path") or ""), conn):
            continue
        by_id.setdefault(str(handler.get("id") or ""), str(route.get("name") or ""))
    return {"by_id": by_id, "by_site": by_site}

class Report:
    """Pinned block formats: ``## n. …``, ``## side A — role``, ``--- title
    (k of n)`` / ``--- title (n)``, ``… +N more label (total T)`` and authz's
    ``(+N more noun, capped at N)``. ``text()`` applies ``_cap_chars`` once."""

    def __init__(self, lines: list[str] | None = None) -> None:
        """Copy initial report lines so callers can safely reuse their list."""
        self.lines: list[str] = list(lines or [])

    def blank(self) -> Report:
        """Append the block separator drivers use between sections."""
        self.lines.append("")
        return self

    def numbered(self, position: int, title: str) -> Report:
        """``## n. title`` (navigation reference blocks)."""
        self.lines.append(f"## {position}. {title}")
        return self

    def section(self, title: str, shown: int, total: int | None = None,
                detail: str = "") -> Report:
        """``--- title (shown of total[detail])``, or ``(shown)`` without a total."""
        if total is None:
            self.lines.append(f"--- {title} ({shown})")
        else:
            self.lines.append(f"--- {title} ({shown} of {total}{detail})")
        return self

    def more(self, rest: int, label: str, total: int | None = None) -> Report:
        """``… +rest more label`` with ``(total N)`` only when known."""
        line = f"… +{rest} more {label}"
        self.lines.append(line + (f" (total {total})" if total is not None else ""))
        return self

    def inline_more(self, rest: int, label: str = "") -> str:
        """Mid-line ``", … +N more label"`` (empty when ``rest <= 0``)."""
        return f", … +{rest} more {label}" if rest > 0 else ""

    def capped(self, rest: int, noun: str, cap: int) -> str:
        """Inline ``"(+N more noun, capped at N)"``."""
        return f" (+{rest} more {noun}, capped at {cap})"

    def text(self) -> str:
        """Join and apply the package character budget once."""
        return _cap_chars("\n".join(self.lines))

def tool_gate(root: str, *, kind: str | None = None, node_id: str | None = None,
              hint: str = "") -> tuple:
    """Resolve the index, connect, and optionally fetch/kind-check one node.

    Returns ``(conn, node, error)``; ``error`` is a ready-to-return char-capped
    string (``""`` on success) and ``node`` is ``None`` when no ``node_id`` was
    given. The caller's ``hint`` is appended verbatim after the em dash in the
    kind-mismatch message, so each tool keeps its own pinned wording.
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return None, None, _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return None, None, _cap_chars(_db.guidance_no_db(root))
    if node_id is None:
        return conn, None, ""
    node = _db.get_node(conn, node_id)
    if node is None:
        return conn, None, _cap_chars(f"ERROR: node not found: {node_id}")
    found = str(node.get("kind") or "")
    if kind is not None and found != kind:
        tail = f" — {hint}" if hint else ""
        return conn, None, _cap_chars(
            f"ERROR: node {node_id} is kind {found!r}, not {kind!r}{tail}")
    return conn, node, ""

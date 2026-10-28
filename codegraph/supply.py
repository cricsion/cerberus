"""SSRF/egress inspection for CodeGraph.

One bounded inspection complements ordinary call-graph analysis: whether a
recognized network call in a function span uses a dynamic URL target.

LAWS
- Egress uses CONSTANT / DYNAMIC / PARTIAL verdicts.
- Source reads stay contained and byte-capped; the tool degrades to a bounded
  success-shaped report and never raises on hostile input.

FORMAT LAW: section titles, scope lines, verdict descriptors, finding JSON and
truncation tails are pin-frozen. The index is read-only; no network,
subprocess, or writes occur. List limits are hard-capped by ``_db.HARD_MAX_ROWS``.

"""
from __future__ import annotations

import json
import re

from harness.codegraph import _common, _db, _ts, sinks
from harness.tools._compat import tool

# ---------------------------------------------------------------------------
# caps — the package-wide env idiom; values frozen
# ---------------------------------------------------------------------------

ENV_FINDINGS = "CODEGRAPH_FINDINGS_LIMIT"
ENV_SINKS = "CODEGRAPH_EGRESS_LIMIT"

DEFAULT_FINDINGS = 10      # candidate findings per tool call
DEFAULT_SINKS = 40         # network call sites reported per span

MAX_EVIDENCE = 160         # per-row evidence truncation

# ---------------------------------------------------------------------------
# shared bodies live once in `_common`; the NAMES stay here because the pin
# suite reaches this module object directly (the widest seam surface in the
# package).  Each comment is the contract the alias keeps.
# ---------------------------------------------------------------------------

_cap_rows = _common._cap_rows        # arg, then env; <=0 unlimited, DB-clamped
_section_cap = _common._section_cap  # section cap never above HARD_MAX_SECTION
_cap_chars = _common._cap_chars      # CODEGRAPH_CHARS budget with the pinned tail
_contained_file = _common._contained_file  # P5 body; None on escape/unreadable
_parsed_file = _common._parsed_file  # (tree, src) parsed once per tool call
_walk = _common._walk                # depth-first, parent before children
_line_of, _end_line_of = _common._line_of, _common._end_line_of
_as_int = _common._as_int            # advisory SQLite column -> int, never raises
_truncate_line = _common._truncate_line  # flatten + cap with the `" …"` tail
_site, _node_span = _common._site, _common._node_span
_node_label = _common._node_label    # `file:line (kind name, span)`
_confidence = _common._confidence    # bounded [0.30, 0.85] heuristic
_candidate_finding = _common._candidate_finding  # hunter finding schema, key order
_call_args = _common._call_arg_records  # supply's historical name; records, not texts
_callee_tail = _common._callee_tail_full  # `db.run_query(...)` -> `run_query`

def _assign_value(node, src: bytes) -> str:
    """The right-hand text of an assignment, whitespace-flattened (supply's reading)."""
    return _common._assign_value(node, src, normalize_ws=True)


# ---------------------------------------------------------------------------
# graph vocabulary used when resolving call arguments
# ---------------------------------------------------------------------------

# Callable definitions whose parameter lists can resolve call arguments.
_CALLABLE_KINDS = ("function", "method", "constructor", "component", "class")

# Confidence remains a bounded heuristic, never a certainty claim.
_CONF_BASE = 0.45
_CONF_EVIDENCE = 0.20     # the setting supports it, or the whole host is dynamic
_CONF_GAP = 0.10          # the reference is unresolved, or the path is dynamic
_CONF_NOGUARD = 0.05      # no one-hop resolution, allow-list or fixup in between

# ---------------------------------------------------------------------------
# 1. trace_egress_and_ssrf_targets
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def trace_egress_and_ssrf_targets(network_sink_node_id: str, root: str = ".",
                                  limit: int | None = None) -> str:
    """
    Classify URL targets used by recognized network calls in a function span.

    The URL argument may resolve through one earlier assignment in the same
    function. Dynamic-host/path results are candidate SSRF signals, not proof;
    upstream allow-lists may constrain them, and unrecognized wrappers are omitted.

    Args:
        network_sink_node_id: Function making the calls, or a node inside it.
        root: Repo root containing the CodeGraph index.
        limit: Network call sites; 0 means unlimited up to the hard cap.

    Returns:
        A bounded span, URL-part verdicts, evidence, and candidate CWE-918 findings.
    """
    conn, node, error = _common.tool_gate(root, node_id=network_sink_node_id)
    if error:
        return error
    file_path = str(node.get("file_path") or "")
    language = str(node.get("language") or "")
    tree, src = _parsed_file(root, file_path, {})
    if tree is None:
        return _cap_chars(
            f"ERROR: source of {network_sink_node_id} is not readable through "
            f"this root ({file_path or 'no file'} — node_modules/vendor are "
            f"never indexed, and a file the indexer skipped has no spans "
            f"here either)")
    span = _egress_span(node, tree)
    if span is None:
        return _cap_chars(
            f"ERROR: no function span resolvable for {network_sink_node_id} "
            f"in {file_path} — pass the function that makes the network "
            f"calls, or a node inside it")

    calls = _ts.calls_in_span(tree, span[0], span[1], src)
    network: list[dict] = []
    for call in calls:
        categories = sinks.classify_call(call["text"], language)
        if "network" not in categories:
            continue
        network.append({
            "line": call["line"], "col": call["col"], "categories": categories,
            "callee": _callee_text(call["node"], src) or call["text"],
            "call_text": call["text"], "node": call["node"]})

    site_cap = _cap_rows(limit, ENV_SINKS, DEFAULT_SINKS)
    out: list[str] = [f"# egress & ssrf: {network_sink_node_id}",
                      f"root: {root}", f"node: {_node_label(node)}",
                      f"span: {file_path}:{span[0]}-{span[1]} "
                      f"({span[1] - span[0] + 1} lines, "
                      f"language {language or 'unknown'})",
                      f"calls in span: {len(calls)}  network: {len(network)}"]
    if not network:
        out += ["",
                "no network call in this span: nothing the effects taxonomy "
                "classifies as network was found",
                "hint: the callee must be recognised as written (requests.get, "
                "fetch, axios.*, http.Client, urllib.request…) — an egress "
                "hidden behind an unrecognised wrapper is not in the table"]
        return _cap_chars("\n".join(out))

    findings: list[dict] = []
    for position, site in enumerate(network[:site_cap], start=1):
        resolved = _resolve_url_argument(site, tree, src, language, conn, root)
        parts = _url_parts(resolved["expression"])
        verdict, severity, cwe, note = _egress_verdict(parts)
        block, finding = _egress_block(position, len(network), site, resolved,
                                       parts, verdict, severity, cwe, note,
                                       src, file_path)
        out += [""] + block
        if finding is not None:
            findings.append(finding)
    if len(network) > site_cap:
        out += ["", f"… +{len(network) - site_cap} more network calls (total "
                    f"{len(network)}); raise the limit to expand"]

    finding_cap = _section_cap(ENV_FINDINGS, DEFAULT_FINDINGS)
    out += ["", f"--- candidate findings ({len(findings)})"]
    if not findings:
        out.append("none: every network call in this span targets a "
                   "fully-constant URL")
    for index, finding in enumerate(findings[:finding_cap], start=1):
        out += [f"{index}. {finding['header']}",
                json.dumps(finding["finding"], indent=2, sort_keys=False)]
    if len(findings) > finding_cap:
        out.append(f"… +{len(findings) - finding_cap} more findings (total "
                   f"{len(findings)}); raise the limit to expand")
    return _cap_chars("\n".join(out))

def _egress_span(node: dict, tree) -> tuple[int, int] | None:
    """``(start, end)`` of the function whose egress is being traced."""
    node_span = _node_span(node)
    start_line = _as_int(node.get("start_line"), 0)
    enclosing = (_ts.enclosing_function(tree, start_line)
                 if tree is not None and start_line else None)
    if enclosing is not None:
        start, end = _line_of(enclosing), _end_line_of(enclosing)
        if start and end and end >= start:
            # Prefer the enclosing function when the node is inside it: the
            # span of a variable node is one line, which would hide every other
            # call in the same function.
            return (start, end)
    return node_span if node_span[0] else None

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

_URLISH_NAME_RE = re.compile(r"^(?:url|uri|endpoint|host|hostname|domain|target|"
                             r"dest|destination|base|baseurl|base_url|api|"
                             r"path|pathurl|callback|webhook)$", re.IGNORECASE)

def _resolve_url_argument(site: dict, tree, src: bytes, language: str, conn,
                          root: str) -> dict:
    """``{argument, keyword, expression, basis, resolved_from}`` for one call."""
    args = _call_args(site["node"], src)
    chosen = None
    basis = ""
    for arg in args:
        if "://" in arg["text"] or re.search(r"\bhttps?\b", arg["text"]):
            chosen, basis = arg, "contains a scheme/http"
            break
    if chosen is None:
        for arg in args:
            name = arg["keyword"] or _param_name(conn, site, arg, language, root)
            if name and _URLISH_NAME_RE.match(name):
                chosen, basis = arg, f"url-ish parameter name ({name})"
                break
    if chosen is None:
        for arg in args:
            if re.match(r"^[frbu]{0,2}[\"']", arg["text"]):
                chosen, basis = arg, "first string literal"
                break
    if chosen is None and args:
        chosen, basis = args[0], "first argument (no scheme, no url-ish name)"

    resolved_from = ""
    expression = chosen["text"] if chosen else ""
    if chosen is not None and chosen["keyword"]:
        # Parse only the keyword value; including `url=` would misclassify literals.
        expression = _strip_keyword_prefix(expression, chosen["keyword"])
    if chosen is not None and re.fullmatch(r"[A-Za-z_$][\w$.]*", expression):
        target = expression.lstrip("@$")
        assignment = _one_hop_assignment(tree, src, site["line"], target)
        if assignment is not None:
            expression = assignment["value"]
            resolved_from = (f"one-hop assignment {assignment['target']} = "
                             f"{assignment['value']} at "
                             f"{assignment['line']} (same function)")
        else:
            expression = ""
            resolved_from = (f"unresolved local {target} — no assignment to it "
                             f"earlier in this function")
    return {"argument": expression, "keyword": chosen["keyword"] if chosen else "",
            "expression": expression, "basis": basis,
            "resolved_from": resolved_from,
            "raw": chosen["text"] if chosen else ""}

def _strip_keyword_prefix(text: str, keyword: str) -> str:
    """Remove a grammar-captured ``name=`` prefix before URL parsing."""
    flat = " ".join(str(text or "").split())
    if not keyword or not flat:
        return flat
    return re.sub(rf"^{re.escape(keyword)}\s*=(?!=)\s*", "", flat).strip()

def _param_name(conn, site: dict, arg: dict, language: str, root: str) -> str:
    """The callee's parameter name for a positional argument, when known."""
    if conn is None:
        return ""
    tail = _callee_tail(site["call_text"])
    if not tail:
        return ""
    for node in _db.find_nodes(conn, name=tail, limit=5):
        if str(node.get("kind") or "") not in _CALLABLE_KINDS:
            continue
        params = _ts.parse_signature_params(str(node.get("signature") or ""),
                                            language or str(node.get("language")
                                                            or ""))
        for param in params:
            if param.get("index") == arg["index"]:
                return str(param.get("name") or "")
    return ""

def _one_hop_assignment(tree, src: bytes, line: int, name: str):
    """``{target, value, line}`` for the last assignment to ``name`` before ``line``."""
    if tree is None or not name:
        return None
    scope = _ts.enclosing_function(tree, line) or _ts.enclosing_node(tree, line)
    if scope is None:
        return None
    best = None
    for node in _walk(scope):
        if not _is_assignment(node):
            continue
        node_line = _line_of(node)
        if not node_line or node_line >= line:
            continue
        target = _assign_target(node, src)
        if target.strip() != name:
            continue
        best = {"target": target.strip(), "value": _assign_value(node, src),
                "line": node_line}
    return best

_ASSIGNMENT_TYPES = frozenset({
    "assignment", "augmented_assignment", "named_expression",
    "assignment_expression", "augmented_assignment_expression",
    "assignment_statement", "local_variable_declaration", "field_declaration",
    "init_declarator", "short_var_declaration", "var_declaration",
    "const_declaration", "variable_declaration", "lexical_declaration",
})
_ASSIGNMENT_SUFFIXES = ("_declaration", "_declarator")

def _is_assignment(node) -> bool:
    """A binding-introducing node: assignment, declaration or declarator."""
    if node.type in _ts.FUNCTION_NODE_TYPES or node.type in _ts.CLASS_NODE_TYPES:
        return False
    return node.type in _ASSIGNMENT_TYPES or node.type.endswith(_ASSIGNMENT_SUFFIXES)

def _assign_target(node, src: bytes) -> str:
    """The left-hand side of an assignment-ish node, whatever the grammar says."""
    for field in ("left", "name", "pattern", "target"):
        child = node.child_by_field_name(field)
        if child is not None:
            return _ts.node_text(child, src)
    text = _ts.node_text(node, src)
    return text.split("=", 1)[0] if "=" in text else ""

_SENTINEL = "\x00"
_URL_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")

def _url_skeleton(expression: str) -> str:
    """Replace interpolated URL regions with a sentinel, preserving literals."""
    text = str(expression or "").strip()
    if not text:
        return ""
    text = re.sub(r"^[fFrRbBuU]{1,2}(?=[\"'])", "", text)
    # A single literal only when nothing is concatenated onto it: ``"a" + b``
    # also fullmatches as one quoted string, which would swallow the operands.
    match = (re.fullmatch(r"([\"'])(.*)\1", text, re.DOTALL)
             if "+" not in text else None)
    if match is not None:
        inner = match.group(2)
    else:
        pieces: list[str] = []
        for part in text.split("+"):
            piece = part.strip()
            quoted = re.match(r"^([\"'])(.*)\1$", piece, re.DOTALL)
            if quoted is not None:
                pieces.append(quoted.group(2))
            elif piece:
                pieces.append(_SENTINEL
                              if re.fullmatch(r"[A-Za-z_$][\w$.\[\]]*", piece)
                              else piece)
        inner = "".join(pieces) if pieces else text
    inner = re.sub(r"\$\{[^{}]*\}", _SENTINEL, inner)
    return re.sub(r"\{[^{}]*\}", _SENTINEL, inner)

def _url_parts(expression: str) -> dict:
    """Split the URL skeleton into scheme, host, port, path, and query parts."""
    skeleton = _url_skeleton(expression)
    if not skeleton:
        return {key: {"value": "", "kind": "DYNAMIC"}
                for key in ("scheme", "host", "port", "path", "query")}
    parts = {key: {"value": "", "kind": "CONSTANT"}
             for key in ("scheme", "host", "port", "path", "query")}
    rest = skeleton
    match = _URL_SCHEME_RE.match(rest)
    if match is not None:
        parts["scheme"] = {"value": match.group(1),
                           "kind": "CONSTANT" if _SENTINEL not in match.group(1)
                           else "DYNAMIC"}
        rest = rest[match.end():]
    elif rest.startswith(_SENTINEL + "://"):
        parts["scheme"] = {"value": "", "kind": "DYNAMIC"}
        rest = rest[len(_SENTINEL) + 3:]
    else:
        parts["scheme"] = {"value": "", "kind": "DYNAMIC"}

    cut = len(rest)
    for ch in "/?#":
        index = rest.find(ch)
        if index >= 0:
            cut = min(cut, index)
    authority, tail = rest[:cut], rest[cut:]
    if "@" in authority:  # userinfo is not part of the host
        authority = authority.rsplit("@", 1)[-1]
    if authority.startswith("["):  # IPv6 literal
        close = authority.find("]")
        if close >= 0:
            host = authority[:close + 1]
            remainder = authority[close + 1:]
            if remainder.startswith(":"):
                parts["port"] = {"value": remainder[1:],
                                 "kind": _part_kind(remainder[1:])}
        else:
            host = authority
        parts["host"] = {"value": host, "kind": _part_kind(host)}
    elif ":" in authority:
        host, _sep, port = authority.partition(":")
        parts["host"] = {"value": host, "kind": _part_kind(host)}
        parts["port"] = {"value": port, "kind": _part_kind(port)}
    else:
        parts["host"] = {"value": authority, "kind": _part_kind(authority)}

    if "?" in tail:
        path, _sep, query = tail.partition("?")
    else:
        path, query = tail, ""
    path = path.split("#", 1)[0]
    parts["path"] = {"value": path, "kind": _part_kind(path)}
    parts["query"] = {"value": query, "kind": _part_kind(query)}
    return parts

def _part_kind(value: str) -> str:
    """CONSTANT when written out, DYNAMIC when the sentinel is in it."""
    return "DYNAMIC" if _SENTINEL in str(value or "") else "CONSTANT"

def _display_value(value: str) -> str:
    """The part's value with the sentinel rendered as ``{}``."""
    return str(value or "").replace(_SENTINEL, "{}")

def _egress_verdict(parts: dict) -> tuple[str, str, str, str]:
    """Map URL-part classifications to the pinned verdict, severity, and CWE."""
    if parts["host"]["kind"] == "DYNAMIC" or not parts["host"]["value"]:
        return ("HOST_DYNAMIC", "high", "CWE-918",
                "the host is built at runtime: the request goes wherever the "
                "expression says (full SSRF)")
    if parts["path"]["kind"] == "DYNAMIC":
        return ("PATH_DYNAMIC", "high", "CWE-918",
                "the host is fixed but the path is built: path traversal / "
                "path-injection SSRF")
    if (parts["scheme"]["kind"] == "DYNAMIC"
            or parts["port"]["kind"] == "DYNAMIC"
            or parts["query"]["kind"] == "DYNAMIC"):
        return ("PARTIAL", "medium", "CWE-918",
                "only the scheme, port or query is dynamic: the target is "
                "constrained but not fixed")
    return ("FULLY_CONSTANT", "info", "",
            "every part of the URL is a literal: the target is fixed (benign)")

def _egress_block(position: int, total: int, site: dict, resolved: dict,
                  parts: dict, verdict: str, severity: str, cwe: str, note: str,
                  src: bytes, file_path: str) -> tuple[list[str], dict | None]:
    """One network call's block, plus its candidate finding when not benign."""
    lines = [f"--- network call {position}/{total}",
             f"file: {file_path}  line: {site['line']}",
             f"call: {site['callee']}",
             f"url_arg: {resolved['raw'] or '(none)'}  [{resolved['basis']}]"]
    if resolved["resolved_from"]:
        lines.append(f"resolved: {resolved['resolved_from']}")
    if resolved["expression"]:
        lines.append(f"expression: {_truncate_line(resolved['expression'], 200)}")
    else:
        lines.append("expression: (unresolvable — treated as fully dynamic)")
    rendered = "  ".join(
        (f"{key}={{}} {parts[key]['kind']}"
         if not parts[key]["value"] and parts[key]["kind"] == "DYNAMIC"
         else (f"{key}={_display_value(parts[key]['value'])} "
               f"{parts[key]['kind']}" if parts[key]["value"]
               else f"{key}=(none)"))
        for key in ("scheme", "host", "port", "path", "query"))
    lines += [f"parts: {rendered}", f"verdict: {verdict} — {note}",
              f"evidence: {_site(file_path, site['line'])}: "
              f"{_truncate_line(_ts.line_text(src, site['line']), MAX_EVIDENCE)}"]
    if verdict == "FULLY_CONSTANT":
        return lines, None
    confidence = _confidence(
        _CONF_BASE,
        _CONF_EVIDENCE if verdict == "HOST_DYNAMIC" else 0.0,
        _CONF_GAP if verdict == "PATH_DYNAMIC" else 0.0,
        _CONF_NOGUARD if not resolved["resolved_from"] else 0.0,
    )
    finding = _candidate_finding(
        title=(f"{verdict.replace('_', ' ').lower()} egress target in "
               f"{site['callee']} at {_site(file_path, site['line'])}"),
        path=file_path, start_line=site["line"], end_line=site["line"],
        cwe=cwe, severity=severity, confidence=confidence,
        taint_source="attacker-controlled URL component",
        taint_sink=f"{site['callee']}({resolved['raw'] or '…'})",
        taint_path=[_site(file_path, site["line"])],
        evidence=(f"{_site(file_path, site['line'])} calls {site['callee']} with "
                  f"url_arg {resolved['raw'] or '(none)'}"
                  + (f" (resolved: {resolved['resolved_from']})"
                     if resolved["resolved_from"] else "")
                  + f"; parts: {rendered}; {note}"),
        rationale=(f"the {verdict.lower().replace('_', ' ')} component of the "
                   f"target is computed at runtime, so the destination of this "
                   f"request is not fixed by the code"),
        note=("CWE-918 (Server-Side Request Forgery); FULLY_CONSTANT sites are "
              "not findings, and a dynamic PART is not proof — an allow-list "
              "upstream still makes it safe"),
    )
    return lines, {"header": (f"## candidate finding ({cwe}, severity "
                              f"{severity}, confidence {confidence})"),
                   "finding": finding}

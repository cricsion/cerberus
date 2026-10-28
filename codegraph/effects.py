"""Effect-category tracing for CodeGraph.

``trace_effect_category`` generalizes :func:`supply.trace_egress_and_ssrf_targets`
from the ``network`` category to every curated effect family in
:mod:`harness.codegraph.sinks` — the processes a recognized call spawns, the
paths it touches, the stores it writes, the mail/queue/payment systems it
reaches. The workflow is identical: match calls in one function span, resolve
the argument that matters through one earlier assignment, render honest
CONSTANT / DYNAMIC verdicts, and emit conservative candidate findings.

LAWS
- A dynamic argument is a candidate signal, not proof: allow-lists and
  parameterized wrappers upstream may make the site safe.
- Source reads stay contained and byte-capped; the tool degrades to a bounded
  success-shaped report and never raises on hostile input.
- Only the injection-directed categories carry CWE findings (process/storage/
  database); the rest are evidence rows, because their risk story needs caller
  intent this view cannot see.

FORMAT LAW: section titles, verdicts, finding JSON and truncation tails follow
the package's pinned shapes. The index is read-only; no network, subprocess,
or writes occur. List limits are hard-capped by ``_db.HARD_MAX_ROWS``.
"""
from __future__ import annotations

import json
import re

from harness.codegraph import _common, _ts, sinks
from harness.codegraph.supply import (_callee_text, _egress_span,
                                      _one_hop_assignment,
                                      _strip_keyword_prefix, _url_skeleton)
from harness.tools._compat import tool

# ---------------------------------------------------------------------------
# caps — the package-wide env idiom; values frozen
# ---------------------------------------------------------------------------

ENV_SITES = "CODEGRAPH_EFFECT_SITES_LIMIT"

DEFAULT_SITES = 40          # effect call sites reported per span
MAX_EVIDENCE = 160          # per-row evidence truncation (matches supply)

# ---------------------------------------------------------------------------
# category vocabulary — exactly what sinks.EFFECT_RULES curates, minus network
# (which has its own dedicated tool with URL-shaped parts and verdicts).
# ``cwe`` is only set where the category itself is an injection family; other
# categories render as evidence rows regardless of the argument's verdict.
# ---------------------------------------------------------------------------

_CATEGORIES: dict[str, tuple] = {
    "process":  ("CWE-78",  "high", "command injection"),
    "storage":  ("CWE-22",  "high", "path traversal / arbitrary file access"),
    "database": ("CWE-89",  "high", "SQL injection (raw, non-parameterized call)"),
    "auth":     ("",        "info", "authentication/authorization effect"),
    "email":    ("",        "info", "mail effect"),
    "queue":    ("",        "info", "message-queue effect"),
    "payments": ("",        "info", "payment-system effect"),
    "response": ("",        "info", "response/render effect"),
}
_KNOWN_CATEGORIES = frozenset(_CATEGORIES)

_CONF_BASE = 0.45
_CONF_GAP = 0.10            # one-hop resolution failed: the value is opaque
_CONF_NOGUARD = 0.05        # no resolvable assignment in between

_SENTINEL = "\x00"          # _url_skeleton's runtime-part sentinel


@tool(parse_docstring=True)
def trace_effect_category(function_node_id: str, category: str,
                          root: str = ".",
                          limit: int | None = None) -> str:
    """
    Trace one effect category (process/storage/database/auth/...) in a span.

    Calls are matched through the curated sinks taxonomy
    (``sinks.classify_call``), so only recognized callees are reported — an
    effect hidden behind an unrecognized wrapper is omitted, as in the egress
    tool. Dynamic arguments are candidate signals, never proof.

    Args:
        function_node_id: Function making the calls, or any node inside it.
        category: One of process, storage, database, auth, email, queue,
            payments, response (network has its own dedicated tool,
            ``trace_egress_and_ssrf_targets``, with URL-part verdicts).
        root: Repo root containing the CodeGraph index.
        limit: Effect call sites; 0 means unlimited up to the hard cap.

    Returns:
        A bounded per-call table (argument verdicts, evidence) plus candidate
        findings where the category carries a CWE.
    """
    cat = str(category or "").strip().lower()
    if cat not in _KNOWN_CATEGORIES:
        return _common._cap_chars(
            f"ERROR: unknown category {category!r}; expected one of: "
            + ", ".join(sorted(_KNOWN_CATEGORIES)))
    if cat == "network":
        return _common._cap_chars(
            "ERROR: category 'network' has URL-shaped parts that "
            "trace_egress_and_ssrf_targets renders specifically — call "
            "that tool instead")

    conn, node, error = _common.tool_gate(root, node_id=function_node_id)
    if error:
        return error
    file_path = str(node.get("file_path") or "")
    language = str(node.get("language") or "")
    tree, src = _common._parsed_file(root, file_path, {})
    if tree is None:
        return _common._cap_chars(
            f"ERROR: source of {function_node_id} is not readable through "
            f"this root ({file_path or 'no file'} — node_modules/vendor are "
            f"never indexed, and a file the indexer skipped has no spans "
            f"here either)")
    span = _egress_span(node, tree)
    if span is None:
        return _common._cap_chars(
            f"ERROR: no function span resolvable for {function_node_id} in "
            f"{file_path} — pass the function containing the calls, or a "
            f"node inside it")

    calls = _ts.calls_in_span(tree, span[0], span[1], src)
    matched: list[dict] = []
    for call in calls:
        categories = sinks.classify_call(call["text"], language)
        if cat in categories:
            # When the whole chain classifies nowhere, the hit came from the
            # taxonomy's last-segment fallback (a bare verb like ``update`` /
            # ``exists``) — over-reported by design; the block says so.
            matched.append({
                "line": call["line"], "col": call["col"],
                "categories": categories,
                "fallback": sinks.classify_effect(call["text"], language) is None,
                "callee": _callee_text(call["node"], src) or call["text"],
                "call_text": call["text"], "node": call["node"]})

    site_cap = _common._cap_rows(limit, ENV_SITES, DEFAULT_SITES)
    out: list[str] = [f"# effect category {cat}: {function_node_id}",
                      f"root: {root}",
                      f"node: {_common._node_label(node)}",
                      f"span: {file_path}:{span[0]}-{span[1]} "
                      f"({span[1] - span[0] + 1} lines, "
                      f"language {language or 'unknown'})",
                      f"calls in span: {len(calls)}  {cat}: {len(matched)}"]
    if not matched:
        out += ["",
                f"no {cat} call in this span: nothing the effects taxonomy "
                "classifies as such was found",
                "hint: the callee must be recognized as written (os.system, "
                "subprocess.run, shutil.rmtree, fs.writeFile, "
                "send_file, session.commit, …) — an effect behind an "
                "unrecognized wrapper is not in the table",
                "hint: network egress has its own tool: "
                "trace_egress_and_ssrf_targets"]
        return _common._cap_chars("\n".join(out))

    cwe, default_severity, cat_risk = _CATEGORIES[cat]
    findings: list[dict] = []
    for position, site in enumerate(matched[:site_cap], start=1):
        resolved = _resolve_effect_argument(site, tree, src)
        verdict, note = _argument_verdict(resolved)
        block, finding = _effect_block(position, len(matched), site, resolved,
                                       verdict, note, cwe, default_severity,
                                       cat_risk, src, file_path)
        out += [""] + block
        if finding is not None:
            findings.append(finding)
    if len(matched) > site_cap:
        out += ["", f"… +{len(matched) - site_cap} more {cat} calls "
                    f"(total {len(matched)}); raise the limit to expand"]

    finding_cap = _common._section_cap("CODEGRAPH_FINDINGS_LIMIT", 10)
    out += ["", f"--- candidate findings ({len(findings)})"]
    if not findings:
        if cwe:
            out.append(f"none: every {cat} call in this span uses a "
                       "fully-constant argument")
        else:
            out.append(f"none: {cat} sites are evidence rows — they need "
                       "caller intent to judge risk, which this view does "
                       "not model")
    for index, finding in enumerate(findings[:finding_cap], start=1):
        out += [f"{index}. {finding['header']}",
                json.dumps(finding["finding"], indent=2, sort_keys=False)]
    if len(findings) > finding_cap:
        out.append(f"… +{len(findings) - finding_cap} more findings (total "
                   f"{len(findings)}); raise the limit to expand")
    return _common._cap_chars("\n".join(out))


def _resolve_effect_argument(site: dict, tree, src: bytes) -> dict:
    """Choose the argument that carries the effect, resolve one hop of it.

    The first argument carries the process command, the storage path, and the
    SQL text for every curated family, so keyword/url-shaped heuristics stay
    with the egress tool and this view reads the first argument only.
    """
    args = _common._call_arg_records(site["node"], src)
    if not args:
        return {"raw": "", "expression": "", "basis": "no arguments",
                "resolved_from": "", "skeleton": ""}
    chosen = args[0]
    basis = "first argument"
    expression = chosen["text"]
    if chosen["keyword"]:
        basis += f" (keyword {chosen['keyword']})"
        expression = _strip_keyword_prefix(expression, chosen["keyword"])
    resolved_from = ""
    if re.fullmatch(r"[A-Za-z_$][\w$.]*", expression):
        target = expression.lstrip("@$")
        assignment = _one_hop_assignment(tree, src, site["line"], target)
        if assignment is not None:
            resolved_from = (f"one-hop assignment {assignment['target']} = "
                             f"{assignment['value']} at "
                             f"{assignment['line']} (same function)")
            expression = assignment["value"]
        else:
            resolved_from = (f"unresolved local {target} — no earlier "
                             f"assignment to it in this function")
            expression = ""
    skeleton = _url_skeleton(expression) if expression else ""
    return {"raw": chosen["text"], "expression": expression, "basis": basis,
            "resolved_from": resolved_from, "skeleton": skeleton}


def _argument_verdict(resolved: dict) -> tuple[str, str]:
    """Honest verdict over the resolved expression.

    - NO_ARGUMENT: the call passes nothing for this view to read.
    - OPAQUE: a bare name with no resolvable assignment — treated as dynamic.
    - FULLY_CONSTANT: one string literal (no sentinel region) — benign.
    - PARTIAL: literal plus sentinel/computed parts — constrained, injectable.
    - DYNAMIC: anything else (tuple builds, calls, resolved containers…).
    """
    if not resolved["basis"]:  # never happens today; defensive
        return ("NO_ARGUMENT", "the call carries no readable argument")
    if resolved["basis"] == "no arguments":
        return ("NO_ARGUMENT", "the call carries no argument for this view")
    if not resolved["expression"]:
        return ("OPAQUE",
                "the argument is a name with no resolvable assignment: "
                "treated as fully dynamic")
    skeleton = resolved["skeleton"]
    if skeleton and _SENTINEL in skeleton:
        return ("PARTIAL",
                "the argument is built from literals plus computed parts: "
                "target constrained but injectable")
    if skeleton:
        return ("FULLY_CONSTANT",
                "the argument is a string literal: the effect target is "
                "fixed (benign)")
    return ("DYNAMIC",
            "the argument is computed at runtime (call or compound "
            "expression): the effect target is wherever it evaluates")


def _effect_block(position: int, total: int, site: dict, resolved: dict,
                  verdict: str, note: str, cwe: str, default_severity: str,
                  cat_risk: str, src: bytes, file_path: str) -> tuple[list[str], dict | None]:
    """One effect call's block, plus its candidate finding when due."""
    lines = [f"--- effect call {position}/{total}",
             f"file: {file_path}  line: {site['line']}",
             f"call: {site['callee']}",
             f"arg: {_common._truncate_line(resolved['raw'], 200) or '(none)'} "
             f"[{resolved['basis']}]"]
    if site.get("fallback"):
        lines.append(
            "note: matched only through the last-segment fallback (a generic "
            "verb like update/exists) — read the line before trusting the "
            "category label")
    if resolved["resolved_from"]:
        lines.append(f"resolved: {resolved['resolved_from']}")
    lines += [f"verdict: {verdict} — {note}",
              f"evidence: {_common._site(file_path, site['line'])}: "
              f"{_common._truncate_line(_ts.line_text(src, site['line']), MAX_EVIDENCE)}"]
    if verdict in ("FULLY_CONSTANT", "NO_ARGUMENT") or not cwe:
        return lines, None
    confidence = _common._confidence(
        _CONF_BASE,
        _CONF_GAP if verdict == "OPAQUE" else 0.0,
        _CONF_NOGUARD if not resolved["resolved_from"] else 0.0,
    )
    finding = _common._candidate_finding(
        title=(f"dynamic argument to {site['callee']} at "
               f"{_common._site(file_path, site['line'])} "
               f"({cat_risk.split(' (')[0]})"),
        path=file_path, start_line=site["line"], end_line=site["line"],
        cwe=cwe, severity=default_severity, confidence=confidence,
        taint_source="computed effect argument",
        taint_sink=(f"{site['callee']}"
                    f"({_common._truncate_line(resolved['raw'], 60) or '…'})"),
        taint_path=[_common._site(file_path, site["line"])],
        evidence=(f"{_common._site(file_path, site['line'])} calls "
                  f"{site['callee']} with arg "
                  f"{_common._truncate_line(resolved['raw'], 120) or '(none)'}"
                  + (f" (resolved: {resolved['resolved_from']})"
                     if resolved["resolved_from"] else "")
                  + f"; verdict {verdict}, verdict note: {note}"),
        rationale=(f"a {verdict.lower()} argument feeding a "
                   f"{cat_risk} sink means the effect target is "
                   "not fixed by the code; allow-lists or parameterization "
                   "upstream still make it safe"),
        note=(f"{cwe} ({cat_risk}); FULLY_CONSTANT sites are not findings, "
              "and a dynamic argument is not proof — treat it as a hunting "
              "lead"),
    )
    return lines, {"header": (f"## candidate finding ({cwe}, severity "
                              f"{default_severity}, confidence {confidence})"),
                   "finding": finding}


__all__ = ["trace_effect_category"]

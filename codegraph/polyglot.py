"""Cross-language bridge, LLM/MCP toxic-flow and PoC-verification tools.

Three questions a taint tracer alone cannot answer, for the Polyglot and
Verifier micro-agents:

- :func:`inspect_cross_language_bridge` — **what crosses a language boundary?**
  CodeGraph synthesizes 53 channels of cross-language edges (React Native's
  ``rn-event-channel``, Fabric native impls, Swift/ObjC interop, gRPC stub
  impls, MyBatis mapper<->XML, Expo modules, ArkUI ...) and every synthesized
  edge carries a ``registeredAt`` wiring site because ``idx_edges_identity``
  forces its own line/col to be a placeholder. This tool renders BOTH sides'
  contracts — signature, parameters parsed from each side's own file, the
  call-site window — and flags the arity and type mismatches that make a bridge
  a vulnerability surface: a value the sender typed as ``number`` arrives in a
  fixed-width ``int``, a 2-argument JS function is served by a 1-parameter
  native one, and the bridge marshals whatever it is given.
- :func:`audit_llm_and_mcp_tool_sinks` — **does external data reach a prompt
  that feeds an LLM with tools?** Indirect prompt injection (CWE-74) is the
  AI-native shape of injection: attacker-controlled text (a document, a search
  result, a ticket body) is interpolated into a prompt, the prompt is sent to a
  model, and the model's tool set can execute. The tool scans one span for LLM
  calls, prompt construction embedding external-looking identifiers, and tool
  registrations (``@tool``, ``mcp.tool``, ``tools=[...]``, ...), classifies
  each registered tool's callees through the sinks taxonomy, and emits the
  toxic flow as a candidate finding.
- :func:`verify_exploit_poc_in_harness` — **did the tainted value really reach
  the sink?** It GENERATES a minimal reproduction test (pytest or jest) that
  monkeypatches the sink and calls the route handler with a canary substituted
  for the attacker-controlled fields, and — only when docker is present AND the
  operator opted in with ``SAST_POC_EXEC=1`` — runs it in an ephemeral
  container with ``--network none``. It NEVER executes target-repo code
  in-process: generation is always safe, execution is always contained, and
  without the opt-in the answer is a ``not-executed`` status plus run
  instructions.

Everything here is read-only against the target repo and deterministic: no
LLM, no network from the tool itself, and no tool raises — a missing index, an
unreadable file, a grammar that is not installed, a malformed edge id and a
docker-less machine are all strings.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path

from harness.codegraph import _db, _ts, sinks
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
# caps — the same shape as navigation.py's and authz.py's, one env idiom
# package-wide
# ---------------------------------------------------------------------------

HARD_MAX_SECTION = 200   # per-section ceiling before _db.HARD_MAX_ROWS applies
CHAR_CAP = int(get_default_config("codegraph.chars"))  # CODEGRAPH_CHARS, 0 = unlimited
ENV_CHARS = "CODEGRAPH_CHARS"

ENV_LLM_CALLS = "CODEGRAPH_LLM_CALLS_LIMIT"
ENV_TEMPLATES = "CODEGRAPH_PROMPT_TEMPLATES_LIMIT"
ENV_TOOL_REGS = "CODEGRAPH_TOOL_REGS_LIMIT"
ENV_LLM_FINDINGS = "CODEGRAPH_LLM_FINDINGS_LIMIT"

DEFAULT_LLM_CALLS = 20      # LLM calls rendered per audit
DEFAULT_TEMPLATES = 20      # prompt templates rendered per audit
DEFAULT_TOOL_REGS = 20      # tool registrations rendered per audit
DEFAULT_LLM_FINDINGS = 10   # candidate findings per audit
DEFAULT_POC_TIMEOUT = 120   # seconds, the docker run's ceiling
MAX_EVIDENCE = 160          # per-row evidence truncation
MAX_PARAMS = 12             # parameters rendered per side of a bridge
MAX_MISMATCHES = 12         # type/arity mismatches rendered per bridge
MAX_FIELDS = 12             # attacker-controlled fields bounded in a PoC
MAX_TEST_CHARS = 6000       # generated test source bound (overall cap still applies)
MAX_MOCK_CHARS = 2000       # the embedded mock-request literal bound
MAX_SINK_BYTES = int(get_default_config("sandbox.max_output_bytes"))  # SAST_BYTES, 0 = unlimited
MAX_STDERR_BYTES = 20000    # stderr bound for the docker run
MAX_SPAN_TEXT = 20000       # the wrapper/field scan is bounded, like every read here

# The canary substituted for every attacker-controlled field. Chosen to be
# greppable in a spy's recorded arguments and impossible to collide with real
# fixture data.
CANARY = "__SAST_CANARY__"
CANARY_MARKER = "SAST_POC_RESULT: canary_reached="

ENV_POC_EXEC = "SAST_POC_EXEC"
ENV_POC_IMAGE = "SAST_POC_IMAGE"
DEFAULT_PY_IMAGE = "python:3.12-slim"
DEFAULT_JS_IMAGE = "node:20-slim"


def _env_int(key: str, default: int) -> int:
    try:
        v = os.environ.get(key)
        if v is None or v == "":
            return default
        return int(v)
    except (TypeError, ValueError):
        return default


def _cap_rows(limit, env_key: str, default: int) -> int:
    """Explicit arg wins, then env, ``<=0`` means unlimited, hard-clamped.

    Mirrors ``_db._resolve_rows`` (private to the foundation module on purpose)
    so polyglot.py does not reach into it; the clamp is still
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
    does not exist, is unreadable, is above the 1 MB per-file cap the
    indexer applies (a file CodeGraph skipped has no symbols here either, so
    parsing one would invent spans the graph disagrees with), or cannot be
    addressed by the OS at all.

    The last case is agent-controlled input, not a missing file: a NUL byte
    raises ``ValueError: embedded null byte`` from ``resolve()`` and a path
    component past NAME_MAX raises ``OSError`` from ``is_file()``. Both are
    caught here so the caller's own error string is what the agent sees.
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
        pass
    if rel.startswith("/"):
        # A leading slash may be the repo's own virtual path ("/app.py").
        try:
            candidates.append(_safe_path(rel))
        except (OSError, ValueError):
            pass
    for cand in candidates:
        try:
            cand.relative_to(base)  # re-check after resolving symlinks
            if not cand.is_file():
                continue
            if cand.stat().st_size > _ts.MAX_FILE_BYTES:
                continue
            cand.read_bytes()  # readability probe: an unreadable file is a miss
        except (OSError, ValueError):
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


def _as_int(value, default: int = 0) -> int:
    """A DB column coerced to int without raising.

    ``nodes.start_line``/``edges.line`` are declared INTEGER, but SQLite column
    types are advisory and an index written by another producer can hold
    anything; a tool that promises never to raise cannot assume otherwise.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _truncate_line(text: str, cap: int = MAX_EVIDENCE) -> str:
    flat = " ".join(str(text or "").split())
    if len(flat) <= cap:
        return flat
    return flat[:cap] + " …"


# ---------------------------------------------------------------------------
# node labels
# ---------------------------------------------------------------------------

def _site(file_path, line) -> str:
    return f"{file_path}:{line}"


def _node_label(node: dict | None, with_span: bool = True) -> str:
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


# ---------------------------------------------------------------------------
# parameter extraction — each side's own def, then nodes.signature
# ---------------------------------------------------------------------------

_ID_LEAF_TYPES = frozenset({
    "identifier", "field_identifier", "property_identifier", "type_identifier",
    "shorthand_property_identifier", "shorthand_property_identifier_pattern",
    "simple_identifier",
})

_PARAM_SKIP_TYPES = frozenset({"comment", "line_comment", "block_comment"})

# Parameter-property / receiver modifiers that sit before a parameter name.
_PARAM_NAME_MODIFIERS = ("public", "private", "protected", "readonly", "static",
                         "final", "override", "var", "let", "const", "in", "out",
                         "ref", "params", "this")

# Languages whose parameter lists read ``Type name`` (Java/C#) rather than
# ``name: Type``; and the ``name Type`` spellings (Go/Rust/Swift/PHP). Kept
# local — the foundation's tables are private to _ts by design.
_TYPE_FIRST_LANGS = frozenset({
    "java", "kotlin", "scala", "csharp", "c", "cpp", "objc", "php",
    "objectivec", "c_sharp",
})
_NAME_FIRST_LANGS = frozenset({"go", "rust", "php", "swift"})

# Container node types that hold a parameter list, per grammar. Field names
# cover the modern grammars; the type fallback covers the older tree-sitter
# builds (e.g. tree-sitter-javascript's ``formal_parameters``).
_PARAM_CONTAINER_TYPES = frozenset({
    "formal_parameters", "parameters", "parameter_list",
    "function_value_parameters", "function_parameters", "lambda_parameters",
})


def _clean_name(text: str) -> str:
    return re.sub(r"^[*.$\s]+", "", str(text or "").strip()).strip()


def _clean_type(text: str) -> str:
    return str(text or "").strip().lstrip(":").strip("`").strip()


def _params_node_of(def_node):
    """The parameter-list child of a def node, or None."""
    for field in ("parameters", "formal_parameters", "parameter_list",
                  "function_value_parameters"):
        child = def_node.child_by_field_name(field)
        if child is not None:
            return child
    for child in def_node.children:
        if child.type in _PARAM_CONTAINER_TYPES:
            return child
    return None


def _param_name_type(child, src: bytes, language: str) -> tuple[str, str]:
    """``(name, type)`` for one parameter node, grammar-agnostic.

    Tries, in order: the grammar's own fields (``pattern``/``name`` +
    ``type``), a ``type_annotation``-style child, a colon split of the written
    text (the Kotlin/Python/TS spelling), and finally a leaf heuristic that
    honours the ``Type name`` / ``name Type`` language families. An empty
    result means the parameter carries no readable name at all.
    """
    text = " ".join(_ts.node_text(child, src).split())
    if not text:
        return "", ""
    # 1. grammar fields
    name_node = (child.child_by_field_name("pattern")
                 or child.child_by_field_name("name"))
    type_node = child.child_by_field_name("type")
    if name_node is not None:
        name = _clean_name(_ts.node_text(name_node, src))
        if name:
            type_text = _ts.node_text(type_node, src).strip() if type_node is not None else ""
            return name, _clean_type(type_text)
    # 2. a type_annotation child (`: Request`, `: string`)
    for sub in child.children:
        if sub.type == "type_annotation":
            type_text = _ts.node_text(sub, src).lstrip(":").strip()
            outside = [n for n in _walk(child)
                       if n.type in _ID_LEAF_TYPES
                       and not (sub.start_byte <= n.start_byte
                                and n.end_byte <= sub.end_byte)]
            name = _clean_name(_ts.node_text(outside[0], src)) if outside else ""
            return name, _clean_type(type_text)
    # 3. colon split of the parameter text (kotlin `name: String`, py `a: int`)
    if ":" in text:
        head, _, tail = text.partition(":")
        tokens = [t for t in head.split() if t and t not in _PARAM_NAME_MODIFIERS]
        if tokens:
            return _clean_name(tokens[-1]), _clean_type(tail)
    # 4. leaf heuristic by language family
    leaves = [n for n in _walk(child) if n.type in _ID_LEAF_TYPES]
    if child.type in _ID_LEAF_TYPES:
        return _clean_name(text), ""
    if leaves:
        if language in _TYPE_FIRST_LANGS and len(leaves) >= 2:
            return (_clean_name(_ts.node_text(leaves[1], src)),
                    _clean_type(_ts.node_text(leaves[0], src)))
        if language in _NAME_FIRST_LANGS and len(leaves) >= 2:
            return (_clean_name(_ts.node_text(leaves[0], src)),
                    _clean_type(_ts.node_text(leaves[1], src)))
        return _clean_name(_ts.node_text(leaves[0], src)), ""
    return "", ""


def _params_from_def(tree, src: bytes, start: int, end: int,
                     language: str) -> list[dict]:
    """The parameters of the def node whose span covers ``[start, end]``.

    A bare keyword token (the ``function`` of ``async function f``) is not a
    def, so candidates without children are skipped — the same trap that makes
    ``_ts.enclosing_function`` return the keyword on older JS grammars.
    """
    def_node = _def_node_at(tree, start, end)
    if def_node is None:
        return []
    params_node = _params_node_of(def_node)
    if params_node is None:
        return []
    out: list[dict] = []
    index = 0
    for child in params_node.named_children:
        if child.type in _PARAM_SKIP_TYPES:
            continue
        name, type_text = _param_name_type(child, src, language)
        if not name and not type_text:
            continue
        variadic = (child.type in ("list_splat_pattern", "dictionary_splat_pattern",
                                   "rest_parameter", "spread_parameter",
                                   "variadic_parameter")
                    or _text_has_variadic(child, src))
        out.append({"name": name, "type": type_text, "index": index,
                    "variadic": variadic})
        index += 1
    return out


def _text_has_variadic(child, src: bytes) -> bool:
    return _ts.node_text(child, src).strip().startswith(("*", "...", "**"))


def _def_node_at(tree, start: int, end: int):
    """The innermost function node whose span covers ``[start, end]``."""
    try:
        root = tree.root_node
    except Exception:
        return None
    best = None
    best_key = None
    for node in _walk(root):
        if node.type not in _ts.FUNCTION_NODE_TYPES or not node.children:
            continue
        s, e = _line_of(node), _end_line_of(node)
        if not s or e < end or s > start:
            continue
        key = (e - s, node.end_byte - node.start_byte)
        if best is None or key < best_key:
            best, best_key = node, key
    return best


def _node_params(node: dict, root: str, cache: dict) -> tuple[list[dict], str]:
    """``(params, basis)`` for a node: its own def, else ``nodes.signature``.

    The basis is reported because it is the honest label for how much the
    parameters can be trusted: a tree-sitter def is the code as written, a
    ``nodes.signature`` string is the indexer's own rendering of it.
    """
    language = str(node.get("language") or "")
    file_path = str(node.get("file_path") or "")
    start, end = _node_span(node)
    tree, src = _parsed_file(root, file_path, cache)
    if tree is not None and start:
        params = _params_from_def(tree, src, start, end, language)
        if params:
            return params, "tree-sitter def"
    return _ts.parse_signature_params(str(node.get("signature") or ""),
                                      language), "nodes.signature"


def _params_render(params: list[dict], cap: int) -> str:
    """``name: type, name`` — the one-line parameter contract, bounded."""
    shown = params[:cap]
    parts = []
    for param in shown:
        type_text = str(param.get("type") or "").strip()
        name = str(param.get("name") or "?").strip()
        parts.append(f"{name}: {type_text}" if type_text else name)
    extra = len(params) - len(shown)
    if extra > 0:
        parts.append(f"… +{extra} more")
    return ", ".join(parts) or "(none)"


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
# edge lookup — numeric edges.id, or a source:target:kind triple
# ---------------------------------------------------------------------------

def _edge_by_id(conn, edge_id: str) -> dict | None:
    """One edge row by its autoincrement id, metadata decoded.

    Direct SQL is deliberate: ``_db.get_edges`` filters by endpoint/kind, and
    the contract's numeric form addresses the row itself. The metadata decode
    mirrors ``_db._row_to_edge`` so the caller sees the same shape either way.
    """
    if conn is None:
        return None
    try:
        row = conn.execute("SELECT * FROM edges WHERE id = ?",
                           (str(edge_id),)).fetchone()
    except sqlite3.Error:
        return None
    if row is None:
        return None
    out = dict(row)
    try:
        out["metadata"] = json.loads(out.get("metadata") or "{}") or {}
    except (TypeError, ValueError):
        out["metadata"] = {}
    return out


def _resolve_edge(conn, ref: str) -> tuple[dict | None, str]:
    """``(edge, error)`` — a numeric ``edges.id`` or ``source:target:kind``.

    Node ids carry colons (``app.py:login``), so a triple is disambiguated by
    trying every split of the head into source/target and keeping the first
    one whose BOTH endpoints resolve to nodes AND whose edge exists — the
    wrong split (``worker.py`` as a file node) simply fails the lookup and
    the next split is tried. Never raises.
    """
    text = str(ref or "").strip()
    if not text:
        return None, ("ERROR: edge_id is required (a numeric edges.id, or a "
                      "'source:target:kind' triple)")
    if text.isdigit():
        edge = _edge_by_id(conn, text)
        if edge is None:
            return None, f"ERROR: edge not found: {ref}"
        return edge, ""
    parts = text.split(":")
    if len(parts) < 3:
        return None, (f"ERROR: edge_id {ref!r} is neither a numeric edge id nor "
                      f"a 'source:target:kind' triple")
    kind = parts[-1].strip()
    head = parts[:-1]
    node_valid: list[tuple[str, str]] = []
    for split in range(1, len(head)):
        source = ":".join(head[:split]).strip()
        target = ":".join(head[split:]).strip()
        if not source or not target:
            continue
        if _db.get_node(conn, source) is None or _db.get_node(conn, target) is None:
            continue
        edges = _db.get_edges(conn, source=source, target=target, kind=kind)
        if edges:
            return edges[0], ""
        node_valid.append((source, target))
    if node_valid:
        source, target = node_valid[0]
        return None, (f"ERROR: no {kind!r} edge from {source} to {target} "
                      f"in the index")
    return None, (f"ERROR: edge not found: {ref} — neither endpoint of any "
                  f"split resolves to a node (node ids carry colons, so the "
                  f"triple is 'source:target:kind')")


# ---------------------------------------------------------------------------
# 1. inspect_cross_language_bridge
# ---------------------------------------------------------------------------

# CodeGraph's cross-language synthesis channels. The exact spellings from
# GRAPHIFY_CODEGRAPH.md's 53-channel registry, plus the two family rules the
# registry itself implies: every ArkUI channel (``arkui-*``) and every
# ``*-cross-platform`` channel bridges languages.
_BRIDGE_CHANNELS = frozenset({
    "rn-event-channel", "fabric-native-impl", "swift-objc",
    "go-grpc-stub-impl", "mybatis-java-xml", "expo-cross-platform",
    "expo-modules-js", "rn-cross-platform", "kotlin-expect-actual",
    "cross-platform",
})


def _is_bridge_channel(synthesized_by) -> bool:
    """Is this ``synthesizedBy`` one of the cross-language channels?"""
    channel = str(synthesized_by or "").strip().lower()
    if not channel:
        return False
    if channel in _BRIDGE_CHANNELS:
        return True
    if channel.startswith("arkui-"):
        return True
    return channel.endswith("-cross-platform") or channel == "cross-platform"


# What each channel marshals, for the trust-boundary note. A framework bridge
# is only as typed as its marshaller, and which marshaller matters.
_CHANNEL_HINTS = {
    "rn-event-channel": ("React Native bridge (native -> JS): arguments cross a "
                         "serialization boundary (JSI/legacy bridge); a JS-side "
                         "type annotation is not a native-side guarantee"),
    "fabric-native-impl": ("Fabric native implementation: C++ props cross the "
                           "JS boundary through the shadow tree"),
    "swift-objc": ("Swift/Objective-C interop: Swift types are bridged to ObjC "
                   "and back — optionals, NSNumber and String carry conversion "
                   "semantics"),
    "go-grpc-stub-impl": ("gRPC stub implementation: protobuf field semantics "
                          "(defaults, oneof, unknown-field preservation) differ "
                          "between generated stubs"),
    "mybatis-java-xml": ("MyBatis mapper interface <-> XML statement: parameter "
                         "names bind by annotation/param name, and the XML "
                         "decides the SQL shape"),
    "expo-cross-platform": ("Expo cross-platform: JS arguments cross the native "
                            "module bridge; the native side validates types at "
                            "runtime, not compile time"),
    "expo-modules-js": ("Expo modules JS side: arguments cross the native module "
                        "bridge; the native side validates types at runtime"),
}


def _channel_hint(channel: str) -> str:
    hint = _CHANNEL_HINTS.get(str(channel or "").lower())
    if hint:
        return hint
    if str(channel or "").lower().startswith("arkui-"):
        return ("ArkUI: cross-language state/emitter wiring (HarmonyOS) — state "
                "propagates through the framework's marshalling")
    if str(channel or "").lower().endswith("cross-platform"):
        return ("cross-platform synthesis: the two sides are wired by a "
                "framework, not by a call the source spells out")
    return ""


# Primitive type families, for cross-boundary comparison. Only KNOWN families
# are compared: a custom type (``Request`` vs ``Owner``) differs legitimately
# across languages and flagging it would be pure noise.
_TYPE_FAMILY = {
    "string": "string", "str": "string", "char": "string", "char*": "string",
    "text": "string", "uuid": "string", "url": "string", "uri": "string",
    "int": "int", "integer": "int", "long": "int", "short": "int", "byte": "int",
    "int8": "int", "int16": "int", "int32": "int", "int64": "int",
    "uint": "int", "uint8": "int", "uint16": "int", "uint32": "int",
    "uint64": "int", "usize": "int", "isize": "int", "bigint": "int",
    "number": "number", "float": "number", "double": "number",
    "decimal": "number", "float32": "number", "float64": "number",
    "real": "number", "nsnumber": "number",
    "bool": "bool", "boolean": "bool",
    "object": "object", "dict": "object", "map": "object",
    "dictionary": "object", "json": "object", "jsonb": "object",
    "record": "object", "hashmap": "object",
    "array": "array", "list": "array", "slice": "array", "vector": "array",
    "set": "array", "sequence": "array", "iterable": "array",
    "any": "any", "unknown": "any", "dynamic": "any",
}
_NUMERIC_FAMILIES = frozenset({"int", "number"})


def _type_family(raw) -> tuple[str, bool]:
    """``(family, optional)`` — the family a type name belongs to.

    Optionality is read off the written form: a trailing ``?``/``!``
    (Kotlin/TS), an ``Optional[…]``/``Nullable<T>`` wrapper (Java/Kotlin).
    """
    text = str(raw or "").strip()
    if not text:
        return "", False
    optional = False
    if text[-1] in "?!":
        optional = True
        text = text[:-1].strip()
    lowered = text.lower()
    match = re.match(r"^(?:optional|nullable|maybe)\s*[<\[(]\s*(.+?)\s*[>\])]$",
                     lowered)
    if match:
        optional = True
        lowered = match.group(2).strip()
    lowered = re.sub(r"\[\]$", "", lowered).strip()
    return _TYPE_FAMILY.get(lowered, ""), optional


def _mismatch_note(family_a: str, family_b: str) -> str:
    """The lossy-conversion reading of one type-family difference."""
    pair = {family_a, family_b}
    if pair <= _NUMERIC_FAMILIES:
        return ("number is float64 and int is fixed-width: a value above 2^53 "
                "or with a fraction is silently lossy (integer narrowing)")
    if "string" in pair and pair & _NUMERIC_FAMILIES:
        return ("no implicit conversion between string and numeric types — the "
                "two sides serialise different shapes for the same parameter")
    if pair == {"string", "bool"}:
        return ("boolean marshalling differs: a JS truthy string is not a typed "
                "boolean")
    if pair <= {"array", "object"}:
        return ("container shape differs across the boundary (element/field "
                "types are not checked)")
    return f"primitive families differ across the boundary ({family_a} vs {family_b})"


def _param_mismatches(params_a: list[dict], params_b: list[dict],
                      label_a: str, label_b: str) -> list[str]:
    """Arity and type mismatches between the two sides' parameter contracts.

    Positional comparison over the shared prefix (a count mismatch already
    says the shapes differ; comparing the overlap says WHERE they diverge).
    Only known primitive families and optionality are flagged — see
    :data:`_TYPE_FAMILY`.
    """
    out: list[str] = []
    if len(params_a) != len(params_b):
        out.append(
            f"parameter-count mismatch: {label_a} declares {len(params_a)} "
            f"parameter(s) [{_params_render(params_a, MAX_PARAMS)}], {label_b} "
            f"declares {len(params_b)} parameter(s) "
            f"[{_params_render(params_b, MAX_PARAMS)}] — the bridge marshals "
            f"whatever the sender passes, so the extra arguments are silently "
            f"dropped or the missing ones default")
    for index in range(min(len(params_a), len(params_b))):
        param_a = params_a[index]
        param_b = params_b[index]
        name_a = str(param_a.get("name") or "?")
        name_b = str(param_b.get("name") or "?")
        family_a, opt_a = _type_family(param_a.get("type"))
        family_b, opt_b = _type_family(param_b.get("type"))
        if family_a and family_b and family_a != family_b:
            out.append(
                f"type mismatch at position {index + 1}: {label_a} "
                f"'{name_a}: {param_a.get('type')}' vs {label_b} "
                f"'{name_b}: {param_b.get('type')}' — "
                f"{_mismatch_note(family_a, family_b)}")
        if opt_a != opt_b and (param_a.get("type") or param_b.get("type")):
            optional_side = label_a if opt_a else label_b
            required_side = label_b if opt_a else label_a
            out.append(
                f"optionality mismatch at position {index + 1}: {optional_side} "
                f"treats the parameter as optional, {required_side} as required "
                f"— a missing value on the wire becomes a default (or a crash) "
                f"on the receiving side")
    return out[:MAX_MISMATCHES]


_LOSSY_RISKS = (
    "integer narrowing: a 64-bit value crossing into a fixed-width type "
    "truncates silently",
    "null-byte truncation: a string containing \\0 is cut short by C-style "
    "string APIs",
    "deserialization shape mismatch: the receiving side's decoder expects a "
    "shape the sender never guaranteed",
)


def _trust_boundary_note(language_a: str, language_b: str, channel: str) -> list[str]:
    """The trust-boundary reading of the edge."""
    lines = []
    if language_a and language_b and language_a != language_b:
        lines.append(f"trust boundary: {language_a} -> {language_b}"
                     + (f" (channel {channel})" if channel else ""))
        lines.append("  a value crossing this edge crosses a language/runtime "
                     "boundary: validate and type-check on the RECEIVING side — "
                     "the sender's static types say nothing about what the "
                     "bridge actually delivers")
    else:
        same = language_a or language_b or "the same language"
        lines.append(f"note: both sides are {same} — not a trust boundary")
    hint = _channel_hint(channel)
    if hint:
        lines.append(f"  channel note: {hint}")
    return lines


@tool(parse_docstring=True)
def inspect_cross_language_bridge(edge_id: str, root: str = ".") -> str:
    """What contract crosses this language boundary, and does it hold?

    Resolves one edge (a numeric ``edges.id`` or a ``source:target:kind``
    triple), renders BOTH sides' contracts — name, kind, file:line, language,
    signature, and parameters parsed from each side's own file — and flags the
    mismatches that make a bridge a vulnerability surface: parameter-count
    differences, differing type names (string vs int, number vs int, optional
    vs required), and the generic lossy-conversion risks (integer narrowing,
    null-byte truncation into C-style strings, deserialization shape
    mismatch). For synthesized edges the wiring site (``metadata.registeredAt``)
    is reported instead of the edge's own line/col, which ``idx_edges_identity``
    usually forces to be a placeholder.

    Use this on any edge CodeGraph synthesized with a cross-language channel
    (``rn-event-channel``, ``fabric-native-impl``, ``swift-objc``,
    ``go-grpc-stub-impl``, ``mybatis-java-xml``, ``expo-cross-platform``,
    ``expo-modules-js``, ``arkui-*``), or on any edge whose ``resolvedBy`` is
    ``framework``, before reasoning about what a native call receives. Do NOT
    use it to prove a dataflow: it renders the STATIC contracts on both sides,
    it does not trace a value; and a non-bridge edge still renders (with an
    informational note) so the caller can see it is not a boundary.

    Args:
        edge_id: The edge to inspect — a numeric ``edges.id``, or a
            ``source:target:kind`` triple (node ids carry colons, so the kind
            is the LAST segment), e.g.
            ``"server.ts:submitForm:bridge.kt:submit:calls"``.
        root: Repo root holding ``.codegraph/codegraph.db``.

    Returns:
        A bounded report: the bridge header (channel, provenance, confidence,
        wiring site), side A and side B contracts with the call-site window,
        the mismatch list, the generic lossy-conversion risks, and the
        trust-boundary note.
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return _db.guidance_no_db(root)

    edge, error = _resolve_edge(conn, edge_id)
    if edge is None:
        # `edge_id` is agent input, so the error that echoes it is capped.
        return _cap_chars(error)

    meta = edge.get("metadata") or {}
    kind = str(edge.get("kind") or "")
    provenance = edge.get("provenance") or "(none)"
    synthesized_by = meta.get("synthesizedBy")
    resolved_by = meta.get("resolvedBy")
    registered_at = meta.get("registeredAt")
    line = _as_int(edge.get("line"), 0)
    channel = str(synthesized_by or "")
    is_bridge = bool(resolved_by == "framework" or _is_bridge_channel(synthesized_by))

    source = _db.get_node(conn, edge.get("source"))
    target = _db.get_node(conn, edge.get("target"))
    if source is None or target is None:
        return _cap_chars(
            f"ERROR: edge {edge_id} references a node the index no longer "
            f"holds (source {edge.get('source')!r} -> target "
            f"{edge.get('target')!r}); the id may be stale after a re-index")

    confidence = meta.get("confidence")
    if confidence is None:
        confidence_text = "not recorded"
    else:
        try:
            value = float(confidence)
            confidence_text = f"{value:g}"
            if value < 0.6:
                confidence_text += (" (below CodeGraph's UNCERTAIN_BELOW=0.6: "
                                    "a name-only guess, not a call)")
        except (TypeError, ValueError):
            confidence_text = "not recorded"

    cache: dict[str, tuple] = {}
    source_file = str(source.get("file_path") or "")
    source_language = str(source.get("language") or "")
    target_language = str(target.get("language") or "")

    out: list[str] = []
    ref_text = str(edge_id).strip()
    out.append(f"# cross-language bridge: edge {ref_text}")
    if is_bridge:
        why = []
        if _is_bridge_channel(synthesized_by):
            why.append(f"cross-language synthesis channel {channel}")
        if resolved_by == "framework":
            why.append("resolvedBy='framework'")
        out.append("bridge: yes (" + "; ".join(why) + ")")
    else:
        detail = []
        if synthesized_by:
            detail.append(f"synthesizedBy={synthesized_by!r}")
        if resolved_by:
            detail.append(f"resolvedBy={resolved_by!r}")
        out.append("bridge: no — not a cross-language bridge ("
                   + ("; ".join(detail) if detail else "no synthesis metadata")
                   + "); rendering both sides anyway, for context")
    out.append(f"provenance: {provenance}")
    out.append(f"confidence: {confidence_text}")
    out.append(f"kind: {kind}")
    out.append(f"edge: {str(source.get('name') or source.get('id'))} -> "
               f"{str(target.get('name') or target.get('id'))}")

    # --- the wiring site / call site ------------------------------------
    notes: list[str] = []
    if synthesized_by and registered_at:
        out.append(f"wiring site: {registered_at} "
                   f"(metadata.registeredAt — the synthesizer's registration "
                   f"point; the edge is synthesized, so its own line/col are "
                   f"suspect, idx_edges_identity often forces a placeholder)")
    elif line:
        out.append(f"call site: {source_file}:{line}"
                   + (f":{_as_int(edge.get('col'), 0)}"
                      if edge.get("col") is not None else "")
                   + " (edge line/col)")
    else:
        out.append("call site: unknown (the edge carries no line/col and no "
                   "wiring site)")

    # --- side A / side B -------------------------------------------------
    out.append("")
    out.append(_render_side("A", "source", source, root, cache))
    out.append("")
    out.append(_render_side("B", "target", target, root, cache))

    # --- call-site window -------------------------------------------------
    out.append("")
    _tree, source_bytes = _parsed_file(root, source_file, cache)
    window = ""
    if source_bytes is not None and line:
        window = _ts.window(source_bytes, line, 3)
    if window:
        out.append("## call-site window")
        out.append(window)
        if synthesized_by and registered_at:
            notes.append(f"the window is centred on the edge's own (suspect) "
                         f"line {line} in {source_file}, not on the wiring site "
                         f"{registered_at}")
    elif registered_at:
        out.append(f"(call-site window unavailable: {registered_at} is a wiring "
                   f"site, not a line in {source_file})")
    else:
        out.append("(call-site window unavailable: no edge line and no wiring "
                   "site)")

    # --- mismatches ---------------------------------------------------------
    params_a, basis_a = _node_params(source, root, cache)
    params_b, basis_b = _node_params(target, root, cache)
    label_a = f"side A ({str(source.get('name') or '?')})"
    label_b = f"side B ({str(target.get('name') or '?')})"
    mismatches = _param_mismatches(params_a, params_b, label_a, label_b)
    out.append("")
    out.append(f"## mismatches ({len(mismatches)})"
               f"  [side A from {basis_a}, side B from {basis_b}]")
    if not mismatches:
        out.append("none: the two sides' parameter contracts agree on count, "
                   "known type families and optionality")
    for index, mismatch in enumerate(mismatches, start=1):
        out.append(f"{index}. {mismatch}")

    if mismatches or (params_a and params_b):
        out.append("")
        out.append("## lossy-conversion risks (generic — check each by hand)")
        for risk in _LOSSY_RISKS:
            out.append(f"  - {risk}")

    # --- trust boundary ------------------------------------------------------
    out.append("")
    out.extend(_trust_boundary_note(source_language, target_language, channel))
    if source_language and target_language and source_language == target_language \
            and is_bridge and not synthesized_by:
        notes.append("a framework-resolved edge inside one language is a "
                     "wiring, not a boundary")
    for note in notes:
        out.append(f"note: {note}")
    return _cap_chars("\n".join(out))


def _render_side(tag: str, role: str, node: dict, root: str, cache: dict) -> str:
    """One side's contract: label, signature, parameters, basis."""
    lines = [f"## side {tag} — {role}",
             _node_label(node),
             f"language: {str(node.get('language') or '(unknown)')}"]
    signature = str(node.get("signature") or "").strip()
    if signature:
        lines.append(f"signature: {_truncate_line(signature, 800)}")
    params, basis = _node_params(node, root, cache)
    lines.append(f"parameters ({basis}): {_params_render(params, MAX_PARAMS)}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 2. audit_llm_and_mcp_tool_sinks
# ---------------------------------------------------------------------------

# An LLM call is a callee the sinks table classifies 'network' whose name
# matches a provider. The name list is the spec's: OpenAI/Anthropic/LangChain
# and friends, plus the generic model-API verbs (invoke/generate/predict and
# the OpenAI method spellings) so a wrapper client still lands.
_LLM_PROVIDER_RE = re.compile(
    r"openai|anthropic|langchain|chatgpt|gpt|claude|gemini|bedrock|vertexai|"
    r"cohere|mistral|ollama|llm|completions|chat\.completions|embeddings|"
    r"messages\.create|generate|invoke|predict|agent\.run",
    re.IGNORECASE)

# External-looking identifiers: the names attacker-controlled data carries as
# it enters a program. A prompt template that embeds one of these is the
# injection surface of indirect prompt injection (CWE-74).
_EXTERNAL_DATA_RE = re.compile(
    r"\b(?:req|request|body|params|query|input|user|message|email|content|doc|"
    r"page|file|untrusted)\b|search\s+results",
    re.IGNORECASE)

# Tool registrations: the spellings an MCP/LangChain tool surface uses. The
# decorator forms (``@tool``, ``@mcp.tool()``, ``@server.tool``) wrap a
# function; the inline forms (``tools=[...]``, ``bind(tools=[...])``,
# ``add_tool``, ``registerTool``, ``function_call``) name symbols.
_TOOL_REGISTRATION_RE = re.compile(
    r"@tool\b|@?mcp\.tool\b|@?server\.tool\b|add_tool\b|registerTool\b|"
    r"tools\s*=\s*\[|bind\s*\(\s*tools|function_call\b")

# Tokens inside a registration that are framework plumbing, never a tool name.
_TOOL_KEYWORDS = frozenset({
    "tool", "tools", "mcp", "server", "add", "register", "bind", "function",
    "call", "function_call", "new", "this", "const", "let", "var", "async",
    "await", "return", "self", "def", "type", "name", "value", "args",
    "kwargs", "params", "arguments", "options", "opts", "config", "require",
    "import", "from", "export", "default", "true", "false", "none", "null",
})

# Node types whose text can carry a registration (an assignment, a call, a
# declaration). Decorators are handled through their ``decorated_definition``
# parent so the registered FUNCTION is resolvable.
_REGISTRATION_NODE_TYPES = frozenset({
    "decorator", "call", "call_expression", "assignment", "variable_declaration",
    "lexical_declaration", "variable_declarator", "expression_statement",
    "augmented_assignment", "declaration", "public_field_definition",
})

# String/template node types across the grammars. Container types win over
# their fragment children in the dedupe below.
_STRING_NODE_TYPES = frozenset({
    "string", "template_string", "string_literal", "concatenated_string",
    "interpolated_string", "raw_string_literal", "interpreted_string_literal",
    "line_string_literal", "multi_line_string_literal", "string_content",
})

_CALLABLE_KINDS = ("function", "method", "constructor", "component")

# The capability families that make an injected instruction DANGEROUS: a
# prompt-injected model that can spawn processes, touch a database or call out
# over the network is remote code execution, not a chatbot annoyance.
_DANGEROUS_CAPABILITIES = frozenset({"process", "database", "network"})

_TOXIC_FLOW_CONF_LINKED = 0.6
_TOXIC_FLOW_CONF_COOCCUR = 0.4


def _assigned_var(tree, src: bytes, template_node) -> str:
    """The variable a template is assigned to (``''`` when it is not one).

    Found through the enclosing declaration on the template's line: the
    assignment's left/name field, or a declarator child's name field, or — as
    a last resort — the identifier before the first ``=``.
    """
    line = _line_of(template_node)
    best = None
    best_key = None
    for node in _walk(tree.root_node):
        if _line_of(node) != line or not _is_declaration(node):
            continue
        if (template_node.start_byte < node.start_byte
                or template_node.end_byte > node.end_byte):
            continue
        key = (node.end_byte - node.start_byte,)
        if best is None or key < best_key:
            best, best_key = node, key
    if best is None:
        return ""
    for field in ("left", "name", "pattern", "target", "declarator"):
        child = best.child_by_field_name(field)
        if child is None:
            continue
        if child.type in ("variable_declarator", "init_declarator",
                          "shorthand_property_assignment", "property_signature"):
            inner = (child.child_by_field_name("name")
                     or child.child_by_field_name("left"))
            if inner is not None:
                return _clean_name(_ts.node_text(inner, src))
        return _clean_name(_ts.node_text(child, src))
    for sub in best.children:
        if sub.type in ("variable_declarator", "init_declarator"):
            name_node = (sub.child_by_field_name("name")
                         or sub.child_by_field_name("left"))
            if name_node is not None:
                return _clean_name(_ts.node_text(name_node, src))
    text = _ts.node_text(best, src)
    head = text.split("=", 1)[0]
    tokens = [t for t in re.split(r"[\s:,]+", head) if t]
    return _clean_name(tokens[-1]) if tokens else ""


def _is_declaration(node) -> bool:
    """A binding-introducing node: assignment, declaration or declarator."""
    if node.type in _ts.FUNCTION_NODE_TYPES or node.type in _ts.CLASS_NODE_TYPES:
        return False
    return node.type in _DECLARATION_TYPES or node.type.endswith(
        _DECLARATION_SUFFIXES)


_DECLARATION_TYPES = frozenset({
    "assignment", "augmented_assignment", "named_expression",
    "assignment_expression", "augmented_assignment_expression",
    "assignment_statement", "local_variable_declaration", "field_declaration",
    "init_declarator", "short_var_declaration", "var_declaration",
    "const_declaration", "variable_declaration", "lexical_declaration",
})
_DECLARATION_SUFFIXES = ("_declaration", "_declarator")


def _template_candidates(tree, src: bytes, start: int, end: int) -> list[dict]:
    """String/template nodes in the span that embed external-looking data.

    Deduped per (line, col) with the longest text winning, so a container
    node (``concatenated_string``) is not double-counted with its fragment
    child. A string whose whole content IS one external identifier (a role
    label like ``"user"``) is skipped: it is a literal, not constructed
    prompt text.
    """
    by_pos: dict[tuple[int, int], dict] = {}
    seen_ranges: list[tuple[int, int]] = []
    for node in _walk(tree.root_node):
        if node.type not in _STRING_NODE_TYPES:
            continue
        # A fragment child of a string node already visited (a python
        # ``string``'s ``string_content``, a ``concatenated_string``'s parts)
        # is the same template, not a second one — pre-order guarantees the
        # container is seen first.
        if any(s <= node.start_byte and node.end_byte <= e
               for s, e in seen_ranges):
            continue
        seen_ranges.append((node.start_byte, node.end_byte))
        line = _line_of(node)
        if not start <= line <= end:
            continue
        text = _ts.node_text(node, src)
        flat = " ".join(text.split())
        if not flat:
            continue
        key = (line, node.start_point[1] + 1)
        current = by_pos.get(key)
        if current is None or len(flat) > len(current["full_text"]):
            by_pos[key] = {"full_text": flat[:500], "node": node, "line": line,
                           "col": node.start_point[1] + 1}
    out: list[dict] = []
    for key in sorted(by_pos):
        entry = by_pos[key]
        flat = entry["full_text"]
        matched = []
        for match in _EXTERNAL_DATA_RE.findall(flat):
            token = " ".join(match.split()).lower()
            if token and token not in matched:
                matched.append(token)
        if not matched:
            continue
        content = flat.strip().strip("\"'`").strip()
        if len(matched) == 1 and content.lower() == matched[0] \
                and len(content) <= 24:
            continue  # a bare identifier literal ("user"), not prompt text
        entry["matched"] = matched
        entry["var"] = _assigned_var(tree, src, entry["node"])
        out.append(entry)
    return out


def _resolve_symbol(conn, name: str, file_path: str) -> dict | None:
    """A registered tool name resolved to its node — same file first."""
    name = str(name or "").strip()
    if not name or len(name) > 120:
        return None
    lookups = [_db.find_nodes(conn, name=name, file_path=file_path or None,
                              limit=5),
               _db.find_nodes(conn, name=name, limit=5)]
    for nodes in lookups:
        for node in nodes:
            if str(node.get("kind") or "") in _CALLABLE_KINDS:
                return node
    return None


def _tool_registrations(tree, src: bytes, start: int, end: int,
                        conn, root: str, cache: dict,
                        file_path: str = "") -> list[dict]:
    """Tool registrations in the span, each resolved to its function node.

    Two shapes: a decorator on a function (the registered function is the
    decorated def) and an inline list/call (the registered symbols are the
    identifier tokens inside it). An unresolvable token is reported as
    ``(unresolved registration)`` rather than dropped — the registration is
    the signal, the resolution is the bonus.
    """
    out: list[dict] = []
    covered: set[int] = set()
    # 1. decorator registrations: @tool / @mcp.tool() / @server.tool(...)
    for node in _walk(tree.root_node):
        if node.type != "decorated_definition":
            continue
        line = _line_of(node)
        if not start <= line <= end:
            continue
        for child in node.children:
            if child.type != "decorator":
                continue
            if not _TOOL_REGISTRATION_RE.search(_ts.node_text(child, src)):
                continue
            inner = None
            for sub in node.children:
                if sub.type in _ts.FUNCTION_NODE_TYPES and sub.children:
                    inner = sub
                    break
            name = ""
            if inner is not None:
                name_node = (inner.child_by_field_name("name")
                             or inner.child_by_field_name("declarator"))
                if name_node is not None:
                    name = _clean_name(_ts.node_text(name_node, src))
                if not name:
                    for leaf in _walk(inner):
                        if leaf.type in _ID_LEAF_TYPES:
                            name = _clean_name(_ts.node_text(leaf, src))
                            break
            target = _resolve_symbol(conn, name, file_path)
            out.append({"site": _line_of(child),
                        "raw": _truncate_line(_ts.node_text(child, src)),
                        "form": "decorator", "name": name, "target": target})
            covered.add(_line_of(child))
    # 2. inline registrations: tools=[...] / bind(tools=[...]) / add_tool(...)
    for node in _walk(tree.root_node):
        if node.type not in _REGISTRATION_NODE_TYPES:
            continue
        line = _line_of(node)
        if not start <= line <= end or line in covered:
            continue
        text = _ts.node_text(node, src)
        if not _TOOL_REGISTRATION_RE.search(text):
            continue
        covered.add(line)
        tokens = []
        for token in re.findall(r"[A-Za-z_$][\w$]*", text):
            if token.lower() in _TOOL_KEYWORDS or len(token) < 2:
                continue
            if token not in tokens:
                tokens.append(token)
        if not tokens:
            out.append({"site": line, "raw": _truncate_line(text),
                        "form": "inline", "name": "", "target": None,
                        "unresolved": True})
            continue
        for token in tokens[:5]:
            target = _resolve_symbol(conn, token, "")
            out.append({"site": line, "raw": _truncate_line(text),
                        "form": "inline", "name": token,
                        "target": target,
                        "unresolved": target is None})
    return out


def _capabilities_of(conn, root: str, node: dict, cache: dict):
    """``(capabilities, note)`` — the effect categories a tool's callees have.

    Every call in the tool's own span is classified through the sinks
    taxonomy; the categories are what an injected instruction could make the
    model do (process/database/network/storage/auth ...).
    """
    language = str(node.get("language") or "")
    file_path = str(node.get("file_path") or "")
    start, end = _node_span(node)
    tree, src = _parsed_file(root, file_path, cache)
    if tree is None or not start:
        return [], "(source not readable — capabilities unknown)"
    out: list[dict] = []
    seen: set[str] = set()
    for call in _ts.calls_in_span(tree, start, end, src):
        for category in sinks.classify_call(call["text"], language):
            if category in seen:
                continue
            seen.add(category)
            out.append({"category": category, "call": call["text"],
                        "line": call["line"]})
    out.sort(key=lambda c: (c["line"], c["category"]))
    return out, ""


def _llm_calls_in(tree, src: bytes, start: int, end: int,
                  language: str) -> list[dict]:
    """Callees classified 'network' whose name matches an LLM provider."""
    out: list[dict] = []
    for call in _ts.calls_in_span(tree, start, end, src):
        categories = sinks.classify_call(call["text"], language)
        if "network" not in categories:
            continue
        if not _LLM_PROVIDER_RE.search(call["text"]):
            continue
        out.append({"line": call["line"], "col": call["col"],
                    "text": call["text"], "node": call["node"],
                    "args_text": _ts.node_text(call["node"], src)[:2000]})
    return out


def _toxic_flows(templates: list[dict], llm_calls: list[dict]) -> list[dict]:
    """Prompt templates that feed an LLM call, with the link's basis.

    A link is a variable name (the template is assigned to ``systemPrompt``
    and the call's arguments mention it) or the template text itself appearing
    inside the call's arguments. When neither is found but both exist in one
    span, a single co-occurrence flow is still reported — labelled as such,
    because that is a weaker link than a textual one.
    """
    flows: list[dict] = []
    for template in templates:
        var = str(template.get("var") or "")
        for call in llm_calls:
            args_text = str(call.get("args_text") or "")
            basis = ""
            if var and re.search(rf"(?<![\w$]){re.escape(var)}(?![\w$])",
                                 args_text):
                basis = (f"variable link '{var}' — the template is assigned to "
                         f"{var} and the LLM call's arguments mention it")
            elif template.get("full_text") and template["full_text"] in args_text:
                basis = ("the template text appears inside the LLM call's "
                         "arguments")
            if basis:
                flows.append({"template": template, "llm": call, "basis": basis})
    if not flows and templates and llm_calls:
        flows.append({"template": templates[0], "llm": llm_calls[0],
                      "basis": ("co-occurrence in the same span (no textual link "
                                "to the LLM call's arguments found)")})
    return flows


def _llm_finding(flow: dict, node: dict, capabilities: list[dict]) -> tuple[dict, str]:
    """The CWE-74 candidate finding for one toxic flow."""
    template = flow["template"]
    call = flow["llm"]
    capability_names = sorted({c["category"] for c in capabilities})
    dangerous = sorted(set(capability_names) & _DANGEROUS_CAPABILITIES)
    severity = "high" if dangerous else "medium"
    cooccur = flow["basis"].startswith("co-occurrence")
    confidence = _TOXIC_FLOW_CONF_COOCCUR if cooccur else _TOXIC_FLOW_CONF_LINKED
    handler_file = str(node.get("file_path") or "")
    start, end = _node_span(node)
    template_site = f"{handler_file}:{template['line']}"
    call_site = f"{handler_file}:{call['line']}"
    template_text = _truncate_line(template["full_text"], 120)
    taint_path = [
        f"{template_site} prompt template {template_text}",
        f"{call_site} llm call {call['text']}",
    ]
    if capability_names:
        tools_note = (f"the model's registered tools carry "
                      f"{', '.join(capability_names)} capability(ies)")
    else:
        tools_note = "no tool registrations were resolved in this span"
    evidence = (f"external data ({', '.join(template['matched'])}) reaches "
                f"{template_site} prompt template {template_text}, which feeds "
                f"{call_site} {call['text']}; {tools_note}")
    finding = _candidate_finding(
        title="Indirect prompt injection to tool execution",
        path=handler_file,
        start_line=start,
        end_line=end,
        cwe="CWE-74",
        severity=severity,
        confidence=confidence,
        taint_source=f"external data: {', '.join(template['matched'])}",
        taint_sink=f"{call['text']} @ {call_site}",
        taint_path=taint_path,
        evidence=evidence,
        rationale=(f"attacker-controlled text ({', '.join(template['matched'])}) "
                   f"is interpolated into a prompt that feeds an LLM call in "
                   f"the same span; {tools_note}. An injected instruction in "
                   f"that text is executed by the model, not by the "
                   f"application's control flow"),
        note=("CWE-74 (Improper Neutralization of Special Elements in Output "
              "Used by a Downstream Component / injection); CWE-77/CWE-78 "
              "cover the command-injection consequence when the tool set "
              "includes process execution"),
    )
    header = (f"## candidate finding (CWE-74, severity {severity}, "
              f"confidence {confidence})")
    return finding, header


@tool(parse_docstring=True)
def audit_llm_and_mcp_tool_sinks(node_id: str, root: str = ".",
                                 limit: int | None = None) -> str:
    """Does external data reach a prompt that feeds an LLM with tools?

    Scans one node's span for the three parts of an AI-native toxic flow:
    (a) LLM calls — callees the sinks taxonomy classifies ``network`` whose
    name matches a provider (openai|anthropic|langchain|gpt|claude|...); (b)
    prompt construction — string/template nodes embedding external-looking
    identifiers (req|request|body|params|query|input|user|message|email|
    content|doc|page|file|untrusted|search results); (c) registered tools —
    ``@tool`` / ``mcp.tool`` / ``add_tool`` / ``registerTool`` / ``server.tool``
    / ``tools=[...]`` / ``bind(tools=...)`` / ``function_call`` — each resolved
    to its function node and classified through the sinks taxonomy so its
    capabilities (process/database/network/storage/auth) are listed. A
    template that feeds an LLM call in the same span is a toxic flow and
    becomes a CWE-74 candidate finding.

    Use this on any handler, agent or chat endpoint before reasoning about
    prompt injection, and on any node that registers tools. Do NOT use it as
    proof of exploitability: the external-data match is a name heuristic (a
    field called ``file`` is flagged whether or not it is attacker-controlled),
    the template-to-LLM link is textual, and tool capabilities are the
    tool's callees, not the model's actual tool schema. Severity is ``high``
    when the tool set includes process/database/network capabilities,
    ``medium`` otherwise; confidence is 0.6 for a textually linked flow and
    0.4 for a co-occurrence-only one.

    Args:
        node_id: The node whose span to audit (a handler, agent or chat
            endpoint; a file node audits the whole file).
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Max LLM calls, prompt templates and tool registrations rendered
            per section. 0 = unlimited.

    Returns:
        A bounded report: ``llm_calls``, ``prompt_templates`` (each flagged
        "external data reaches prompt"), ``registered_tools`` with their
        capabilities, ``toxic_flows``, and one candidate finding block
        (CWE-74) per flow.
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return _db.guidance_no_db(root)

    node = _db.get_node(conn, node_id)
    if node is None:
        return _cap_chars(f"ERROR: node not found: {node_id}")

    start, end = _node_span(node)
    language = str(node.get("language") or "")
    file_path = str(node.get("file_path") or "")
    out: list[str] = [
        f"# llm/mcp tool-sink audit: {_node_label(node)}",
        f"span: {file_path}:{start}-{end} ({language or 'unknown language'})",
    ]
    if not start:
        out.append("note: this node has no usable line span — nothing to scan")
        return _cap_chars("\n".join(out))

    cache: dict[str, tuple] = {}
    tree, src = _parsed_file(root, file_path, cache)
    if tree is None:
        out.append("(source file not readable through this root — the span "
                   "cannot be scanned; node_modules/vendor are never indexed)")
        return _cap_chars("\n".join(out))

    llm_calls = _llm_calls_in(tree, src, start, end, language)
    templates = _template_candidates(tree, src, start, end)
    registrations = _tool_registrations(tree, src, start, end, conn, root,
                                        cache, file_path)

    # --- llm_calls ---------------------------------------------------------
    call_cap = _cap_rows(limit, ENV_LLM_CALLS, DEFAULT_LLM_CALLS)
    out.append("")
    out.append(f"## llm_calls ({len(llm_calls)})")
    if not llm_calls:
        out.append("none: no callee in this span is both classified 'network' "
                   "by the sinks table and named like an LLM provider")
    for index, call in enumerate(llm_calls[:call_cap], start=1):
        out.append(f"{index}. {call['text']} @ {file_path}:{call['line']} "
                   f"(network)")
    if len(llm_calls) > call_cap:
        out.append(f"… +{len(llm_calls) - call_cap} more llm calls "
                   f"(total {len(llm_calls)})")

    # --- prompt_templates ----------------------------------------------------
    template_cap = _cap_rows(limit, ENV_TEMPLATES, DEFAULT_TEMPLATES)
    out.append("")
    out.append(f"## prompt_templates ({len(templates)})")
    if not templates:
        out.append("none: no string/template node in this span embeds an "
                   "external-looking identifier")
    for index, template in enumerate(templates[:template_cap], start=1):
        var_text = f" -> {template['var']}" if template.get("var") else ""
        out.append(f"{index}. {_truncate_line(template['full_text'], 120)} @ "
                   f"{file_path}:{template['line']}{var_text} — external data "
                   f"reaches prompt: {', '.join(template['matched'])}")
    if len(templates) > template_cap:
        out.append(f"… +{len(templates) - template_cap} more prompt templates "
                   f"(total {len(templates)})")

    # --- registered_tools -----------------------------------------------------
    tool_cap = _cap_rows(limit, ENV_TOOL_REGS, DEFAULT_TOOL_REGS)
    capabilities: list[dict] = []
    out.append("")
    out.append(f"## registered_tools ({len(registrations)})")
    if not registrations:
        out.append("none: no tool registration (``@tool`` / ``mcp.tool`` / "
                   "``add_tool`` / ``registerTool`` / ``server.tool`` / "
                   "``tools=[...]`` / ``bind(tools=...)`` / ``function_call``) "
                   "in this span")
    for index, reg in enumerate(registrations[:tool_cap], start=1):
        target = reg.get("target")
        if target is None:
            out.append(f"{index}. (unresolved registration) @ "
                       f"{file_path}:{reg['site']} — {reg['raw']}")
            continue
        caps, note = _capabilities_of(conn, root, target, cache)
        capabilities.extend(caps)
        cap_text = ", ".join(sorted({c["category"] for c in caps})) or "none"
        out.append(f"{index}. {str(target.get('name') or reg['name'])} @ "
                   f"{_node_label(target, with_span=False)} — capabilities: "
                   f"{cap_text}")
        for cap in caps[:4]:
            out.append(f"     callee: {cap['call']} @ "
                       f"{str(target.get('file_path'))}:{cap['line']} "
                       f"({cap['category']})")
        if note:
            out.append(f"     {note}")
    if len(registrations) > tool_cap:
        out.append(f"… +{len(registrations) - tool_cap} more registrations "
                   f"(total {len(registrations)})")

    # --- toxic_flows + findings -------------------------------------------------
    flows = _toxic_flows(templates, llm_calls)
    out.append("")
    out.append(f"## toxic_flows ({len(flows)})")
    if not flows:
        out.append("none: no prompt template in this span feeds an LLM call "
                   "(a flow needs both, linked by variable name or by the "
                   "template text appearing in the call's arguments)")
    for index, flow in enumerate(flows, start=1):
        out.append(f"{index}. external data "
                   f"[{', '.join(flow['template']['matched'])}] -> prompt "
                   f"template @ {file_path}:{flow['template']['line']} -> "
                   f"{flow['llm']['text']} @ {file_path}:{flow['llm']['line']}")
        out.append(f"     basis: {flow['basis']}")

    finding_cap = _section_cap(ENV_LLM_FINDINGS, DEFAULT_LLM_FINDINGS)
    out.append("")
    out.append(f"## findings ({len(flows)})")
    if not flows:
        out.append("no candidate finding: no external data reaches a prompt "
                   "that feeds an LLM call in this span")
    for index, flow in enumerate(flows[:finding_cap], start=1):
        finding, header = _llm_finding(flow, node, capabilities)
        out.append("")
        out.extend(_finding_lines(finding, header))
    if len(flows) > finding_cap:
        out.append("")
        out.append(f"… +{len(flows) - finding_cap} more toxic flows "
                   f"(total {len(flows)}); re-run with a narrower node or a "
                   f"higher limit")
    return _cap_chars("\n".join(out))


# ---------------------------------------------------------------------------
# 3. verify_exploit_poc_in_harness
# ---------------------------------------------------------------------------

# Route -> handler edge kinds (framework-resolver dependent: Spring/Rails/
# Laravel emit `references`, Express emits `calls`) and the handler kinds
# getRoutingManifest accepts — mirrored locally so this module never reaches
# into the foundation's private table.
_ROUTE_EDGE_KINDS = ("references", "calls")
_HANDLER_KINDS = ("function", "method", "class", "constant", "variable",
                  "component")

_TEST_FILE_PY = "test_sast_poc.py"
_TEST_FILE_JS = "poc.test.js"


def _resolve_route(conn, route_id: str) -> tuple[dict | None, str]:
    """The route node: direct lookup, then the routing manifest, then name."""
    text = str(route_id or "").strip()
    if not text:
        return None, "ERROR: route_id is required (a route node id or its URL)"
    node = _db.get_node(conn, text)
    if node is not None and str(node.get("kind") or "") == "route":
        return node, ""
    if node is not None and str(node.get("kind") or "") != "route":
        return None, (f"ERROR: node {text} is kind {node.get('kind')!r}, not "
                      f"'route' — pass the route node id (a routing manifest "
                      f"route_id) or its URL, not its handler")
    for row in _db.routing_manifest(conn, limit=0):
        if str(row.get("route_id")) == text or str(row.get("url")) == text:
            found = _db.get_node(conn, row.get("route_id"))
            if found is not None:
                return found, ""
    for found in _db.find_nodes(conn, kind="route", name=text, limit=5):
        return found, ""
    for found in _db.find_nodes(conn, kind="route", name_like=f"%{text}%",
                                limit=5):
        return found, ""
    return None, f"ERROR: route not found: {route_id}"


def _handler_for_route(conn, route_id: str) -> dict | None:
    """The route's handler: outgoing ``references``/``calls`` to a handler kind.

    Mirrors ``getRoutingManifest``'s join (queries.ts:1258) so this tool and
    the manifest can never disagree about which symbol serves a URL.
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


def _module_of(file_path: str) -> str:
    """The importable module of a file path: ``lib/db.py`` -> ``lib.db``."""
    parts = [p for p in str(file_path or "").replace("\\", "/").split("/")
             if p and p != "."]
    if parts and parts[-1] == "__init__.py":
        parts = parts[:-1]
    if parts:
        parts[-1] = re.sub(r"\.pyw?$", "", parts[-1])
    return ".".join(parts)


def _poc_style(language: str) -> str:
    """``pytest`` for a python handler, ``jest`` for js/ts, else ``unsupported``."""
    lang = str(language or "").lower()
    if lang in ("javascript", "typescript", "tsx", "jsx"):
        return "jest"
    if lang == "python":
        return "pytest"
    return "unsupported"


def _handler_fields(handler: dict, root: str, cache: dict) -> tuple[list[str], list[str]]:
    """``(param_names, external_ids)`` the attacker controls, both bounded.

    Parameters come from the handler's own def; external ids are the
    external-looking identifiers its BODY reads — the def line is skipped
    because its identifiers ARE the parameters, already captured. A match
    immediately followed by ``(`` is a callee (``db.query``), not a field
    read, so it is not attacker-controlled. Both lists are capped, because a
    handler with fifty parameters is not a PoC, it is a flood.
    """
    params, _basis = _node_params(handler, root, cache)
    names: list[str] = []
    for param in params:
        name = str(param.get("name") or "").strip()
        if not name or name in ("self", "cls") or name in names:
            continue
        names.append(name)
    external: list[str] = []
    tree, src = _parsed_file(root, str(handler.get("file_path") or ""), cache)
    if tree is not None and src is not None:
        start, end = _node_span(handler)
        if start:
            lines = src.decode("utf-8", errors="replace").splitlines()
            # lines[start:end] skips the def/signature line itself
            chunk = "\n".join(lines[start:end])[:MAX_SPAN_TEXT]
            for match in _EXTERNAL_DATA_RE.finditer(chunk):
                if chunk[match.end():match.end() + 1] == "(":
                    continue  # a callee (db.query), not a field read
                token = " ".join(match.group(0).split()).lower()
                if token and token not in external:
                    external.append(token)
    return names[:MAX_FIELDS], external[:MAX_FIELDS]


def _poc_kwargs(parsed, param_names: list[str],
                external_ids: list[str]) -> tuple[dict | None, list[str], str]:
    """``(kwargs, attacker_fields, note)`` — the canary substituted everywhere.

    A mock key matching a handler parameter or an external-looking identifier
    becomes the canary; every handler parameter missing from the mock is
    filled with the canary too, because in a PoC the attacker controls all of
    them. Returns ``(None, [], error)`` when the mock is not an object.
    """
    if not isinstance(parsed, dict):
        return None, [], ("ERROR: mock_request_json must be a JSON object (the "
                          "request shape the handler receives)")
    attacker = {n.lower() for n in param_names} | {i.lower() for i in external_ids}
    fields: list[str] = []
    for name in param_names + external_ids:
        if name.lower() not in {f.lower() for f in fields}:
            fields.append(name)
    kwargs: dict = {}
    for key, value in parsed.items():
        text = str(key)
        kwargs[text] = CANARY if text.lower() in attacker else value
    for name in param_names:
        kwargs.setdefault(name, CANARY)
    if len(kwargs) > MAX_FIELDS:
        return (dict(list(kwargs.items())[:MAX_FIELDS]), fields,
                f"bounded to {MAX_FIELDS} fields")
    return kwargs, fields, ""


def _shrink_value(value, limit: int):
    """A value that survives ``json.dumps`` under ``limit`` characters.

    Strings are cut; containers are cut entry-by-entry with the budget split
    across them. Everything else (numbers, booleans, None) is already short.
    """
    if limit <= 0:
        limit = 0
    if isinstance(value, str):
        return value if len(value) <= limit else value[:limit] + "…"
    if isinstance(value, dict):
        items = list(value.items())[:MAX_FIELDS]
        share = max(1, limit // max(1, len(items)))
        return {str(k): _shrink_value(v, share) for k, v in items}
    if isinstance(value, (list, tuple)):
        items = list(value)[:MAX_FIELDS]
        share = max(1, limit // max(1, len(items)))
        return [_shrink_value(v, share) for v in items]
    return value


def _bounded_mock_literal(kwargs: dict) -> tuple[str, list[str]]:
    """``(json_literal, notes)`` — a mock literal that is ALWAYS valid JSON.

    The naive form was ``json.dumps(kwargs)[:MAX_MOCK_CHARS]``, which cuts the
    serialised text wherever the budget lands — mid-string, mid-escape, or
    between the digits of a number. The generated test then embeds a broken
    literal in ``json.loads(...)``, which runs OUTSIDE the try/except guarding
    the handler: the exception propagates, the canary marker is never printed,
    and the PoC reports a clean "no canary marker" negative for a test that
    never ran. That is a silent false negative in the one tool whose job is
    runtime proof.

    So the bound is applied to the STRUCTURE — each value shrunk to its share
    of the budget, the document re-serialised, and the result verified to
    parse — and whatever was dropped or shrunk is reported as a note rather
    than hidden.
    """
    notes: list[str] = []
    items = list(kwargs.items())[:MAX_FIELDS]
    if len(kwargs) > len(items):
        notes.append(f"bounded to {MAX_FIELDS} mock fields of {len(kwargs)}")
    per_value = max(16, MAX_MOCK_CHARS // max(1, len(items)))
    bounded: dict = {}
    for key, value in items:
        shrunk = _shrink_value(value, per_value)
        if shrunk != value:
            notes.append(f"mock field {str(key)!r} shrunk to fit the "
                         f"{MAX_MOCK_CHARS}-char mock budget")
        bounded[str(key)] = shrunk
    literal = json.dumps(bounded, sort_keys=True)
    # Long KEYS (not values) can still overflow; drop tail entries until the
    # document fits, and say so.
    while len(literal) > MAX_MOCK_CHARS and bounded:
        dropped = bounded.popitem()
        notes.append(f"mock field {dropped[0]!r} dropped to fit the "
                     f"{MAX_MOCK_CHARS}-char mock budget")
        literal = json.dumps(bounded, sort_keys=True)
    try:
        json.loads(literal)          # never ship a literal that will not parse
    except ValueError:               # pragma: no cover - defensive
        literal = "{}"
        notes.append("the bounded mock fell back to {} — the literal could "
                     "not be re-serialised as valid JSON")
    return literal, notes


def _gen_python_test(handler_module: str, handler_name: str,
                     sink_module: str, sink_name: str, mock_literal: str,
                     route_label: str, sink_label: str) -> str:
    """A pytest function that patches the sink and calls the handler.

    The sink is patched BY MODULE PATH (derived from the sink node's
    ``file_path``) so the handler's own ``db.run_query(...)`` call lands on the
    spy. A handler that raises before the sink is data, not a failure: the
    error is recorded and reported alongside the canary verdict.

    ``mock_literal`` arrives already bounded by :func:`_bounded_mock_literal`
    and is embedded verbatim: it is valid JSON by construction, so the test's
    own ``json.loads`` cannot be the thing that fails.
    """
    patch_target = f"{sink_module}.{sink_name}"
    lines = [
        '"""Generated by verify_exploit_poc_in_harness — do not edit.',
        "",
        f"Confirms whether attacker-controlled input reaches {sink_label}",
        f"through {route_label}.",
        f"Canary: {CANARY}",
        '"""',
        "import json",
        "import sys",
        "",
        'sys.path.insert(0, "/repo")  # the repo is mounted read-only here',
        "",
        f"CANARY = {CANARY!r}",
        "",
        "",
        "def test_sast_poc(monkeypatch):",
        f"    import {sink_module}  # the sink's module (nodes.file_path)",
        "    received = []",
        "",
        "    def _sast_spy(*args, **kwargs):",
        '        received.append({"args": [str(a) for a in args],',
        '                         "kwargs": {k: str(v) for k, v in kwargs.items()}})',
        "        return None",
        "",
        f'    monkeypatch.setattr("{patch_target}", _sast_spy)',
        "",
        f"    import {handler_module}",
        f"    mock = json.loads({mock_literal!r})",
        "    handler_error = None",
        "    try:",
        f"        {handler_module}.{handler_name}(**mock)",
        "    except Exception as exc:  # crashing before the sink is data, not failure",
        "        handler_error = repr(exc)",
        "    hit = any(CANARY in json.dumps(entry, default=str)",
        "              for entry in received)",
        "    if hit:",
        f'        print("{CANARY_MARKER}yes")',
        "        assert True",
        "    else:",
        f'        print("{CANARY_MARKER}no")',
        "        assert False, (",
        f'            "canary did not reach {patch_target}: "',
        # These braces are the GENERATED f-string's own interpolation, so
        # they must reach it singly: doubling them here printed the literal
        # text "{received!r}" as the negative-path evidence.
        '            f"received={received!r} "',
        '            f"handler_error={handler_error!r}")',
    ]
    return "\n".join(lines)


def _gen_jest_test(handler_file: str, handler_name: str, sink_file: str,
                   sink_name: str, mock_literal: str, route_label: str,
                   sink_label: str) -> str:
    """A jest-style equivalent: the sink is stubbed, the handler is called.

    ``mock_literal`` is the already-bounded, valid-JSON mock from
    :func:`_bounded_mock_literal`, embedded as the handler's argument.
    """
    lines = [
        "// Generated by verify_exploit_poc_in_harness — do not edit.",
        f"// Confirms whether attacker-controlled input reaches {sink_label}",
        f"// through {route_label}. Canary: {CANARY}",
        f"const CANARY = {CANARY!r};",
        "",
        f'describe("SAST PoC: {route_label} -> {sink_label}", () => {{',
        '  it("canary reaches the sink", () => {',
        "    const received = [];",
        f'    const sinkModule = require("/repo/{sink_file}");',
        f"    const original = sinkModule.{sink_name};",
        f"    sinkModule.{sink_name} = function sastSpy(...args) {{",
        "      received.push(args.map(String));",
        "      return null;",
        "    };",
        "    let handlerError = null;",
        "    try {",
        f'      const handler = require("/repo/{handler_file}");',
        f"      handler.{handler_name}({mock_literal});",
        "    } catch (exc) {",
        "      handlerError = String(exc);",
        "    } finally {",
        f"      sinkModule.{sink_name} = original;",
        "    }",
        "    const hit = received.some((entry) =>",
        "      JSON.stringify(entry).includes(CANARY));",
        '    console.log("SAST_POC_RESULT: canary_reached=" +',
        '      (hit ? "yes" : "no"));',
        "    if (!hit) {",
        f'      throw new Error("canary did not reach {sink_label}: " +',
        '        JSON.stringify(received) + " handler_error=" + handlerError);',
        "    }",
        "  });",
        "});",
    ]
    return "\n".join(lines)


def _parse_canary(stdout: str, stderr: str) -> str:
    """``yes``/``no`` from the generated test's marker line, else ``''``."""
    match = re.search(r"SAST_POC_RESULT:\s*canary_reached=(yes|no)",
                      f"{stdout or ''}\n{stderr or ''}")
    return match.group(1) if match else ""


def _canary_evidence(stdout: str) -> str:
    """The assertion output a finding cites: the marker and its context."""
    keep = []
    for line in (stdout or "").splitlines():
        if "canary" in line.lower() or "SAST_POC" in line:
            keep.append(line.strip())
    return " | ".join(keep)[:400] or (stdout or "").strip()[:400]


def _run_poc(root: str, test_file_name: str, test_source: str, image: str,
             test_cmd: list[str], timeout: int) -> dict:
    """Run the generated test in an ephemeral, network-less container.

    The repo is bind-mounted READ-ONLY at ``/repo``, the test lives in a
    fresh temp dir mounted at ``/poc``, the network is blocked, and the child
    inherits the harness's scrubbed env — the same discipline as
    ``harness.tools.sast._run``, because the container is executing
    attacker-reachable code.
    """
    from harness.tools._compat import scrubbed_env
    max_bytes = _env_int("SAST_BYTES", MAX_SINK_BYTES)
    try:
        repo = _safe_path(str(root))
    except (OSError, ValueError) as e:
        # A root that stopped resolving between the index check and here is a
        # reported error, not a crash inside the docker path.
        return {"error": str(e) or e.__class__.__name__}
    tmpdir = tempfile.mkdtemp(prefix="sast-poc-")
    try:
        (Path(tmpdir) / test_file_name).write_text(test_source)
        cmd = ["docker", "run", "--rm", "--network", "none",
               "-v", f"{repo}:/repo:ro", "-v", f"{tmpdir}:/poc",
               "-w", "/poc", image] + list(test_cmd)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, env=scrubbed_env())
        except subprocess.TimeoutExpired:
            return {"error": f"timeout after {timeout}s"}
        except OSError as e:
            return {"error": str(e)}
        stdout = proc.stdout if max_bytes <= 0 else proc.stdout[:max_bytes]
        return {"returncode": proc.returncode, "stdout": stdout,
                "stderr": proc.stderr[:MAX_STDERR_BYTES],
                "truncated": bool(max_bytes > 0
                                  and len(proc.stdout) > max_bytes)}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@tool(parse_docstring=True)
def verify_exploit_poc_in_harness(route_id: str, sink_id: str,
                                  mock_request_json: str, root: str = ".",
                                  timeout: int = 120) -> str:
    """Did the attacker-controlled value really reach the sink?

    Resolves the route (``kind='route'``, via direct lookup or the routing
    manifest) and the sink function node, identifies the attacker-controlled
    fields the handler reads (its parameters plus external-looking
    identifiers), substitutes the canary ``__SAST_CANARY__`` for them in
    ``mock_request_json``, and GENERATES a minimal reproduction test: a pytest
    function (python handlers) that monkeypatches the sink BY MODULE PATH
    derived from its ``file_path`` and calls the handler, or a jest-style
    equivalent (js/ts handlers). The test asserts whether the canary reached
    the sink.

    Execution policy — READ THIS: the generated test is NEVER run in-process.
    It runs ONLY in an ephemeral docker container (``--network none``, repo
    bind-mounted read-only, workdir ``/poc``) and ONLY when the docker binary
    exists AND the operator opted in with ``SAST_POC_EXEC=1``. Without both,
    the tool returns status ``not-executed`` with the reason, the full
    generated test source, and run instructions. Use this to confirm a taint
    path a static finding claims. Do NOT use it to explore: the canary
    substitutes for identified attacker fields only, and the verdict is only
    as good as the handler actually reaching the sink at runtime.

    Args:
        route_id: The route node id (a routing manifest ``route_id``) or its
            URL (e.g. ``"POST /login"``).
        sink_id: The sink function node id whose module path the test patches.
        mock_request_json: A JSON object — the request shape the handler
            receives. Keys matching attacker-controlled fields are replaced
            with the canary.
        root: Repo root holding ``.codegraph/codegraph.db``.
        timeout: Seconds the docker run may take (default 120).

    Returns:
        A bounded report: the resolved route/handler/sink, the substituted
        mock request, ``status`` (executed|not-executed|error),
        ``canary_reached`` (yes|no|unknown), the generated test source, the
        capped stdout/stderr when executed, and — when the canary reached the
        sink — a candidate finding (CWE-20, severity high, confidence 1.0).
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return _db.guidance_no_db(root)

    # The mock request is pure input: parse it before touching the index so a
    # malformed one is an input error, not a graph error.
    raw_mock = str(mock_request_json or "").strip()
    try:
        parsed_mock = json.loads(raw_mock) if raw_mock else {}
    except (TypeError, ValueError) as e:
        # The parser's message quotes the input, so it is capped too.
        return _cap_chars(f"ERROR: mock_request_json is not valid JSON: {e}")

    route, route_error = _resolve_route(conn, route_id)
    if route is None:
        return _cap_chars(route_error)   # echoes the agent's route_id
    handler = _handler_for_route(conn, str(route.get("id") or ""))
    if handler is None:
        return _cap_chars(
            f"ERROR: no handler resolvable for route {route_id} — no "
            f"outgoing references/calls edge from the route node to a "
            f"node of kind {'|'.join(_HANDLER_KINDS)}")
    sink = _db.get_node(conn, sink_id)
    if sink is None:
        return _cap_chars(f"ERROR: node not found: {sink_id}")

    handler_name = str(handler.get("name") or "").strip()
    sink_name = str(sink.get("name") or "").strip()
    if not handler_name:
        return _cap_chars(f"ERROR: handler node {handler.get('id')} has no "
                          f"name to call")
    if not sink_name:
        return _cap_chars(f"ERROR: sink node {sink_id} has no name to patch")

    cache: dict[str, tuple] = {}
    param_names, external_ids = _handler_fields(handler, root, cache)
    kwargs, attacker_fields, poc_note = _poc_kwargs(parsed_mock, param_names,
                                                    external_ids)
    if kwargs is None:
        return poc_note  # the error string from _poc_kwargs

    # The embedded mock is bounded on the STRUCTURE, never by slicing the
    # serialisation: a mid-token cut is invalid JSON, and the generated test's
    # own json.loads runs outside the guard around the handler.
    mock_literal, mock_notes = _bounded_mock_literal(kwargs)
    poc_notes: list[str] = []
    if poc_note:
        poc_notes.append(poc_note)
    poc_notes.extend(mock_notes)

    try:
        run_timeout = max(1, min(int(timeout), 3600))
    except (TypeError, ValueError):
        run_timeout = DEFAULT_POC_TIMEOUT

    style = _poc_style(handler.get("language"))
    if style == "unsupported":
        return _cap_chars(
            f"ERROR: PoC generation supports python and javascript/"
            f"typescript handlers only (handler language: "
            f"{handler.get('language')!r}); a Go/Java/Kotlin route cannot "
            f"be confirmed by this harness's pytest/jest runner")

    handler_file = str(handler.get("file_path") or "")
    sink_file = str(sink.get("file_path") or "")
    route_label = str(route.get("name") or route_id)
    sink_label = f"{sink_name} @ {sink_file}"
    # The sink's module path, for the python patch target and the finding's
    # rationale (the jest style patches the module object instead, but the
    # same path is what an analyst reads).
    sink_module = _module_of(sink_file) or "sink"
    if style == "pytest":
        handler_module = _module_of(handler_file) or "handler"
        test_source = _gen_python_test(handler_module, handler_name,
                                       sink_module, sink_name, mock_literal,
                                       route_label, sink_label)
        test_file_name = _TEST_FILE_PY
        image = os.environ.get(ENV_POC_IMAGE) or DEFAULT_PY_IMAGE
        test_cmd = ["python", "-m", "pytest", f"/poc/{_TEST_FILE_PY}",
                    "-s", "-q", "-p", "no:cacheprovider"]
        runner = ("the image must provide pytest (SAST_POC_IMAGE can point at "
                  "an image that does)")
    else:
        test_source = _gen_jest_test(handler_file, handler_name, sink_file,
                                     sink_name, mock_literal, route_label,
                                     sink_label)
        test_file_name = _TEST_FILE_JS
        image = os.environ.get(ENV_POC_IMAGE) or DEFAULT_JS_IMAGE
        test_cmd = ["npx", "--yes", "jest", "--ci", "--runInBand",
                    f"/poc/{_TEST_FILE_JS}"]
        runner = ("the image must provide jest — with --network none npx cannot "
                  "fetch it (SAST_POC_IMAGE can point at an image that does)")

    # --- the report head ---------------------------------------------------
    out: list[str] = [
        f"# poc verification: {route_label} -> {sink_label}",
        f"route: {_node_label(route)}",
        f"handler: {_node_label(handler)}",
        f"sink: {_node_label(sink)}",
        f"mock_request: {_truncate_line(raw_mock, 300)}",
        "attacker-controlled fields: "
        + (", ".join(attacker_fields) or "(none identified)"),
    ]
    for note in poc_notes:
        out.append(f"note: {note}")

    # --- execution policy -----------------------------------------------------
    docker_ok = shutil.which("docker") is not None
    opted_in = os.environ.get(ENV_POC_EXEC) == "1"
    result = None
    if not docker_ok or not opted_in:
        reasons = []
        if not docker_ok:
            reasons.append("docker binary not found")
        if not opted_in:
            reasons.append(f"{ENV_POC_EXEC} is not set (the operator has not "
                           f"opted in to PoC execution)")
        out.append("")
        out.append("status: not-executed")
        out.append("reason: " + "; ".join(reasons)
                   + " — generation is always safe, execution is always "
                     "contained, and without the opt-in nothing runs")
        out.append("canary_reached: unknown")
    else:
        result = _run_poc(root, test_file_name, test_source, image, test_cmd,
                          run_timeout)

    # --- the generated test -----------------------------------------------------
    out.append("")
    out.append(f"## generated test ({style})")
    out.append(f"```{'python' if style == 'pytest' else 'javascript'}")
    out.append(test_source[:MAX_TEST_CHARS])
    out.append("```")

    if result is None:
        out.append("")
        out.append("## run instructions")
        out.append(f"1. save the test above as {test_file_name} in a scratch "
                   f"directory")
        out.append(f'2. docker run --rm --network none -v "<repo>:/repo:ro" '
                   f'-v "<scratch>:/poc" -w /poc {image} '
                   f'{" ".join(test_cmd)}')
        out.append(f"   the repo is mounted READ-ONLY and the container has no "
                   f"network; {runner}")
        out.append(f"3. or re-run this tool with {ENV_POC_EXEC}=1 and docker "
                   f"available to execute it here")
        return _cap_chars("\n".join(out))

    # --- executed -----------------------------------------------------------------
    out.append("")
    if "error" in result:
        out.append("status: error")
        out.append(f"reason: {result['error']}")
        out.append("canary_reached: unknown")
        return _cap_chars("\n".join(out))

    stdout = str(result.get("stdout") or "")
    stderr = str(result.get("stderr") or "")
    canary = _parse_canary(stdout, stderr)
    out.append(f"status: executed (docker {image}, exit "
               f"{result.get('returncode')})")
    out.append(f"canary_reached: {canary or 'unknown'}")
    if not canary:
        out.append("note: the run produced no canary marker — the test did "
                   "not complete (missing runner, import error, or the "
                   "handler crashed before the marker)")
    elif canary == "no" and "handler_error=" in stdout + stderr:
        out.append("note: the handler raised before the sink was reached — "
                   "the PoC did not confirm reachability")
    out.append("")
    out.append(f"## stdout ({len(stdout)} chars"
               + (", truncated" if result.get("truncated") else "") + ")")
    out.append(stdout or "(empty)")
    if stderr:
        out.append("")
        out.append(f"## stderr ({len(stderr)} chars)")
        out.append(stderr)

    if canary == "yes":
        start, end = _node_span(handler)
        finding = _candidate_finding(
            title=(f"Attacker-controlled input reaches {sink_name} "
                   f"(PoC-confirmed)"),
            path=handler_file,
            start_line=start,
            end_line=end,
            cwe="CWE-20",
            severity="high",
            confidence=1.0,
            taint_source=(f"attacker-controlled fields: "
                          f"{', '.join(attacker_fields) or 'none'}"),
            taint_sink=f"{sink_name} @ {sink_file}",
            taint_path=[f"{handler_file}:{start} handler {handler_name}",
                        f"{sink_file} sink {sink_name} (patched spy)"],
            evidence=_canary_evidence(stdout),
            rationale=(f"the generated PoC patched {sink_module}.{sink_name} "
                       f"and called {handler_name} with the canary "
                       f"substituted for the attacker-controlled fields; the "
                       f"spy recorded the canary, so the taint path is "
                       f"confirmed at runtime, not inferred"),
            note=("CWE-20 (Improper Input Validation): the value crossed the "
                  "handler's boundary unvalidated; the sink it reached "
                  "decides the concrete weakness (CWE-89 for SQL, CWE-78 for "
                  "a shell, CWE-22 for a path)"),
        )
        out.append("")
        out.extend(_finding_lines(
            finding, f"## candidate finding (CWE-20, severity high, "
                     f"confidence 1.0)"))
    return _cap_chars("\n".join(out))

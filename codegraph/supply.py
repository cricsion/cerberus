"""Supply-chain, config-hygiene and egress tools for the hunter micro-agents.

Three questions the index can answer that a taint tracer cannot, because each
one is about something OUTSIDE the call graph:

- :func:`verify_cve_symbol_reachability` — **Reachable-SCA.** A CVE advisory
  names ``package.symbol``; the scanner question is not "is the package
  installed" but "does anything call that symbol". CodeGraph never indexes
  ``node_modules``/``vendor``, so a call into the package lands in
  ``unresolved_refs`` — which is exactly where this tool looks, plus the direct
  ``calls`` edges that would prove an in-repo namesake instead. Each symbol then
  gets a backward callers' BFS to the routing manifest, so a verdict says
  whether an external HTTP route can reach the vulnerable code.
- :func:`inspect_config_and_secret_hygiene` — **zero-exfiltration config
  audit.** CodeGraph's config-leaf ``constant`` nodes expose the KEY and never
  the value, so this tool reads one line per leaf, classifies the value into an
  env-var reference or a length/class/entropy descriptor, and NEVER echoes a
  literal back. Structural settings (``debug: true``) are returned, because a
  boolean is a setting, not a secret.
- :func:`trace_egress_and_ssrf_targets` — **egress resolution.** A network call
  is a sink; the URL argument is the verdict. Each one is resolved (one-hop
  local assignment included), split into scheme/host/port/path/query and each
  part marked CONSTANT or DYNAMIC, which is what separates a fixed webhook from
  a full SSRF (CWE-918).

Everything here is read-only against the target repo: the index is opened
``mode=ro`` by :func:`harness.codegraph._db.connect`, source is read through the
same containment check every harness tool uses, and no LLM, network, subprocess
or write is involved. No tool here raises: a missing index, an unreadable file,
a grammar that is not installed and a symbol the index never saw are all
strings. Every list is capped (``limit<=0`` means unlimited, hard-clamped at
:data:`_db.HARD_MAX_ROWS`), the whole answer at ``CODEGRAPH_CHARS`` (20000), and
a truncated section says so with a ``… +N more`` marker.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from harness.codegraph import _db, _ts, sinks
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
CHAR_CAP = 20000         # overall output cap (CODEGRAPH_CHARS, 0 = unlimited)
ENV_CHARS = "CODEGRAPH_CHARS"

ENV_SYMBOLS = "CODEGRAPH_SYMBOLS_LIMIT"
ENV_SITES = "CODEGRAPH_SITES_LIMIT"
ENV_MANIFESTS = "CODEGRAPH_MANIFESTS_LIMIT"
ENV_REACH_DEPTH = "CODEGRAPH_REACH_DEPTH"
ENV_REACH_NODES = "CODEGRAPH_REACH_NODES"
ENV_FINDINGS = "CODEGRAPH_FINDINGS_LIMIT"
ENV_LEAVES = "CODEGRAPH_LEAVES_LIMIT"
ENV_SINKS = "CODEGRAPH_EGRESS_LIMIT"

DEFAULT_SYMBOLS = 40       # vulnerable symbols verified per call
DEFAULT_SITES = 40         # call sites reported per symbol
DEFAULT_MANIFESTS = 40     # manifest declaration lines reported
DEFAULT_REACH_DEPTH = 6    # backward BFS depth for reachability
DEFAULT_REACH_NODES = 500  # nodes visited per backward BFS
DEFAULT_FINDINGS = 10      # candidate findings per tool call
DEFAULT_LEAVES = 200       # config leaves / egress sites reported per call
DEFAULT_SINKS = 40         # network call sites reported per span

MAX_EVIDENCE = 160         # per-row evidence truncation
MAX_MANIFEST_BYTES = 1_000_000   # same 1 MB cap the indexer applies
MAX_VALUE_CHARS = 160      # a config value longer than this is not evidence
MAX_DEPTH = 16             # never walk a BFS deeper than this, env or not


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
    so this module does not reach into it; the clamp is still
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


def _depth_cap() -> int:
    """The reachability BFS depth: env-driven, but never unbounded."""
    return max(1, min(_env_int(ENV_REACH_DEPTH, DEFAULT_REACH_DEPTH), MAX_DEPTH))


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
    reading one would invent spans the graph disagrees with), or cannot be
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


def _read_bytes(root: str, file_path: str):
    """``(source_bytes, path)`` for a contained file, or ``(None, None)``."""
    path = _contained_file(root, file_path)
    if path is None:
        return None, None
    try:
        return path.read_bytes(), path
    except (OSError, ValueError):
        return None, None


def _unaddressable(root: str, rel: str) -> str:
    """Why ``rel`` cannot be addressed under ``root`` at all, or ``""``.

    Distinct from "not a file": a NUL byte raises ``ValueError: embedded null
    byte`` from ``resolve()`` and a component past NAME_MAX raises ``OSError``
    from ``is_file()`` (``resolve()`` alone does not stat every component on
    every platform, so both probes are needed). The path is then not merely
    absent — it is unaddressable, which is agent input the tool names instead
    of silently falling through to the (empty) prefix reading. Never raises.
    """
    text = str(rel or "")
    if not text.strip():
        return ""
    try:
        base = _safe_path(str(root) if root is not None else ".")
    except (OSError, ValueError):
        return ""       # the root is the caller's problem, already reported
    try:
        candidate = (base / text).resolve()
        candidate.is_file()          # the OS-level addressability probe
    except (OSError, ValueError) as e:
        return str(e) or e.__class__.__name__
    return ""


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


# ---------------------------------------------------------------------------
# graph vocabulary
# ---------------------------------------------------------------------------

# Handler kinds getRoutingManifest accepts — mirrors queries.ts:1258. Kept local
# so this module never reaches into the foundation's private table.
_HANDLER_KINDS = ("function", "method", "class", "constant", "variable",
                  "component")

# The kinds a direct in-repo call can land on: a namesake is only a namesake if
# something actually calls it, and only these kinds carry a ``calls`` target.
_NAMESAKE_KINDS = ("function", "method", "constructor", "component", "class")

# The getCallers edge set for the backward reachability BFS.
_CALLER_EDGE_KINDS = ("calls", "references", "instantiates", "navigates")

# Edge kinds a route uses to reach its handler (framework resolver dependent:
# Spring/Rails/Laravel emit `references`, Express emits `calls`).
_ROUTE_EDGE_KINDS = ("references", "calls")

# Manifests a SCA question can be answered from, in the order they are read.
# Deliberately NOT the lockfiles: a lockfile pins what is installed, and this
# tool answers "is it declared", which is the manifest's job.
MANIFEST_NAMES = (
    "package.json", "requirements.txt", "requirements-dev.txt",
    "requirements.in", "pyproject.toml", "setup.py", "setup.cfg", "pipfile",
    "go.mod", "gemfile", "pom.xml", "build.gradle", "build.gradle.kts",
    "cargo.toml", "composer.json", "packages.config",
)

# File extensions whose contents are a config file rather than a dependency
# declaration — the empty-prefix reading of the config audit.
CONFIG_SUFFIXES = (".yaml", ".yml", ".properties", ".json", ".toml", ".cfg",
                   ".ini", ".xml", ".env")

# Config-leaf keys whose VALUE decides a security posture. Matched as a
# case-insensitive substring of the key, because the ecosystems spell the same
# setting ten ways (``allowedOrigins`` / ``allowed-origins`` / ``cors.origins``).
SETTING_KEY_RE = re.compile(
    r"cors|csrf|jwt|cookie|samesite|httponly|secure|tls|ssl|session|auth|secret|"
    r"key|password|token|algorithm|introspect|actuator|allowedorigin|"
    r"allowed_origins|permissions.?policy|hsts|keystore|truststore|mtls|oidc|"
    r"saml|ldap|debug|exposed|public|acl|firewall|securitygroup|ingress",
    re.IGNORECASE)

# A value of one of these classes, at least this long, under a secret-ish key is
# a credential and is redacted. Shorter values and booleans are settings:
# ``debug: true`` and ``cors.allowed-origins: "*"`` are the shape the
# weak-setting rule reports, and redacting them would hide the very thing an
# analyst has to fix. The floor is 4, not 8: an 8-digit numeric token, a
# 4-char PIN or a short API key is still a credential written into a committed
# file, and it is the short ones that look innocuous. A NUMBER under a
# secret-ish key is therefore credential-shaped too (``auth_token = 12345678``),
# while a boolean stays a setting everywhere and a number under a
# non-secret-ish key (``port: 8080``) is still structural.
SECRET_MIN_CHARS = 4
_SECRET_LITERAL_CLASSES = frozenset({"quoted-string", "hex", "base64", "token"})
_CREDENTIAL_CLASSES = _SECRET_LITERAL_CLASSES | {"number"}

# The env-var reference spellings. A config that reads ``${VAR}`` is the GOOD
# shape, so these are recognised before any literal classification runs. Each
# pattern matches the whole reference expression, so the form can be echoed
# without echoing a value — and the brace form carries a capture for that:
# ``${JWT_SECRET:-deadbeef}`` echoes ``${JWT_SECRET}``, never the default,
# which is a literal this module must not return.
ENV_REF_RES = (
    re.compile(r"\$\{\s*([A-Za-z_][\w]*)\s*(?::-\s*[^}]*)?\}"),      # ${VAR:-def}
    re.compile(r"\bprocess\s*\.\s*env\s*\.\s*[A-Za-z_$][\w$]*"),   # process.env.X
    re.compile(r"\bos\s*\.\s*(?:environ\s*(?:\.\s*get)?\s*[\[(]\s*"
               r"['\"][A-Za-z_][\w]*['\"]\s*[\])]|environ\s*\.\s*"
               r"[A-Za-z_][\w]*|getenv\s*\(\s*['\"][A-Za-z_][\w]*['\"]\s*\))"),
    re.compile(r"\{\{\s*\.?\s*[Ee]nv(?:\s*\.\s*[A-Za-z_][\w.]*)?\s*\}\}"),
)

# Weak-setting readings. Each is (label, predicate) over the lower-cased key and
# value, so the finding can name the exact shape the analyst must fix.
WEAK_SETTINGS = (
    ("debug mode enabled",
     lambda k, v: "debug" in k and v in ("true", "1", "yes", "on")),
    ("wildcard CORS origin",
     lambda k, v: ("origin" in k or "cors" in k) and v.strip("*") == ""),
    ("JWT algorithm none",
     lambda k, v: "algorithm" in k and re.search(r"\bnone\b|\[\s*['\"]?none"
                 r"['\"]?\s*\]", v) is not None),
    ("TLS/certificate verification disabled",
     lambda k, v: "verify" in k and v in ("false", "0", "no", "off")),
    ("secure cookie flag disabled",
     lambda k, v: "secure" in k and "insecure" not in k
     and v in ("false", "0", "no", "off")),
    ("SameSite none",
     lambda k, v: "samesite" in k and v.strip("'\"") == "none"),
    ("introspection/actuator exposure enabled",
     lambda k, v: ("introspect" in k or "actuator" in k or "exposed" in k)
     and v in ("true", "1", "yes", "on")),
)

# The confidence formula, documented per tool because it is a heuristic and it
# never claims certainty.
_CONF_MIN = 0.30
_CONF_MAX = 0.85
_CONF_BASE = 0.45
_CONF_EVIDENCE = 0.20     # a manifest declares it, or the whole host is dynamic
_CONF_GAP = 0.10          # the reference is unresolved, or the path is dynamic
_CONF_STRENGTH = 0.10     # more than one corroborating site
_CONF_NOGUARD = 0.05     # nothing in between: no one-hop resolution, no
                         # allow-list, no fixup between the call and its target


def _confidence(base: float, *bonuses: float) -> float:
    """Bounded, documented confidence: a heuristic never claims certainty."""
    return round(max(_CONF_MIN, min(_CONF_MAX, base + sum(bonuses))), 2)


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
# shared: hygiene filter and route/handler resolution
# ---------------------------------------------------------------------------

def _is_low_value(file_path: str, conn) -> bool:
    """The routing manifest's hygiene filter: test/generated files are dropped.

    A handler in a generated file (``api_pb2.py``) or a test file is not
    production traffic, and ``getRoutingManifest`` drops exactly those rows, so
    reachability here must drop them too or the two would disagree.
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


def _route_map(conn) -> dict:
    """``{by_id, by_site}``: handler -> url, manifest rows plus the id join.

    ``getRoutingManifest`` applies the test/generated hygiene filter and a row
    cap but does not expose the handler's node id, so the id-based join runs as
    well: a manifest row is matched by (handler_file, handler_line), and a route
    the manifest's cap dropped is still found by its own edge. Only node ids go
    into ``by_id`` — a handler NAME is not a node id, and putting it there would
    be a key that can never be looked up.
    """
    by_id: dict[str, str] = {}
    by_site: dict[tuple, str] = {}
    for row in _db.routing_manifest(conn, limit=0):
        url = str(row.get("url") or "")
        key = (str(row.get("handler_file") or ""), _as_int(row.get("handler_line")))
        by_site.setdefault(key, url)
    for route in _db.find_nodes(conn, kind="route", limit=0):
        handler = _handler_for_route(conn, str(route.get("id") or ""))
        if handler is None:
            continue
        # The manifest's hygiene filter is not in this join, so it is applied
        # here: a handler in a generated or test file is not production
        # traffic, and the two readings must not disagree about that.
        if _is_low_value(str(handler.get("file_path") or ""), conn):
            continue
        by_id.setdefault(str(handler.get("id") or ""),
                         str(route.get("name") or ""))
    return {"by_id": by_id, "by_site": by_site}


# ---------------------------------------------------------------------------
# 1. verify_cve_symbol_reachability
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def verify_cve_symbol_reachability(package_name: str, vulnerable_symbols: str,
                                   root: str = ".", limit: int | None = None) -> str:
    """Does any reachable code actually call this package's vulnerable symbol?

    Reachable-SCA: an advisory naming ``package.symbol`` is only exploitable
    when something calls ``symbol``, and the graph answers that from two places
    at once. Calls into a third-party package land in ``unresolved_refs``
    (``node_modules``/``vendor`` are never indexed, so those references fail on
    purpose and are kept with ``status='failed'``), and the same name can also
    be an in-repo function a ``calls`` edge resolves — a namesake, which is the
    finding that would otherwise be reported twice. Each real third-party call
    site is then run through a backward callers' BFS to the routing manifest, so
    the verdict says whether an external HTTP route reaches the vulnerable code
    rather than merely that the package is installed.

    Use this when an SCA scanner reports ``package@version`` with a CVE, when
    triaging which of many advisories matters, and before claiming a dependency
    is unused. Do NOT use it as proof of exploitability: reachability says a
    route reaches the CALL, not that the arguments are attacker-controlled — the
    caller may be a CLI job the manifest's depth cap never reaches, and a
    namesake is matched by name only. Verdicts are ``REACHABLE`` (a route
    reaches a third-party call site), ``NOT-REACHABLE`` (third-party call sites
    exist but no route reaches them) and ``NO-CALL-SITE`` (nothing calls the
    symbol at all, or only an in-repo namesake does).

    Confidence is ``0.45 + 0.20`` when a manifest declares the package, ``+0.10``
    because the call site is an unresolved reference rather than a resolved edge
    and ``+0.10`` when more than one site calls the symbol — clamped to
    [0.30, 0.85], because reachability is evidence, never a verdict.

    Args:
        package_name: The package as declared (``lodash``,
            ``github.com/gin-gonic/gin``, ``org.apache.commons:commons-lang3``).
        vulnerable_symbols: The advisory's symbols, comma-separated
            (``merge,set``) or a JSON list (``["merge","set"]``). A bare
            ``merge`` matches ``obj.merge`` and ``merge`` alike.
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Max call sites reported per symbol. 0 = unlimited.

    Returns:
        A bounded report: manifest declarations (``file:line`` per manifest),
        import evidence, and per symbol the third-party call sites, the in-repo
        namesakes, ``reachable_from_routes`` (url, handler, hops), the verdict,
        and — when reachable — one candidate finding block (CWE-1395, severity
        high, taint source "external HTTP route").
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return _db.guidance_no_db(root)

    package = str(package_name or "").strip()
    if not package:
        return "ERROR: package_name is required (e.g. 'lodash')"
    symbols = _split_symbols(vulnerable_symbols)
    if not symbols:
        return ("ERROR: vulnerable_symbols is required (comma-separated, e.g. "
                "'merge,set', or a JSON list)")

    site_cap = _cap_rows(limit, ENV_SITES, DEFAULT_SITES)
    symbol_cap = _section_cap(ENV_SYMBOLS, DEFAULT_SYMBOLS)
    finding_cap = _section_cap(ENV_FINDINGS, DEFAULT_FINDINGS)

    out: list[str] = [f"# cve symbol reachability: {package}",
                      f"root: {root}",
                      f"symbols: {len(symbols)} "
                      f"({', '.join(symbols[:symbol_cap])}"
                      + (f", … +{len(symbols) - symbol_cap} more"
                         if len(symbols) > symbol_cap else "") + ")"]

    # --- (a) manifest evidence -------------------------------------------
    manifests, manifest_notes = _manifest_evidence(package, root)
    out.append("")
    out.append(f"--- manifest declarations ({len(manifests)})")
    if manifests:
        manifest_cap = _cap_rows(limit, ENV_MANIFESTS, DEFAULT_MANIFESTS)
        for rel, line_no, text in manifests[:manifest_cap]:
            out.append(f"{rel}:{line_no}: {_truncate_line(text, 120)}")
        if len(manifests) > manifest_cap:
            out.append(f"… +{len(manifests) - manifest_cap} more "
                       f"declarations (total {len(manifests)})")
    else:
        out.append(f"(package not declared in any manifest: {package})")
    out.extend(manifest_notes)

    # --- (b) usage evidence ----------------------------------------------
    imports = _import_evidence(conn, package)
    out.append("")
    out.append(f"--- import evidence ({len(imports)})")
    if imports:
        for row in imports[:HARD_MAX_SECTION]:
            out.append(f"{row['file']}:{row['line']}: {row['text']} "
                       f"[{row['basis']}]")
        if len(imports) > HARD_MAX_SECTION:
            out.append(f"… +{len(imports) - HARD_MAX_SECTION} more imports "
                       f"(total {len(imports)})")
    else:
        out.append(f"(no import node or imports edge names {package} — "
                   f"node_modules/vendor are never indexed, so a call into the "
                   f"package shows up as an unresolved reference instead)")

    # --- per symbol: call sites, namesakes, backward reachability ----------
    findings: list[tuple[dict, str]] = []
    verdicts: dict[str, int] = {"REACHABLE": 0, "NOT-REACHABLE": 0,
                                "NO-CALL-SITE": 0}
    shown = symbols[:symbol_cap]
    for position, symbol in enumerate(shown, start=1):
        block, verdict, finding = _symbol_report(
            conn, package, symbol, position, len(shown), site_cap,
            manifest_declared=bool(manifests))
        out.append("")
        out.extend(block)
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
        if finding is not None:
            findings.append(finding)

    out.append("")
    out.append("--- verdict summary")
    for name in ("REACHABLE", "NOT-REACHABLE", "NO-CALL-SITE"):
        out.append(f"{name}: {verdicts.get(name, 0)}")
    if len(symbols) > len(shown):
        out.append(f"… +{len(symbols) - len(shown)} more symbols not verified "
                   f"(total {len(symbols)}; raise the limit to expand)")

    out.append("")
    out.append(f"--- candidate findings ({len(findings)})")
    if not findings:
        out.append("none: no verified symbol is reachable from a route")
    for index, (finding, header) in enumerate(findings[:finding_cap], start=1):
        out.append(f"{index}. " + _finding_lines(finding, header)[0])
        out.append(json.dumps(finding, indent=2, sort_keys=False))
    if len(findings) > finding_cap:
        out.append(f"… +{len(findings) - finding_cap} more findings (total "
                   f"{len(findings)}); raise the limit to expand")
    return _cap_chars("\n".join(out))


def _split_symbols(raw) -> list[str]:
    """Comma/whitespace-separated symbols, or a JSON list of them."""
    text = str(raw or "").strip()
    if not text:
        return []
    symbols: list[str] = []
    seen: set[str] = set()
    if text[0] in "[{":  # a JSON list is the richer spelling an LLM may send
        try:
            data = json.loads(text)
            if isinstance(data, list):
                for item in data:
                    name = str(item or "").strip()
                    if name and name not in seen:
                        seen.add(name)
                        symbols.append(name)
                return symbols
        except (ValueError, TypeError):
            pass
    for token in re.split(r"[,\s;]+", text):
        name = token.strip().strip("\"'")
        if not name or name in seen:
            continue
        seen.add(name)
        symbols.append(name)
    return symbols


def _manifest_evidence(package: str, root: str) -> tuple[list[tuple], list[str]]:
    """``[(rel_path, line_no, line_text)]`` where ``package`` is declared.

    Reads each known manifest through the same containment check every other
    read here uses, so a manifest outside the repo boundary is never touched.
    The package name is matched as a whole token on a line that is not a
    comment, which is what keeps ``merge`` from matching ``merge-extra``.
    """
    out: list[tuple] = []
    notes: list[str] = []
    needle = re.compile(r"(?<![\w.\-/])" + re.escape(package) + r"(?![\w.\-])")
    for rel, path in _manifest_paths(root):
        try:
            if path.stat().st_size > MAX_MANIFEST_BYTES:
                notes.append(f"note: {rel} is over the 1 MB read cap — skipped")
                continue
            raw = path.read_bytes()
        except (OSError, ValueError):
            notes.append(f"note: {rel} is unreadable — skipped")
            continue
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            continue
        for index, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "*", "<!--")):
                continue
            if needle.search(line):
                out.append((rel, index, stripped))
                break  # one declaration per manifest is the evidence needed
    return out, notes


def _manifest_paths(root: str) -> list[tuple[str, Path]]:
    """``(repo_relative, resolved)`` for every known manifest under ``root``.

    Only the repo root and its immediate children are scanned: a manifest three
    levels down is a different project, and an unbounded walk is how a tool
    turns a bounded read into a directory scan.

    Containment is checked on the RESOLVED path, not the textual spelling.
    ``child.is_dir()`` follows symlinks, so a symlinked ``<repo>/backend ->
    /tmp/outside`` used to be descended into: the docstring's promise that "a
    manifest outside the repo boundary is never touched" was false for exactly
    the interesting case, because the textual ``backend/requirements.txt``
    resolves inside the repo while its bytes live outside it. Every candidate
    directory is therefore resolved and re-checked before descending, and every
    candidate file likewise before it is read.
    """
    try:
        base = _safe_path(str(root) if root is not None else ".")
        try:
            if base.is_file():
                base = base.parent
        except (OSError, ValueError):
            return []
    except (OSError, ValueError):
        return []
    out: list[tuple[str, Path]] = []
    seen: set[str] = set()
    candidates: list[Path] = []
    try:
        children = sorted(base.iterdir())
    except (OSError, ValueError):
        return []
    candidates.extend(children)
    for child in children:
        # One level down: a monorepo's backend/ and frontend/ manifests.
        try:
            if not child.is_dir() or child.name.startswith("."):
                continue
            if child.name in ("node_modules", "vendor", "dist", "build",
                              "target", "__pycache__", ".venv", "venv"):
                continue
            real = child.resolve()
            real.relative_to(base)  # re-check after resolving symlinks
        except (OSError, ValueError):
            continue    # escaping, unresolvable, or unaddressable: never descend
        try:
            candidates.extend(sorted(real.iterdir()))
        except (OSError, ValueError):
            continue
    for cand in candidates:
        try:
            # The same resolved check on the candidate itself: a symlinked
            # ``requirements.txt`` is read only where it actually resolves.
            real = cand.resolve()
            real.relative_to(base)
            if not real.is_file():
                continue
            rel = str(real.relative_to(base)).replace("\\", "/")
        except (OSError, ValueError):
            continue
        if rel in seen:
            continue
        lowered = real.name.lower()
        if lowered in MANIFEST_NAMES or lowered.startswith("requirements"):
            seen.add(rel)
            out.append((rel, real))
    return out


def _import_evidence(conn, package: str) -> list[dict]:
    """Import nodes and ``imports`` edges that name ``package``.

    Both sides are needed: CodeGraph models an import as a node AND as an edge,
    and either one alone misses half the repos (some resolvers emit only the
    node, others only the edge).
    """
    out: list[dict] = []
    seen: set[tuple] = set()
    if conn is None:
        return out
    for node in _db.find_nodes(conn, kind="import", limit=0):
        name = str(node.get("name") or "")
        if package not in name:
            continue
        key = (str(node.get("file_path") or ""), _as_int(node.get("start_line")))
        if key in seen:
            continue
        seen.add(key)
        out.append({"file": key[0], "line": key[1],
                    "text": _truncate_line(name, 120), "basis": "import node"})
    for edge in _db.get_edges(conn, kind="imports", limit=0):
        target = _db.get_node(conn, edge.get("target"))
        source = _db.get_node(conn, edge.get("source"))
        name = str((target or {}).get("name") or "")
        if package not in name:
            continue
        key = (str((source or {}).get("file_path") or ""),
               _as_int(edge.get("line")) or _as_int((target or {}).get("start_line")))
        if key in seen:
            continue
        seen.add(key)
        out.append({"file": key[0], "line": key[1],
                    "text": _truncate_line(name, 120),
                    "basis": "imports edge"})
    out.sort(key=lambda row: (row["file"], row["line"]))
    return out


def _symbol_report(conn, package: str, symbol: str, position: int, total: int,
                   site_cap: int, manifest_declared: bool = False
                   ) -> tuple[list[str], str, tuple | None]:
    """One symbol's block: call sites, namesakes, reachability, verdict."""
    third_party, namesakes = _symbol_call_sites(conn, symbol, site_cap)
    reachable: list[dict] = []
    if third_party:
        reachable = _reachable_from_routes(conn, third_party)

    verdict = _symbol_verdict(third_party, namesakes, reachable)
    lines = [f"--- symbol {position}/{total}: {package}.{symbol}",
             f"third-party call sites: {len(third_party)}  "
             f"in-repo namesake call sites: {len(namesakes)}"]
    if third_party:
        for row in third_party[:site_cap]:
            lines.append(f"  call: {row['file']}:{row['line']} in "
                         f"{row['function']}() — {row['evidence']}")
        if len(third_party) > site_cap:
            lines.append(f"  … +{len(third_party) - site_cap} more call sites "
                         f"(total {len(third_party)})")
    else:
        lines.append("  call: (none — the symbol is never called anywhere in "
                     "this index)")
    if namesakes:
        for row in namesakes[:site_cap]:
            lines.append(f"  in-repo namesake, not third-party: "
                         f"{row['file']}:{row['line']} in {row['function']}() "
                         f"— calls {row['symbol']} at {row['site']}")
        if len(namesakes) > site_cap:
            lines.append(f"  … +{len(namesakes) - site_cap} more namesake sites "
                         f"(total {len(namesakes)})")

    lines.append(f"reachable_from_routes: {len(reachable)}")
    for row in reachable[:site_cap]:
        lines.append(f"  {row['url']}  handler {row['handler']}  "
                     f"hops {row['hops']}  via {row['via']}")
    if not reachable and third_party:
        lines.append("  (no route reaches any of these call sites within "
                     f"{_depth_cap()} backward hops)")

    lines.append(f"verdict: {verdict}")
    finding = None
    if verdict == "REACHABLE":
        finding = _cve_finding(package, symbol, third_party, reachable,
                               manifest_declared)
        if finding is not None:
            lines.append(f"## candidate finding ({finding[0]['cwe']}, severity "
                         f"{finding[0]['severity']}, confidence "
                         f"{finding[0]['confidence']})")
    elif verdict == "NOT-REACHABLE":
        lines.append("no candidate finding: the symbol is called, but nothing "
                     "route-reachable reaches it")
    else:
        lines.append("no candidate finding: nothing calls this symbol")
    return lines, verdict, finding


def _symbol_verdict(third_party: list[dict], namesakes: list[dict],
                    reachable: list[dict]) -> str:
    if not third_party:
        # A namesake is a different function that happens to share the name:
        # the package's own symbol is still never called.
        return "NO-CALL-SITE"
    if not reachable:
        return "NOT-REACHABLE"
    return "REACHABLE"


def _symbol_call_sites(conn, symbol: str, cap: int) -> tuple[list[dict], list[dict]]:
    """``(third_party_sites, in_repo_namesake_sites)`` for one symbol.

    Third-party: ``unresolved_refs`` rows whose ``reference_name`` or
    ``name_tail`` IS the symbol — this is where a call into unindexed
    ``node_modules``/``vendor`` lands, kept by CodeGraph on purpose with
    ``status='failed'`` so a later sync can retry it. Namesake: ``calls`` edges
    to an in-repo node named exactly the symbol, which proves the repo has its
    OWN function of that name and not a call into the package.
    """
    third_party: list[dict] = []
    seen: set[tuple] = set()
    if conn is not None:
        for ref in _db.unresolved_refs(conn, limit=0):
            name = str(ref.get("reference_name") or "")
            tail = str(ref.get("name_tail") or "") or name.rsplit(".", 1)[-1]
            if symbol not in (name, tail):
                continue
            caller = _db.get_node(conn, ref.get("from_node_id")) or {}
            file_path = str(caller.get("file_path") or ref.get("file_path") or "")
            line = _as_int(ref.get("line"), 0)
            key = (file_path, line, str(caller.get("id") or ""))
            if key in seen:
                continue
            seen.add(key)
            third_party.append({
                "file": file_path,
                "line": line,
                "function": str(caller.get("name") or "?"),
                "node_id": str(caller.get("id") or ""),
                "span": _node_span(caller),
                "evidence": (f"unresolved reference {name or symbol} "
                             f"(name_tail {tail}, status "
                             f"{ref.get('status') or 'failed'}) — the callee is "
                             f"not indexed, which is where a call into "
                             f"node_modules/vendor lands"),
            })
    namesakes: list[dict] = []
    seen_namesakes: set[tuple] = set()
    if conn is not None:
        for node in _db.find_nodes(conn, name=symbol, limit=0):
            if str(node.get("kind") or "") not in _NAMESAKE_KINDS:
                continue
            node_id = str(node.get("id") or "")
            for edge in _db.incoming_edges(conn, node_id, kinds=["calls"],
                                           limit=HARD_MAX_SECTION):
                caller = _db.get_node(conn, edge.get("source"))
                if caller is None:
                    continue
                file_path = str(caller.get("file_path") or "")
                line = _as_int(edge.get("line"), 0)
                key = (file_path, line, str(caller.get("id") or ""))
                if key in seen_namesakes:
                    continue
                seen_namesakes.add(key)
                namesakes.append({
                    "file": file_path,
                    "line": line,
                    "function": str(caller.get("name") or "?"),
                    "node_id": str(caller.get("id") or ""),
                    "span": _node_span(caller),
                    "symbol": symbol,
                    "site": _site(str(node.get("file_path") or ""),
                                  _as_int(node.get("start_line"))),
                })
    third_party.sort(key=lambda row: (row["file"], row["line"]))
    namesakes.sort(key=lambda row: (row["file"], row["line"]))
    return third_party[:cap], namesakes[:cap]


def _reachable_from_routes(conn, sites: list[dict]) -> list[dict]:
    """``[{url, handler, hops, via}]`` for every route-reachable call site.

    One BFS per call site, over the getCallers edge set backwards, stopping at
    the first handler the routing manifest names — that is the shallowest, and
    therefore the one an agent should be shown.
    """
    if conn is None:
        return []
    route_map = _route_map(conn)
    cache: dict[str, str] = {}
    out: list[dict] = []
    seen_routes: set[str] = set()
    depth = _depth_cap()
    for site in sites:
        caller_id = site.get("node_id") or ""
        if not caller_id:
            continue
        hit = _bfs_to_handler(conn, caller_id, route_map, depth)
        if hit is None:
            continue
        url, handler_name, hops, via = hit
        if url in seen_routes:
            continue
        seen_routes.add(url)
        out.append({"url": url, "handler": handler_name, "hops": hops,
                    "via": via})
    out.sort(key=lambda row: (row["hops"], row["url"]))
    return out


def _node_cap() -> int:
    """The BFS node budget: env-driven, hard-clamped at the package ceiling."""
    return max(1, min(_env_int(ENV_REACH_NODES, DEFAULT_REACH_NODES),
                      _db.HARD_MAX_ROWS))


def _bfs_to_handler(conn, start_id: str, route_map: dict,
                    depth: int) -> tuple | None:
    """The shallowest route handler backwards from ``start_id``.

    Returns ``(url, handler_name, hops, via_site)``. The direct check first:
    a call site inside a handler is already at the route, hops 0. The walk is
    bounded twice — depth, then a node budget — because a hub node with ten
    thousand callers is a reason to stop, not to keep going.
    """
    node = _db.get_node(conn, start_id)
    if node is None:
        return None
    direct = (route_map["by_id"].get(start_id)
              or route_map["by_site"].get((str(node.get("file_path") or ""),
                                           _as_int(node.get("start_line")))))
    if direct:
        return direct, str(node.get("name") or "?"), 0, _node_label(node)

    seen = {start_id}
    frontier = [start_id]
    budget = _node_cap()
    for hop in range(1, depth + 1):
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
                url = (route_map["by_id"].get(source)
                       or route_map["by_site"].get(
                           (str(caller.get("file_path") or ""),
                            _as_int(caller.get("start_line")))))
                if url:
                    return url, str(caller.get("name") or "?"), hop, \
                        _node_label(caller)
                nxt.append(source)
                if len(seen) >= budget:
                    return None  # budget spent: an unanswered question, not a "no"
        frontier = nxt
        if not frontier:
            break
    return None


def _cve_finding(package: str, symbol: str, sites: list[dict],
                 reachable: list[dict], declared: bool) -> tuple | None:
    """The candidate finding for a reachable vulnerable symbol."""
    if not sites or not reachable:
        return None
    site = sites[0]
    route = reachable[0]
    confidence = _confidence(
        _CONF_BASE,
        _CONF_EVIDENCE if declared else 0.0,
        _CONF_GAP,                                   # the reference is unresolved
        _CONF_STRENGTH if len(sites) > 1 else 0.0,
    )
    taint_path = [f"{route['url']} @ {route['handler']}"]
    for extra in reachable[1:4]:
        taint_path.append(f"{extra['url']} @ {extra['handler']}")
    taint_path.append(f"{site['file']}:{site['line']} ({site['function']})")
    evidence = (f"{package}.{symbol} is called at {_site(site['file'], site['line'])} "
                f"in {site['function']}() through an unresolved reference "
                f"(node_modules/vendor are never indexed), and the call is "
                f"reachable from {route['url']} ({route['handler']}, "
                f"{route['hops']} backward hop(s))")
    finding = _candidate_finding(
        title=(f"reachable third-party symbol {package}.{symbol} "
               f"(CVE candidate) at {_site(site['file'], site['line'])}"),
        path=site["file"],
        start_line=site["span"][0] or site["line"],
        end_line=site["span"][1] or site["line"],
        cwe="CWE-1395",
        severity="high",
        confidence=confidence,
        taint_source="external HTTP route",
        taint_sink=f"{package}.{symbol}",
        taint_path=taint_path,
        evidence=evidence,
        rationale=(f"an SCA advisory for {package} names {symbol} and the graph "
                   f"shows a call to it reached from {route['url']}; the call "
                   f"resolves into the unindexed package, not to any in-repo "
                   f"definition of that name"),
        note=("CWE-1395 (Use of a Component with a Known Vulnerability); the "
              "reachability half is what makes it a candidate and not a "
              "dependency-list entry"),
    )
    header = (f"## candidate finding (CWE-1395, severity high, "
              f"confidence {confidence})")
    return finding, header


# ---------------------------------------------------------------------------
# 2. inspect_config_and_secret_hygiene
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def inspect_config_and_secret_hygiene(config_prefix_or_file: str, root: str = ".",
                                      limit: int | None = None) -> str:
    """Which config settings are weak, and which hold a hardcoded secret?

    Zero-exfiltration config audit. For every config leaf the tool reads ONE
    line — the leaf's own — and classifies the value without ever returning it:
    an env-var reference (``${VAR}``, ``${VAR:-default}``, ``process.env.X``,
    ``os.environ``, ``{{ env }}``) is reported as ``ENV_VAR_REF``, and a
    credential-shaped literal under a secret-ish key is reported as
    ``<REDACTED: N-char <class> literal, entropy=<high|low>>``, where class is
    hex/base64/quoted-string/token. A non-secret structural setting
    (``debug: true``, ``port: 8080``, a wildcard ``allowed-origins``) is
    returned as written, because a boolean, a number and a policy token are
    settings, not credentials — that is the one case where a value comes back
    verbatim, and it is never a credential-shaped literal.

    CodeGraph's config-leaf ``constant`` nodes expose the KEY and never the
    value, so a leaf reached through the graph is read from its own line in the
    file — and when the argument names an existing file instead, that file is
    read the same bounded way. Two finding shapes follow: a hardcoded literal
    under a secret-ish key (CWE-798, high) and a weak setting — debug on, a
    wildcard origin, JWT ``algorithms: none``, ``verify: false``,
    ``secure: false``, ``samesite: none``, introspection/actuator exposed
    (CWE-16, medium).

    Use this before claiming a repo is secret-clean, on any Spring/Flask/
    Django/Node config file, and when an advisory mentions exposed actuator or
    permissive CORS. Do NOT use it as a secret scanner: it audits the settings
    the graph already indexes (or one named file), it never greps for patterns,
    and an env-var reference says the value is externalised, not that it is
    strong. The docstring's guarantee is the contract: no literal value is ever
    echoed into the answer.

    Confidence is ``0.45 + 0.20`` for a hardcoded literal, ``+0.10`` when the
    literal is high-entropy and ``+0.05`` when it is hex/base64, and a flat
    ``0.65`` for a weak setting — clamped to [0.30, 0.85].

    Args:
        config_prefix_or_file: An existing file under the root (``config/
            app.yaml``) — read line by line, bounded — or a prefix selecting
            ``constant`` nodes (``cors.``, ``jwt``). Empty means the constants
            in config-ish files (.yaml/.yml/.properties/.json/.toml/.cfg/.ini/
            .xml/.env).
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Max leaves reported per section. 0 = unlimited.

    Returns:
        A bounded report with ``structural_settings``, ``secrets`` and
        ``findings`` sections; the secrets section holds descriptors only.
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return _db.guidance_no_db(root)

    selector = str(config_prefix_or_file or "").strip()
    # A selector the OS cannot address at all (a NUL byte, a component past
    # NAME_MAX) is agent input, not a prefix: name it instead of reporting an
    # empty scan that looks like a clean bill of health.
    problem = _unaddressable(root, selector) if selector else ""
    if problem:
        return _cap_chars(f"ERROR: {selector!r} is not a readable path under "
                          f"this root: {problem}")
    leaf_cap = _cap_rows(limit, ENV_LEAVES, DEFAULT_LEAVES)
    finding_cap = _section_cap(ENV_FINDINGS, DEFAULT_FINDINGS)

    # An existing file wins over the prefix reading: the argument names it.
    target = _contained_file(root, selector) if selector else None
    if target is not None:
        leaves, basis = _file_leaves(target, selector)
        described = f"{selector} ({basis}, {len(leaves)} leaf line(s))"
    else:
        leaves, basis = _constant_leaves(conn, root, selector)
        described = (f"{selector or '(all config constants)'} "
                     f"({basis}, {len(leaves)} leaf node(s))")

    out: list[str] = ["# config & secret hygiene: "
                      f"{selector or '(all config constants)'}",
                      f"root: {root}",
                      f"scope: {described}",
                      "zero-exfiltration guarantee: every value below is either "
                      "an env-var reference, a redaction descriptor, or a "
                      "non-secret structural setting — no literal is returned"]

    # The split runs over EVERY collected leaf and the cap is applied to what
    # is RENDERED, never to what was collected: capping first would drop a
    # leaf past the limit before the split, and the tool would then assert a
    # negative ("secrets: none") about a file it never finished reading. The
    # findings below are computed from the same complete list, so a secret
    # past the render cap is still a finding and the "none" verdict only
    # appears when there genuinely is nothing to report.
    structural = [leaf for leaf in leaves if not leaf["in_secrets"]]
    secrets = [leaf for leaf in leaves if leaf["in_secrets"]]

    out.append("")
    out.append(f"--- structural_settings ({len(structural)} of {len(leaves)} "
               f"leaves)")
    if not structural:
        out.append("(none)")
    for leaf in structural[:leaf_cap]:
        out.append(_leaf_row(leaf))
    if len(structural) > leaf_cap:
        out.append(f"… +{len(structural) - leaf_cap} more structural settings "
                   f"(total {len(structural)}) not rendered — raise the limit "
                   f"to expand")

    out.append("")
    out.append(f"--- secrets ({len(secrets)} of {len(leaves)} leaves)")
    if not secrets:
        out.append("(none — every secret-ish key is unset, absent, or "
                   "externalised through an env-var reference)")
    for leaf in secrets[:leaf_cap]:
        out.append(_leaf_row(leaf))
    if len(secrets) > leaf_cap:
        out.append(f"… +{len(secrets) - leaf_cap} more secret-ish keys "
                   f"(total {len(secrets)}) not rendered — raise the limit "
                   f"to expand; the findings below still cover all of them")

    findings = _config_findings(leaves)
    out.append("")
    out.append(f"--- findings ({len(findings)})")
    if not findings:
        out.append("none: no hardcoded literal under a secret-ish key and no "
                   "weak setting recognised in any of the "
                   f"{len(leaves)} collected leaves")
    for index, finding in enumerate(findings[:finding_cap], start=1):
        out.append(f"{index}. {finding['header']}")
        out.append(json.dumps(finding["finding"], indent=2, sort_keys=False))
    if len(findings) > finding_cap:
        out.append(f"… +{len(findings) - finding_cap} more findings (total "
                   f"{len(findings)}); raise the limit to expand")
    return _cap_chars("\n".join(out))


def _leaf_row(leaf: dict) -> str:
    """One leaf line: key, descriptor-or-value, and where it was read from."""
    return (f"   {_site(leaf['file'], leaf['line'])}  {leaf['display_key']} = "
            f"{leaf['display']}  [{leaf['basis']}]")


def _file_leaves(path: Path, rel: str) -> tuple[list[dict], str]:
    """Leaves of one named config file, read line by line and bounded.

    Bounded by the 1 MB read cap, not by a row count: the caller applies the
    render cap AFTER the structural/secrets split, so no leaf is dropped
    before the split can see it.
    """
    out: list[dict] = []
    basis = "file read"
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            return out, f"{basis} skipped — over the 1 MB cap"
        raw = path.read_bytes()
    except (OSError, ValueError):
        return out, "file read failed — unreadable"
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    parents: list[tuple[int, str]] = []  # (indent, key) of the open blocks
    for index, line in enumerate(lines, start=1):
        indent = len(line) - len(line.lstrip())
        while parents and indent <= parents[-1][0]:
            parents.pop()
        nested = re.match(r"^(\s*)([A-Za-z_$][\w.\-]*)\s*:\s*$", line)
        if nested is not None:
            # A block header, not a leaf: it is the next leaf's context.
            parents.append((indent, nested.group(2).strip()))
            continue
        parsed = _parse_setting_line(line)
        if parsed is None:
            continue
        key, value = parsed
        context = ".".join([name for _i, name in parents] + [key])
        out.append(_classify_leaf(rel, index, key, value, context))
    return out, basis


def _constant_leaves(conn, root: str, prefix: str) -> tuple[list[dict], str]:
    """Config leaves reached through the graph's ``constant`` nodes.

    CodeGraph's config-leaf constants expose the KEY and never the value, so
    the value is read from the leaf's own line in its file — one line, never
    the file's neighbours. An empty prefix selects the constants in config-ish
    files only; a prefix selects nodes by name wherever they live. The node
    page is the foundation's own bounded read; the render cap belongs to the
    caller, applied after the split.
    """
    out: list[dict] = []
    if conn is None:
        return out, "no index"
    cache: dict[str, list[str]] = {}
    nodes = _db.find_nodes(conn, kind="constant", limit=0)
    basis = "constant nodes"
    if prefix:
        nodes = [n for n in nodes
                 if prefix.lower() in str(n.get("name") or "").lower()
                 or prefix.lower() in str(n.get("qualified_name") or "").lower()]
        basis = f"constant nodes matching {prefix!r}"
    else:
        nodes = [n for n in nodes
                 if str(n.get("file_path") or "").lower().endswith(CONFIG_SUFFIXES)]
        basis = ("constant nodes in config-ish files "
                 f"({'/'.join(CONFIG_SUFFIXES)})")
    for node in nodes:
        file_path = str(node.get("file_path") or "")
        line_no = _as_int(node.get("start_line"), 0)
        name = str(node.get("name") or "")
        if not file_path or not line_no:
            continue
        if file_path not in cache:
            src, _path = _read_bytes(root, file_path)
            cache[file_path] = (src.decode("utf-8", errors="replace").splitlines()
                                if src is not None else [])
        lines = cache[file_path]
        if line_no < 1 or line_no > len(lines):
            continue
        parsed = _parse_setting_line(lines[line_no - 1])
        if parsed is None:
            # A leaf whose line has no ``key = value`` shape: report the key
            # itself, which is all CodeGraph gives us, and no value at all.
            out.append(_classify_leaf(file_path, line_no, name, "", name))
        else:
            key_name, value = parsed
            out.append(_classify_leaf(file_path, line_no, key_name or name,
                                      value, name))
    return out, basis


def _parse_setting_line(line: str) -> tuple[str, str] | None:
    """``(key, value)`` from one config line, or None when it is not a leaf.

    Handles YAML/TOML/properties (``key: value``), INI/env (``key=value``) and
    the XML attribute spelling (``key="…" value="…"``). A comment, a blank line
    and a bracket/brace structural line are all not leaves.
    """
    text = str(line or "").strip()
    if not text or text.startswith(("#", ";", "//", "*", "<!--", "]", "}", ")")):
        return None
    match = re.match(r"<[^>]*\bkey\s*=\s*[\"']([^\"']+)[\"'][^>]*\bvalue\s*=\s*"
                     r"[\"']([^\"']*)[\"']", text)
    if match:
        return match.group(1).strip(), match.group(2).strip()
    for index, ch in enumerate(text):
        if ch not in "=:":
            continue
        key = text[:index].strip().strip("\"'")
        value = text[index + 1:].strip().rstrip(",").strip()
        if not key or not value:
            return None
        return key, _strip_quotes(value)
    return None


def _strip_quotes(value: str) -> str:
    text = str(value or "").strip()
    for quote in ("\"", "'"):
        if len(text) >= 2 and text.startswith(quote) and text.endswith(quote):
            return text[1:-1]
    return text


def _classify_leaf(file_path: str, line: int, key: str, value: str,
                   context: str = "") -> dict:
    """One leaf: key, secret-ishness, and the value's descriptor.

    The value never leaves this function as a literal when it is
    credential-shaped under a secret-ish key: it becomes ``ENV_VAR_REF`` when
    the config reads it from the environment (the good shape) or a
    length/class/entropy descriptor when it does not. A boolean or a number is
    a SETTING, not a credential — ``debug: true`` and ``port: 8080`` come back
    as written, which is why the redaction rule needs a length floor as well as
    a class test.

    ``context`` is the leaf's dotted path (``management.introspection.enabled``),
    which the line alone does not give: a YAML leaf named ``enabled`` only means
    something with its parents, and CodeGraph's own config-leaf constants are
    named with the full path.
    """
    secret_ish = bool(SETTING_KEY_RE.search(str(key or ""))
                      or (context and SETTING_KEY_RE.search(context)))
    env_ref = _env_reference(value)
    literal_class = _literal_class(value)
    length = len(str(value or ""))
    entropy = _entropy(value)
    redacted = (secret_ish and not env_ref
                and literal_class in _CREDENTIAL_CLASSES
                and length >= SECRET_MIN_CHARS)
    if env_ref:
        display = f"ENV_VAR_REF {env_ref}"
        basis = "env-var reference — value is externalised, not stored here"
    elif redacted:
        display = (f"<REDACTED: {length}-char {literal_class} literal, "
                   f"entropy={_entropy_label(entropy, length)}>")
        basis = "redacted — the literal is never returned"
    else:
        display = _truncate_line(_strip_quotes(value), MAX_VALUE_CHARS)
        basis = ("structural setting — value returned as written"
                 if not secret_ish else
                 "security-relevant key with a non-credential value — "
                 "returned as written")
    return {"file": file_path, "line": line, "key": key, "context": context,
            "display_key": context or key, "value": value,
            "display": display, "secret_ish": secret_ish,
            "in_secrets": bool(redacted or (secret_ish and env_ref)),
            "redacted": bool(redacted),
            "is_env_ref": bool(env_ref), "is_literal": bool(redacted),
            "entropy": entropy, "length": length,
            "value_class": literal_class, "basis": basis}


def _env_reference(value: str) -> str:
    """The env-var reference spelling in ``value``, or ``""``.

    Recognised forms: ``${VAR}``, ``${VAR:-default}``, ``process.env.X``,
    ``os.environ`` / ``os.environ["X"]`` / ``os.getenv("X")`` and the Jinja/
    Helm ``{{ env.X }}`` / ``{{ .Env.X }}``.

    Only the NAME comes back. ``${JWT_SECRET:-deadbeef}`` echoes
    ``${JWT_SECRET}``: the default after ``:-`` is a literal written into the
    config, and echoing it verbatim would break the zero-exfiltration
    guarantee for a value that is, by construction, the fallback secret.
    """
    text = str(value or "")
    for pattern in ENV_REF_RES:
        match = pattern.search(text)
        if match:
            return _truncate_line(_reference_spelling(match), 60)
    return ""


def _reference_spelling(match) -> str:
    """The reference as echoed: ``${VAR}``, never ``${VAR:-default}``."""
    try:
        named = match.group(1) if match.re.groups else ""
    except Exception:
        return match.group(0)
    if named and match.group(0).startswith("${"):
        return "${" + named + "}"
    return match.group(0)


def _literal_class(value: str) -> str:
    """hex / base64 / quoted-string / number / boolean / token."""
    text = _strip_quotes(str(value or "").strip())
    if not text:
        return "empty"
    if text.lower() in ("true", "false", "yes", "no", "on", "off", "none"):
        return "boolean"
    if re.fullmatch(r"-?\d+(\.\d+)?", text):
        return "number"
    if re.fullmatch(r"[0-9a-fA-F]{8,}", text):
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9+/_\-]{16,}={0,2}", text):
        return "base64"
    if re.search(r"\s", text):
        return "quoted-string"
    return "token"


def _entropy(value: str) -> float:
    """Shannon entropy of the literal, in bits per character."""
    text = str(value or "")
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(text))
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * _log2(p)
    return round(entropy, 2)


def _log2(value: float) -> float:
    import math
    return math.log(value, 2)


def _entropy_label(entropy: float, length: int) -> str:
    """``high`` for a long, high-entropy literal; ``low`` otherwise."""
    if length >= 16 and entropy >= 3.5:
        return "high"
    return "low"


def _weak_setting(leaf: dict) -> str | None:
    """The weak-setting label for one leaf, or None when it is not weak.

    The dotted context joins the match: a YAML leaf written ``enabled: true``
    under ``management: / introspection:`` is the actuator exposure an advisory
    names, while a bare ``enabled`` anywhere else is not.
    """
    key = str(leaf.get("key") or "").lower()
    context = str(leaf.get("context") or "").lower()
    value = _strip_quotes(str(leaf.get("value") or "")).strip().lower()
    if not key or not value:
        return None
    for label, predicate in WEAK_SETTINGS:
        try:
            if predicate(key, value) or (context and predicate(context, value)):
                return label
        except Exception:
            continue
    return None


def _config_findings(leaves: list[dict]) -> list[dict]:
    """CWE-798 for a hardcoded literal, CWE-16 for a weak setting.

    An env-var reference is never a secret finding: externalising the value is
    the mitigation, and the descriptor for it says so explicitly.
    """
    findings: list[dict] = []
    for leaf in leaves:
        if leaf.get("redacted"):
            length = leaf.get("length") or len(str(leaf.get("value") or ""))
            entropy = leaf.get("entropy") or 0.0
            high = _entropy_label(entropy, length) == "high"
            confidence = _confidence(
                _CONF_BASE,
                _CONF_EVIDENCE,
                _CONF_GAP if high else 0.0,
                _CONF_NOGUARD if leaf.get("value_class") in ("hex", "base64")
                else 0.0,
            )
            evidence = (f"{_site(leaf['file'], leaf['line'])} "
                        f"{leaf['display_key']} "
                        f"holds a {length}-char {leaf.get('value_class')} "
                        f"literal (entropy {_entropy_label(entropy, length)}) "
                        f"instead of an env-var reference")
            findings.append({
                "header": (f"## candidate finding (CWE-798, severity high, "
                           f"confidence {confidence})"),
                "finding": _candidate_finding(
                    title=(f"hardcoded secret in config: "
                           f"{leaf['display_key']} "
                           f"({leaf['file']}:{leaf['line']})"),
                    path=leaf["file"],
                    start_line=leaf["line"],
                    end_line=leaf["line"],
                    cwe="CWE-798",
                    severity="high",
                    confidence=confidence,
                    taint_source=f"config file {leaf['file']}",
                    taint_sink=f"{leaf['display_key']} = {leaf['display']}",
                    taint_path=[_site(leaf["file"], leaf["line"])],
                    evidence=evidence,
                    rationale=(f"the value of {leaf['key']} is written into the "
                               f"config file, so it is committed to version "
                               f"control, visible to anyone with repo access, "
                               f"and rotated only by editing code"),
                    note=("CWE-798 (Use of Hard-coded Credentials); read the "
                          "value from the environment (ENV_VAR_REF) or a secret "
                          "manager instead — the literal itself is not returned "
                          "here"),
                ),
            })
            continue
        weak = _weak_setting(leaf)
        if weak is None:
            continue
        confidence = _confidence(_CONF_BASE, _CONF_EVIDENCE)
        findings.append({
            "header": (f"## candidate finding (CWE-16, severity medium, "
                       f"confidence {confidence})"),
            "finding": _candidate_finding(
                title=(f"weak security setting: {weak} "
                       f"({leaf['display_key']})"),
                path=leaf["file"],
                start_line=leaf["line"],
                end_line=leaf["line"],
                cwe="CWE-16",
                severity="medium",
                confidence=confidence,
                taint_source=f"config file {leaf['file']}",
                taint_sink=f"{leaf['key']} = {leaf['display']}",
                taint_path=[_site(leaf["file"], leaf["line"])],
                evidence=(f"{_site(leaf['file'], leaf['line'])} "
                          f"{leaf['display_key']} = {leaf['display']} — {weak}"),
                rationale=(f"{weak} weakens the posture this setting is supposed "
                           f"to enforce; the setting itself is not a secret, so "
                           f"its value is returned as written"),
                note=("CWE-16 (Configuration); the specific weakness is named "
                      "in the evidence line"),
            ),
        })
    return findings


# ---------------------------------------------------------------------------
# 3. trace_egress_and_ssrf_targets
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def trace_egress_and_ssrf_targets(network_sink_node_id: str, root: str = ".",
                                  limit: int | None = None) -> str:
    """Do this function's network calls go to a fixed URL, or to an attacker's?

    Egress resolution. The node is resolved (a function, or the wrapper a
    network sink sits inside), its whole span is scanned with tree-sitter, and
    every callee the effects taxonomy classifies ``network`` is kept. For each
    one the URL argument is found — the first argument containing ``://``/http,
    or whose parameter name is url-ish (``url|uri|endpoint|host|domain|target|
    dest|base|api|path``), else the first string literal — and a bare identifier
    is resolved one hop through an assignment earlier in the same function
    (``unresolved local`` when nothing assigns it). The URL is then split into
    scheme/host/port/path/query and each part marked CONSTANT or DYNAMIC, which
    is what separates the verdicts:

    - ``FULLY_CONSTANT`` — every part is a literal; benign.
    - ``HOST_DYNAMIC`` — the host is built (f-string, template, concatenation,
      unresolved identifier): full SSRF, CWE-918, high.
    - ``PATH_DYNAMIC`` — the host is fixed but the path is built:
      path-injection SSRF, CWE-918, high.
    - ``PARTIAL`` — only the query or port is dynamic: medium.

    Use this on any function that calls out (webhooks, URL fetchers, image
    proxies, OAuth callbacks, ``requests.get``/``fetch``/``axios`` wrappers) and
    before claiming an SSRF is not reachable. Do NOT use it as proof: the
    resolution is ONE hop, so a URL threaded through two functions reads as
    ``unresolved local``; a dynamic part may still be validated upstream; and
    the taxonomy is call-shape based, so an egress written through an
    unrecognised wrapper is simply not in the list.

    Confidence is ``0.45 + 0.20`` for a dynamic host, ``+0.10`` for a dynamic
    path, and ``+0.05`` when the URL is written at the call site rather than
    resolved through an assignment — clamped to [0.30, 0.85], since a dynamic
    part is a candidate and an allow-list upstream still makes it safe.

    Args:
        network_sink_node_id: The function making the calls, or any node inside
            it (a wrapper, a variable) — the enclosing function is used.
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Max network call sites reported. 0 = unlimited.

    Returns:
        A bounded report: the resolved span, one block per network call
        (``{file:line, call, url_arg, parts, verdict, evidence}``), and one
        candidate finding block per non-benign verdict (CWE-918).
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return _db.guidance_no_db(root)

    node = _db.get_node(conn, network_sink_node_id)
    if node is None:
        # The node id is agent input, so the error string that echoes it goes
        # through the same char cap as the successful report.
        return _cap_chars(f"ERROR: node not found: {network_sink_node_id}")

    file_path = str(node.get("file_path") or "")
    language = str(node.get("language") or "")
    cache: dict[str, tuple] = {}
    tree, src = _parsed_file(root, file_path, cache)
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
            "line": call["line"],
            "col": call["col"],
            "callee": _callee_text(call["node"], src) or call["text"],
            "call_text": call["text"],
            "node": call["node"],
            "categories": categories,
        })

    site_cap = _cap_rows(limit, ENV_SINKS, DEFAULT_SINKS)
    out: list[str] = [f"# egress & ssrf: {network_sink_node_id}",
                      f"root: {root}",
                      f"node: {_node_label(node)}",
                      f"span: {file_path}:{span[0]}-{span[1]} "
                      f"({span[1] - span[0] + 1} lines, "
                      f"language {language or 'unknown'})",
                      f"calls in span: {len(calls)}  network: {len(network)}"]

    if not network:
        out.append("")
        out.append("no network call in this span: nothing the effects taxonomy "
                   "classifies as network was found")
        out.append("hint: the callee must be recognised as written (requests.get, "
                   "fetch, axios.*, http.Client, urllib.request…) — an egress "
                   "hidden behind an unrecognised wrapper is not in the table")
        return _cap_chars("\n".join(out))

    findings: list[dict] = []
    for position, site in enumerate(network[:site_cap], start=1):
        resolved = _resolve_url_argument(site, tree, src, language, conn, root)
        parts = _url_parts(resolved["expression"])
        verdict, severity, cwe, note = _egress_verdict(parts)
        block, finding = _egress_block(position, len(network), site, resolved,
                                       parts, verdict, severity, cwe, note,
                                       src, file_path)
        out.append("")
        out.extend(block)
        if finding is not None:
            findings.append(finding)
    if len(network) > site_cap:
        out.append("")
        out.append(f"… +{len(network) - site_cap} more network calls (total "
                   f"{len(network)}); raise the limit to expand")

    finding_cap = _section_cap(ENV_FINDINGS, DEFAULT_FINDINGS)
    out.append("")
    out.append(f"--- candidate findings ({len(findings)})")
    if not findings:
        out.append("none: every network call in this span targets a "
                   "fully-constant URL")
    for index, finding in enumerate(findings[:finding_cap], start=1):
        out.append(f"{index}. " + finding["header"])
        out.append(json.dumps(finding["finding"], indent=2, sort_keys=False))
    if len(findings) > finding_cap:
        out.append(f"… +{len(findings) - finding_cap} more findings (total "
                   f"{len(findings)}); raise the limit to expand")
    return _cap_chars("\n".join(out))


def _egress_span(node: dict, tree) -> tuple[int, int] | None:
    """``(start, end)`` of the function whose egress is being traced.

    The node's own span when it IS a function; otherwise the enclosing function
    of the node's first line, which is the case when the caller passes a
    wrapper node (a variable holding the client, a constant holding the base
    URL) rather than the function itself.
    """
    node_span = _node_span(node)
    start_line = _as_int(node.get("start_line"), 0)
    enclosing = None
    if tree is not None and start_line:
        enclosing = _ts.enclosing_function(tree, start_line)
    if enclosing is not None:
        start, end = _line_of(enclosing), _end_line_of(enclosing)
        if start and end and end >= start:
            # Prefer the enclosing function when the node is inside it: the
            # span of a variable node is one line, which would hide every other
            # call in the same function.
            return (start, end)
    if node_span[0]:
        return node_span
    return None


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


def _call_args(call_node, src: bytes) -> list[dict]:
    """Top-level argument expressions as ``{index, text, keyword, node}``.

    ``keyword`` is the parameter name when the argument is written as one
    (``url=target``), which is how the url-ish parameter rule sees it.
    """
    args = _args_node(call_node)
    if args is None:
        return []
    out: list[dict] = []
    index = 0
    for child in args.named_children:
        if child.type in ("comment", "line_comment", "block_comment"):
            continue
        text = _ts.node_text(child, src).strip()
        if not text:
            continue
        flat = " ".join(text.split())
        keyword = ""
        match = re.match(r"^([A-Za-z_$][\w$]*)\s*=(?!=)", flat)
        if match:
            keyword = match.group(1)
        out.append({"index": index, "text": _truncate_line(flat, MAX_VALUE_CHARS),
                    "keyword": keyword, "node": child})
        index += 1
    return out


_URLISH_NAME_RE = re.compile(r"^(?:url|uri|endpoint|host|hostname|domain|target|"
                             r"dest|destination|base|baseurl|base_url|api|"
                             r"path|pathurl|callback|webhook)$", re.IGNORECASE)


def _resolve_url_argument(site: dict, tree, src: bytes, language: str, conn,
                          root: str) -> dict:
    """``{argument, keyword, expression, basis, resolved_from}`` for one call.

    The URL argument is the first one containing ``://`` or ``http``, or whose
    parameter name is url-ish; the fallback is the first string literal, then
    the first argument whatever it is. A bare identifier is then resolved one
    hop through an assignment earlier in the same function.
    """
    args = _call_args(site["node"], src)
    chosen = None
    basis = ""
    for arg in args:
        text = arg["text"]
        if "://" in text or re.search(r"\bhttps?\b", text):
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
        # A keyword argument is chosen for its VALUE, never its prefix:
        # `requests.get(url="https://api.example.com/v1", timeout=5)` used to
        # be skeletoned with the `url=` still on it, so the URL parser saw a
        # host of `url="https` and reported a constant host plus a dynamic
        # path — a false CWE-918 for a fully literal call. The prefix is the
        # grammar's `name=` reading, already computed above; strip it here so
        # only the value reaches `_url_skeleton`.
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
    """``url="https://x"`` -> ``"https://x"`` — drop the keyword spelling.

    ``_call_args`` records the parameter name (:func:`_resolve_url_argument`
    uses it for the url-ish rule), so the argument text keeps the ``name=``
    prefix the grammar matched. A URL parser must never see it: a leading
    ``url=`` turns the scheme into part of the host and every verdict
    downstream of it becomes noise.
    """
    flat = " ".join(str(text or "").split())
    if not keyword or not flat:
        return flat
    return re.sub(rf"^{re.escape(keyword)}\s*=(?!=)\s*", "", flat).strip()


def _param_name(conn, site: dict, arg: dict, language: str, root: str) -> str:
    """The callee's parameter name for a positional argument, when known.

    Only for an in-repo callee: a third-party signature is not in the index, and
    guessing a parameter name would invent evidence.
    """
    if conn is None:
        return ""
    tail = _callee_tail(site["call_text"])
    if not tail:
        return ""
    for node in _db.find_nodes(conn, name=tail, limit=5):
        if str(node.get("kind") or "") not in _NAMESAKE_KINDS:
            continue
        params = _ts.parse_signature_params(str(node.get("signature") or ""),
                                           language or str(node.get("language")
                                                          or ""))
        for param in params:
            if param.get("index") == arg["index"]:
                return str(param.get("name") or "")
    return ""


def _callee_tail(text: str) -> str:
    """``db.run_query`` -> ``run_query`` — the segment a name match uses."""
    tail = str(text or "").strip()
    if "(" in tail:
        tail = tail.split("(", 1)[0].strip()
    tail = tail.rsplit(".", 1)[-1]
    return tail.lstrip("?!").strip()


def _one_hop_assignment(tree, src: bytes, line: int, name: str):
    """``{target, value, line}`` for the last assignment to ``name`` before ``line``.

    One hop only, and only inside the function that makes the call: a
    two-function URL build reads as ``unresolved local`` rather than being
    followed across the graph, which keeps the verdict honest about how far the
    resolution actually went.
    """
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


def _assign_value(node, src: bytes) -> str:
    """The right-hand side of an assignment-ish node."""
    for field in ("right", "value"):
        child = node.child_by_field_name(field)
        if child is not None:
            return " ".join(_ts.node_text(child, src).split())
    text = _ts.node_text(node, src)
    return " ".join(text.split("=", 1)[1].split()) if "=" in text else ""


_SENTINEL = "\x00"
_URL_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")


def _url_skeleton(expression: str) -> str:
    """The URL expression with every dynamic region replaced by a sentinel.

    A plain literal keeps its text; an f-string/template interpolation
    (``{x}``/``${x}``) and a concatenation's non-literal operand both become the
    sentinel, so ``f"https://{d}/api"`` -> ``https://\\x00/api`` and
    ``"https://" + host`` -> ``https://\\x00``. Everything downstream then only
    has to ask "does this part contain the sentinel".
    """
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
    inner = re.sub(r"\{[^{}]*\}", _SENTINEL, inner)
    return inner


def _url_parts(expression: str) -> dict:
    """scheme/host/port/path/query, each CONSTANT or DYNAMIC."""
    skeleton = _url_skeleton(expression)
    parts = {
        "scheme": {"value": "", "kind": "CONSTANT"},
        "host": {"value": "", "kind": "CONSTANT"},
        "port": {"value": "", "kind": "CONSTANT"},
        "path": {"value": "", "kind": "CONSTANT"},
        "query": {"value": "", "kind": "CONSTANT"},
    }
    if not skeleton:
        for key in parts:
            parts[key] = {"value": "", "kind": "DYNAMIC"}
        parts["host"]["value"] = ""
        return parts

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
            remainder = ""
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
    """``(verdict, severity, cwe, note)`` from the part classifications."""
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
    lines.append(f"parts: {rendered}")
    lines.append(f"verdict: {verdict} — {note}")
    lines.append(f"evidence: {_site(file_path, site['line'])}: "
                 f"{_truncate_line(_ts.line_text(src, site['line']), MAX_EVIDENCE)}")

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
        path=file_path,
        start_line=site["line"],
        end_line=site["line"],
        cwe=cwe,
        severity=severity,
        confidence=confidence,
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

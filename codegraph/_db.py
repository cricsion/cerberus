"""Read-only access to the CodeGraph SQLite index for the SAST tools.

What this gives that raw ``sqlite3`` does not:

- **A contained, cached, always-read-only handle** (:func:`connect`). The DB is
  opened through a ``mode=ro`` URI (never read-write: a SAST tool has no
  business writing the target repo's index), pinned to
  ``PRAGMA query_only=ON``, keyed by ``(resolved path, mtime)`` so a re-index
  invalidates the cache, and it degrades instead of raising: a missing or
  unreadable index yields ``None`` and every helper below then returns
  ``[]``/``None``/the :func:`guidance_no_db` string.
- **Decoded rows.** ``nodes.decorators`` / ``nodes.type_parameters`` and
  ``edges.metadata`` are JSON text in SQLite; every helper here hands back
  plain dicts/lists, so callers never re-parse.
- **The CodeGraph semantics an agent needs**, ported from
  ``codegraph/src/db/queries.ts``: the routing-manifest join (route node ->
  handler), the test/generated-file hygiene filter, ``unresolved_refs`` as a
  first-class "an edge may be missing here" warning, and the FTS5 join with a
  safe MATCH fallback.
- **Honest caps.** Every list helper takes ``limit<=0`` as "unlimited" and
  clamps to a hard maximum of 500 rows (``CODEGRAPH_*_LIMIT`` env overrides,
  0 = unlimited), so a pathological repo cannot flood an agent context.

Node ids are content hashes and edge autoincrement ids are NOT stable across
re-indexes — fingerprint the ``(source, target, kind, line, col)`` tuple.
``node_modules``/``vendor`` are never indexed, so anything missing here is
missing on purpose. ``UNCERTAIN_BELOW = 0.6`` in CodeGraph: below it an edge is
a name-only guess, not a call.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import urllib.parse
from pathlib import Path

# Where CodeGraph puts its index, relative to the repo root. Resolved under
# the same containment check every other harness tool module uses.
DB_RELATIVE_PATH = ".codegraph/codegraph.db"

# The success-shaped guidance string every CodeGraph-backed tool returns when
# connect() is None. Mirrors CodeGraph's own policy (NotIndexedError ->
# textResult): an un-indexed repo is a SUCCESS-shaped answer carrying guidance,
# never an error, and never a hidden tool.
GUIDANCE_NO_DB = (
    "(no codegraph index for this repo: run `codegraph index` — falling back to grep)"
)

# Hard ceiling for every list-returning helper, per the contract: limit<=0
# means unlimited, but unlimited still stops at this many rows.
HARD_MAX_ROWS = 500

# Env-var names for the per-helper caps (0 = unlimited, then clamped).
ENV_NODES = "CODEGRAPH_NODES_LIMIT"
ENV_EDGES = "CODEGRAPH_EDGES_LIMIT"
ENV_ROUTES = "CODEGRAPH_ROUTES_LIMIT"
ENV_FTS = "CODEGRAPH_FTS_LIMIT"

# "ro" when the index opened normally, "immutable" when SQLite needed the
# degraded WAL-without--shm open, "" when nothing is open.
last_open_mode: str = ""

_CONN_CACHE: dict[str, tuple[float, str, sqlite3.Connection]] = {}
_LOCK = threading.Lock()

_JSON_COLUMNS = ("decorators", "type_parameters", "candidates")

# Handler kinds getRoutingManifest accepts — mirrors queries.ts:1258.
_HANDLER_KINDS = ("function", "method", "class", "constant", "variable", "component")


# ---------------------------------------------------------------------------
# hygiene: test/generated-file filtering (port of isLowValueFile)
# ---------------------------------------------------------------------------

# Path-only generated-file conventions (extraction/generated-detection.ts).
_GENERATED_PATH_PATTERNS = tuple(re.compile(p) for p in (
    r"\.pb\.go$", r"\.pulsar\.go$", r"_grpc\.pb\.go$", r"_mock\.go$", r"_mocks\.go$",
    r"^mock_[^/]+\.go$", r"\.generated\.[jt]sx?$", r"\.gen\.[jt]sx?$", r"\.pb\.[jt]s$",
    r"_pb\.[jt]s$", r"_grpc_pb\.[jt]s$", r"[.-]min\.m?js$", r"_pb2(_grpc)?\.py$",
    r"_pb2\.pyi$", r"\.pb\.(cc|h)$", r"\.g\.cs$", r"Grpc\.cs$", r"OuterClass\.java$",
    r"Grpc\.java$", r"\.pb\.swift$", r"\.g\.dart$", r"\.freezed\.dart$", r"\.pb\.dart$",
    r"\.pbgrpc\.dart$", r"\.chopper\.dart$", r"\.generated\.rs$",
))

# Non-production directories: examples, samples, benchmarks, fixtures, demos
# (search/query-utils.ts matchesNonProductionDir).
_NON_PRODUCTION_DIRS = (
    "integration", "sample", "samples", "example", "examples", "fixture",
    "fixtures", "benchmark", "benchmarks", "demo", "demos",
)

_TEST_FILENAME = re.compile(
    r"^test[_.]|[._-](?:test|tests|unittest|unittests|spec|specs)\.[a-z0-9]+$|"
    r"(?:Test|Tests|TestCase|Tester|Spec|Specs)\.[A-Za-z0-9]+$"
)
_TEST_DIR = re.compile(
    r"(?:^|/)(?:tests?|__tests__|specs?|testlib|testing|e2e|unittests|[\w.]+[-_]unittests?)/|"
    r"(?:^|/)[A-Za-z0-9]*(?:Test|Tests|Spec)/|"
    r"(?:^|/)(?:[\w.]+[-_]tests?(?:ing)?|testdata|testutils?|test[-_]utils?|fakes?|mocks?|__mocks__|stubs)/"
)


def _is_generated_path(file_path: str) -> bool:
    return any(p.search(file_path) for p in _GENERATED_PATH_PATTERNS)


def _is_non_production_dir(lower_path: str) -> bool:
    marker = "/src/"
    idx = lower_path.find(marker)
    if idx >= 0:
        scope = lower_path[: idx + 1]
    elif lower_path.startswith("src/"):
        scope = ""
    else:
        scope = lower_path
    return any(f"/{d}/" in scope or scope.startswith(f"{d}/") for d in _NON_PRODUCTION_DIRS)


def is_test_file(file_path: str) -> bool:
    """The wide reading: a test suite, example, sample, fixture or benchmark.

    Port of ``isTestFile`` from ``codegraph/src/search/query-utils.ts``.
    """
    lower = str(file_path or "").lower().replace("\\", "/")
    name = lower.rsplit("/", 1)[-1]
    if _TEST_FILENAME.search(name):
        return True
    if _TEST_DIR.search(lower):
        return True
    return _is_non_production_dir(lower)


def _is_low_value_file(file_path: str, generated: frozenset[str] | set[str]) -> bool:
    """Port of ``isLowValueFile``: indexed flag ∪ path test/generated signals."""
    if file_path in generated:
        return True
    return is_test_file(file_path) or _is_generated_path(file_path)


# ---------------------------------------------------------------------------
# limits
# ---------------------------------------------------------------------------

def _env_int(key: str, default: int) -> int:
    try:
        v = os.environ.get(key)
        if v is None or v == "":
            return default
        return int(v)
    except (TypeError, ValueError):
        return default


def _resolve_rows(value, env_key: str, default: int) -> int:
    """limit -> hard-capped row count. <=0 means unlimited, capped at HARD_MAX_ROWS."""
    if value is None:
        n = _env_int(env_key, default)
    else:
        try:
            n = int(value)
        except (TypeError, ValueError):
            n = default
    if n <= 0:
        return HARD_MAX_ROWS
    return min(n, HARD_MAX_ROWS)


# ---------------------------------------------------------------------------
# bound parameters
# ---------------------------------------------------------------------------

def _safe_param(value) -> str:
    """Text SQLite can actually bind, whatever the agent handed us.

    Python's ``str`` admits lone surrogates (a JSON ``\\uD800`` escape, a
    decoder's error path, a shell's undecodable byte), but SQLite binds text
    as UTF-8 and raises ``UnicodeEncodeError`` from inside ``conn.execute``
    for them. Every helper below binds agent-controlled strings, so every one
    of them passes through here first.

    The replacement is lossy on purpose and only for characters that cannot
    exist in the index: a node id or file path carrying a surrogate matches
    nothing, which is the correct answer — that id was never indexed. Nothing
    that is not a lone surrogate is touched, so ordinary queries keep their
    exact semantics.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-8", "replace").decode("utf-8", "replace")
    return text


# ---------------------------------------------------------------------------
# connect / state
# ---------------------------------------------------------------------------

def resolve_db_path(root: str = ".") -> Path:
    """Resolve ``<root>/.codegraph/codegraph.db`` under repo containment.

    Raises ``ValueError`` when root escapes the repo — callers exposed as
    tools convert that to an agent-facing error string. An OS-level refusal
    (a path component past NAME_MAX, an unreadable parent directory) is
    reported the same way instead of as a bare ``OSError``: the containment
    check itself stats the filesystem, so a hostile root can fail there, and
    the shape every tool caller knows how to convert is this one.

    Nothing here can raise ``OSError`` — that is the degradation contract.
    """
    from harness.tools.code import _safe_path
    try:
        base = _safe_path(str(root) if root is not None else ".")
        try:
            if base.is_file():
                base = base.parent
        except OSError:
            pass
        # Force one addressability check on the root itself. The shared path
        # resolver must allow writes to not-yet-existing children, so it does
        # not stat every candidate; codegraph still needs a hostile root
        # (NAME_MAX+, unreadable parent) to surface as ValueError here.
        base.stat()
        return (base / DB_RELATIVE_PATH).resolve()
    except OSError as e:
        raise ValueError(
            f"cannot resolve codegraph index path for {root!r}: {e}") from None


def _open_connection(db: Path) -> tuple[sqlite3.Connection | None, str]:
    """Open read-only; fall back to immutable when the WAL sidecar is absent."""
    quoted = urllib.parse.quote(str(db))
    for mode in ("mode=ro", "mode=ro&immutable=1"):
        try:
            conn = sqlite3.connect(f"file:{quoted}?{mode}", uri=True,
                                   check_same_thread=False)
        except sqlite3.Error:
            continue
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            # Probe: the open above is lazy, so force a real read now — a DB
            # whose WAL cannot be replayed fails here, not later in a helper.
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
            return conn, ("ro" if mode == "mode=ro" else "immutable")
        except sqlite3.Error:
            try:
                conn.close()
            except sqlite3.Error:
                pass
            continue
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            continue
    return None, ""


def connect(root: str = ".") -> sqlite3.Connection | None:
    """Cached read-only connection, or None when the index is missing/unreadable.

    The cache is keyed by (resolved db path, mtime) — the same staleness rule
    ``graphify.py._load_nx`` uses — so a re-index or a fresh ``codegraph sync``
    re-opens instead of serving the old inode.

    Never raises. A hostile root — one whose path components are longer than
    NAME_MAX, or that the OS refuses to address at all — degrades to ``None``
    (the "DB not available" shape) instead of leaking ``OSError`` from a stat,
    while a containment ``ValueError`` from :func:`resolve_db_path` keeps
    propagating to the callers that turn it into an ``ERROR: ...`` string.
    """
    global last_open_mode
    try:
        db = resolve_db_path(root)
    except (ValueError, OSError):
        return None
    try:
        if not db.is_file():
            return None
        mtime = db.stat().st_mtime
    except OSError:
        return None
    key = str(db)
    with _LOCK:
        hit = _CONN_CACHE.get(key)
        if hit is not None and hit[0] == mtime:
            last_open_mode = hit[1]
            return hit[2]
    conn, mode = _open_connection(db)
    if conn is None:
        with _LOCK:
            _CONN_CACHE.pop(key, None)
        last_open_mode = ""
        return None
    with _LOCK:
        _CONN_CACHE[key] = (mtime, mode, conn)
    last_open_mode = mode
    return conn


def close_cached() -> None:
    """Drop every cached connection (tests, long-lived processes)."""
    with _LOCK:
        for _mtime, _mode, conn in _CONN_CACHE.values():
            try:
                conn.close()
            except Exception:
                pass
        _CONN_CACHE.clear()


def guidance_no_db(root: str = ".") -> str:
    """The guidance string every tool returns when connect() is None.

    ``root`` is accepted for signature symmetry with the helpers that follow
    the ``conn = connect(root)`` / ``if None -> guidance_no_db(root)`` shape.
    """
    return GUIDANCE_NO_DB


def _count(conn: sqlite3.Connection, table: str, where: str = "", params: tuple = ()) -> int:
    try:
        row = conn.execute(f"SELECT count(*) FROM {table} {where}", params).fetchone()
        return int(row[0]) if row else 0
    except (sqlite3.Error, UnicodeEncodeError):
        return 0


def index_state(root: str = ".") -> dict:
    """What the caller needs to know before trusting graph answers.

    ``mode`` reports how the index was opened (``ro`` or the degraded
    ``immutable``); ``refs_pending`` counts ``unresolved_refs`` still in the
    ``pending`` lifecycle state, and ``unresolved_refs`` the failed ones —
    CodeGraph's own gate is ``pendingRefs == 0`` and ``index.state == complete``,
    so a caller that sees ``refs_pending > 0`` knows edges are still missing.
    """
    out = {"available": False, "path": "", "mode": "", "nodes": 0, "edges": 0,
           "unresolved_refs": 0, "refs_pending": 0}
    try:
        db = resolve_db_path(root)
        out["path"] = str(db)
    except (ValueError, OSError):
        return out
    conn = connect(root)
    if conn is None:
        return out
    out["available"] = True
    out["mode"] = last_open_mode
    out["nodes"] = _count(conn, "nodes")
    out["edges"] = _count(conn, "edges")
    out["unresolved_refs"] = _count(conn, "unresolved_refs", "WHERE status = 'failed'")
    out["refs_pending"] = _count(conn, "unresolved_refs", "WHERE status = 'pending'")
    return out


# ---------------------------------------------------------------------------
# node rows
# ---------------------------------------------------------------------------

def _row_to_node(row: sqlite3.Row) -> dict:
    out = dict(row)
    for col in _JSON_COLUMNS:
        if col in out:
            out[col] = _decode_json(out[col])
    return out


def _decode_json(raw):
    if raw is None or raw == "":
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def get_node(conn, node_id: str) -> dict | None:
    """One node by id, JSON columns decoded. None when absent/unreadable."""
    if conn is None:
        return None
    try:
        row = conn.execute("SELECT * FROM nodes WHERE id = ?",
                           (_safe_param(node_id),)).fetchone()
    except (sqlite3.Error, UnicodeEncodeError):
        return None
    return _row_to_node(row) if row is not None else None


def find_nodes(conn, *, kind=None, name=None, name_like=None, file_path=None,
               language=None, limit=50) -> list[dict]:
    """Filtered node lookup. Every filter is optional; results are capped."""
    if conn is None:
        return []
    clause: list[str] = []
    params: list = []
    if kind:
        clause.append("kind = ?")
        params.append(_safe_param(kind))
    if name:
        clause.append("name = ?")
        params.append(_safe_param(name))
    if name_like:
        clause.append("name LIKE ?")
        v = _safe_param(name_like)
        params.append(v if "%" in v else f"%{v}%")
    if file_path:
        clause.append("file_path = ?")
        params.append(_safe_param(file_path))
    if language:
        clause.append("language = ?")
        params.append(_safe_param(language))
    where = f"WHERE {' AND '.join(clause)}" if clause else ""
    rows = _resolve_rows(limit, ENV_NODES, 50)
    try:
        cur = conn.execute(
            f"SELECT * FROM nodes {where} ORDER BY file_path, start_line, id LIMIT ?",
            (*params, rows),
        )
        return [_row_to_node(r) for r in cur.fetchall()]
    except (sqlite3.Error, UnicodeEncodeError):
        return []


# ---------------------------------------------------------------------------
# edge rows
# ---------------------------------------------------------------------------

def _row_to_edge(row: sqlite3.Row) -> dict:
    out = dict(row)
    out["metadata"] = _decode_json(out.get("metadata")) or {}
    return out


def get_edges(conn, *, source=None, target=None, kind=None, provenance=None,
              limit=100) -> list[dict]:
    """Edges by endpoint/kind/provenance, with ``metadata`` decoded to a dict.

    ``id`` is exposed for display only — it is an autoincrement and NOT stable
    across re-indexes. The stable fingerprint is ``(source, target, kind, line,
    col)``.
    """
    if conn is None:
        return []
    clause: list[str] = []
    params: list = []
    for col, val in (("source", source), ("target", target), ("kind", kind),
                     ("provenance", provenance)):
        if val:
            clause.append(f"{col} = ?")
            params.append(_safe_param(val))
    where = f"WHERE {' AND '.join(clause)}" if clause else ""
    rows = _resolve_rows(limit, ENV_EDGES, 100)
    try:
        cur = conn.execute(
            f"SELECT * FROM edges {where} ORDER BY line, col, id LIMIT ?",
            (*params, rows),
        )
        return [_row_to_edge(r) for r in cur.fetchall()]
    except (sqlite3.Error, UnicodeEncodeError):
        return []


def node_children(conn, node_id: str, kinds=None, limit=50) -> list[dict]:
    """Nodes this node ``contains`` (a file's symbols, a class's methods)."""
    if conn is None:
        return []
    kinds = _normalise_kinds(kinds)
    rows = _resolve_rows(limit, ENV_NODES, 50)
    clause = "AND h.kind IN (%s)" % ",".join("?" * len(kinds)) if kinds else ""
    try:
        cur = conn.execute(
            f"SELECT h.* FROM edges e JOIN nodes h ON h.id = e.target "
            f"WHERE e.source = ? AND e.kind = 'contains' {clause} "
            f"ORDER BY h.start_line, h.id LIMIT ?",
            (_safe_param(node_id), *kinds, rows),
        )
        return [_row_to_node(r) for r in cur.fetchall()]
    except (sqlite3.Error, UnicodeEncodeError):
        return []


def node_parent(conn, node_id: str) -> dict | None:
    """The node that ``contains`` this one (a symbol's file or class)."""
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT p.* FROM edges e JOIN nodes p ON p.id = e.source "
            "WHERE e.target = ? AND e.kind = 'contains' "
            "ORDER BY p.start_line, p.id LIMIT 1",
            (_safe_param(node_id),),
        ).fetchone()
    except (sqlite3.Error, UnicodeEncodeError):
        return None
    return _row_to_node(row) if row is not None else None


def _normalise_kinds(kinds) -> tuple[str, ...]:
    if not kinds:
        return ()
    if isinstance(kinds, str):
        kinds = [kinds]
    return tuple(_safe_param(k) for k in kinds if str(k).strip())


def incoming_edges(conn, node_id: str, kinds=None, limit=100) -> list[dict]:
    """Edges pointing at this node, optionally filtered by kind."""
    if conn is None:
        return []
    ks = _normalise_kinds(kinds)
    where_kinds = " AND e.kind IN (%s)" % ",".join("?" * len(ks)) if ks else ""
    rows = _resolve_rows(limit, ENV_EDGES, 100)
    try:
        cur = conn.execute(
            f"SELECT e.* FROM edges e WHERE e.target = ?{where_kinds} "
            f"ORDER BY e.line, e.col, e.id LIMIT ?",
            (_safe_param(node_id), *ks, rows),
        )
        return [_row_to_edge(r) for r in cur.fetchall()]
    except (sqlite3.Error, UnicodeEncodeError):
        return []


def outgoing_edges(conn, node_id: str, kinds=None, limit=100) -> list[dict]:
    """Edges leaving this node, optionally filtered by kind."""
    if conn is None:
        return []
    ks = _normalise_kinds(kinds)
    where_kinds = " AND e.kind IN (%s)" % ",".join("?" * len(ks)) if ks else ""
    rows = _resolve_rows(limit, ENV_EDGES, 100)
    try:
        cur = conn.execute(
            f"SELECT e.* FROM edges e WHERE e.source = ?{where_kinds} "
            f"ORDER BY e.line, e.col, e.id LIMIT ?",
            (_safe_param(node_id), *ks, rows),
        )
        return [_row_to_edge(r) for r in cur.fetchall()]
    except (sqlite3.Error, UnicodeEncodeError):
        return []


def unresolved_refs(conn, *, node_id=None, file_path=None, status=None,
                    limit=100) -> list[dict]:
    """References the resolver saw and failed on — an edge may be missing here.

    CodeGraph keeps ``status='failed'`` rows on purpose so a later sync can
    retry them; ``pending`` means the resolution pass has not run yet. Either
    way the SAST reading is the same: under-approximation, be explicit about it.
    """
    if conn is None:
        return []
    clause: list[str] = []
    params: list = []
    if node_id:
        clause.append("from_node_id = ?")
        params.append(_safe_param(node_id))
    if file_path:
        clause.append("file_path = ?")
        params.append(_safe_param(file_path))
    if status:
        clause.append("status = ?")
        params.append(_safe_param(status))
    where = f"WHERE {' AND '.join(clause)}" if clause else ""
    rows = _resolve_rows(limit, ENV_EDGES, 100)
    try:
        cur = conn.execute(
            f"SELECT * FROM unresolved_refs {where} ORDER BY file_path, line LIMIT ?",
            (*params, rows),
        )
        return [_row_to_ref(r) for r in cur.fetchall()]
    except (sqlite3.Error, UnicodeEncodeError):
        return []


def _row_to_ref(row: sqlite3.Row) -> dict:
    out = dict(row)
    if "candidates" in out:
        out["candidates"] = _decode_json(out["candidates"]) or []
    return out


# ---------------------------------------------------------------------------
# routing manifest
# ---------------------------------------------------------------------------

def routing_manifest(conn, limit: int = 40) -> list[dict]:
    """URL -> handler rows, exact semantics of ``getRoutingManifest`` (queries.ts).

    One join: ``nodes r(kind='route')`` -> ``edges e(kind IN
    ('references','calls'))`` -> ``nodes h(kind IN (function, method, class,
    constant, variable, component))``, ordered by ``r.file_path,
    r.start_line``. Edge kind varies by framework resolver (Spring/Rails/
    Laravel emit ``references``, Express emits ``calls``), so both are accepted.

    The rows are then passed through the same test/generated hygiene filter the
    UI applies (``files.generated`` ∪ path conventions); when the ``files``
    table lookup fails the filter is skipped rather than dropping everything.
    Unlike the TypeScript helper this returns the list directly — an agent
    asking "what routes exist" wants the rows, not null because a repo happens
    to have fewer than three of them.
    """
    if conn is None:
        return []
    rows = _resolve_rows(limit, ENV_ROUTES, 40)
    sql = (
        "SELECT r.name AS url, r.id AS route_id, r.file_path AS route_file, "
        "r.start_line AS route_line, h.name AS handler, h.file_path AS handler_file, "
        "h.start_line AS handler_line, h.kind AS handler_kind "
        "FROM nodes r "
        "JOIN edges e ON e.source = r.id "
        "JOIN nodes h ON e.target = h.id "
        "WHERE r.kind = 'route' AND e.kind IN ('references', 'calls') "
        f"AND h.kind IN ({', '.join('?' * len(_HANDLER_KINDS))}) "
        "ORDER BY r.file_path, r.start_line LIMIT ?"
    )
    try:
        cur = conn.execute(sql, (*_HANDLER_KINDS, rows))
        raw = [dict(r) for r in cur.fetchall()]
    except (sqlite3.Error, UnicodeEncodeError):
        return []
    generated: set[str] = set()
    try:
        files = {r["handler_file"] for r in raw}
        if files:
            placeholders = ",".join("?" * len(files))
            flagged = conn.execute(
                f"SELECT path FROM files WHERE generated = 1 AND path IN ({placeholders})",
                tuple(_safe_param(f) for f in files),
            ).fetchall()
            generated = {r[0] for r in flagged}
    except (sqlite3.Error, UnicodeEncodeError):
        generated = set()
    return [r for r in raw if not _is_low_value_file(r["handler_file"], generated)]


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------

def _fts_match_text(query: str) -> str:
    """Quote each token so agent input cannot break the FTS5 MATCH grammar.

    FTS5 has its own query language (AND/OR/NEAR/prefix*/"phrases"); a bare
    agent string is not valid in it. Each whitespace/underscore token becomes a
    quoted OR-term, so ``login handler`` -> ``"login" OR "handler"`` and a
    stray ``(`` or ``"`` can never raise a syntax error.
    """
    tokens = [t for t in re.split(r"[\s_\-.:/\\]+", str(query or "")) if t]
    if not tokens:
        return ""
    return " OR ".join('"' + t.replace('"', " ") + '"' for t in tokens)


def search_nodes_fts(conn, query: str, limit: int = 20) -> list[dict]:
    """FTS5 name/signature/docstring search, LIKE-fallback when FTS is missing.

    CodeGraph itself ranks FTS with BM25 weights and applies a -15 penalty to
    test/fixture/benchmark paths — neither is reproduced here: this returns
    recall-complete candidates ranked by FTS's own ``rank``, and a security
    lookup must not silently drop the tests directory.
    """
    if conn is None:
        return []
    rows = _resolve_rows(limit, ENV_FTS, 20)
    # Sanitised, not trusted: a lone surrogate cannot be bound as UTF-8, and
    # the LIKE/MATCH strings below reach the same execute.
    text = _safe_param(query).strip()
    if not text or not re.search(r"\w", text):
        return []  # an empty (or punctuation-only) query is not a query
    match = _fts_match_text(text)
    if match:
        try:
            cur = conn.execute(
                "SELECT n.* FROM nodes_fts f JOIN nodes n ON n.id = f.id "
                "WHERE nodes_fts MATCH ? ORDER BY rank LIMIT ?",
                (match, rows),
            )
            return [_row_to_node(r) for r in cur.fetchall()]
        except (sqlite3.Error, UnicodeEncodeError):
            pass
    # LIKE fallback: FTS5 absent from the SQLite build, or a schema without the
    # virtual table. Substring on name/qualified_name, never a syntax error.
    try:
        needle = f"%{text}%"
        cur = conn.execute(
            "SELECT * FROM nodes WHERE name LIKE ? OR qualified_name LIKE ? "
            "ORDER BY file_path, start_line, id LIMIT ?",
            (needle, needle, rows),
        )
        return [_row_to_node(r) for r in cur.fetchall()]
    except (sqlite3.Error, UnicodeEncodeError):
        return []


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------

def node_line_span(conn, node_id) -> tuple[int, int] | None:
    """(start_line, end_line) for a node — the span a finding should cite."""
    node = get_node(conn, node_id)
    if not node:
        return None
    try:
        return int(node.get("start_line")), int(node.get("end_line"))
    except (TypeError, ValueError):
        return None


def is_generated_file(conn, file_path: str) -> bool:
    """``files.generated`` when the index knows it; False on any miss.

    Only the DB flag is consulted — the path-convention half lives in
    :func:`_is_generated_path` / :func:`is_test_file` and does not need a DB.
    """
    if conn is None:
        return False
    try:
        row = conn.execute(
            "SELECT generated FROM files WHERE path = ?", (_safe_param(file_path),)
        ).fetchone()
    except (sqlite3.Error, UnicodeEncodeError):
        return False
    if row is None:
        return False
    try:
        return int(row[0]) == 1
    except (TypeError, ValueError, IndexError):
        return False

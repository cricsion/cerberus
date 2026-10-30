"""Read-only access to the CodeGraph SQLite index for the SAST tools.

Purpose
Expose a contained, read-only query layer with decoded rows and success-shaped
degradation when an index is unavailable.

Laws: never write the index (``mode=ro`` or degraded ``immutable``, plus
``PRAGMA query_only=ON``); never raise (a missing index gives ``None`` from
:func:`connect`, then ``[]``/``None``/:func:`guidance_no_db`); ``limit <= 0``
means "unlimited" but stops at :data:`HARD_MAX_ROWS` (``CODEGRAPH_*_LIMIT``, 0
= unlimited, is folded through :func:`_resolve_rows`); agent strings bind via
:func:`_safe_param`, so a lone surrogate matches nothing instead of raising.

Invariants: :func:`connect` caches one handle per ``(resolved path, mtime)``, so
a re-index invalidates it and :data:`last_open_mode` mirrors the live handle;
node ids are content hashes and edge autoincrement ids are NOT stable across
re-indexes — fingerprint ``(source, target, kind, line, col)``.

Format laws: the schema is CodeGraph's (``nodes``, ``edges``, ``files``,
``unresolved_refs`` and ``nodes_fts``, a virtual table some builds lack);
``decorators``/``type_parameters``/``metadata``/``candidates`` are JSON text
that helpers hand back decoded (``None``/``{}``/``[]`` when unparsable);
``node_modules``/``vendor`` are never indexed; below CodeGraph's
``UNCERTAIN_BELOW = 0.6`` an edge is a name-only guess, not a call.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import urllib.parse
from pathlib import Path

# Index location relative to the repo root.
DB_RELATIVE_PATH = ".codegraph/codegraph.db"

# Success-shaped guidance every tool returns when connect() is None: an
# un-indexed repo is guidance, never an error and never a hidden tool.
GUIDANCE_NO_DB = "(no codegraph index for this repo: run `codegraph index`)"

# Hard ceiling for every list helper: limit<=0 is unlimited-but-capped.
HARD_MAX_ROWS = 500

# Per-helper cap overrides (0 = unlimited, then clamped).
ENV_NODES = "CODEGRAPH_NODES_LIMIT"
ENV_EDGES = "CODEGRAPH_EDGES_LIMIT"
ENV_ROUTES = "CODEGRAPH_ROUTES_LIMIT"

# "ro" for a normal open, "immutable" for the degraded WAL-without--shm open,
# "" when nothing is open.
last_open_mode: str = ""

_CONN_CACHE: dict[str, tuple[float, str, sqlite3.Connection]] = {}
_LOCK = threading.Lock()

_JSON_COLUMNS = ("decorators", "type_parameters", "candidates")

# Handler kinds getRoutingManifest accepts — mirrors queries.ts:1258.
_HANDLER_KINDS = ("function", "method", "class", "constant", "variable", "component")


# --- hygiene: test/generated-file filtering (port of isLowValueFile) -----------

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
    """True when the path alone carries a generated-file convention."""
    return any(p.search(file_path) for p in _GENERATED_PATH_PATTERNS)


def _is_non_production_dir(lower_path: str) -> bool:
    """True when a non-production segment precedes the nearest ``/src/``."""
    marker = lower_path.find("/src/")
    if marker >= 0:
        scope = lower_path[: marker + 1]
    else:
        scope = "" if lower_path.startswith("src/") else lower_path
    return any(f"/{d}/" in scope or scope.startswith(f"{d}/") for d in _NON_PRODUCTION_DIRS)


def is_test_file(file_path: str) -> bool:
    """The wide reading: a test suite, example, sample, fixture or benchmark.

    Port of ``isTestFile`` from ``codegraph/src/search/query-utils.ts``.
    """
    lower = str(file_path or "").lower().replace("\\", "/")
    return bool(_TEST_FILENAME.search(lower.rsplit("/", 1)[-1])
                or _TEST_DIR.search(lower)
                or _is_non_production_dir(lower))


def _is_low_value_file(file_path: str, generated: frozenset[str] | set[str]) -> bool:
    """Port of ``isLowValueFile``: indexed flag ∪ path test/generated signals."""
    return (file_path in generated or is_test_file(file_path)
            or _is_generated_path(file_path))


# --- limits and SQL plumbing ---------------------------------------------------

def _env_int(key: str, default: int) -> int:
    """Env override as int; ``default`` when unset or invalid (never raises)."""
    try:
        v = os.environ.get(key)
        return int(v) if v else default
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
    return HARD_MAX_ROWS if n <= 0 else min(n, HARD_MAX_ROWS)


def _safe_param(value) -> str:
    """Text SQLite can bind, whatever the agent handed us.

    Python ``str`` admits lone surrogates while SQLite binds UTF-8 and raises
    from ``conn.execute``; replacing them is lossy on purpose — such an id was
    never indexed, so matching nothing is correct. ``None`` binds as ``""``.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-8", "replace").decode("utf-8", "replace")
    return text


def _where(clause: list[str]) -> str:
    """``WHERE a AND b`` for a non-empty clause list, otherwise ``""``."""
    return f"WHERE {' AND '.join(clause)}" if clause else ""


def _fetch(conn, sql: str, params: tuple = ()):
    """Every row of one query, or ``None`` when SQLite or the binding refuses it."""
    try:
        return conn.execute(sql, params).fetchall()
    except (sqlite3.Error, UnicodeEncodeError):
        return None


def _fetch_one(conn, sql: str, params: tuple = ()):
    """First row of one query, or ``None`` when SQLite or the binding refuses it."""
    try:
        return conn.execute(sql, params).fetchone()
    except (sqlite3.Error, UnicodeEncodeError):
        return None


# --- connect / state -----------------------------------------------------------

def resolve_db_path(root: str = ".") -> Path:
    """Resolve ``<root>/.codegraph/codegraph.db`` under repo containment.

    Raises ``ValueError`` when root escapes the repo or the OS refuses to
    address it (NAME_MAX component, unreadable parent), so tool callers get the
    error string they know; nothing here raises ``OSError``.
    """
    from harness.tools.code import _safe_path
    try:
        base = _safe_path(str(root) if root is not None else ".")
        try:
            if base.is_file():
                base = base.parent
        except OSError:
            pass
        # One addressability check: _safe_path permits not-yet-existing children,
        # but codegraph needs a hostile root to surface as ValueError here.
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

    The cache is keyed by (resolved db path, mtime), so a re-index or a fresh
    ``codegraph sync`` re-opens instead of serving the old inode.

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

    ``root`` exists for signature symmetry with the ``connect(root)`` callers.
    """
    return GUIDANCE_NO_DB


def _count(conn: sqlite3.Connection, table: str, where: str = "", params: tuple = ()) -> int:
    """Row count for a table/where pair; 0 when the query cannot run."""
    row = _fetch_one(conn, f"SELECT count(*) FROM {table} {where}", params)
    return int(row[0]) if row else 0


def index_state(root: str = ".") -> dict:
    """What the caller needs to know before trusting graph answers.

    ``mode`` is ``ro`` or the degraded ``immutable``; ``refs_pending`` counts
    ``unresolved_refs`` still pending and ``unresolved_refs`` the failed ones.
    CodeGraph's gate is ``pendingRefs == 0`` and ``index.state == complete``, so
    either count above zero means edges are still missing.
    """
    out = {"available": False, "path": "", "mode": "", "nodes": 0, "edges": 0,
           "unresolved_refs": 0, "refs_pending": 0}
    try:
        out["path"] = str(resolve_db_path(root))
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


# --- node rows -----------------------------------------------------------------

def _decode_json(raw):
    """Decoded JSON column; ``None`` for empty/unparsable input, values pass through."""
    if raw is None or raw == "":
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def _row_to_node(row: sqlite3.Row) -> dict:
    """A node row as a dict, with its JSON columns decoded."""
    return {k: _decode_json(v) if k in _JSON_COLUMNS else v for k, v in dict(row).items()}


def get_node(conn, node_id: str) -> dict | None:
    """One node by id, JSON columns decoded. None when absent/unreadable."""
    if conn is None:
        return None
    row = _fetch_one(conn, "SELECT * FROM nodes WHERE id = ?", (_safe_param(node_id),))
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
    rows = _fetch(conn, f"SELECT * FROM nodes {_where(clause)} "
                        f"ORDER BY file_path, start_line, id LIMIT ?",
                  (*params, _resolve_rows(limit, ENV_NODES, 50)))
    return [_row_to_node(r) for r in rows or ()]


# --- edge rows -----------------------------------------------------------------

def _row_to_edge(row: sqlite3.Row) -> dict:
    """An edge row as a dict with ``metadata`` decoded to a dict."""
    out = dict(row)
    out["metadata"] = _decode_json(out.get("metadata")) or {}
    return out


def get_edges(conn, *, source=None, target=None, kind=None, provenance=None,
              limit=100) -> list[dict]:
    """Edges by endpoint/kind/provenance, with ``metadata`` decoded to a dict.

    ``id`` is display-only: an autoincrement, NOT stable across re-indexes. The
    stable fingerprint is ``(source, target, kind, line, col)``.
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
    rows = _fetch(conn, f"SELECT * FROM edges {_where(clause)} "
                        f"ORDER BY line, col, id LIMIT ?",
                  (*params, _resolve_rows(limit, ENV_EDGES, 100)))
    return [_row_to_edge(r) for r in rows or ()]


def node_children(conn, node_id: str, kinds=None, limit=50) -> list[dict]:
    """Nodes this node ``contains`` (a file's symbols, a class's methods)."""
    if conn is None:
        return []
    kinds = _normalise_kinds(kinds)
    clause = "AND h.kind IN (%s)" % ",".join("?" * len(kinds)) if kinds else ""
    rows = _fetch(conn,
                  f"SELECT h.* FROM edges e JOIN nodes h ON h.id = e.target "
                  f"WHERE e.source = ? AND e.kind = 'contains' {clause} "
                  f"ORDER BY h.start_line, h.id LIMIT ?",
                  (_safe_param(node_id), *kinds, _resolve_rows(limit, ENV_NODES, 50)))
    return [_row_to_node(r) for r in rows or ()]


def node_parent(conn, node_id: str) -> dict | None:
    """The node that ``contains`` this one (a symbol's file or class)."""
    if conn is None:
        return None
    row = _fetch_one(conn,
                     "SELECT p.* FROM edges e JOIN nodes p ON p.id = e.source "
                     "WHERE e.target = ? AND e.kind = 'contains' "
                     "ORDER BY p.start_line, p.id LIMIT 1",
                     (_safe_param(node_id),))
    return _row_to_node(row) if row is not None else None


def _normalise_kinds(kinds) -> tuple[str, ...]:
    """Kinds as a tuple of bindable strings; empty/blank input yields ``()``."""
    if not kinds:
        return ()
    if isinstance(kinds, str):
        kinds = [kinds]
    return tuple(_safe_param(k) for k in kinds if str(k).strip())


def _edges_by_endpoint(conn, column: str, node_id, kinds, limit: int) -> list[dict]:
    """Edges whose ``column`` endpoint (source/target) is ``node_id``."""
    if conn is None:
        return []
    ks = _normalise_kinds(kinds)
    where_kinds = " AND e.kind IN (%s)" % ",".join("?" * len(ks)) if ks else ""
    rows = _fetch(conn,
                  f"SELECT e.* FROM edges e WHERE e.{column} = ?{where_kinds} "
                  f"ORDER BY e.line, e.col, e.id LIMIT ?",
                  (_safe_param(node_id), *ks, _resolve_rows(limit, ENV_EDGES, 100)))
    return [_row_to_edge(r) for r in rows or ()]


def incoming_edges(conn, node_id: str, kinds=None, limit=100) -> list[dict]:
    """Edges pointing at this node, optionally filtered by kind."""
    return _edges_by_endpoint(conn, "target", node_id, kinds, limit)


def outgoing_edges(conn, node_id: str, kinds=None, limit=100) -> list[dict]:
    """Edges leaving this node, optionally filtered by kind."""
    return _edges_by_endpoint(conn, "source", node_id, kinds, limit)


def unresolved_refs(conn, *, node_id=None, file_path=None, status=None,
                    limit=100) -> list[dict]:
    """References the resolver saw and failed on — an edge may be missing here.

    ``failed`` rows are kept so a later sync can retry them; ``pending`` means
    resolution has not run yet. Either way the SAST reading is the same:
    under-approximation, stated explicitly.
    """
    if conn is None:
        return []
    clause: list[str] = []
    params: list = []
    for col, val in (("from_node_id", node_id), ("file_path", file_path),
                     ("status", status)):
        if val:
            clause.append(f"{col} = ?")
            params.append(_safe_param(val))
    rows = _fetch(conn, f"SELECT * FROM unresolved_refs {_where(clause)} "
                        f"ORDER BY file_path, line LIMIT ?",
                  (*params, _resolve_rows(limit, ENV_EDGES, 100)))
    return [_row_to_ref(r) for r in rows or ()]


def _row_to_ref(row: sqlite3.Row) -> dict:
    """An unresolved-ref row with ``candidates`` decoded to a list."""
    out = dict(row)
    if "candidates" in out:
        out["candidates"] = _decode_json(out["candidates"]) or []
    return out


# --- routing manifest ----------------------------------------------------------

def routing_manifest(conn, limit: int = 40) -> list[dict]:
    """URL -> handler rows, exact semantics of ``getRoutingManifest`` (queries.ts).

    ``route`` nodes join through ``references``/``calls`` edges (the resolver
    varies by framework) to ``_HANDLER_KINDS`` nodes, ordered by
    ``r.file_path, r.start_line``, then filtered by the same test/generated rule
    the UI applies; a failed ``files`` lookup skips the filter rather than
    dropping everything. Returns the rows directly, never ``None``.
    """
    if conn is None:
        return []
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
    rows = _fetch(conn, sql, (*_HANDLER_KINDS, _resolve_rows(limit, ENV_ROUTES, 40)))
    if rows is None:
        return []
    raw = [dict(r) for r in rows]
    files = {r["handler_file"] for r in raw}
    generated: set[str] = set()
    if files:
        placeholders = ",".join("?" * len(files))
        flagged = _fetch(conn,
                         f"SELECT path FROM files WHERE generated = 1 "
                         f"AND path IN ({placeholders})",
                         tuple(_safe_param(f) for f in files))
        generated = {r[0] for r in flagged or ()}
    return [r for r in raw if not _is_low_value_file(r["handler_file"], generated)]


# --- misc ----------------------------------------------------------------------

def is_generated_file(conn, file_path: str) -> bool:
    """``files.generated`` when the index knows it; False on any miss.

    Only the DB flag is consulted — the path-convention half lives in
    :func:`_is_generated_path` / :func:`is_test_file` and needs no DB.
    """
    if conn is None:
        return False
    row = _fetch_one(conn, "SELECT generated FROM files WHERE path = ?",
                     (_safe_param(file_path),))
    if row is None:
        return False
    try:
        return int(row[0]) == 1
    except (TypeError, ValueError, IndexError):
        return False

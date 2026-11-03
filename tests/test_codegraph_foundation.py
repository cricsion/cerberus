"""Foundation tests for cerberus.codegraph: DB access, tree-sitter, sinks, memory.

The fixture builder (:func:`build_mini_db`) is deliberately reusable: later test
files for the tool modules import it and get the same realistic mini-index —
real source files on disk with node spans that match them, a route with its
handler, a cross-file call with a persisted confidence, a SYNTHESIZED edge
carrying its ``registeredAt`` wiring site, and an ``unresolved_refs`` row that
says "an edge may be missing here".

Nothing here talks to a network, writes into the repo under test, or leaks
process-global env (conftest snapshots TARGET_REPO per test).
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest
from cerberus.codegraph import _db, _ts, sinks
from codegraph_support import close_cached

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# fixture
# ---------------------------------------------------------------------------

APP_PY = '''\
from flask import Flask, request

app = Flask(__name__)
DEBUG = True
@app.route("/login", methods=["POST"])
def login(username, password):
    user = auth.verify_token(username)
    if user is None:
        return "denied"
    return unsafe_query("SELECT * FROM users WHERE name = '%s'" % username)


def unsafe_query(sql):
    return db.run_query(sql)
'''

DB_PY = '''\
import sqlite3

DB_PATH = "app.db"


def run_query(sql):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
'''

WORKER_PY = '''\
"""Queue wiring: the registrant, and the consumer the synthesizer joined."""

from bullmq import Queue

export_queue = Queue("exports")


def enqueue_export(payload):
    export_queue.add("export", payload)


def handle_export(job):
    return unsafe_query(job.sql)
'''

SERVER_TS = '''\
import { db } from "./db";
const MAX_ROWS = 100;

export function handleExport(req: Request, res: Response) {
  const rows = db.query("SELECT * FROM exports");
  res.json(rows);
}
'''

DASHBOARD_TSX = '''\
import { handleExport } from "./server";

export function Dashboard() {
  return handleExport;
}
'''


def _find_schema_sql() -> Path | None:
    """Locate the authoritative schema: env override, repo-relative, then a walk."""
    override = (os.environ.get("CODEGRAPH_SCHEMA_SQL") or "").strip()
    if override:
        candidate = Path(override)
        return candidate if candidate.is_file() else None
    direct = REPO_ROOT / "codegraph" / "src" / "db" / "schema.sql"
    if direct.is_file():
        return direct
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "codegraph" / "src" / "db" / "schema.sql"
        if candidate.is_file():
            return candidate
    return None


def _node(node_id: str, kind: str, name: str, file_path: str, language: str,
          start_line: int, end_line: int, *, signature: str | None = None,
          decorators: str | None = None, docstring: str | None = None,
          qualified_name: str | None = None, is_exported: int = 0,
          start_column: int = 0, end_column: int = 0) -> tuple:
    return (
        node_id, kind, name, qualified_name or name, file_path, language,
        start_line, end_line, start_column, end_column, docstring, signature,
        None, is_exported, 0, 0, 0, decorators, None, None, 1_700_000_000_000,
    )


NODE_COLUMNS = ("id, kind, name, qualified_name, file_path, language, "
                "start_line, end_line, start_column, end_column, docstring, "
                "signature, visibility, is_exported, is_async, is_static, "
                "is_abstract, decorators, type_parameters, return_type, updated_at")

# The two INSERT statements every fixture seeder replays; defined once here
# (NODE_COLUMNS' home) so a schema-column change is one edit, not seven.
_NODES_SQL = (f"INSERT INTO nodes ({NODE_COLUMNS}) VALUES "
              f"({','.join('?' * len(NODE_COLUMNS.split(',')))})")
_EDGES_SQL = ("INSERT INTO edges (source, target, kind, metadata, line, col, "
              "provenance) VALUES (?, ?, ?, ?, ?, ?, ?)")


def build_mini_db(tmp_path) -> Path:
    """Seed a realistic mini CodeGraph index at ``<tmp_path>/.codegraph/codegraph.db``.

    Writes real source files whose node spans match the text, then builds the
    index from the REAL ``codegraph/src/db/schema.sql`` (so triggers, FTS5 and
    the edge-identity index are all exercised). Returns the DB path.
    """
    schema = _find_schema_sql()
    if schema is None:
        pytest.skip("codegraph source not available")

    root = Path(tmp_path)
    (root / ".codegraph").mkdir(parents=True, exist_ok=True)
    for name, text in (("app.py", APP_PY), ("db.py", DB_PY), ("worker.py", WORKER_PY),
                       ("server.ts", SERVER_TS), ("Dashboard.tsx", DASHBOARD_TSX)):
        (root / name).write_text(text)
    (root / "generated").mkdir(exist_ok=True)
    (root / "generated" / "api_pb2.py").write_text("# generated\n")

    db_path = root / ".codegraph" / "codegraph.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(schema.read_text())
        nodes = [
            _node("app.py:app.py", "file", "app.py", "app.py", "python", 1, 14),
            _node("app.py:login", "function", "login", "app.py", "python", 6, 10,
                  signature="def login(username, password):", is_exported=1,
                  decorators=json.dumps(['@app.route("/login", methods=["POST"])']),
                  qualified_name="app.login"),
            _node("app.py:unsafe_query", "function", "unsafe_query", "app.py", "python",
                  13, 14, signature="def unsafe_query(sql):",
                  qualified_name="app.unsafe_query"),
            _node("app.py:DEBUG", "constant", "DEBUG", "app.py", "python", 4, 4,
                  signature="DEBUG = True", qualified_name="app.DEBUG"),
            _node("app.py:POST /login", "route", "POST /login", "app.py", "python", 5, 10,
                  qualified_name="app.py:POST /login"),
            _node("db.py:db.py", "file", "db.py", "db.py", "python", 1, 10),
            _node("db.py:DB_PATH", "constant", "DB_PATH", "db.py", "python", 3, 3,
                  signature='DB_PATH = "app.db"', qualified_name="db.DB_PATH"),
            _node("db.py:run_query", "function", "run_query", "db.py", "python", 6, 10,
                  signature="def run_query(sql):", qualified_name="db.run_query"),
            _node("worker.py:worker.py", "file", "worker.py", "worker.py", "python", 1, 13),
            _node("worker.py:export_queue", "variable", "export_queue", "worker.py",
                  "python", 5, 5, qualified_name="worker.export_queue"),
            _node("worker.py:enqueue_export", "function", "enqueue_export", "worker.py",
                  "python", 8, 9, signature="def enqueue_export(payload):",
                  qualified_name="worker.enqueue_export"),
            _node("worker.py:handle_export", "function", "handle_export", "worker.py",
                  "python", 12, 13, signature="def handle_export(job):",
                  qualified_name="worker.handle_export"),
            _node("server.ts:server.ts", "file", "server.ts", "server.ts", "typescript", 1, 7),
            _node("server.ts:MAX_ROWS", "constant", "MAX_ROWS", "server.ts", "typescript",
                  2, 2, signature="const MAX_ROWS = 100", qualified_name="server.MAX_ROWS"),
            _node("server.ts:handleExport", "function", "handleExport", "server.ts",
                  "typescript", 4, 7,
                  signature="function handleExport(req: Request, res: Response)",
                  is_exported=1, qualified_name="server.handleExport"),
            _node("Dashboard.tsx:Dashboard.tsx", "file", "Dashboard.tsx", "Dashboard.tsx",
                  "tsx", 1, 5),
            _node("Dashboard.tsx:Dashboard", "component", "Dashboard", "Dashboard.tsx",
                  "tsx", 3, 5, signature="function Dashboard(): JSX.Element",
                  is_exported=1, qualified_name="Dashboard"),
            # A route whose handler lives in an index-flagged generated file:
            # getRoutingManifest's hygiene filter must drop it.
            _node("generated/api_pb2.py:GET /index", "route", "GET /index",
                  "generated/api_pb2.py", "python", 4, 6,
                  qualified_name="api_pb2.GET /index"),
            _node("generated/api_pb2.py:index", "function", "index",
                  "generated/api_pb2.py", "python", 5, 6,
                  signature="def index():", qualified_name="api_pb2.index"),
        ]
        conn.executemany(_NODES_SQL, nodes)
        edges = [
            # containment: every file's symbols
            ("app.py:app.py", "app.py:login", "contains", None, 6, 1, "static"),
            ("app.py:app.py", "app.py:unsafe_query", "contains", None, 13, 1, "static"),
            ("app.py:app.py", "app.py:DEBUG", "contains", None, 4, 1, "static"),
            ("app.py:app.py", "app.py:POST /login", "contains", None, 5, 1, "static"),
            ("db.py:db.py", "db.py:DB_PATH", "contains", None, 3, 1, "static"),
            ("db.py:db.py", "db.py:run_query", "contains", None, 6, 1, "static"),
            ("worker.py:worker.py", "worker.py:export_queue", "contains", None, 5, 1, "static"),
            ("worker.py:worker.py", "worker.py:enqueue_export", "contains", None, 8, 1, "static"),
            ("worker.py:worker.py", "worker.py:handle_export", "contains", None, 12, 1, "static"),
            ("server.ts:server.ts", "server.ts:MAX_ROWS", "contains", None, 2, 1, "static"),
            ("server.ts:server.ts", "server.ts:handleExport", "contains", None, 4, 1, "static"),
            ("Dashboard.tsx:Dashboard.tsx", "Dashboard.tsx:Dashboard", "contains", None, 3, 1, "static"),
            # route -> handler: framework resolver, capped at 0.85
            ("app.py:POST /login", "app.py:login", "references",
             json.dumps({"confidence": 0.85, "resolvedBy": "framework"}), 5, 1, "static"),
            ("app.py:POST /login", "app.py:login", "decorates",
             json.dumps({"context": "decorator"}), 5, 1, "static"),
            # in-file call, 0.9
            ("app.py:login", "app.py:unsafe_query", "calls",
             json.dumps({"confidence": 0.9, "resolvedBy": "own-file"}), 10, 12, "static"),
            # cross-file call with import evidence, 0.95
            ("app.py:unsafe_query", "db.py:run_query", "calls",
             json.dumps({"confidence": 0.95, "resolvedBy": "import"}), 14, 12, "static"),
            # SYNTHESIZED: provenance heuristic, wiring site recorded separately
            ("worker.py:enqueue_export", "worker.py:handle_export", "calls",
             json.dumps({"synthesizedBy": "queue-job", "registeredAt": "queues.py:28",
                         "confidence": 0.85}), 9, 5, "heuristic"),
            # a route into a generated file: the manifest's hygiene filter
            # drops the row rather than showing the agent a stub handler
            ("generated/api_pb2.py:GET /index", "generated/api_pb2.py:index",
             "references", None, 4, 1, "static"),
        ]
        conn.executemany(_EDGES_SQL, edges)
        files = [
            ("app.py", "hash-app", "python", len(APP_PY), 1_700_000_000_000,
             1_700_000_000_000, 5, None, 0),
            ("db.py", "hash-db", "python", len(DB_PY), 1_700_000_000_000,
             1_700_000_000_000, 3, None, 0),
            ("worker.py", "hash-worker", "python", len(WORKER_PY), 1_700_000_000_000,
             1_700_000_000_000, 4, None, 0),
            ("server.ts", "hash-server", "typescript", len(SERVER_TS), 1_700_000_000_000,
             1_700_000_000_000, 3, None, 0),
            ("Dashboard.tsx", "hash-dashboard", "tsx", len(DASHBOARD_TSX),
             1_700_000_000_000, 1_700_000_000_000, 2, None, 0),
            # Index-flagged generated: no nodes, and never a handler.
            ("generated/api_pb2.py", "hash-pb", "python", 12, 1_700_000_000_000,
             1_700_000_000_000, 0, None, 1),
        ]
        conn.executemany(
            "INSERT INTO files (path, content_hash, language, size, modified_at, "
            "indexed_at, node_count, errors, generated) VALUES (?,?,?,?,?,?,?,?,?)",
            files,
        )
        refs = [
            ("app.py:login", "auth.verify_token", "call", 7, 12, None, "app.py",
             "python", "failed", "verify_token"),
            ("worker.py:handle_export", "unsafe_query", "call", 13, 11, None,
             "worker.py", "python", "pending", "unsafe_query"),
        ]
        conn.executemany(
            "INSERT INTO unresolved_refs (from_node_id, reference_name, reference_kind, "
            "line, col, candidates, file_path, language, status, name_tail) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            refs,
        )
        conn.commit()
    finally:
        conn.close()
    return db_path


@pytest.fixture
def mini(tmp_path, monkeypatch):
    """A seeded index plus TARGET_REPO pointed at it, with a clean conn cache."""
    db_path = build_mini_db(tmp_path)
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    close_cached()
    yield tmp_path, db_path
    close_cached()


# ---------------------------------------------------------------------------
# 1. missing DB degrades
# ---------------------------------------------------------------------------

def test_missing_db_degrades_everywhere(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    close_cached()
    assert _db.connect(str(empty)) is None
    state = _db.index_state(str(empty))
    assert state["available"] is False
    assert state["nodes"] == 0 and state["edges"] == 0
    assert state["refs_pending"] == 0 and state["mode"] == ""
    assert state["path"].endswith(".codegraph/codegraph.db")
    assert _db.guidance_no_db(str(empty)) == _db.GUIDANCE_NO_DB
    # Every helper degrades, none raises.
    assert _db.get_node(None, "app.py:login") is None
    assert _db.find_nodes(None, name="login") == []
    assert _db.get_edges(None, source="app.py:login") == []
    assert _db.node_children(None, "app.py:app.py") == []
    assert _db.node_parent(None, "app.py:login") is None
    assert _db.incoming_edges(None, "app.py:login") == []
    assert _db.unresolved_refs(None, node_id="app.py:login") == []
    assert _db.routing_manifest(None) == []
    assert _db.is_generated_file(None, "app.py") is False


def test_containment_escape_is_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    with pytest.raises(ValueError):
        _db.resolve_db_path("../../etc")
    # connect() swallows it into None, the shape a tool converts to an error.
    assert _db.connect("../../etc") is None
    monkeypatch.delenv("TARGET_REPO", raising=False)
    with pytest.raises(ValueError):
        _db.resolve_db_path("/etc/passwd")


# ---------------------------------------------------------------------------
# 2. seeded rows
# ---------------------------------------------------------------------------

def test_seeded_rows(mini):
    root, db_path = mini
    assert db_path.is_file()
    conn = _db.connect(str(root))
    assert conn is not None
    assert _db.last_open_mode in ("ro", "immutable")

    login = _db.get_node(conn, "app.py:login")
    assert login is not None
    assert login["kind"] == "function"
    assert login["name"] == "login"
    assert login["file_path"] == "app.py"
    assert login["language"] == "python"
    assert (login["start_line"], login["end_line"]) == (6, 10)
    assert login["signature"] == "def login(username, password):"
    # JSON column decoded, not a string.
    assert login["decorators"] == ['@app.route("/login", methods=["POST"])']
    assert _db.get_node(conn, "nope") is None

    by_name = _db.find_nodes(conn, name="login")
    assert [n["id"] for n in by_name] == ["app.py:login"]
    by_kind = _db.find_nodes(conn, kind="route")
    assert [n["name"] for n in by_kind] == ["POST /login", "GET /index"]
    by_like = _db.find_nodes(conn, name_like="%query%")
    assert {n["id"] for n in by_like} == {"app.py:unsafe_query", "db.py:run_query"}
    assert _db.find_nodes(conn, kind="function", file_path="db.py")[0]["name"] == "run_query"
    assert all(n["language"] == "python" for n in _db.find_nodes(conn, language="python"))

    # containment
    assert [n["id"] for n in _db.node_children(conn, "app.py:app.py")] == [
        "app.py:DEBUG", "app.py:POST /login", "app.py:login", "app.py:unsafe_query"]
    assert _db.node_children(conn, "app.py:app.py", kinds=["function"]) == [
        _db.get_node(conn, "app.py:login"), _db.get_node(conn, "app.py:unsafe_query")]
    assert _db.node_parent(conn, "app.py:login")["id"] == "app.py:app.py"
    assert _db.node_parent(conn, "app.py:app.py") is None

    # edges: decoded metadata, stable identity tuple, provenance
    call = _db.get_edges(conn, source="app.py:unsafe_query", target="db.py:run_query",
                         kind="calls")
    assert len(call) == 1
    assert call[0]["metadata"] == {"confidence": 0.95, "resolvedBy": "import"}
    assert call[0]["provenance"] == "static"
    assert (call[0]["source"], call[0]["target"], call[0]["kind"],
            call[0]["line"], call[0]["col"]) == (
        "app.py:unsafe_query", "db.py:run_query", "calls", 14, 12)

    heuristic = _db.get_edges(conn, provenance="heuristic")
    assert len(heuristic) == 1
    assert heuristic[0]["metadata"]["synthesizedBy"] == "queue-job"
    assert heuristic[0]["metadata"]["registeredAt"] == "queues.py:28"
    assert heuristic[0]["metadata"]["confidence"] == 0.85

    incoming = _db.incoming_edges(conn, "db.py:run_query", kinds=["calls"])
    assert [e["source"] for e in incoming] == ["app.py:unsafe_query"]
    outgoing = _db.get_edges(conn, source="app.py:unsafe_query", kind="calls")
    assert outgoing[0]["target"] == "db.py:run_query"
    # a kind filter is a filter, not a hardcoded list
    assert _db.incoming_edges(conn, "db.py:run_query", kinds=["imports"]) == []

    decorates = _db.get_edges(conn, source="app.py:POST /login", kind="decorates")
    assert len(decorates) == 1 and decorates[0]["target"] == "app.py:login"

    # routing manifest: exact queries.ts join, decorators + generated hygiene
    manifest = _db.routing_manifest(conn)
    # the generated-file handler is filtered out by the hygiene rule
    assert len(manifest) == 1
    row = manifest[0]
    assert row["url"] == "POST /login"
    assert row["route_id"] == "app.py:POST /login"
    assert row["route_file"] == "app.py"
    assert row["route_line"] == 5
    assert row["handler"] == "login"
    assert row["handler_file"] == "app.py"
    assert row["handler_line"] == 6
    assert row["handler_kind"] == "function"
    assert _db.routing_manifest(conn, limit=0) == manifest  # <=0 means unlimited

    # unresolved refs: "an edge may be missing here"
    refs = _db.unresolved_refs(conn, node_id="app.py:login")
    assert len(refs) == 1
    assert refs[0]["reference_name"] == "auth.verify_token"
    assert refs[0]["reference_kind"] == "call"
    assert refs[0]["name_tail"] == "verify_token"
    assert refs[0]["status"] == "failed"
    assert refs[0]["file_path"] == "app.py"
    assert refs[0]["line"] == 7 and refs[0]["col"] == 12
    assert _db.unresolved_refs(conn, status="pending")[0][
        "reference_name"] == "unsafe_query"
    assert _db.unresolved_refs(conn, file_path="db.py") == []

    assert _db.is_generated_file(conn, "generated/api_pb2.py") is True
    assert _db.is_generated_file(conn, "app.py") is False
    assert _db.is_generated_file(conn, "never/indexed.py") is False


def test_index_state_and_caching(mini, monkeypatch):
    root, db_path = mini
    state = _db.index_state(str(root))
    assert state["available"] is True
    assert state["nodes"] == 19
    assert state["edges"] == 18
    assert state["unresolved_refs"] == 1
    assert state["refs_pending"] == 1
    assert state["mode"] in ("ro", "immutable")
    # Same connection object while the file is untouched, a fresh one after a
    # re-index (mtime bump) — the index-cache staleness rule.
    first = _db.connect(str(root))
    assert _db.connect(str(root)) is first
    os.utime(db_path, (1_800_000_000, 1_800_000_000))
    assert _db.connect(str(root)) is not first


def test_spans_match_the_seeded_source(mini):
    """The fixture is only useful if the graph agrees with the files on disk."""
    root, _db_path = mini
    conn = _db.connect(str(root))
    app_lines = (root / "app.py").read_text().splitlines()
    for node in _db.find_nodes(conn, file_path="app.py", limit=0):
        if node["kind"] == "file":
            continue  # a file node spans the whole file
        first = app_lines[node["start_line"] - 1].strip()
        if node["kind"] == "route":
            # a route node sits on the decorator that registers it
            assert node["name"] == "POST /login" and "/login" in first
            continue
        assert node["name"] in first, (
            f"{node['id']} at {node['start_line']}: {first!r}")
    assert "def login(" in app_lines[5]
    assert app_lines[3] == "DEBUG = True"
    assert '@app.route("/login", methods=["POST"])' in app_lines[4]
    assert "def unsafe_query(sql):" in app_lines[12]
    db_lines = (root / "db.py").read_text().splitlines()
    assert "def run_query(sql):" in db_lines[_db.get_node(conn, "db.py:run_query")["start_line"] - 1]


# ---------------------------------------------------------------------------
# 4. tree-sitter
# ---------------------------------------------------------------------------

def test_ts_parse_and_spans():
    tree = _ts.parse_source(APP_PY, "python")
    assert tree is not None and tree.root_node.type == "module"
    assert _ts.parser_for_file("x.py") is _ts.parser_for_language("python")
    assert _ts.parser_for_file("x.txt") is None
    assert _ts.parser_for_language("csharp") is _ts.parser_for_language("c_sharp")
    assert _ts.parser_for_language("tsx") is not None
    assert _ts.parser_for_language("brainfuck") is None

    src = APP_PY.encode()
    for line, expected in ((6, "login"), (7, "login"), (9, "login"), (13, "unsafe_query"),
                           (14, "unsafe_query"), (4, None)):
        node = _ts.enclosing_function(tree, line)
        if expected is None:
            assert node is None
        else:
            assert node is not None
            text = _ts.node_text(node, src)
            assert text.startswith(f"def {expected}("), (line, text[:40])
    assert _ts.enclosing_function(tree, 99) is None
    assert _ts.enclosing_node(tree, 7).type == "function_definition"

    calls = _ts.calls_in_span(tree, 6, 10, src)
    assert [(c["line"], c["text"]) for c in calls] == [(7, "auth.verify_token"),
                                                       (10, "unsafe_query")]
    assert all(c["col"] > 0 and c["node"] is not None for c in calls)
    assert _ts.calls_in_span(tree, 99, 120, src) == []
    assert _ts.calls_in_span(None, 1, 2, src) == []
    ts_calls = _ts.calls_in_span(_ts.parse_source(SERVER_TS, "typescript"), 1, 7,
                                 SERVER_TS.encode())
    assert ("db.query", 5) in [(c["text"], c["line"]) for c in ts_calls]

    assert _ts.line_text(APP_PY.encode(), 6).startswith("def login(")
    assert _ts.line_text(APP_PY.encode(), 999) == ""
    assert _ts.line_text(APP_PY.encode(), 0) == ""


def test_ts_parse_file_roundtrip(mini):
    root, _db_path = mini
    parsed = _ts.parse_file(root / "app.py")
    assert parsed is not None
    tree, src = parsed
    assert src == APP_PY.encode()
    assert _ts.node_text(_ts.enclosing_function(tree, 7), src).startswith("def login")
    # The CodeGraph cap: a file above 1 MB yields no symbols, so no parse.
    big = root / "big.py"
    big.write_bytes(b"x = 1\n" * 400_000)
    assert big.stat().st_size > _ts.MAX_FILE_BYTES
    assert _ts.parse_file(big) is None
    assert _ts.parse_file(root / "missing.py") is None
    assert _ts.parse_file(root / "schema.txt") is None
    tsx = _ts.parse_file(root / "Dashboard.tsx")
    assert tsx is not None and tsx[0].root_node is not None


def test_parse_signature_params():
    py = _ts.parse_signature_params("def login(username, password):", "python")
    assert py == [{"name": "username", "type": "", "default": "", "index": 0},
                  {"name": "password", "type": "", "default": "", "index": 1}]
    typed = _ts.parse_signature_params("def f(a: int, b: str = 'x') -> bool", "python")
    assert typed[0] == {"name": "a", "type": "int", "default": "", "index": 0}
    assert typed[1] == {"name": "b", "type": "str", "default": "'x'", "index": 1}
    ts = _ts.parse_signature_params(
        "async handle(req: Request, res: Response)", "typescript")
    assert [p["name"] for p in ts] == ["req", "res"]
    assert [p["type"] for p in ts] == ["Request", "Response"]
    js = _ts.parse_signature_params("function handleExport(req: Request, res: Response)", "tsx")
    assert [p["name"] for p in js] == ["req", "res"]
    jvm = _ts.parse_signature_params("public void save(Owner owner, String note)", "java")
    assert [(p["type"], p["name"]) for p in jvm] == [("Owner", "owner"), ("String", "note")]
    # never raises, and unparsable means "no parameters", not a crash
    assert _ts.parse_signature_params("", "python") == []
    assert _ts.parse_signature_params(None, "python") == []
    assert _ts.parse_signature_params("no parens at all", "python") == []


def test_window():
    numbered = _ts.window(APP_PY, 7, 2)
    assert numbered.splitlines() == [
        "5: @app.route(\"/login\", methods=[\"POST\"])",
        "6: def login(username, password):",
        "7:     user = auth.verify_token(username)",
        "8:     if user is None:",
        "9:         return \"denied\"",
    ]
    assert _ts.window(APP_PY.encode(), 14, 1).splitlines() == [
        "13: def unsafe_query(sql):", "14:     return db.run_query(sql)"]
    assert _ts.window(APP_PY, 999) == ""
    assert _ts.window(APP_PY, 0) == ""
    assert _ts.window(APP_PY, 7, 0) == "7:     user = auth.verify_token(username)"


# ---------------------------------------------------------------------------
# 5. sinks
# ---------------------------------------------------------------------------

def test_sinks_categories():
    known = [
        ("child_process.exec", "javascript", "process"),
        ("fetch", "javascript", "network"),
        ("axios.get", "javascript", "network"),
        ("cursor.execute", "python", "database"),
        ("subprocess.run", "python", "process"),
        ("requests.get", "python", "network"),
        ("jwt.sign", "javascript", "auth"),
        ("queue.add", "javascript", "queue"),
    ]
    for text, language, category in known:
        assert sinks.classify_call(text, language) == [category], (text, language)
    # the whole member chain, not the last segment
    assert sinks.classify_call("res.status(404).json", "javascript") == ["response"]
    assert sinks.classify_call("this.jwtService.signAsync", "typescript") == ["auth"]
    assert sinks.classify_call("prisma.article.findFirst", "typescript") == ["database"]
    # normaliseCall: leading await/new dropped, ?. and !. folded to .
    assert sinks.classify_call("await axios.post", "typescript") == ["network"]
    # normaliseCall keeps the argument list; the rule pass strips it later.
    assert sinks.normalise_call("await new  Foo.bar()") == "Foo.bar()"
    assert sinks.normalise_call("a?.b!.c") == "a.b.c"
    assert sinks.normalise_call("  return   await  x.y.z()") == "x.y.z()"
    # a plain library call is not an effect
    assert sinks.classify_call("Math.max", "javascript") == []
    assert sinks.classify_call("len", "python") == []
    assert sinks.classify_call("", "python") == []


def test_sinks_family_gating():
    # A py-only rule does not fire for javascript.
    assert sinks.classify_call("subprocess.run", "python") == ["process"]
    assert sinks.classify_call("subprocess.run", "javascript") == []
    assert sinks.classify_call("cursor.execute", "python") == ["database"]
    assert sinks.classify_call("cursor.execute", "javascript") == []
    # session.get is the ORM in Python and a request in the browser.
    assert sinks.classify_call("session.get", "python") == ["database"]
    assert sinks.classify_call("session.get", "javascript") == []
    # open( is a file in Python and nothing in TypeScript.
    assert sinks.classify_call("open", "python") == ["storage"]
    assert sinks.classify_call("open", "javascript") == []
    # An ungated rule applies everywhere.
    assert sinks.classify_call("redis.get", "python") == ["cache"]
    assert sinks.classify_call("redis.get", "javascript") == ["cache"]
    # An ungated language still gets the JS rows (the TS table's own rule).
    assert sinks.classify_call("fetch", None) == ["network"]
    assert sinks.classify_call("subprocess.run", None) == []


def test_sinks_table_shape():
    assert len(sinks.EFFECT_RULES) > 70
    for rule in sinks.EFFECT_RULES:
        assert set(rule) == {"category", "pattern", "only", "instantiates"}
        assert isinstance(rule["pattern"], type(sinks.EFFECT_RULES[0]["pattern"]))
        assert rule["pattern"].pattern  # compiled and carries its source
        assert rule["only"] is None or isinstance(rule["only"], frozenset)
        assert isinstance(rule["instantiates"], bool)
        assert rule["category"] in {
            "network", "storage", "device", "telemetry", "database", "response",
            "queue", "email", "payments", "cache", "auth", "process"}
    # only the gated rules carry a family; first-match-wins order is preserved
    assert sinks.EFFECT_RULES[0]["category"] == "response"
    assert sinks.EFFECT_RULES[0]["only"] == frozenset({"js"})
    assert any(r["instantiates"] for r in sinks.EFFECT_RULES)
    assert set(sinks.FAMILIES) == {"js", "py", "jvm", "cs", "go", "c", "rb", "php",
                                   "swift", "rs"}
    assert sinks.FAMILIES["js"] == frozenset({"javascript", "typescript", "tsx", "jsx"})
    assert sinks.FAMILIES["cs"] == frozenset({"csharp"})
    assert sinks.classify_call("stripe.charges.create", "typescript") == ["payments"]
    assert sinks.classify_call("Sentry.captureException", "python") == ["telemetry"]
    assert sinks.classify_call("sh.rm", "python") == ["process"]
    assert sinks.classify_call("Timer.scheduledTimer", "swift") == []
    # receiver-declared type: `OwnerRepository owners` makes owners.save a DB write
    detail = sinks.classify_effect("owners.save", "java", "calls", "OwnerRepository")
    assert detail == {"category": "database", "model": "Owner", "access": "write"}


# Pinned against the expectations asserted by
# codegraph/__tests__/ui-effects.test.ts — the authoritative suite for this
# table. If a ported regex drifts, this fails before a downstream tool ships a
# sink list that quietly misses. (text, language, kind, expected category or None)
TS_SUITE = [
    ("client.post", "javascript", "calls", "network"),
    ("fetch", "tsx", "calls", "network"),
    ("AsyncStorage.setItem", "tsx", "calls", "storage"),
    ("Linking.openURL", "tsx", "calls", "device"),
    ("DdRum.addAction", "tsx", "calls", "telemetry"),
    ("Math.max", "tsx", "calls", None),
    ("i18n.t", "tsx", "calls", None),
    ("Object.create", "typescript", "calls", None),
    ("prisma.article.findFirst", "typescript", "calls", "database"),
    ("this.prisma.user.create", "typescript", "calls", "database"),
    ("this.usersRepository.save", "typescript", "calls", "database"),
    ("this.catModel.find", "typescript", "calls", "database"),
    ("db.insert", "typescript", "calls", "database"),
    ("User.findOne", "typescript", "calls", "database"),
    ("Promise.all", "typescript", "calls", None),
    ("res.status(404).json", "typescript", "calls", "response"),
    ("reply.code(201).send", "typescript", "calls", "response"),
    ("NotFoundException", "typescript", "instantiates", "response"),
    ("Error", "typescript", "instantiates", None),
    ("this.emailQueue.add", "typescript", "calls", "queue"),
    ("this.mailerService.sendMail", "typescript", "calls", "email"),
    ("stripe.checkout.sessions.create", "typescript", "calls", "payments"),
    ("this.cacheManager.get", "typescript", "calls", "cache"),
    ("this.jwtService.signAsync", "typescript", "calls", "auth"),
    ("crypto.createHmac", "typescript", "calls", "auth"),
    ("crypto.createHash", "typescript", "calls", None),
    ("s3.putObject", "typescript", "calls", "storage"),
    ("spawn", "typescript", "calls", "process"),
    ("process.exit", "typescript", "calls", "process"),
    ("session.exec", "python", "calls", "database"),
    ("session.add", "python", "calls", "database"),
    ("User.objects.filter", "python", "calls", "database"),
    ("HTTPException", "python", "calls", "response"),
    ("jsonify", "python", "calls", "response"),
    ("send_email.delay", "python", "calls", "queue"),
    ("send_mail", "python", "calls", "email"),
    ("httpx.AsyncClient", "python", "calls", "network"),
    ("open", "python", "calls", "storage"),
    ("subprocess.run", "python", "calls", "process"),
    ("jwt.encode", "python", "calls", "auth"),
    ("pwd_context.verify", "python", "calls", "auth"),
    ("print", "python", "calls", None),
    ("item.model_dump", "python", "calls", None),
    ("this.ownerRepository.findAll", "java", "calls", "database"),
    ("jdbcTemplate.update", "java", "calls", "database"),
    ("ResponseEntity.status(HttpStatus.NOT_FOUND).body", "java", "calls", "response"),
    ("ResourceNotFoundException", "java", "instantiates", "response"),
    ("IllegalArgumentException", "java", "instantiates", None),
    ("rabbitTemplate.convertAndSend", "java", "calls", "queue"),
    ("mailSender.send", "java", "calls", "email"),
    ("restTemplate.getForObject", "java", "calls", "network"),
    ("passwordEncoder.encode", "java", "calls", "auth"),
    ("Files.write", "java", "calls", "storage"),
    ("viewModelScope.launch", "kotlin", "calls", None),
    ("model.addAttribute", "java", "calls", None),
    ("sharedPreferences.edit", "kotlin", "calls", "storage"),
    ("workManager.enqueueUniqueWork", "kotlin", "calls", "queue"),
    ("_context.TodoItems.Add", "csharp", "calls", "database"),
    ("TypedResults.NoContent", "csharp", "calls", "response"),
    ("_bus.Publish", "csharp", "calls", "queue"),
    ("_httpClient.GetAsync", "csharp", "calls", "network"),
    ("_userManager.CreateAsync", "csharp", "calls", "auth"),
    ("File.ReadAllText", "csharp", "calls", "storage"),
    ("sender.Send", "csharp", "calls", None),
    ("db.QueryRow", "go", "calls", "database"),
    ("c.JSON", "go", "calls", "response"),
    ("http.Get", "go", "calls", "network"),
    ("os.ReadFile", "go", "calls", "storage"),
    ("exec.Command", "go", "calls", "process"),
    ("jwt.NewWithClaims", "go", "calls", "auth"),
    ("fmt.Sprintf", "go", "calls", None),
    ("fopen", "c", "calls", "storage"),
    ("curl_easy_perform", "c", "calls", "network"),
    ("pthread_create", "c", "calls", "process"),
    ("strlen", "c", "calls", None),
    ("Abort", "swift", "calls", "response"),
    ("todo.save", "swift", "calls", "database"),
    ("URLSession.shared.dataTask", "swift", "calls", "network"),
    ("render", "ruby", "calls", "response"),
    ("User.find_by", "ruby", "calls", "database"),
    ("UserMailer.welcome", "ruby", "calls", "email"),
    ("HardJob.perform_later", "ruby", "calls", "queue"),
    ("User::find", "php", "calls", "database"),
    ("Mail::to", "php", "calls", "email"),
    ("abort", "php", "calls", "response"),
    ("foo.bar", "ruby", "calls", None),
    ("save", "python", "calls", None),
    ("render", "java", "calls", None),
]


def test_sinks_matches_the_typescript_suite():
    # The TS suite calls every case through a helper pinned to project='api':
    # only then does a thrown web exception count as a response.
    failures = []
    for text, language, kind, expected in TS_SUITE:
        got = sinks.classify_effect(text, language, kind, None, "api")
        category = got["category"] if got else None
        if category != expected:
            failures.append(f"{text!r} ({language}, {kind}): {category!r} != {expected!r}")
    assert not failures, "\n".join(failures)



# ---------------------------------------------------------------------------
# 7. hostile input degrades — the audit regressions
# ---------------------------------------------------------------------------

# One path component past NAME_MAX (255 on APFS/ext4), and one past any
# filesystem's patience at all. Both used to raise OSError out of connect().
LONG_COMPONENT = "a" * 300
HUGE_COMPONENT = "b" * 200_000

# A lone surrogate: legal in a Python str, unbindable as SQLite text — the
# exact hostile id the audit bound into every helper.
SURROGATE = "app.py:log\ud800in"


@pytest.mark.parametrize("component", [
    pytest.param(LONG_COMPONENT, id="300-byte-component"),
    pytest.param(HUGE_COMPONENT, id="200000-byte-component"),
])
def test_connect_degrades_on_a_hostile_root(tmp_path, monkeypatch, component):
    """A root the OS cannot address is "DB not available", never an exception."""
    root = str(tmp_path / component)
    monkeypatch.setenv("TARGET_REPO", root)
    close_cached()
    # Both the absolute root and the relative form, which walk the same stats.
    for form in (root, "."):
        assert _db.connect(form) is None, form
        state = _db.index_state(form)
        assert state["available"] is False, form
        assert state["mode"] == "", form
        assert state["nodes"] == 0 and state["edges"] == 0
        assert state["unresolved_refs"] == 0 and state["refs_pending"] == 0
        assert _db.guidance_no_db(form) == _db.GUIDANCE_NO_DB, form
    # the absolute root cannot even be resolved, so it reports no path at all
    assert _db.index_state(root)["path"] == ""


def test_connect_degrades_on_a_nul_byte_root(tmp_path, monkeypatch):
    """A NUL in the root is unreachable at the OS layer — still not a crash."""
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    close_cached()
    for root in ("a\x00b", "/a\x00b", "a\x00b/.codegraph/codegraph.db"):
        assert _db.connect(root) is None, repr(root)
        state = _db.index_state(root)
        assert state["available"] is False, repr(root)
        assert state["path"] == "" and state["mode"] == ""
        assert _db.guidance_no_db(root) == _db.GUIDANCE_NO_DB


def test_lone_surrogates_bind_safely(mini):
    """Every helper that binds agent-controlled text degrades instead of raising.

    SQLite binds text as UTF-8, so a lone surrogate raised ``UnicodeEncodeError``
    from inside ``conn.execute``. The sanitising param keeps the query runnable,
    and a hostile id then matches nothing — the correct answer for an id that
    cannot exist in the index.
    """
    root, _db_path = mini
    conn = _db.connect(str(root))
    assert conn is not None

    assert _db.get_node(conn, SURROGATE) is None
    assert _db.get_node(conn, "\ud800") is None

    for rows in (_db.find_nodes(conn, name=SURROGATE),
                 _db.find_nodes(conn, name_like=SURROGATE),
                 _db.find_nodes(conn, file_path=SURROGATE),
                 _db.find_nodes(conn, language=SURROGATE),
                 _db.find_nodes(conn, kind=SURROGATE),
                 _db.get_edges(conn, source=SURROGATE),
                 _db.get_edges(conn, target=SURROGATE),
                 _db.get_edges(conn, kind=SURROGATE),
                 _db.get_edges(conn, provenance=SURROGATE),
                 _db.node_children(conn, SURROGATE),
                 _db.node_children(conn, "app.py:app.py", kinds=[SURROGATE]),
                 _db.incoming_edges(conn, SURROGATE),
                 _db.incoming_edges(conn, "db.py:run_query", kinds=[SURROGATE]),
                 _db.unresolved_refs(conn, node_id=SURROGATE),
                 _db.unresolved_refs(conn, file_path=SURROGATE),
                 _db.unresolved_refs(conn, status=SURROGATE)):
        assert rows == [], rows

    assert _db.node_parent(conn, SURROGATE) is None
    assert _db.is_generated_file(conn, SURROGATE) is False

    # ... and the pinned read-only handle is untouched by any of that: the
    # mtime-keyed cache, the mode=ro URI and PRAGMA query_only all still refuse
    # a write through the same cached connection.
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("INSERT INTO nodes (id, kind) VALUES ('x', 'function')")
    assert (_db.get_node(conn, "app.py:login") or {}).get("name") == "login"


def test_resolve_db_path_reports_containment_and_os_failures_alike(
        tmp_path, monkeypatch):
    """The ValueError contract the tool modules catch is preserved exactly."""
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    with pytest.raises(ValueError) as escape:
        _db.resolve_db_path("../../etc")
    assert "path escapes repo" in str(escape.value)
    monkeypatch.delenv("TARGET_REPO", raising=False)
    with pytest.raises(ValueError):
        _db.resolve_db_path("/etc/passwd")
    # An OS refusal keeps that same convertible shape rather than an OSError no
    # tool caller knows how to handle.
    hostile_root = str(tmp_path / LONG_COMPONENT)
    monkeypatch.setenv("TARGET_REPO", hostile_root)
    with pytest.raises(ValueError) as hostile:
        _db.resolve_db_path(hostile_root)
    assert "cannot resolve codegraph index path" in str(hostile.value)
    # The relative form does not stat, so it resolves — the refusal lands one
    # step later in connect(), which is what the hostile-root test pins.
    assert _db.connect(".") is None
    assert _db.index_state(".")["available"] is False


def test_guard_condition_fallback_does_not_require_cap():
    """Regression: a node with none of condition/value/subject returns its first
    line instead of raising ``TypeError`` for the missing ``_truncate_line`` cap.
    Swift ``switch_statement`` is the product path that hits this fallback."""
    from cerberus.codegraph import _common

    src = b"switch value {\ncase .a: break\n}\n"

    class _Node:
        type = "switch_statement"
        start_byte = 0
        end_byte = len(src)

        def child_by_field_name(self, _name):
            return None

    assert _common._guard_condition(_Node(), src) == "switch value {"

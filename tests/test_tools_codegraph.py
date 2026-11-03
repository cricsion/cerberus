"""P2 binding tests for ``cerberus.tools.codegraph`` — the code-intelligence surface.

This module pins the *binding* layer (plan §7 P2, §4 D3/D4), not the tools'
internals (those live in ``test_codegraph_*.py``). Three contracts:

1. **``_db``-first paths** — on a live-built tiny index (the real ``codegraph``
   CLI, 1.6.2, in a scratch ``tmp_path``) ``callers``/``callees``/
   ``framework_routes``/``affected`` answer from the graph, and a bound
   ``cerberus.codegraph`` tool (``get_ast_slice``/``resolve_blind_spot``) reads it
   too. The live fixtures are authored here and nowhere near an original repo.
2. **The grep fallback contract** — with no index, and with the DB-visible half
   of the build gate failing (a ``pending`` ``unresolved_refs`` row), the same
   tools fall back to the deterministic grep implementation in the *same output
   format* (``## def``/``## calls`` markers, ``path:line:`` prefixes, the
   ``(no matches)`` sentinel); a symbol the index does not know about falls back
   even when the gate is open.
3. **Output-format pins for routes** — the ``_db`` route line and the grep
   decorator line are distinct, and only the former matches the module-local
   :data:`ROUTE_LINE_RE`.

P1.5 schema corrections these tests rely on (verified against live 1.6.2): entity
node ids are TEXT ``kind:<md5>`` while ``file``/``route`` nodes use path-shaped
ids; line columns are ``start_line``/``end_line``; ``edges.provenance`` is NULL
everywhere with resolution in ``edges.metadata``; ``unresolved_refs`` rows are all
``status='failed'`` (so ``index.pendingRefs`` and ``unresolved_refs`` are
unrelated counts — the gate uses the DB-visible ``pending`` proxy).

The live tests ``skipif`` when no CLI is on the host; nothing here touches the
network, the LLM, or a checked-in fixture.
"""
from __future__ import annotations

import ast
import json
import os
import re
import sqlite3
import subprocess
from pathlib import Path

import pytest
from cerberus.codegraph import _db
from cerberus.tools import codegraph as cg
from codegraph_support import _insert_rows, close_cached, live_cli
from test_codegraph_foundation import _node, mini

_DB_REL = ".codegraph/codegraph.db"
_GUIDANCE = _db.GUIDANCE_NO_DB

# The pinned route line, emitted by the ``_db``-first framework_routes path:
#     <route_file>:<route_line>: [route] <url> -> <handler> (<handler_file>:<handler_line>)
ROUTE_LINE_RE = re.compile(
    r"^(?P<route_file>.+?):(?P<route_line>\d+): \[route\] "
    r"(?P<url>.+?) -> (?P<handler>\S+) "
    r"\((?P<handler_file>.+?):(?P<handler_line>\d+)\)$"
)


# ---------------------------------------------------------------------------
# live fixture: author a tiny repo and build a real index
# ---------------------------------------------------------------------------

# Line anchors the assertions below depend on (see _LIVE_APP): the route
# decorator is line 6, its handler `login` line 7, the `verify` call line 8, the
# `verify` definition line 11; `run_query` lives at pkg/util.py:3.
_LIVE_APP = '''\
from flask import Flask, request
from pkg.util import run_query

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login(username, password):
    user = verify(username)
    return run_query("SELECT * FROM users WHERE n = '%s'" % username)

def verify(u):
    return u
'''

_LIVE_UTIL = '''\
import sqlite3

def run_query(sql):
    conn = sqlite3.connect("app.db")
    return conn.execute(sql).fetchall()
'''

_LIVE_FILES = {"app.py": _LIVE_APP, "pkg/util.py": _LIVE_UTIL}


def _write_files(root: Path, files: dict[str, str]) -> None:
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)


def _cli(args: list[str], root: Path, timeout: int = 300) -> subprocess.CompletedProcess:
    """Run the CLI with the D9 hygiene env pinned on every call."""
    env = dict(os.environ)
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "CODEGRAPH_NO_DAEMON": "1",
        "CODEGRAPH_TELEMETRY": "0",
        "CODEGRAPH_NO_UPDATE_CHECK": "1",
        "DO_NOT_TRACK": "1",
    })
    return subprocess.run([live_cli(), *args], cwd=str(root), capture_output=True,
                          text=True, timeout=timeout, env=env)


def _build_live_index(root: Path) -> dict:
    """``init -y`` -> ``index -q`` -> ``status -j``; the gate payload back."""
    _cli(["init", "-y", str(root)], root)
    _cli(["index", "-q", str(root)], root)
    payload = json.loads(_cli(["status", "-j", str(root)], root).stdout)
    assert payload["index"]["state"] == "complete", payload
    assert payload["index"]["pendingRefs"] == 0, payload
    return payload


@pytest.fixture(scope="module")
def live_root(tmp_path_factory) -> Path:
    """A tiny repo with a real 1.6.2 index (built once for the module)."""
    root = tmp_path_factory.mktemp("cg_p2_live")
    _write_files(root, _LIVE_FILES)
    _build_live_index(root)
    return root


@pytest.fixture
def live(live_root, monkeypatch) -> Path:
    """The live root, with TARGET_REPO pointed at it and a clean conn cache."""
    monkeypatch.setenv("TARGET_REPO", str(live_root))
    close_cached()
    yield live_root
    close_cached()


def _live_node_id(root: Path, name: str) -> str:
    """The index's own node id for a symbol (md5 ids are not portable)."""
    handle = sqlite3.connect(str(root / _DB_REL))
    try:
        row = handle.execute(
            "SELECT id FROM nodes WHERE name = ? ORDER BY kind, id LIMIT 1",
            (name,)).fetchone()
    finally:
        handle.close()
    assert row, f"no node named {name!r} in the live index"
    return row[0]


# ---------------------------------------------------------------------------
# 1. live _db-first paths
# ---------------------------------------------------------------------------

def test_live_callers_answers_from_the_index(live):
    out = cg.callers.func("verify", root=str(live))
    assert out.startswith("## def")
    assert "app.py:11: def verify(u):" in out        # the def, span-matched
    assert "## calls" in out
    assert re.search(r"^app\.py:8: ", out, re.M)     # the call site line
    assert "    user = verify(username)" in out      # raw source, index line


def test_live_callers_def_only_when_no_call_edge(live):
    # Nothing CALLS `login` (the route reaches it via a `references` edge), so
    # the index path emits a `## def` block and no `## calls` block. The grep
    # fallback would add a spurious `## calls` row (it matches `login(` in the
    # def line), which is exactly the difference this pins.
    out = cg.callers.func("login", root=str(live))
    assert out.startswith("## def")
    assert "app.py:7: def login(username, password):" in out
    assert "## calls" not in out


def test_live_callees_labels_by_definition_file(live):
    out = cg.callees.func("login", root=str(live))
    assert "app.py:verify()" in out
    # The index path labels the callee by ITS file; the grep path labels both
    # by the DEFINITION's file (app.py:run_query()) — so this line is db-only.
    assert "pkg/util.py:run_query()" in out
    assert "app.py:run_query()" not in out


def test_live_framework_routes_uses_route_nodes(live):
    out = cg.framework_routes.func(root=str(live))
    first = out.splitlines()[0]
    match = ROUTE_LINE_RE.match(first)
    assert match, first
    assert match.group("route_file") == "app.py"
    assert match.group("route_line") == "6"
    assert match.group("url") == "POST /login"
    assert match.group("handler") == "login"
    assert match.group("handler_file") == "app.py"
    assert match.group("handler_line") == "7"
    # The regex fallback's raw decorator text never appears on the index path.
    assert "@app.route" not in out


def test_live_affected_follows_get_impact_radius(live):
    out = cg.affected.func("run_query", root=str(live))
    assert out.startswith("Affected nodes for run_query (depth<=3,")
    assert "seeds: pkg/util.py:3" in out
    # A reached container (the importing FILE) walks down into its children.
    assert re.search(
        r"^- login \[function\] app\.py:7 \(hop 1, contains, confidence 1\.00\)$",
        out, re.M)
    # ... and the route that references the handler is reached at the next hop,
    # with the persisted edge confidence.
    assert re.search(
        r"^- POST /login \[route\] app\.py:6 \(hop 2, references, confidence 0\.90\)$",
        out, re.M)


def test_live_bound_navigation_tool_reads_the_index(live):
    node_id = _live_node_id(live, "run_query")
    out = cg.get_ast_slice.func(node_id, root=str(live))
    assert out.startswith("# pkg/util.py:3-5 (function run_query)")
    assert "3: def run_query(sql):" in out


def test_live_blind_spot_reads_unresolved_refs(live):
    node_id = _live_node_id(live, "login")
    out = cg.resolve_blind_spot.func(node_id, root=str(live))
    assert out.startswith("# blind spot recovery:")
    assert "unresolved reference(s)" in out
    assert "status: failed" in out


def test_live_gate_opens_and_schema_1_6_2_shapes_hold(live):
    conn, ok = cg._index_gate(str(live))
    assert ok is True and conn is not None

    state = _db.index_state(str(live))
    assert state["available"] is True
    assert state["refs_pending"] == 0          # the DB-visible gate proxy
    assert state["unresolved_refs"] >= 1       # ... while failed markers remain

    # P1.5: every unresolved_refs row is 'failed' on a real build, so the
    # pending proxy and the failed marker can never be the same count.
    refs = _db.unresolved_refs(conn, limit=0)
    assert refs and all(r["status"] == "failed" for r in refs)

    # The schema facts below are third-party CLI 1.6.2's, not this repo's
    # contract: on a newer CLI they may drift for reasons outside the gate.
    version = subprocess.run([live_cli(), "--version"], capture_output=True,
                             text=True, timeout=60).stdout.strip()
    if version != "1.6.2":
        pytest.skip(f"schema shape pinned for codegraph 1.6.2 (host: {version!r})")

    # P1.5: edges.provenance is NULL everywhere (resolution lives in metadata).
    handle = sqlite3.connect(str(live / _DB_REL))
    try:
        provenance = {row[0] for row in handle.execute("SELECT provenance FROM edges")}
        assert provenance == {None}
    finally:
        handle.close()

    # P1.5: entity node ids are TEXT `kind:<md5>`.
    assert re.match(r"^function:[0-9a-f]{32}$", _live_node_id(live, "run_query"))


# ---------------------------------------------------------------------------
# 2. grep fallback contract
# ---------------------------------------------------------------------------

@pytest.fixture
def unindexed(tmp_path, monkeypatch) -> Path:
    """A target root with the same sources but NO ``.codegraph`` index."""
    _write_files(tmp_path, _LIVE_FILES)
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    close_cached()
    assert not (tmp_path / ".codegraph").exists()
    yield tmp_path
    close_cached()


def test_no_index_callers_returns_guidance(unindexed):
    assert cg._index_gate(str(unindexed))[1] is False
    out = cg.callers.func("verify", root=str(unindexed))
    assert out == _GUIDANCE


def test_no_index_callees_returns_guidance(unindexed):
    out = cg.callees.func("login", root=str(unindexed))
    assert out == _GUIDANCE


def test_no_index_framework_routes_returns_guidance(unindexed):
    out = cg.framework_routes.func(root=str(unindexed))
    assert out == _GUIDANCE


def test_no_index_affected_returns_guidance(unindexed):
    out = cg.affected.func("run_query", root=str(unindexed))
    assert out == _GUIDANCE


def test_no_index_empty_queries_hit_the_guidance_sentinel(unindexed):
    assert cg.callers.func("zzz_nope", root=str(unindexed)) == _GUIDANCE
    assert cg.callees.func("zzz_nope", root=str(unindexed)) == _GUIDANCE


def test_fallbacks_never_emit_the_pipeline_unavailable_marker(unindexed):
    for out in (cg.callers.func("verify", root=str(unindexed)),
                cg.callees.func("login", root=str(unindexed)),
                cg.framework_routes.func(root=str(unindexed))):
        assert "(unavailable" not in out


# --- gate failure (pending refs) forces the fail-closed guidance -------------

@pytest.fixture
def seeded(mini):
    """The shared mini-index fixture (real schema), TARGET_REPO pointed at it."""
    return mini


def _drop_pending_refs(db_path: Path) -> None:
    """Clear the one ``pending`` unresolved_ref so the DB-visible gate opens."""
    handle = sqlite3.connect(str(db_path))
    try:
        handle.execute("DELETE FROM unresolved_refs WHERE status = 'pending'")
        handle.commit()
    finally:
        handle.close()


def test_seeded_gate_closed_by_a_pending_ref(seeded):
    root, _db_path = seeded
    conn, ok = cg._index_gate(str(root))
    assert conn is not None
    assert ok is False                               # refs_pending > 0
    assert _db.index_state(str(root))["refs_pending"] == 1


def test_gate_failure_returns_guidance(seeded):
    root, _db_path = seeded                          # pending ref left in place
    assert cg._index_gate(str(root))[1] is False
    out = cg.framework_routes.func(root=str(root))
    assert out == _GUIDANCE


def test_gate_open_serves_route_nodes(seeded):
    root, db_path = seeded
    _drop_pending_refs(db_path)
    close_cached()
    assert cg._index_gate(str(root))[1] is True
    out = cg.framework_routes.func(root=str(root))
    match = ROUTE_LINE_RE.match(out.splitlines()[0])
    assert match and match.group("url") == "POST /login"
    assert match.group("route_line") == "5" and match.group("handler_line") == "6"
    assert "GET /index" not in out


def test_index_open_but_symbol_unindexed_returns_no_matches(seeded):
    root, db_path = seeded
    _drop_pending_refs(db_path)
    close_cached()
    conn, ok = cg._index_gate(str(root))
    assert ok is True
    (root / "extra.py").write_text(
        "def ghost_fn():\n    return 1\n\n\ndef caller():\n    return ghost_fn()\n")
    out = cg.callers.func("ghost_fn", root=str(root))
    assert out == "(no matches)"


# ---------------------------------------------------------------------------
# 3. output-format pins
# ---------------------------------------------------------------------------

def test_route_line_re_pins_the_db_shape():
    match = ROUTE_LINE_RE.match("app.py:5: [route] POST /login -> login (app.py:6)")
    assert match and match.groupdict() == {
        "route_file": "app.py", "route_line": "5", "url": "POST /login",
        "handler": "login", "handler_file": "app.py", "handler_line": "6"}
    # A URL with slashes/braces still parses (non-greedy up to " -> ").
    braced = ROUTE_LINE_RE.match(
        "routes.py:12: [route] GET /a/{id} -> show (routes.py:40)")
    assert braced and braced.group("url") == "GET /a/{id}"
    # The grep fallback's decorator line is NOT a route line.
    assert ROUTE_LINE_RE.match(
        'app.py:5: @app.route("/login", methods=["POST"])') is None


def test_callers_line_prefix_and_markers(seeded):
    root, db_path = seeded
    _drop_pending_refs(db_path)
    close_cached()
    out = cg.callers.func("unsafe_query", root=str(root))
    assert "## def" in out and "## calls" in out
    assert re.search(r"^app\.py:\d+: def unsafe_query\(sql\):$", out, re.M)
    # The call site comes from the index edge (login calls unsafe_query).
    assert re.search(r"^app\.py:10: ", out, re.M)


def test_callees_line_format(seeded):
    root, db_path = seeded
    _drop_pending_refs(db_path)
    close_cached()
    out = cg.callees.func("login", root=str(root))
    assert re.search(r"^app\.py:unsafe_query\(\)$", out, re.M)


def test_callees_and_callers_limit_zero_unlimited(seeded):
    root, db_path = seeded
    _drop_pending_refs(db_path)
    close_cached()
    out_callees = cg.callees.func("login", limit=0, root=str(root))
    assert "unsafe_query()" in out_callees
    out_callers = cg.callers.func("unsafe_query", limit=0, root=str(root))
    assert "app.py:10:" in out_callers


def test_callers_file_disambiguates_same_named_defs(seeded):
    root, db_path = seeded
    _drop_pending_refs(db_path)
    (root / "other.py").write_text("def run_query(sql):\n    return sql\n")
    _insert_rows(
        db_path,
        [_node("other.py:run_query", "function", "run_query", "other.py",
               "python", 1, 2, signature="def run_query(sql):")],
        [])
    close_cached()
    both = cg.callers.func("run_query", root=str(root))
    assert "db.py:6:" in both and "other.py:1:" in both
    narrowed = cg.callers.func("run_query", file="db.py", root=str(root))
    assert "db.py:6:" in narrowed
    assert "other.py" not in narrowed


# ---------------------------------------------------------------------------
# 4. the binding surface itself (D3) + import law
# ---------------------------------------------------------------------------

def test_the_nine_codegraph_tools_are_reexported():
    """Both binding surfaces still resolve every ``cerberus.codegraph`` tool.

    ``cerberus/agents/toolsets.py`` binds them through ``codegraph_tools()``, so
    this pins the re-export names on both the package and the binding module
    to keep the two surfaces from drifting apart (plan § D3).
    """
    import cerberus.codegraph as package
    names = [
        "get_ast_slice",
        "trace_interprocedural_hop",
        "resolve_blind_spot",
        "compare_sibling_route_security",
        "find_shared_state_readers_writers",
        "trace_state_machine_transitions",
        "inspect_type_contract",
        "trace_egress_and_ssrf_targets",
        "trace_effect_category",
    ]
    for name in names:
        assert getattr(package, name, None) is not None
        assert getattr(cg, name, None) is not None


def test_the_db_first_and_native_tools_are_exported():
    for name in ("callers", "callees", "framework_routes", "affected",
                 "codegraph_explore", "find_path",
                 "impact_radius", "type_hierarchy", "build_context",
                 "detect_circular_and_dead_code", "get_routing_manifest"):
        assert getattr(cg, name, None) is not None
    # ... and the names toolsets.py binds all resolve.
    import cerberus.tools.verify as verify
    assert hasattr(verify, "reachability_check")
    assert hasattr(cg, "affected")


def test_native_codegraph_tools_execution():
    """Verify that native CodeGraph tools execute cleanly."""
    from cerberus.codegraph import native

    # explore
    res = native.explore("get_config")
    assert isinstance(res, str)

    # find_path
    path = native.find_path("get_config", "load_config")
    assert path is not None
    assert len(path) >= 2

    # impact
    imp = native.impact("get_config", depth=2)
    assert imp["affected_count"] > 0

    # type hierarchy: ancestors and descendants (the 1.6.2 native
    # getTypeHierarchy() drops descendants because of a shared visited set)
    th = native.type_hierarchy("_Sections")
    assert any(n["name"] == "Report" for n in th["nodes"])
    assert any(e["kind"] == "extends" for e in th["edges"])
    th = native.type_hierarchy("Report")
    assert any(n["name"] == "_Sections" for n in th["nodes"])
    text = cg.type_hierarchy.func("_Sections")
    assert "Report" in text and "extends" in text

    # circular and dead
    cd = native.circular_and_dead_code()
    assert "circular_dependencies" in cd
    assert "dead_code" in cd

    # build_context
    ctx = native.build_context("authentication")
    assert "entryPoints" in ctx or "summary" in ctx


def test_import_law_no_new_dependencies():
    # No new third-party dep, no graphify/networkx import, and no CLI shell-out:
    # the tools are in-process and read-only (plan § D10/§ 2.4). Graphify is
    # fully removed and must not leak back in.
    # Parsed, not string-scanned: a comment mentioning `subprocess` is legal,
    # an `importlib.import_module("subprocess")` is not.
    tree = ast.parse(Path(cg.__file__).read_text())
    forbidden = {"subprocess", "networkx", "graphify"}
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(f"{node.module or ''}.{alias.name}"
                            for alias in node.names)
    hits = {name for name in imported
            if name.split(".")[0] in forbidden}
    assert not hits, hits
    dynamic = [arg.value for node in ast.walk(tree)
               if isinstance(node, ast.Call)
               and getattr(node.func, "attr", getattr(node.func, "id", ""))
               in ("import_module", "__import__")
               for arg in node.args if isinstance(arg, ast.Constant)]
    assert not {name for name in dynamic
                if str(name).split(".")[0] in forbidden}

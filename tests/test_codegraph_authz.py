"""Tests for cerberus.codegraph.authz — the AuthZ & business-logic tools.

The fixture is the foundation's mini index (``build_mini_db``: real source files,
a route with its handler, cross-file edges with confidence, a synthesized
queue-job edge, unresolved refs, a generated file) EXTENDED here with the rows
the three authz questions need:

- ``controllers.py`` — four sibling ``/api/orders`` + ``/api/users`` routes, three
  carrying ``@RequireTenantRole`` and a guard call, one (the refund route)
  carrying neither;
- ``helpers.py`` — the guard callees, one of them only recognisable through a
  cached ``AUTH_GUARD`` summary;
- ``misc.py`` — a lone route with no siblings at all;
- ``accounts.py`` — a ``balance`` field read and written by three functions, one
  of them across an ``await`` with no wrapper and one inside a lock;
- ``orders.py`` / ``orders_routes.py`` — an ``Order.status`` field with a guarded
  transition, an unguarded one, a WHERE-clause-guarded one and an initialiser.

Every node span is derived from the file text (:func:`_block_span`) rather than
hard-coded, so a fixture edit cannot silently desynchronise graph from source.
"""
from __future__ import annotations

import json
import re
import sqlite3

import pytest
from _graphseed import GraphSeed
from cerberus.codegraph import _db, _ts, authz, summaries, supply
from cerberus.codegraph._common import _contained_file
from codegraph_support import (
    _assert_finding_schema,
    _block_span,
    _finding_blocks,
    _fn_span,
    _insert_rows,
    _route_line,
    _route_node,
    close_cached,
    conn,
    mini_index,
)
from test_codegraph_foundation import _EDGES_SQL, _NODES_SQL, _node, build_mini_db

# The merged cross-module cases at the end of this file run each module's own
# scenario against that module's own fixture, so the two sibling test modules
# are imported for their source constants and their ``mini`` fixture.  The
# fixture is aliased because pytest resolves a fixture by the name it has in
# the importing module's namespace.
from test_codegraph_supply import SOURCES as SUPPLY_SOURCES
from test_codegraph_supply import mini as supply_mini

# ---------------------------------------------------------------------------
# fixture source
# ---------------------------------------------------------------------------

CONTROLLERS_PY = '''\
from flask import Flask, request

app = Flask(__name__)


@app.route("/api/orders/<int:order_id>", methods=["DELETE"])
@RequireTenantRole("admin")
def delete_order(order_id):
    assert_tenant_owner(order_id)
    db.delete(order_id)
    return "ok"


@app.route("/api/orders/<int:order_id>", methods=["GET"])
@RequireTenantRole("admin")
def get_order(order_id):
    assert_tenant_owner(order_id)
    return db.find(order_id)


@app.route("/api/orders/<int:order_id>/refund", methods=["POST"])
def refund_order(order_id):
    db.refund(order_id)
    return "ok"


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@RequireTenantRole("admin")
def delete_user(user_id):
    check_permission(user_id)
    tenant_gate(user_id)
    db.delete(user_id)
    return "ok"
'''

HELPERS_PY = '''\
def assert_tenant_owner(resource_id):
    tenant = current_tenant()
    return resource_id.tenant_id == tenant.id


def check_permission(user_id):
    return current_user().can("delete", user_id)


def tenant_gate(user_id):
    return current_tenant().owns(user_id)
'''

MISC_PY = '''\
from flask import Flask

app = Flask(__name__)


@app.route("/solo/ping", methods=["GET"])
def solo_ping():
    return "pong"
'''

ACCOUNTS_PY = '''\
class Account:
    def __init__(self, balance):
        self.balance = balance

    async def withdraw(self, amount):
        current = self.balance
        await self.audit(amount)
        self.balance = current - amount
        return current

    async def safe_transfer(self, other, amount):
        async with self.lock:
            current = self.balance
            await self.audit(amount)
            self.balance = current - amount
            return current

    def show(self):
        return self.balance
'''

ORDERS_PY = '''\
from flask import Flask

app = Flask(__name__)


class Order:
    def __init__(self):
        self.status = "pending"

    @app.route("/fulfilment/ship", methods=["POST"])
    def ship(self):
        if self.status == "pending":
            self.status = "shipped"

    def cancel(self):
        self.status = "cancelled"

    def restock(self):
        row = db.query("SELECT * FROM orders WHERE status = 'shipped'")
        self.status = "restocked"
'''

ORDERS_ROUTES_PY = '''\
from flask import Flask
from orders import Order

app = Flask(__name__)


@app.route("/fulfilment/cancel", methods=["POST"])
def cancel_endpoint(order_id):
    order = Order.load(order_id)
    order.cancel()
'''

SOURCES = {
    "controllers.py": CONTROLLERS_PY,
    "helpers.py": HELPERS_PY,
    "misc.py": MISC_PY,
    "accounts.py": ACCOUNTS_PY,
    "orders.py": ORDERS_PY,
    "orders_routes.py": ORDERS_ROUTES_PY,
}


# ---------------------------------------------------------------------------
# span helpers — the graph must agree with the files on disk
# ---------------------------------------------------------------------------

def _class_span(text: str, name: str) -> tuple[int, int]:
    return _block_span(text, rf"^(\s*)class\s+{re.escape(name)}\b")


def _async_node(*args, **kwargs):
    """``_node`` with ``is_async = 1`` (the 15th column, which _node hardcodes)."""
    row = list(_node(*args, **kwargs))
    row[14] = 1
    return tuple(row)


# ---------------------------------------------------------------------------
# fixture
# ---------------------------------------------------------------------------

def _seed_rows(root, db_path) -> None:
    """Write the extra sources and the nodes/edges/files rows they imply."""
    seed = GraphSeed(root, db_path, SOURCES)
    seed.write_sources()
    nodes, edges, files = seed.nodes, seed.edges, seed.files
    file_node, contains = seed.file_node, seed.contains

    # ---- controllers.py: four routes, three guarded ----------------------
    controllers = file_node("controllers.py", CONTROLLERS_PY, "python")
    # (handler, url path, method, [(guard callee, offset from the def line)])
    handlers = [
        ("delete_order", "/api/orders/<int:order_id>", "DELETE",
         [("assert_tenant_owner", 1)]),
        ("get_order", "/api/orders/<int:order_id>", "GET",
         [("assert_tenant_owner", 1)]),
        ("refund_order", "/api/orders/<int:order_id>/refund", "POST", []),
        ("delete_user", "/api/users/<int:user_id>", "DELETE",
         [("check_permission", 1), ("tenant_gate", 2)]),
    ]
    for name, path, method, guard_calls in handlers:
        start, end = _fn_span(CONTROLLERS_PY, name)
        node_id = f"controllers.py:{name}"
        route_id = f"controllers.py:{name}:route"
        route_name = f"{method} {path}"
        route_line = _route_line(CONTROLLERS_PY, path)
        decorators = [f'@app.route("{path}", methods=["{method}"])']
        if name != "refund_order":
            decorators.append('@RequireTenantRole("admin")')
        nodes.append(_node(node_id, "function", name, "controllers.py", "python",
                           start, end, signature=f"def {name}(order_id):",
                           decorators=json.dumps(decorators),
                           qualified_name=f"controllers.{name}"))
        nodes.append(_route_node(route_id, route_name, "controllers.py", "python",
                                 route_line, end))
        contains(controllers, node_id, start)
        contains(controllers, route_id, route_line)
        edges.append((route_id, node_id, "references",
                      json.dumps({"confidence": 0.85, "resolvedBy": "framework"}),
                      route_line, 1, "static"))
        for guard, offset in guard_calls:
            edges.append((node_id, f"helpers.py:{guard}", "calls",
                          json.dumps({"confidence": 0.9, "resolvedBy": "own-file"}),
                          start + offset, 5, "static"))

    # ---- helpers.py: the guard callees -----------------------------------
    helpers = file_node("helpers.py", HELPERS_PY, "python")
    for name in ("assert_tenant_owner", "check_permission", "tenant_gate"):
        start, end = _fn_span(HELPERS_PY, name)
        node_id = f"helpers.py:{name}"
        nodes.append(_node(node_id, "function", name, "helpers.py", "python",
                           start, end, signature=f"def {name}(id):",
                           qualified_name=f"helpers.{name}"))
        contains(helpers, node_id, start)

    # ---- misc.py: a route with no siblings -------------------------------
    misc = file_node("misc.py", MISC_PY, "python")
    ping_start, ping_end = _fn_span(MISC_PY, "solo_ping")
    ping_route = _route_line(MISC_PY, "/solo/ping")
    nodes.append(_node("misc.py:solo_ping", "function", "solo_ping", "misc.py",
                       "python", ping_start, ping_end,
                       signature="def solo_ping():",
                       decorators=json.dumps(['@app.route("/solo/ping", '
                                              'methods=["GET"])']),
                       qualified_name="misc.solo_ping"))
    nodes.append(_route_node("misc.py:GET /solo/ping:route", "GET /solo/ping",
                             "misc.py", "python", ping_route, ping_end))
    contains(misc, "misc.py:solo_ping", ping_start)
    contains(misc, "misc.py:GET /solo/ping:route", ping_route)
    edges.append(("misc.py:GET /solo/ping:route", "misc.py:solo_ping", "references",
                  json.dumps({"confidence": 0.85}), ping_route, 1, "static"))

    # ---- accounts.py: balance readers and writers ------------------------
    accounts = file_node("accounts.py", ACCOUNTS_PY, "python")
    account_class = "accounts.py:Account"
    class_start, class_end = _class_span(ACCOUNTS_PY, "Account")
    nodes.append(_node(account_class, "class", "Account", "accounts.py", "python",
                       class_start, class_end, qualified_name="accounts.Account"))
    contains(accounts, account_class, class_start)
    balance_start, balance_end = _fn_span(ACCOUNTS_PY, "__init__")
    nodes.append(_node("accounts.py:balance", "field", "balance", "accounts.py",
                       "python", balance_start + 1, balance_start + 1,
                       signature="self.balance = balance",
                       qualified_name="accounts.Account.balance"))
    contains(account_class, "accounts.py:balance", balance_start + 1)

    balance_sites = {
        "__init__": [balance_start + 1],
        "withdraw": [6, 8],
        "safe_transfer": [13, 15],
        "show": [19],
    }
    for name, lines in balance_sites.items():
        start, end = _fn_span(ACCOUNTS_PY, name)
        node_id = f"accounts.py:{name}"
        is_async = name in ("withdraw", "safe_transfer")
        maker = _async_node if is_async else _node
        nodes.append(maker(node_id, "method", name, "accounts.py", "python",
                           start, end,
                           signature=f"def {name}(self, amount):",
                           qualified_name=f"accounts.Account.{name}"))
        contains(account_class, node_id, start)
        for line in lines:
            edges.append((node_id, "accounts.py:balance", "references", None,
                          line, 18 if line in (6, 8, 13, 15) else 15, "static"))

    # ---- orders.py: the status field and its transitions -----------------
    orders = file_node("orders.py", ORDERS_PY, "python")
    order_class = "orders.py:Order"
    order_start, order_end = _class_span(ORDERS_PY, "Order")
    nodes.append(_node(order_class, "class", "Order", "orders.py", "python",
                       order_start, order_end, qualified_name="orders.Order"))
    contains(orders, order_class, order_start)
    status_line = _fn_span(ORDERS_PY, "__init__")[0] + 1
    nodes.append(_node("orders.py:status", "field", "status", "orders.py",
                       "python", status_line, status_line,
                       signature='self.status = "pending"',
                       qualified_name="orders.Order.status"))
    contains(order_class, "orders.py:status", status_line)

    ship_start, ship_end = _fn_span(ORDERS_PY, "ship")
    cancel_start, cancel_end = _fn_span(ORDERS_PY, "cancel")
    restock_start, restock_end = _fn_span(ORDERS_PY, "restock")
    init_start, init_end = _fn_span(ORDERS_PY, "__init__")
    for name, start, end in (("__init__", init_start, init_end),
                             ("ship", ship_start, ship_end),
                             ("cancel", cancel_start, cancel_end),
                             ("restock", restock_start, restock_end)):
        node_id = f"orders.py:{name}"
        decorators = None
        if name == "ship":
            decorators = json.dumps(['@app.route("/fulfilment/ship", '
                                     'methods=["POST"])'])
        nodes.append(_node(node_id, "method", name, "orders.py", "python",
                           start, end, signature=f"def {name}(self):",
                           decorators=decorators,
                           qualified_name=f"orders.Order.{name}"))
        contains(order_class, node_id, start)

    ship_route_line = _route_line(ORDERS_PY, "/fulfilment/ship")
    nodes.append(_route_node("orders.py:POST /fulfilment/ship:route",
                             "POST /fulfilment/ship", "orders.py", "python",
                             ship_route_line, ship_end))
    contains(orders, "orders.py:POST /fulfilment/ship:route", ship_route_line)
    edges.append(("orders.py:POST /fulfilment/ship:route", "orders.py:ship",
                  "references",
                  json.dumps({"confidence": 0.85, "resolvedBy": "framework"}),
                  ship_route_line, 1, "static"))

    # status references: the read inside ship's guard, plus every assignment
    for source, line in (("orders.py:__init__", status_line),
                         ("orders.py:ship", ship_start + 1),
                         ("orders.py:ship", ship_start + 2),
                         ("orders.py:cancel", cancel_start + 1),
                         ("orders.py:restock", restock_start + 1),
                         ("orders.py:restock", restock_start + 2)):
        edges.append((source, "orders.py:status", "references", None, line, 18,
                      "static"))

    # ---- orders_routes.py: the endpoint that reaches cancel by call ------
    routes = file_node("orders_routes.py", ORDERS_ROUTES_PY, "python")
    cancel_endpoint_start, cancel_endpoint_end = _fn_span(
        ORDERS_ROUTES_PY, "cancel_endpoint")
    cancel_route_line = _route_line(ORDERS_ROUTES_PY, "/fulfilment/cancel")
    nodes.append(_node("orders_routes.py:cancel_endpoint", "function",
                       "cancel_endpoint", "orders_routes.py", "python",
                       cancel_endpoint_start, cancel_endpoint_end,
                       signature="def cancel_endpoint(order_id):",
                       decorators=json.dumps(['@app.route("/fulfilment/cancel", '
                                              'methods=["POST"])']),
                       qualified_name="orders_routes.cancel_endpoint"))
    nodes.append(_route_node("orders_routes.py:POST /fulfilment/cancel:route",
                             "POST /fulfilment/cancel", "orders_routes.py", "python",
                             cancel_route_line, cancel_endpoint_end))
    contains(routes, "orders_routes.py:cancel_endpoint", cancel_endpoint_start)
    contains(routes, "orders_routes.py:POST /fulfilment/cancel:route",
             cancel_route_line)
    edges.append(("orders_routes.py:POST /fulfilment/cancel:route",
                  "orders_routes.py:cancel_endpoint", "references",
                  json.dumps({"confidence": 0.85}), cancel_route_line, 1, "static"))
    edges.append(("orders_routes.py:cancel_endpoint", "orders.py:cancel", "calls",
                  json.dumps({"confidence": 0.95, "resolvedBy": "import"}),
                  cancel_endpoint_start + 2, 11, "static"))

    seed.flush()


@pytest.fixture
def mini(tmp_path, monkeypatch):
    """The foundation's mini index, extended with the authz fixture rows."""
    with mini_index(tmp_path, monkeypatch, _seed_rows) as index:
        # One guard callee is only recognisable through the analyst's own
        # memory: `tenant_gate` matches no name pattern, so it joins the
        # consensus solely through a cached AUTH_GUARD summary (the summaries
        # module's read path).
        assert summaries.record_summary(
            str(tmp_path), "helpers.py:tenant_gate", "AUTH_GUARD", "284",
            "row-level tenant ownership check").startswith("recorded AUTH_GUARD")
        close_cached()
        yield index


# ---------------------------------------------------------------------------
# 0. degradation: no index, bad input
# ---------------------------------------------------------------------------

def test_unknown_and_wrong_kind_nodes(mini):
    root, _db_path = mini
    out = authz.compare_sibling_route_security.func(
        "controllers.py:nope:route", str(root))
    assert out.startswith("ERROR: node not found")

    # A handler id is not a route id — the tool says so instead of guessing.
    out = authz.compare_sibling_route_security.func(
        "controllers.py:refund_order", str(root))
    assert out.startswith("ERROR:") and "not 'route'" in out


def test_empty_required_arguments(mini):
    root, _db_path = mini
    assert authz.find_shared_state_readers_writers.func("", str(root)).startswith(
        "ERROR: state_symbol_or_table is required")
    assert authz.trace_state_machine_transitions.func("", str(root)).startswith(
        "ERROR: entity_name is required")


def test_unknown_state_symbol_and_entity(mini):
    root, _db_path = mini
    state = authz.find_shared_state_readers_writers.func("no_such_symbol", str(root))
    assert "no state carrier" in state and "CodeGraph models no table nodes" in state

    machine = authz.trace_state_machine_transitions.func("NoSuchEntity", str(root))
    assert "no status field" in machine


# ---------------------------------------------------------------------------
# 1. compare_sibling_route_security
# ---------------------------------------------------------------------------

def test_consensus_catches_missing_decorator_and_guard(mini):
    root, _db_path = mini
    out = authz.compare_sibling_route_security.func(
        "controllers.py:refund_order:route", str(root))

    # the target's own profile
    assert "POST /api/orders/<int:order_id>/refund" in out
    assert "refund_order" in out
    assert "sibling_count: 3" in out

    # consensus: the decorator on all three siblings, the guard call on two
    assert "@RequireTenantRole (3/3)" in out
    assert "assert_tenant_owner (2/3)" in out
    assert "missing_on_target: decorators @RequireTenantRole; guard_calls " \
           "assert_tenant_owner" in out

    # the sibling that carries a guard only a cached summary knows about
    assert "tenant_gate (cached AUTH_GUARD summary)" in out
    assert "check_permission (guard-shaped name)" in out

    # the candidate finding, with the severity/confidence heuristic applied
    blocks = _finding_blocks(out)
    assert len(blocks) == 1
    finding = blocks[0]
    _assert_finding_schema(finding)
    assert finding["cwe"] == "CWE-639"
    assert "CWE-284" in finding["note"]
    assert finding["severity"] == "high"          # an auth-shaped decorator gap
    assert finding["confidence"] == 0.85          # clamped at the ceiling
    assert finding["path"] == "controllers.py"
    assert finding["start_line"] == _fn_span(CONTROLLERS_PY, "refund_order")[0]
    assert finding["taint"]["source"].startswith("sibling consensus")
    assert "POST /api/orders/<int:order_id>/refund" in finding["taint"]["sink"]


def test_guarded_route_produces_no_finding(mini, conn):
    root, _db_path = mini
    out = authz.compare_sibling_route_security.func(
        "controllers.py:delete_order:route", str(root))
    assert "missing_on_target: decorators (none); guard_calls (none)" in out
    assert "no candidate finding" in out
    assert _finding_blocks(out) == []


def test_route_with_no_siblings(mini):
    root, _db_path = mini
    out = authz.compare_sibling_route_security.func(
        "misc.py:GET /solo/ping:route", str(root))
    assert "GET /solo/ping" in out
    assert "sibling_count: 0" in out
    assert "consensus needs at least one sibling" in out
    assert _finding_blocks(out) == []


def test_limit_caps_the_sibling_population(mini):
    root, _db_path = mini
    out = authz.compare_sibling_route_security.func(
        "controllers.py:refund_order:route", str(root), limit=1)
    assert "sibling_count: 1" in out
    assert "+2 more routes found, capped at 1" in out
    # With one sibling the majority is that sibling alone, so the check it
    # carries is still consensus — the report says how thin the vote was.
    assert "@RequireTenantRole (1/1)" in out
    assert len(_finding_blocks(out)) == 1


# ---------------------------------------------------------------------------
# 2. find_shared_state_readers_writers
# ---------------------------------------------------------------------------

def test_reader_writer_classification_and_racy_pairs(mini):
    root, _db_path = mini
    out = authz.find_shared_state_readers_writers.func("balance", str(root))

    assert "carrier accounts.py:3 (field balance, 3)" in out
    assert "reference sites: 6 (3 reader, 3 writer)" in out

    # classification: read-modify-write is a writer, a bare read is not
    assert "accounts.py:6  reader withdraw(method)" in out
    assert "accounts.py:8  writer withdraw(method)" in out
    assert "accounts.py:19  reader show(method)" in out
    assert "async: yes  wrapper: no" in out              # withdraw
    assert "accounts.py:15  writer safe_transfer(method)" in out
    assert "async: yes  wrapper: yes" in out             # safe_transfer
    assert "self.balance = current - amount" in out      # writer evidence

    # the racy shapes — and only the pairs with nothing between them
    blocks = _finding_blocks(out)
    assert len(blocks) == 4
    toctou = [b for b in blocks if b["cwe"] == "CWE-367"]
    race = [b for b in blocks if b["cwe"] == "CWE-362"]
    assert len(toctou) == 1 and len(race) == 3

    toctou = toctou[0]
    _assert_finding_schema(toctou)
    assert toctou["severity"] == "high"
    assert toctou["taint"] == {
        "source": "state check",
        "sink": "state mutation",
        "path": ["accounts.py:6", "accounts.py:8"],
    }
    assert "await at line 7" in toctou["evidence"]
    assert toctou["path"] == "accounts.py"
    assert toctou["start_line"] == _fn_span(ACCOUNTS_PY, "withdraw")[0]

    assert {"accounts.py:19", "accounts.py:8"} == set(
        next(b for b in race if b["taint"]["path"] == ["accounts.py:19", "accounts.py:8"])
        ["taint"]["path"])
    for finding in race:
        _assert_finding_schema(finding)
        assert finding["severity"] == "medium"
        assert finding["confidence"] == 0.55
    assert all(finding["taint"]["source"] == "state check"
               and finding["taint"]["sink"] == "state mutation" for finding in blocks)

    # the lock-protected pair is NOT one of them
    for finding in blocks:
        assert "safe_transfer" not in finding["evidence"]
    assert "in safe_transfer() — different functions" not in out
    assert "safe_transfer() then write" not in out


def test_dotted_state_symbol_prefers_the_owner(mini):
    root, _db_path = mini
    out = authz.find_shared_state_readers_writers.func("Account.balance", str(root))
    assert "owner: accounts.py:1 (class Account, 1-19)" in out
    assert "reference sites: 6 (3 reader, 3 writer)" in out
    assert "# shared state readers/writers: Account.balance" in out


def test_update_style_call_is_a_writer(mini, monkeypatch):
    """A receiver update (`ledger.save(...)`) writes even without an assignment."""
    root, db_path = mini
    ledger = '''\
class Ledger:
    def __init__(self):
        self.total = 0

    def credit(self, amount):
        self.save(self.total + amount)
'''
    (root / "ledger.py").write_text(ledger)
    start, end = _fn_span(ledger, "__init__")
    credit_start, credit_end = _fn_span(ledger, "credit")
    nodes = [
        _node("ledger.py:ledger.py", "file", "ledger.py", "ledger.py", "python",
              1, len(ledger.splitlines())),
        _node("ledger.py:Ledger", "class", "Ledger", "ledger.py", "python", 1,
              len(ledger.splitlines()), qualified_name="ledger.Ledger"),
        _node("ledger.py:total", "field", "total", "ledger.py", "python",
              start + 1, start + 1, signature="self.total = 0",
              qualified_name="ledger.Ledger.total"),
        _node("ledger.py:credit", "method", "credit", "ledger.py", "python",
              credit_start, credit_end, signature="def credit(self, amount):",
              qualified_name="ledger.Ledger.credit"),
    ]
    edges = [
        ("ledger.py:ledger.py", "ledger.py:Ledger", "contains", None, 1, 1, "static"),
        ("ledger.py:Ledger", "ledger.py:total", "contains", None, start + 1, 1,
         "static"),
        ("ledger.py:Ledger", "ledger.py:credit", "contains", None, credit_start, 1,
         "static"),
        ("ledger.py:credit", "ledger.py:total", "references", None, credit_start + 1,
         21, "static"),
    ]
    handle = sqlite3.connect(str(db_path))
    try:
        handle.executemany(_NODES_SQL, nodes)
        handle.executemany(_EDGES_SQL, edges)
        handle.commit()
    finally:
        handle.close()
    close_cached()

    out = authz.find_shared_state_readers_writers.func("total", str(root))
    assert "ledger.py:6  writer credit(method)" in out
    assert "update-style call save" in out


# ---------------------------------------------------------------------------
# 3. trace_state_machine_transitions
# ---------------------------------------------------------------------------

def test_transition_table_guarded_and_unguarded(mini):
    root, _db_path = mini
    out = authz.trace_state_machine_transitions.func("Order", "status", str(root))

    assert "status field orders.py:8 (field status, 8)" in out
    assert "owner: orders.py:6 (class Order, 6-20)" in out
    assert "transitions: 4 (2 guarded, 2 unguarded)" in out

    # guarded by an if-statement, reached straight from its route
    assert "pending -> shipped  orders.py:13  POST /fulfilment/ship  guard: yes" in out
    # guarded by a WHERE clause, reachable by nothing
    assert "shipped -> restocked  orders.py:20  (not route-reachable)  guard: yes" in out
    # unguarded, reached through the controller that calls it
    assert "(unguarded) -> cancelled  orders.py:16  POST /fulfilment/cancel  " \
           "guard: NO" in out

    blocks = _finding_blocks(out)
    assert len(blocks) == 2
    for finding in blocks:
        _assert_finding_schema(finding)
        assert finding["cwe"] == "CWE-840"
        assert finding["severity"] == "medium"
        assert "CWE-840" in finding["note"]
    paths = {(b["path"], b["start_line"]) for b in blocks}
    assert paths == {("orders.py", _fn_span(ORDERS_PY, "cancel")[0]),
                     ("orders.py", _fn_span(ORDERS_PY, "__init__")[0])}
    cancelled = next(b for b in blocks
                 if b["start_line"] == _fn_span(ORDERS_PY, "cancel")[0])
    assert cancelled["confidence"] == 0.70   # route-reachable + a real state machine
    assert "POST /fulfilment/cancel" in cancelled["taint"]["path"][0]
    assert cancelled["taint"]["sink"] == 'status = cancelled'


def test_transitions_of_a_read_only_reference_are_skipped(mini):
    root, _db_path = mini
    out = authz.trace_state_machine_transitions.func("Order", "status", str(root))
    # ship() reads the field in its guard (line 12) — that is not a transition
    assert "orders.py:12" not in out


def test_non_matching_status_field_falls_back(mini):
    root, _db_path = mini
    out = authz.trace_state_machine_transitions.func("Order", "state", str(root))
    # No `state` field exists anywhere: the fallback finds nothing and says so.
    assert "no status field for Order.state" in out


# ---------------------------------------------------------------------------
# 4. regression tests for the confirmed audit findings
# ---------------------------------------------------------------------------

# The wallet module in two prose variants: byte-identical CODE, different
# prose around it. One carries the exact strings the audit proved suppressed
# the TOCTOU finding (a docstring mentioning "update the ledger", a
# "# TODO: add a lock here" / "# NOTE: no lock is taken here yet" pair, and a
# raw-SQL UPDATE mutation); the other carries none of them. Only the line
# count is fixed — the two must be indistinguishable to the tool.
WALLET_PROSE_PY = '''\
class Wallet:
    """Withdraw funds; update the ledger after the audit."""

    def __init__(self, balance):
        self.balance = balance

    async def withdraw(self, amount):
        # TODO: add a lock here
        # NOTE: no lock is taken here yet
        current = self.balance
        await self.audit(amount)
        self.db.execute("UPDATE wallets SET balance = balance - 1 WHERE id = ?")
        return current
'''

WALLET_QUIET_PY = '''\
class Wallet:
    """Withdraw funds."""

    def __init__(self, balance):
        self.balance = balance

    async def withdraw(self, amount):
        # ordinary bookkeeping
        # nothing to see here
        current = self.balance
        await self.audit(amount)
        self.db.execute("UPDATE wallets SET balance = balance - 1 WHERE id = ?")
        return current
'''

# The same module plus a method whose writes cannot be attributed to the
# carrier: a dynamic statement and a DML that names another table's column.
WALLET_SQL_PY = '''\
class Wallet:
    """Withdraw funds; update the ledger after the audit."""

    def __init__(self, balance):
        self.balance = balance

    async def withdraw(self, amount):
        # TODO: add a lock here
        current = self.balance
        await self.audit(amount)
        self.db.execute("UPDATE wallets SET balance = balance - 1 WHERE id = ?")
        return current

    async def flush(self, sql):
        self.db.execute(sql)
        self.db.execute("UPDATE audit SET run = 1 WHERE wallet_id = ?")
'''

# The four lock SPELLINGS the wrapper scan must recognise (the other half of
# FIX 1: prose must not count, syntax must).
LEDGER_SYNTAX_PY = '''\
class Ledger:
    """Ledger of the lock spellings the wrapper scan has to see."""

    def __init__(self, total):
        self.total = total

    @transactional
    def with_decorator(self):
        return self.total

    def with_call(self):
        Order.objects.select_for_update()
        return self.total

    def with_sql(self):
        db.execute("SELECT * FROM ledger WHERE id = 1 FOR UPDATE")
        return self.total
'''

# A raw-SQL status write: the transition the audit found silently dropped,
# plus a sibling write whose target state is not a literal.
RAW_ORDERS_SQL_PY = '''\
import db


class Order:
    def __init__(self):
        self.status = "pending"

    def cancel(self, ids):
        db.execute("UPDATE orders SET status = 'cancelled' WHERE id IN (%s)" % ids)

    def rebind(self, ids, value):
        db.execute("UPDATE orders SET status = ? WHERE id IN (%s)", (value, ids))
'''

# The same write, with the graph's reference recorded on another line of the
# same function (the index puts an edge where the NAME appears, not where the
# SQL sits), so the write must still reach the table — exactly once.
RAW_ORDERS_FALLBACK_PY = '''\
import db


class Order:
    def __init__(self):
        self.status = "pending"

    def cancel(self, ids):
        log(self.status)
        db.execute("UPDATE orders SET status = 'cancelled' WHERE id IN (%s)" % ids)
'''


def _seed_carrier(root, db_path, file_name: str, source: str, *, field: str,
                  class_name: str) -> None:
    """Write one module and the graph rows its state carrier implies.

    Reference sites are derived from the source — every line inside a method
    that touches ``field`` or runs a raw-SQL call — so the graph agrees with
    the file on disk the way the accounts.py half of the fixture does.
    """
    (root / file_name).write_text(source)
    nodes: list[tuple] = []
    edges: list[tuple] = []
    lines = source.splitlines()
    file_id = f"{file_name}:{file_name}"
    class_id = f"{file_name}:{class_name}"
    field_id = f"{file_name}:{field}"
    class_start, class_end = _class_span(source, class_name)
    field_line = _fn_span(source, "__init__")[0] + 1
    nodes.append(_node(file_id, "file", file_name, file_name, "python", 1,
                       len(lines)))
    nodes.append(_node(class_id, "class", class_name, file_name, "python",
                       class_start, class_end,
                       qualified_name=f"{class_name}"))
    nodes.append(_node(field_id, "field", field, file_name, "python",
                       field_line, field_line, signature=f"self.{field} = {field}",
                       qualified_name=f"{class_name}.{field}"))
    edges.append((file_id, class_id, "contains", None, class_start, 1, "static"))
    edges.append((class_id, field_id, "contains", None, field_line, 1, "static"))
    for name in re.findall(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(", source, re.M):
        start, end = _fn_span(source, name)
        method_id = f"{file_name}:{name}"
        is_async = bool(re.search(
            rf"^\s*async\s+def\s+{re.escape(name)}\s*\(", source, re.M))
        maker = _async_node if is_async else _node
        nodes.append(maker(method_id, "method", name, file_name, "python",
                           start, end, signature=f"def {name}(self):",
                           qualified_name=f"{class_name}.{name}"))
        edges.append((class_id, method_id, "contains", None, start, 1, "static"))
        for line_no in range(start + 1, end + 1):
            text = lines[line_no - 1]
            if field in text or "db.execute" in text:
                edges.append((method_id, field_id, "references", None, line_no, 18,
                              "static"))
    _insert_rows(db_path, nodes, edges)


def _carrier_report(root, monkeypatch, source: str, *, file_name="wallet.py",
                    field="balance", class_name="Wallet", symbol=None):
    """Seed ``source`` in its own mini index and report on its carrier."""
    db_path = build_mini_db(root)
    _seed_carrier(root, db_path, file_name, source, field=field,
                  class_name=class_name)
    monkeypatch.setenv("TARGET_REPO", str(root))
    close_cached()
    return authz.find_shared_state_readers_writers.func(symbol or field, str(root))


def _raw_status_report(root, monkeypatch, source: str) -> str:
    db_path = build_mini_db(root)
    _seed_carrier(root, db_path, "raw_orders.py", source, field="status",
                  class_name="Order")
    monkeypatch.setenv("TARGET_REPO", str(root))
    close_cached()
    return authz.trace_state_machine_transitions.func("Order", "status", str(root))


def test_prose_is_not_a_wrapper_and_the_toctou_finding_survives(tmp_path, monkeypatch):
    """FIX 1 (W-1): a lock is a SYNTAX, not a word in the text.

    The audit's four probes — a docstring saying "update the ledger", a
    "# TODO: add a lock here" comment, a "# NOTE: no lock is taken here yet"
    comment and the UPDATE mutation itself — all used to read as
    wrapper=yes and produced zero racy pairs. The code below is
    byte-identical in both variants; only the prose differs. Both must read
    as unsynchronised and emit the CWE-367 finding, so the two reports have
    to come out byte-identical too.
    """
    (tmp_path / "prose").mkdir()
    (tmp_path / "quiet").mkdir()
    prose = _carrier_report(tmp_path / "prose", monkeypatch, WALLET_PROSE_PY)
    quiet = _carrier_report(tmp_path / "quiet", monkeypatch, WALLET_QUIET_PY)

    assert "wallet.py:10  reader withdraw(method)" in prose
    assert "wallet.py:12  writer withdraw(method)" in prose
    assert "async: yes  wrapper: no" in prose          # the docstring is not a lock
    assert "wallet.py:5  writer __init__(method)" in prose

    blocks = _finding_blocks(prose)
    toctou = [b for b in blocks if b["cwe"] == "CWE-367"]
    assert len(toctou) == 1                            # the finding is emitted
    _assert_finding_schema(toctou[0])
    assert toctou[0]["severity"] == "high"
    assert toctou[0]["taint"]["path"] == ["wallet.py:10", "wallet.py:12"]
    assert "await at line 11" in toctou[0]["evidence"]

    # prose-independent: the same code with different prose is the same answer
    assert prose == quiet


def test_wrapper_is_syntax_not_vocabulary():
    """FIX 1 (W-1), the vocabulary itself: a lock is a SYNTAX, not a word.

    Every shape in the first block WRAPS (a with on a lock/transaction/session
    expression, a lock-shaped decorator, ``select_for_update()``, a
    ``SELECT … FOR UPDATE`` literal). Every shape in the second block is
    prose or an unrelated word — including the four strings the audit proved
    suppressed the TOCTOU findings — and must NOT read as synchronised.
    """
    wraps = [
        "with self.lock:", "async with self.lock:", "with transaction.atomic():",
        "with db.session.begin():", "with self.mutex:", "with unit_of_work():",
        "with self.with_for_update():", "Order.objects.select_for_update()",
        'cursor.execute("SELECT * FROM wallets WHERE id = 1 FOR UPDATE")',
        'cursor.execute("select * from t for update")',
    ]
    for shape in wraps:
        source = f"def f(self):\n    {shape}\n    pass\n"
        assert authz._has_wrapper(_ts.parse_source(source, "python").root_node,
                                  source.encode()), shape

    for decorator in ("@transactional", "@with_lock", "@Synchronized"):
        source = f"{decorator}\ndef f(self):\n    pass\n"
        tree = _ts.parse_source(source, "python")
        fn = _ts.enclosing_function(tree, 2)
        assert authz._has_wrapper(fn, source.encode()), decorator
        # ... and the same name in the index's decorators column
        assert authz._has_wrapper(fn, source.encode(), [decorator]), decorator

    prose = [
        '"""Withdraw funds; update the ledger after the audit."""',
        "# TODO: add a lock here",
        "# NOTE: no lock is taken here yet",
        'self.db.execute("UPDATE wallets SET balance = balance - 1 WHERE id = ?")',
        "# synchronized", "self.begin()", "self.update()",
        '"""Use select_for_update() here."""',
        "with self.deadlock_detector:", "with self.blocking_queue:",
        "with self.update_helper():", 'print("update the ledger")',
        "@login_required", '@app.route("/x")',
    ]
    for shape in prose:
        source = f"def f(self):\n    {shape}\n    pass\n"
        assert not authz._has_wrapper(
            _ts.parse_source(source, "python").root_node, source.encode()), shape


def test_lock_shaped_syntax_is_a_wrapper(tmp_path, monkeypatch):
    out = _carrier_report(tmp_path, monkeypatch, LEDGER_SYNTAX_PY,
                          file_name="ledger.py", field="total",
                          class_name="Ledger")
    assert ("ledger.py:9  reader with_decorator(method)  span 8-9  async: no  "
            "wrapper: yes" in out)                       # @transactional
    assert ("ledger.py:13  reader with_call(method)  span 11-13  async: no  "
            "wrapper: yes" in out)                       # select_for_update()
    assert ("ledger.py:17  reader with_sql(method)  span 15-17  async: no  "
            "wrapper: yes" in out)                       # SELECT … FOR UPDATE
    # a SELECT … FOR UPDATE literal is a locked READ, not a mutation
    assert "ledger.py:16  reader with_sql(method)" in out
    assert "unclassified" not in out
    assert _finding_blocks(out) == []


def test_raw_sql_update_is_a_writer_and_the_toctou_finding_fires(tmp_path, monkeypatch):
    """FIX 2 (W-2): `self.db.execute("UPDATE …")` is a writer, not a reader.

    The audit's probe reported the raw-SQL mutation as a reader with
    wrapper:yes — a false all-clear on the exact line that moves the money.
    """
    out = _carrier_report(tmp_path, monkeypatch, WALLET_SQL_PY)

    assert "wallet.py:9  reader withdraw(method)" in out
    assert "wallet.py:11  writer withdraw(method)" in out
    assert "raw SQL DML names the carrier" in out
    assert "UPDATE wallets SET balance = balance - 1 WHERE id = ?" in out
    assert "wallet.py:11  reader" not in out           # never a silent reader
    assert "wrapper: no" in out

    blocks = _finding_blocks(out)
    toctou = [b for b in blocks if b["cwe"] == "CWE-367"]
    assert len(toctou) == 1, [b["cwe"] for b in blocks]
    assert toctou[0]["severity"] == "high"
    assert toctou[0]["taint"]["path"] == ["wallet.py:9", "wallet.py:11"]

    # A mutation the tool cannot attribute to this carrier is reported
    # unclassified, never folded into the readers.
    assert "reference sites: 5 (1 reader, 2 writer, 2 unclassified)" in out
    assert "wallet.py:15  unclassified flush(method)" in out
    assert "wallet.py:16  unclassified flush(method)" in out


def test_guarded_target_is_not_reported_as_omitting_the_check(mini):
    """FIX 3 (S-1): a differently-named guard is not a proven omission.

    delete_user carries check_permission (guard-shaped name) and tenant_gate
    (cached AUTH_GUARD); its siblings carry assert_tenant_owner. The old
    set-difference emitted "missing function-level access control … enforce
    the check this handler omits" at severity high — on a target that does
    check access. The honest shape is a note, not a verdict.
    """
    root, _db_path = mini
    out = authz.compare_sibling_route_security.func(
        "controllers.py:delete_user:route", str(root))

    assert "the check this handler omits" not in out
    assert "missing function-level access control" not in out
    # the set-difference data stays — it is informative
    assert "missing_on_target: decorators (none); guard_calls " \
           "assert_tenant_owner" in out

    blocks = _finding_blocks(out)
    assert len(blocks) == 1
    finding = blocks[0]
    _assert_finding_schema(finding)
    assert finding["severity"] == "info"
    assert finding["confidence"] <= 0.3            # never escalates off guard_hint
    assert "name-based matching cannot prove equivalence" in finding["note"]
    assert "target enforces check_permission, tenant_gate" in finding["note"]
    assert "assert_tenant_owner not matched by name" in finding["note"]
    assert "consensus check not matched by name" in finding["title"]
    # and the honest wording is in the report body, not only the JSON block
    assert "note: target enforces check_permission, tenant_gate" in out
    assert "severity info" in out


def test_raw_sql_status_write_reaches_the_transition_table(tmp_path, monkeypatch):
    """FIX 4 (M-1): a raw-SQL status write is a transition or an explicit skip.

    `db.execute("UPDATE orders SET status = 'cancelled' …")` never reached
    the table, the skipped counter only moved on unparseable files, and the
    report read as exhaustive.
    """
    out = _raw_status_report(tmp_path, monkeypatch, RAW_ORDERS_SQL_PY)

    # the write is a transition: to_state from the literal, endpoint resolved
    assert "transitions: 2 (0 guarded, 2 unguarded)" in out
    assert "(unguarded) -> cancelled  raw_orders.py:9" in out
    assert "UPDATE orders SET status = 'cancelled'" in out
    blocks = _finding_blocks(out)
    cancelled = [b for b in blocks
                 if b["taint"]["sink"] == "status = cancelled"]
    assert len(cancelled) == 1
    _assert_finding_schema(cancelled[0])
    assert cancelled[0]["cwe"] == "CWE-840"

    # a write with no readable target state is counted, not silently dropped
    assert "skipped (1 unclassified status writes)" in out
    assert "not exhaustive" in out


def test_raw_sql_status_write_with_the_reference_on_another_line(
        tmp_path, monkeypatch):
    """FIX 4, robustness: the write is found wherever the index put the edge.

    The graph records a reference by its own line, which need not sit inside
    the statement that writes, so the enclosing function is scanned too — and
    the write is emitted once, not once per reference that saw it.
    """
    out = _raw_status_report(tmp_path, monkeypatch, RAW_ORDERS_FALLBACK_PY)
    assert "transitions: 2 (0 guarded, 2 unguarded)" in out
    assert "(unguarded) -> cancelled  raw_orders.py:10" in out
    # one statement, one row: the reference on line 10 does not duplicate it
    blocks = _finding_blocks(out)
    assert len([b for b in blocks
                if b["taint"]["sink"] == "status = cancelled"]) == 1


def test_hostile_state_symbol_is_capped(tmp_path, monkeypatch):
    """FIX 5: every returned string goes through the char cap.

    A 200 KB state symbol used to make the no-carrier guidance echo it twice
    for a 400 KB answer, and the error paths were never capped at all.
    """
    db_path = build_mini_db(tmp_path)
    assert db_path.is_file()
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    monkeypatch.setenv("CODEGRAPH_CHARS", "200")
    close_cached()

    out = authz.find_shared_state_readers_writers.func("A" * 200_000, str(tmp_path))
    assert len(out) < 300
    assert "more chars (total" in out
    assert "no state carrier" in out

    # the error paths of the other two tools are capped too
    for symbol in ("x" * 100_000, "app.py:login"):
        capped = authz.compare_sibling_route_security.func(symbol, str(tmp_path))
        assert len(capped) < 300, symbol[:20]
    assert "more chars (total" in authz.compare_sibling_route_security.func(
        "x" * 100_000, str(tmp_path))
    for entity in ("z" * 100_000,):
        capped = authz.trace_state_machine_transitions.func(entity, "status",
                                                            str(tmp_path))
        assert len(capped) < 300
        assert "more chars (total" in capped


# ---------------------------------------------------------------------------
# cross-module cases
# ---------------------------------------------------------------------------
#
# ``test_missing_db_returns_guidance``, ``test_fixture_spans_match_the_source``,
# ``test_char_cap_is_applied`` and
# ``test_contained_file_never_raises_on_hostile_paths`` each existed once per
# module under the same name.  Every row below is one module's scenario,
# unchanged — its own tool calls, its own env value, its own bound, its own
# skip-list — run against that module's own fixture.  Only the name collided.

# (does the tool get a fresh subdirectory instead of TARGET_REPO itself,
#  [(tool, leading args), ...]) — the unindexed root is appended to every call.
_NO_INDEX_CASES = [
    pytest.param(False, [
        (authz.compare_sibling_route_security,
         ("controllers.py:refund_order:route",)),
        (authz.find_shared_state_readers_writers, ("balance",)),
        (authz.trace_state_machine_transitions, ("Order", "status")),
    ], id="authz"),
    pytest.param(False, [
        (supply.trace_egress_and_ssrf_targets, ("egress.py:fetch_dynamic_host",)),
    ], id="supply"),
]


@pytest.mark.parametrize("subdir, calls", _NO_INDEX_CASES)
def test_missing_db_returns_guidance(tmp_path, monkeypatch, subdir, calls):
    """Every module's tools answer an unindexed repo with the same guidance."""
    root = tmp_path / "empty"
    root.mkdir()
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    close_cached()
    target = str(root if subdir else tmp_path)
    expected = _db.guidance_no_db(target)
    for tool, args in calls:
        assert tool.func(*args, target) == expected


# (repo fixture, the module's sources, node kinds its fixture rows may skip,
#  whether a route node is asserted to sit on the registering decorator)
_SPAN_CASES = [
    pytest.param("mini", SOURCES, ("file",), True, id="authz"),
    pytest.param("supply_mini", SUPPLY_SOURCES,
                 ("file", "import", "constant", "variable"), True, id="supply"),
]


# Vacuity guard: every assertion above lives inside the node loop, so a graph
# that seeds nothing (or seeds nothing into ``sources``) would make the row
# pass without checking anything. The floor is the number of nodes each row
# actually verifies today. Raise it when a fixture legitimately grows; a drop
# means the fixture stopped seeding what this test exists to prove.
_SPAN_FLOOR = {"mini": 28, "supply_mini": 5}


@pytest.mark.parametrize("repo_fixture, sources, skip_kinds, check_route", _SPAN_CASES)
def test_fixture_spans_match_the_source(request, repo_fixture, sources, skip_kinds,
                                        check_route):
    """The fixture is only useful if the graph agrees with the files on disk.

    ``scanned`` is the anti-vacuity guard: an empty node set would otherwise
    satisfy every assertion in the loop below.
    """
    root, _db_path = request.getfixturevalue(repo_fixture)
    conn = _db.connect(str(root))
    assert conn is not None
    scanned = 0
    for rel, text in sources.items():
        lines = text.splitlines()
        for node in _db.find_nodes(conn, file_path=rel, limit=0):
            if node["kind"] in skip_kinds:
                continue
            scanned += 1
            first = lines[node["start_line"] - 1].strip()
            if node["kind"] == "route":
                if check_route:
                    assert "@app.route(" in first, (node["id"], first)
                continue
            assert node["name"] in first, (node["id"], first)
    assert scanned >= _SPAN_FLOOR[repo_fixture], (repo_fixture, scanned)


# (repo fixture, CODEGRAPH_CHARS, the length that value must bind, tool, args)
_CHAR_CAP_CASES = [
    pytest.param("mini", "600", 700, authz.compare_sibling_route_security,
                 ("controllers.py:refund_order:route",), id="authz"),
]


@pytest.mark.parametrize("repo_fixture, chars, cap, tool, args", _CHAR_CAP_CASES)
def test_char_cap_is_applied(request, monkeypatch, repo_fixture, chars, cap, tool,
                             args):
    """``CODEGRAPH_CHARS`` truncates the module's own longest report."""
    root, _db_path = request.getfixturevalue(repo_fixture)
    monkeypatch.setenv("CODEGRAPH_CHARS", chars)
    out = tool.func(*args, str(root))
    assert len(out) <= cap
    assert "more chars (total" in out


def _contained_file_block_authz(root, db_path) -> None:
    """FIX 6: OSError out of the pathlib calls degrades to a miss.

    A NUL byte raises ValueError and a 400-byte component raises OSError
    (ENAMETOOLONG) out of ``is_file()``/``stat()``; both used to escape.
    """
    assert _contained_file(str(root), "bad\x00path") is None
    assert _contained_file(str(root), "a" * 400) is None
    assert _contained_file(str(root), "a" * 400 + "/wallet.py") is None
    assert _contained_file(str(root), "nope/../escape.py") is None

    # ... and a tool reading a node whose file_path is hostile returns a
    # string, not an exception.
    hostile = "a" * 400
    handle = sqlite3.connect(str(db_path))
    try:
        handle.executemany(
            _NODES_SQL,
            [_node("wallet.py:hostile", "method", "withdraw", hostile, "python",
                   11, 12, signature="def withdraw(self, amount):",
                   qualified_name="Wallet.withdraw")])
        handle.executemany(
            _EDGES_SQL,
            [("wallet.py:hostile", "accounts.py:balance", "references", None, 11, 18,
              "static")])
        handle.commit()
    finally:
        handle.close()
    close_cached()

    out = authz.find_shared_state_readers_writers.func("balance", str(root))
    assert "source not parseable" in out
    assert "reader/writer undecided" in out


def _contained_file_block_supply(root, _db_path) -> None:
    """S-1 / S-common: the read helper degrades, it does not raise."""
    hostile = [
        "a\x00b", "../../etc/passwd", "a" * 400, "b" * 400 + "/c",
        "a" * 300 + "/" + "b" * 300 + "/c.yaml",
    ]
    for path in hostile:
        assert supply._contained_file(str(root), path) is None, repr(path)
    # and a real file still resolves through the same helper
    assert supply._contained_file(str(root), "app.py") is not None


@pytest.mark.parametrize("repo_fixture, check", [
    pytest.param("mini", _contained_file_block_authz, id="authz"),
    pytest.param("supply_mini", _contained_file_block_supply, id="supply"),
])
def test_contained_file_never_raises_on_hostile_paths(request, repo_fixture, check):
    """Every contained-read helper degrades on hostile paths instead of raising.

    A NUL byte, a traversal spelling and an over-long component are all misses;
    supply's block also pins the real-file case, and authz's pins the tool that
    consumes the helper.
    """
    root, db_path = request.getfixturevalue(repo_fixture)
    check(root, db_path)

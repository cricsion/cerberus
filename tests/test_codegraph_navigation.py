"""Navigation tools: bounded source slices, one-hop argument maps, blind spots.

The fixture is the same mini-index ``tests/test_codegraph_foundation.py`` builds
(``build_mini_db``), because a tool's answer is only meaningful against spans
that match real files on disk. Where the shared fixture has no coverage — a
>60-line function to slice, a method reached through a receiver, an interface
with nine implementers — this file writes its own sources into the fixture repo
and inserts matching node/edge/unresolved_ref rows, deriving every span from the
text it just wrote so the graph cannot disagree with the disk.

Nothing here touches the network or the LLM; the only write is the summary
sidecar the tool itself is contracted to read.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from cerberus.codegraph import _db, summaries
from cerberus.codegraph import navigation as nav
from codegraph_support import close_cached, mini_index
from test_codegraph_foundation import NODE_COLUMNS, _node

# The CodeGraph ``nodes.language`` spelling for this module's own sources.
_LANGS = {"py": "python", "ts": "typescript", "tsx": "tsx"}

# How many implementers stand behind the "polymorphic" blind spot. CodeGraph
# flags a type as polymorphic at >= 8, so more than that must be seeded.
_IMPLEMENTERS = 9

# Files this module adds on top of the shared fixture (for the span check).
_EXTENDED_FILES = ("svc.py", "handler.py", "controller.py", "auth.py", "legacy.py",
                   "payments.py")

# ---------------------------------------------------------------------------
# in-test sources
# ---------------------------------------------------------------------------

# A class method called through a receiver — the case that shifts every
# positional argument by one when ``self`` is treated as an argument.
SVC_PY = '''\
class Exporter:
    """Sends a batch somewhere."""

    def handle(self, payload):
        return payload["rows"]


def run_export(payload):
    svc = Exporter()
    return svc.handle(payload)
'''

# 69 lines of def: past the 60-line verbatim threshold, with 18 declarations
# and 16 control-flow guards to cap.
HANDLER_PY = '''\
"""A deliberately long bulk-upload handler: not a verbatim answer."""
import json


def handle_bulk_upload(request, session, storage, logger):
    payload = request.json
    records = payload.get("records", [])
    accepted = []
    rejected = []
    total = len(records)
    index = 0
    retries = 0
    checksum = 0
    errors = []
    warnings = []
    batch_size = 25
    cursor = 0
    trace = payload.get("trace_id", "")
    while cursor < total:
        batch = records[cursor:cursor + batch_size]
        if not batch:
            break
        for record in batch:
            if not isinstance(record, dict):
                rejected.append(record)
                continue
            if record.get("trace_id") != trace:
                rejected.append(record)
                continue
            if index >= 100:
                warnings.append(record)
                continue
            if retries > 3:
                warnings.append(record)
                continue
            if record.get("amount") is None:
                rejected.append(record)
                continue
            if int(record.get("amount", 0)) < 0:
                rejected.append(record)
                continue
            if record.get("currency") not in ("usd", "eur"):
                rejected.append(record)
                continue
            if not record.get("merchant"):
                rejected.append(record)
                continue
            if len(record.get("note", "")) > 512:
                warnings.append(record)
                continue
            if record.get("duplicate"):
                warnings.append(record)
                continue
            try:
                stored = storage.put(record["id"], record)
            except OSError as exc:
                errors.append(str(exc))
                continue
            finally:
                checksum += 1
            accepted.append(stored)
            index += 1
        cursor += batch_size
        if len(accepted) > total:
            break
        if errors and len(errors) > 10:
            break
        if warnings:
            logger.warning("%s warnings", len(warnings))
    return json.dumps({"accepted": len(accepted),
                       "rejected": len(rejected),
                       "errors": errors})
'''

# 23 routine guards (loop bounds, dedupe checks, missing-field rejections) and
# then THREE guard-shaped rows at the END of the function: an expired session
# that returns 401, and two authorization tests. Under the old 12-row default
# cap every one of those three fell off the end of the guard section, so the
# slice answered "no guards here" about the exact row the finding is about.
CONTROLLER_PY = '''\
"""A long admin controller: routine guards first, the authorization checks last."""


def handle_admin_action(request, session, audit, cache, queue, mailer, logger):
    payload = request.json
    records = payload.get("records", [])
    accepted = []
    rejected = []
    total = len(records)
    index = 0
    retries = 0
    checksum = 0
    errors = []
    warnings = []
    batch_size = 25
    cursor = 0
    trace = payload.get("trace_id", "")
    while cursor < total:
        batch = records[cursor:cursor + batch_size]
        if not batch:
            break
        for record in batch:
            if not isinstance(record, dict):
                rejected.append(record)
                continue
            if record.get("trace_id") != trace:
                rejected.append(record)
                continue
            if index >= 100:
                warnings.append(record)
                continue
            if retries > 3:
                warnings.append(record)
                continue
            if record.get("amount") is None:
                rejected.append(record)
                continue
            if int(record.get("amount", 0)) < 0:
                rejected.append(record)
                continue
            if record.get("currency") not in ("usd", "eur"):
                rejected.append(record)
                continue
            if not record.get("merchant"):
                rejected.append(record)
                continue
            if len(record.get("note", "")) > 512:
                warnings.append(record)
                continue
            if record.get("duplicate"):
                warnings.append(record)
                continue
            if record.get("region") is None:
                rejected.append(record)
                continue
            if record.get("tenant") is None:
                rejected.append(record)
                continue
            if record.get("channel") is None:
                rejected.append(record)
                continue
            if record.get("locale") is None:
                rejected.append(record)
                continue
            if record.get("source") is None:
                rejected.append(record)
                continue
            if record.get("campaign") is None:
                rejected.append(record)
                continue
            if record.get("device") is None:
                rejected.append(record)
                continue
            if record.get("referrer") is None:
                rejected.append(record)
                continue
            if record.get("user_agent") is None:
                rejected.append(record)
                continue
            if record.get("session_id") is None:
                rejected.append(record)
                continue
            if record.get("ab_test") is None:
                rejected.append(record)
                continue
            if record.get("experiment") is None:
                rejected.append(record)
                continue
            if session.expired:
                return 401
            if not is_authorized(session.user, "admin"):
                audit.deny(session.user, "admin")
                return 403
            if not has_scope(session, "orders:write"):
                audit.deny(session, "orders:write")
                return 403
            accepted.append(record)
            index += 1
        cursor += batch_size
    return accepted
'''

# The module the index's resolver never reached: the seeded failed reference
# ``auth.verify_token`` in app.py really does resolve to this.
AUTH_PY = '''\
"""The module the resolver never reached."""


def verify_token(token, scopes):
    return {"sub": token, "scopes": scopes}
'''
# A bare name-tail match in another file, so ranking has something to lose to.
LEGACY_PY = '''\
def verify_token(token):
    return token
'''


def _payments_source(implementers: int) -> str:
    """An interface with ``implementers`` implementers, called through a key."""
    lines = ['"""A keyed dispatch behind a widely-implemented interface."""',
             "", "",
             "class RefundCache:", '    """The registry hides behind this."""',
             "", "    def get(self, order_id, key):",
             "        return self._store.get(key)", ""]
    for n in range(implementers):
        lines += [f"class Impl{n}:", "    def get(self, key):", "        return None", ""]
    lines += ["def refund(order, key):", "    cache = RefundCache()",
              "    return cache.get(order, key)"]
    return "\n".join(lines) + "\n"


def _span(lines: list[str], header: str, occurrence: int = 1) -> tuple[int, int]:
    """1-based (start, end) of the block whose header line contains ``header``.

    The block runs to the last line indented deeper than the header, which is
    the span a parser assigns to a ``def``/``class`` at that indent.
    """
    seen = 0
    start = 0
    for number, text in enumerate(lines, start=1):
        if header in text:
            seen += 1
            if seen == occurrence:
                start = number
                break
    assert start, f"no line contains {header!r}"
    indent = len(lines[start - 1]) - len(lines[start - 1].lstrip())
    end = start
    for number in range(start + 1, len(lines) + 1):
        text = lines[number - 1]
        if not text.strip():
            continue
        if (len(text) - len(text.lstrip())) <= indent:
            break
        end = number
    return start, end


def _block(path: Path, node_id, kind, name, header, *, occurrence=1,
           **kwargs) -> tuple[tuple, int, int]:
    """A symbol node whose span is read off the file just written."""
    start, end = _span(path.read_text().splitlines(), header, occurrence)
    row = _node(node_id, kind, name, path.name, _LANGS[path.suffix[1:]],
               start, end, **kwargs)
    return row, start, end


def _file_node(path: Path, node_id) -> tuple:
    """A file node: by definition the whole file."""
    lines = path.read_text().splitlines()
    return _node(node_id, "file", path.name, path.name,
                 _LANGS[path.suffix[1:]], 1, len(lines),
                 qualified_name=path.name)


def _build_rows(root: Path):
    """Write this module's sources and return their (nodes, edges, refs)."""
    nodes: list[tuple] = []
    edges: list[tuple] = []
    refs: list[tuple] = []

    svc = root / "svc.py"
    svc.write_text(SVC_PY)
    cls, cls_start, _cls_end = _block(svc, "svc.py:Exporter", "class", "Exporter",
                                      "class Exporter:", qualified_name="svc.Exporter")
    method, method_start, _method_end = _block(
        svc, "svc.py:Exporter.handle", "method", "handle", "def handle(self, payload)",
        signature="def handle(self, payload):",
        qualified_name="svc.Exporter.handle")
    func, func_start, func_end = _block(
        svc, "svc.py:run_export", "function", "run_export", "def run_export(payload)",
        signature="def run_export(payload):", is_exported=1,
        qualified_name="svc.run_export")
    nodes += [_file_node(svc, "svc.py:svc.py"), cls, method, func]
    edges += [
        ("svc.py:svc.py", "svc.py:Exporter", "contains", None, cls_start, 1, "static"),
        ("svc.py:Exporter", "svc.py:Exporter.handle", "contains", None,
         method_start, 5, "static"),
        ("svc.py:svc.py", "svc.py:run_export", "contains", None, func_start, 1, "static"),
        # a method reached through a receiver, at the callee's own column
        ("svc.py:run_export", "svc.py:Exporter.handle", "calls",
         json.dumps({"confidence": 0.9, "resolvedBy": "own-file"}), func_end, 12, "static"),
    ]

    handler = root / "handler.py"
    handler.write_text(HANDLER_PY)
    long_fn, long_start, long_end = _block(
        handler, "handler.py:handle_bulk_upload", "function", "handle_bulk_upload",
        "def handle_bulk_upload(",
        signature="def handle_bulk_upload(request, session, storage, logger):",
        is_exported=1, qualified_name="handler.handle_bulk_upload")
    nodes += [_file_node(handler, "handler.py:handler.py"), long_fn]
    edges.append(("handler.py:handler.py", "handler.py:handle_bulk_upload",
                  "contains", None, long_start, 1, "static"))

    controller = root / "controller.py"
    controller.write_text(CONTROLLER_PY)
    long_ctl, ctl_start, ctl_end = _block(
        controller, "controller.py:handle_admin_action", "function",
        "handle_admin_action", "def handle_admin_action(",
        signature="def handle_admin_action(request, session, audit, cache, queue, "
                  "mailer, logger):",
        is_exported=1, qualified_name="controller.handle_admin_action")
    nodes += [_file_node(controller, "controller.py:controller.py"), long_ctl]
    edges.append(("controller.py:controller.py", "controller.py:handle_admin_action",
                  "contains", None, ctl_start, 1, "static"))

    auth = root / "auth.py"
    auth.write_text(AUTH_PY)
    auth_fn, auth_start, _auth_end = _block(
        auth, "auth.py:verify_token", "function", "verify_token",
        "def verify_token(", signature="def verify_token(token, scopes):",
        qualified_name="auth.verify_token")
    nodes += [_file_node(auth, "auth.py:auth.py"), auth_fn]
    edges.append(("auth.py:auth.py", "auth.py:verify_token", "contains",
                  None, auth_start, 1, "static"))

    legacy = root / "legacy.py"
    legacy.write_text(LEGACY_PY)
    legacy_fn, legacy_start, _legacy_end = _block(
        legacy, "legacy.py:verify_token", "function", "verify_token",
        "def verify_token(", signature="def verify_token(token):",
        qualified_name="legacy.verify_token")
    nodes += [_file_node(legacy, "legacy.py:legacy.py"), legacy_fn]
    edges.append(("legacy.py:legacy.py", "legacy.py:verify_token", "contains",
                  None, legacy_start, 1, "static"))

    payments = root / "payments.py"
    payments.write_text(_payments_source(_IMPLEMENTERS))
    iface, iface_start, _ = _block(payments, "payments.py:RefundCache", "class",
                                   "RefundCache", "class RefundCache:",
                                   qualified_name="payments.RefundCache")
    iface_method, iface_method_start, _ = _block(
        payments, "payments.py:RefundCache.get", "method", "get",
        "def get(self, order_id, key):",
        signature="def get(self, order_id, key):",
        qualified_name="payments.RefundCache.get")
    refund, refund_start, _ = _block(payments, "payments.py:refund", "function",
                                     "refund", "def refund(order, key)",
                                     signature="def refund(order, key):",
                                     qualified_name="payments.refund")
    nodes += [_file_node(payments, "payments.py:payments.py"), iface, iface_method, refund]
    edges += [
        ("payments.py:payments.py", "payments.py:RefundCache", "contains",
         None, iface_start, 1, "static"),
        ("payments.py:RefundCache", "payments.py:RefundCache.get", "contains",
         None, iface_method_start, 5, "static"),
        ("payments.py:payments.py", "payments.py:refund", "contains",
         None, refund_start, 1, "static"),
    ]
    for n in range(_IMPLEMENTERS):
        impl, impl_start, _ = _block(payments, f"payments.py:Impl{n}", "class",
                                     f"Impl{n}", f"class Impl{n}:",
                                     qualified_name=f"payments.Impl{n}")
        impl_method, impl_method_start, _ = _block(
            payments, f"payments.py:Impl{n}.get", "method", "get",
            "def get(self, key):", occurrence=n + 1,
            signature="def get(self, key):", qualified_name=f"payments.Impl{n}.get")
        nodes += [impl, impl_method]
        edges += [
            (f"payments.py:Impl{n}", "payments.py:RefundCache", "implements",
             None, impl_start, 1, "static"),
            (f"payments.py:Impl{n}", f"payments.py:Impl{n}.get", "contains",
             None, impl_method_start, 5, "static"),
        ]
    pay_lines = payments.read_text().splitlines()
    ref_line = next(i for i, l in enumerate(pay_lines, 1)
                    if "cache.get(order, key)" in l)
    refs.append(("payments.py:refund", "cache.get", "call", ref_line, 10, None,
                 "payments.py", "python", "failed", "get"))

    # A node whose file is not on disk: graph metadata only, never an exception.
    nodes.append(_node("vendor/missing.py:gone", "function", "gone",
                       "vendor/missing.py", "python", 3, 8,
                       signature="def gone(x):", qualified_name="missing.gone"))

    # No `calls` edge for this pair, and a confidence under UNCERTAIN_BELOW=0.6.
    worker_lines = (root / "worker.py").read_text().splitlines()
    fuzzy_line = next(i for i, l in enumerate(worker_lines, 1)
                      if "unsafe_query(job.sql)" in l)
    edges.append(("worker.py:handle_export", "app.py:unsafe_query", "references",
                  json.dumps({"confidence": 0.4, "resolvedBy": "fuzzy"}),
                  fuzzy_line, 12, "static"))
    # Two SYNTHESIZED edges with NO metadata.registeredAt: one carries only the
    # heuristic provenance, the other only metadata.synthesizedBy. Both report a
    # line/col that belongs to nobody, which the basis must say out loud.
    edges += [
        ("app.py:login", "db.py:run_query", "calls",
         json.dumps({"confidence": 0.8, "resolvedBy": "name-only"}), 7, 12,
         "heuristic"),
        ("app.py:POST /login", "db.py:run_query", "calls",
         json.dumps({"synthesizedBy": "queue-job", "confidence": 0.7}), 7, 12,
         "heuristic"),
    ]
    return nodes, edges, refs


def _insert(db_path: Path, *, nodes=(), edges=(), refs=()) -> None:
    """Insert rows into the already-built mini index, then drop the cache."""
    conn = sqlite3.connect(str(db_path))
    try:
        if nodes:
            conn.executemany(
                f"INSERT OR REPLACE INTO nodes ({NODE_COLUMNS}) VALUES "
                f"({','.join('?' * len(NODE_COLUMNS.split(',')))})", nodes)
        if edges:
            conn.executemany(
                "INSERT INTO edges (source, target, kind, metadata, line, col, "
                "provenance) VALUES (?, ?, ?, ?, ?, ?, ?)", edges)
        if refs:
            conn.executemany(
                "INSERT INTO unresolved_refs (from_node_id, reference_name, "
                "reference_kind, line, col, candidates, file_path, language, "
                "status, name_tail) VALUES (?,?,?,?,?,?,?,?,?,?)", refs)
        conn.commit()
    finally:
        conn.close()
    # The cached handle is keyed on the db file and its mtime has not changed,
    # so drop it: the next connect() must see the rows just written.
    close_cached()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """The seeded mini index, with TARGET_REPO pointed at it per test."""
    with mini_index(tmp_path, monkeypatch) as index:
        yield index


@pytest.fixture
def extended(repo):
    """The mini index plus the sources and rows this module's cases need."""
    root, db_path = repo
    nodes, edges, refs = _build_rows(root)
    _insert(db_path, nodes=nodes, edges=edges, refs=refs)
    return root, db_path


# The long function's span, derived from the source this module writes, so the
# assertions below cannot drift from the fixture.
_HANDLER_LINES = HANDLER_PY.splitlines()
HANDLER_START, HANDLER_END = _span(_HANDLER_LINES, "def handle_bulk_upload(")
HANDLER_SPAN = HANDLER_END - HANDLER_START + 1
FILE_SPAN = len(_HANDLER_LINES)

# ... and the controller's: 26 guards whose last three are guard-shaped, so the
# guard-shaped rows sit at guard positions 24, 25 and 26 — past the default
# section cap, and exactly what a line-order truncation would drop first.
_CONTROLLER_LINES = CONTROLLER_PY.splitlines()
CTRL_START, CTRL_END = _span(_CONTROLLER_LINES, "def handle_admin_action(")
CTRL_SPAN = CTRL_END - CTRL_START + 1
CTRL_GUARDS = sum(1 for line in _CONTROLLER_LINES[CTRL_START - 1:CTRL_END]
                  if line.strip().startswith("if "))

def _line_of(path: Path, needle: str) -> int:
    return next(i for i, l in enumerate(path.read_text().splitlines(), 1) if needle in l)


def _line_of_text(lines: list[str], needle: str) -> int:
    """1-based line of ``needle`` inside an in-memory source."""
    return next(i for i, l in enumerate(lines, 1) if needle in l)


CTRL_CAP = nav._SECTION_LINES
# the guard-shaped rows, and the last two rows that must go instead
CTRL_AUTH_LINE = _line_of_text(_CONTROLLER_LINES, 'not is_authorized(session.user')
CTRL_SCOPE_LINE = _line_of_text(_CONTROLLER_LINES, 'not has_scope(session')
CTRL_EXPIRED_LINE = _line_of_text(_CONTROLLER_LINES, "if session.expired:")
CTRL_DROPPED_LINES = [
    _line_of_text(_CONTROLLER_LINES, 'if record.get("ab_test") is None:'),
    _line_of_text(_CONTROLLER_LINES, 'if record.get("experiment") is None:'),
]


def _section(body: list[str], title: str) -> list[str]:
    """The lines under a ``--- title`` header, up to the next header/footer."""
    start = next(i for i, l in enumerate(body) if l == f"--- {title}")
    out = []
    for line in body[start + 1:]:
        if line.startswith(("---", "sliced:", "…")):
            break
        out.append(line)
    return out


# ---------------------------------------------------------------------------
# degradation: no DB, containment escape, unknown ids
# ---------------------------------------------------------------------------

def test_every_tool_guides_when_the_repo_is_not_indexed(repo):
    root, _db_path = repo
    # an un-indexed directory INSIDE the repo: contained, but no codegraph.db
    empty = root / "unindexed"
    empty.mkdir()
    guidance = _db.guidance_no_db(str(empty))
    assert nav.get_ast_slice.func("app.py:login", root=str(empty)) == guidance
    assert nav.trace_interprocedural_hop.func("app.py:login", "app.py:unsafe_query",
                                              root=str(empty)) == guidance
    assert nav.resolve_blind_spot.func("app.py:login", root=str(empty)) == guidance


def test_containment_escape_is_an_error_string_not_an_exception(repo):
    root, _db_path = repo
    outside = str(root.parent.parent)
    assert nav.get_ast_slice.func("app.py:login", root=outside).startswith(
        "ERROR: path escapes repo:")
    assert nav.trace_interprocedural_hop.func("app.py:login", "app.py:unsafe_query",
                                              root=outside).startswith(
        "ERROR: path escapes repo:")
    assert nav.resolve_blind_spot.func("app.py:login", root=outside).startswith(
        "ERROR: path escapes repo:")


def test_unknown_node_ids_are_named_in_the_error(repo):
    assert nav.get_ast_slice.func("app.py:ghost") == "ERROR: node not found: app.py:ghost"
    assert nav.trace_interprocedural_hop.func("app.py:ghost", "app.py:login") == (
        "ERROR: node not found: app.py:ghost")
    assert nav.trace_interprocedural_hop.func("app.py:login", "app.py:ghost") == (
        "ERROR: node not found: app.py:ghost")
    assert nav.resolve_blind_spot.func("app.py:ghost") == (
        "ERROR: node not found: app.py:ghost")


# ---------------------------------------------------------------------------
# 1. get_ast_slice — the verbatim path
# ---------------------------------------------------------------------------

def test_full_span_injects_the_cached_summary(repo):
    root, _db_path = repo
    assert "[CACHED SUMMARY" not in nav.get_ast_slice.func("app.py:login", root=str(root))

    assert summaries.record_summary(str(root), "app.py:login", "SANITIZER", "89",
                                    "parameterises the query").startswith("recorded")
    out = nav.get_ast_slice.func("app.py:login", root=str(root))

    lines = out.splitlines()
    assert lines[0] == "# app.py:6-10 (function login)"
    assert "[CACHED SUMMARY: SANITIZER for CWE-89] parameterises the query" in lines
    assert 'decorators: @app.route("/login", methods=["POST"])' in lines
    assert "signature: def login(username, password):" in lines
    assert "6: def login(username, password):" in lines
    assert ('10:     return unsafe_query("SELECT * FROM users WHERE name = \'%s\'" '
            "% username)") in lines
    assert "11: " not in out
    assert "note:" not in out


def test_signature_and_decorators_come_from_the_index(repo):
    root, _db_path = repo
    out = nav.get_ast_slice.func("app.py:login", root=str(root))
    assert "signature: def login(username, password):" in out
    assert '@app.route("/login", methods=["POST"])' in out
    # a variable node carries neither
    plain = nav.get_ast_slice.func("worker.py:export_queue", root=str(root))
    assert "signature:" not in plain and "decorators:" not in plain
    assert "5: export_queue = Queue(\"exports\")" in plain


def test_body_mode_is_verbatim_even_when_the_span_is_long(extended):
    root, _db_path = extended
    out = nav.get_ast_slice.func("handler.py:handle_bulk_upload", mode="body",
                                 root=str(root))
    assert "note: span is" not in out
    assert "--- declarations" not in out
    assert "sliced:" not in out
    lines = (root / "handler.py").read_text().splitlines()
    assert f"{len(lines)}: {lines[-1]}" in out
    assert "5: def handle_bulk_upload(request, session, storage, logger):" in out


def test_body_mode_ignores_focus_line(extended):
    root, _db_path = extended
    focus = _line_of(root / "handler.py", "records = payload.get(")
    out = nav.get_ast_slice.func("handler.py:handle_bulk_upload", mode="body",
                                 focus_line=focus, root=str(root))
    assert f"note: focus_line {focus} ignored — full span shown" in out
    assert "--- focus" not in out


def test_def_use_slice_mode_slices_a_small_node_too(repo):
    """``def_use_slice`` names the question; a small span answers it verbatim."""
    root, _db_path = repo
    out = nav.get_ast_slice.func("app.py:login", mode="def_use_slice", root=str(root))
    # span <= 60 lines: the exact body is the better answer, so no slicing note
    assert "note: span is" not in out
    assert "--- def header" not in out
    assert "6: def login(username, password):" in out


def test_focus_line_outside_the_span_is_annotated(repo):
    root, _db_path = repo
    out = nav.get_ast_slice.func("app.py:login", focus_line=99, root=str(root))
    assert "note: focus_line 99 is outside node span 6-10 — full span shown" in out
    assert "6: def login(username, password):" in out


def test_a_malformed_focus_line_degrades_instead_of_raising(extended):
    root, _db_path = extended
    out = nav.get_ast_slice.func("handler.py:handle_bulk_upload",
                                 focus_line="not-a-line", root=str(root))
    assert "note: focus_line 'not-a-line' is not a line number — ignored" in out
    assert "--- focus" not in out


def test_unknown_mode_is_refused(repo):
    root, _db_path = repo
    out = nav.get_ast_slice.func("app.py:login", mode="everything", root=str(root))
    assert out.startswith("ERROR: unknown mode 'everything' (use one of ")
    assert "full_or_window, body, def_use_slice" in out


def test_a_node_whose_file_is_not_readable_returns_graph_metadata_only(extended):
    root, _db_path = extended
    out = nav.get_ast_slice.func("vendor/missing.py:gone", root=str(root))
    assert out.splitlines()[0] == "# vendor/missing.py:3-8 (function gone)"
    assert "signature: def gone(x):" in out
    assert "(source file not readable through this root" in out
    assert "node_modules/vendor are never indexed" in out


# ---------------------------------------------------------------------------
# 1. get_ast_slice — the sliced path
# ---------------------------------------------------------------------------

def test_a_long_span_comes_back_sliced(extended):
    root, _db_path = extended
    out = nav.get_ast_slice.func("handler.py:handle_bulk_upload", root=str(root))
    body = out.splitlines()
    assert body[0] == f"# handler.py:{HANDLER_START}-{HANDLER_END} " \
                      "(function handle_bulk_upload)"
    assert f"note: span is {HANDLER_SPAN} lines — sliced (mode=full_or_window)" in out
    assert "--- def header" in body
    assert "def handle_bulk_upload(request, session, storage, logger):" in body
    # the raw span is withheld: that is the whole point of the slice
    assert not any(line.startswith("37:") for line in body)
    # The default per-section cap is now wide enough that a 68-line handler
    # keeps every guard it has: the whole section comes back, un-truncated.
    assert "--- declarations (18 of 18)" in out
    assert "--- guards (16 of 16)" in out
    assert "… +" not in out
    assert (f"sliced: {HANDLER_SPAN} lines -> 36 shown (declarations 18/18, "
            f"guards 16/16, focus 0/0)") in out


def test_declarations_and_guards_are_capped_with_totals(extended):
    root, _db_path = extended
    body = nav.get_ast_slice.func(
        "handler.py:handle_bulk_upload", limit=3, root=str(root)).splitlines()
    assert body[body.index("--- declarations (3 of 18)") + 1:body.index(
        "--- declarations (3 of 18)") + 4] == [
            "6: payload = request.json",
            "7: records = payload.get(\"records\", [])",
            "8: accepted = []",
    ]
    assert "… +15 more declarations (total 18)" in body
    assert _section(body, "guards (3 of 16)") == [
        "21: not batch",
        "24: not isinstance(record, dict)",
        "27: record.get(\"trace_id\") != trace",
    ]
    assert "… +13 more guards (total 16)" in body
    # no focus section at all when no focus line was given
    assert "--- focus" not in body
    assert (f"sliced: {HANDLER_SPAN} lines -> 8 shown (declarations 3/18, "
            "guards 3/16, focus 0/0)") in body


def test_section_caps_honour_the_env_override(extended, monkeypatch):
    root, _db_path = extended
    monkeypatch.setenv("CODEGRAPH_SLICE_LIMIT", "2")
    assert "--- declarations (2 of 18)" in nav.get_ast_slice.func(
        "handler.py:handle_bulk_upload", root=str(root))
    assert "… +16 more declarations (total 18)" in nav.get_ast_slice.func(
        "handler.py:handle_bulk_upload", root=str(root))
    # an explicit argument still wins over the env var
    assert "--- declarations (5 of 18)" in nav.get_ast_slice.func(
        "handler.py:handle_bulk_upload", limit=5, root=str(root))


def test_focus_section_lists_only_the_identifier_users(extended):
    root, _db_path = extended
    focus = _line_of(root / "handler.py", "records = payload.get(")
    out = nav.get_ast_slice.func("handler.py:handle_bulk_upload", focus_line=focus,
                                 limit=3, root=str(root))
    body = out.splitlines()
    header = f"focus (line {focus}: records, payload, get) (3 of 11)"
    assert f"--- {header}" in body
    rows = _section(body, header)
    assert len(rows) == 3
    for row in rows:
        number, text = row.split(": ", 1)
        assert int(number) != focus                     # the focus line itself
        assert "records" in text or "payload" in text or "get" in text, row
    assert "… +8 more focus (total 11)" in body
    # a line that touches none of the focus identifiers never appears here
    assert not any("logger.warning" in row for row in rows)


def test_focus_line_without_identifiers_is_annotated(extended):
    root, _db_path = extended
    blank = _line_of(root / "handler.py", "        continue")
    out = nav.get_ast_slice.func("handler.py:handle_bulk_upload", focus_line=blank,
                                 root=str(root))
    assert f"note: no identifiers parsed on focus_line {blank}" in out


def test_focus_line_outside_the_node_span_is_annotated_in_a_slice(extended):
    root, _db_path = extended
    out = nav.get_ast_slice.func("handler.py:handle_bulk_upload", focus_line=1,
                                 root=str(root))
    assert f"note: focus_line 1 is outside node span {HANDLER_START}-{HANDLER_END}" in out


def test_the_character_cap_can_be_lowered_by_env(extended, monkeypatch):
    root, _db_path = extended
    monkeypatch.setenv("CODEGRAPH_CHARS", "400")
    out = nav.get_ast_slice.func("handler.py:handle_bulk_upload", mode="body",
                                 root=str(root))
    assert out.startswith(f"# handler.py:{HANDLER_START}-{HANDLER_END} "
                          "(function handle_bulk_upload)")
    assert "more chars (total" in out
    assert len(out) < 400 + 120                 # the cap, plus its own marker
    assert '"errors": errors})' not in out      # the tail is cut off


def test_a_file_node_has_no_def_to_slice(extended):
    root, _db_path = extended
    out = nav.get_ast_slice.func("handler.py:handler.py", mode="def_use_slice",
                                 root=str(root))
    body = out.splitlines()
    assert body[0] == f"# handler.py:1-{FILE_SPAN} (file handler.py)"
    assert f"note: span is {FILE_SPAN} lines — sliced (mode=def_use_slice)" in out
    assert "--- def header" not in body
    assert (f"sliced: {FILE_SPAN} lines -> 0 shown (declarations 0/0, "
            "guards 0/0, focus 0/0)") in body


# ---------------------------------------------------------------------------
# 1. get_ast_slice — the guard section cap keeps what a finding is about
# ---------------------------------------------------------------------------

def test_the_late_authorization_guard_survives_the_default_cap(extended):
    """N-1: the guard-shaped rows are the ones the cap keeps, in a >60-line fn.

    The controller's last three guards are ``session.expired`` (an early
    return) and the two authorization tests, so plain line-order truncation
    drops every one of them — the slice would then report a handler with no
    access control at all.
    """
    root, _db_path = extended
    out = nav.get_ast_slice.func("controller.py:handle_admin_action",
                                 root=str(root))
    body = out.splitlines()
    assert f"note: span is {CTRL_SPAN} lines — sliced (mode=full_or_window)" in out
    assert body[0] == f"# controller.py:{CTRL_START}-{CTRL_END} " \
                      "(function handle_admin_action)"
    # the cap really did bind: more guards exist than the section holds
    assert CTRL_GUARDS > CTRL_CAP
    assert f"--- guards ({CTRL_CAP} of {CTRL_GUARDS})" in body
    rows = _section(body, f"guards ({CTRL_CAP} of {CTRL_GUARDS})")
    assert len(rows) == CTRL_CAP
    kept = {int(row.split(": ", 1)[0]) for row in rows}
    # every guard-shaped row survived, including the one at the very end
    assert CTRL_EXPIRED_LINE in kept
    assert CTRL_AUTH_LINE in kept
    assert CTRL_SCOPE_LINE in kept
    assert f'{CTRL_AUTH_LINE}: not is_authorized(session.user, "admin")' in rows
    # ... and what went instead is the least security-relevant rows
    assert not (set(CTRL_DROPPED_LINES) & kept)
    for dropped in CTRL_DROPPED_LINES:
        assert not any(row.startswith(f"{dropped}: ") for row in body)
    # the section is still read top-down, so the auth guard is the last row
    assert rows[-1] == (f"{CTRL_SCOPE_LINE}: not has_scope(session, "
                        f"\"orders:write\")")
    # the output says the cap applies and names what it withheld
    assert (f"note: the guard section is capped at {CTRL_CAP} row(s) of "
            f"{CTRL_GUARDS}" in out)
    assert "guard-shaped conditions (authorization, permission, ownership, " \
           "validation and early-return guards) are kept first" in out
    dropped_list = out.split("least security-relevant rows were dropped: ")[1]
    dropped_list = dropped_list.splitlines()[0].split(";")[0]
    assert dropped_list == ", ".join(str(l) for l in CTRL_DROPPED_LINES)
    # no recovery path needed: pass mode='body' (or limit=0) for the rest
    assert "pass limit=0 (or mode='body') for the rest" in out


def test_an_explicit_limit_still_drives_the_cap(extended):
    """``limit`` keeps its meaning: it sets the cap, not the selection rule."""
    root, _db_path = extended
    out = nav.get_ast_slice.func("controller.py:handle_admin_action", limit=4,
                                 root=str(root))
    body = out.splitlines()
    assert f"--- guards (4 of {CTRL_GUARDS})" in body
    rows = _section(body, f"guards (4 of {CTRL_GUARDS})")
    assert len(rows) == 4
    # the guard-shaped rows are still the ones kept, and they are the LAST
    # guards in the function — a line-order slice would have shown none of them
    kept = {int(row.split(": ", 1)[0]) for row in rows}
    assert CTRL_AUTH_LINE in kept and CTRL_SCOPE_LINE in kept
    assert f"note: the guard section is capped at 4 row(s) of {CTRL_GUARDS}" in out


def test_declarations_are_capped_by_line_order_unchanged(extended):
    """Only the guard section is prioritised; declarations stay source-ordered."""
    root, _db_path = extended
    out = nav.get_ast_slice.func("controller.py:handle_admin_action", limit=3,
                                 root=str(root))
    assert "--- declarations (3 of 16)" in out
    rows = _section(out.splitlines(), "declarations (3 of 16)")
    assert [int(r.split(": ", 1)[0]) for r in rows] == [5, 6, 7]
    assert "payload = request.json" in rows[0]


def test_a_guard_with_no_security_shape_is_not_promoted(extended):
    """The promotion is about relevance, not syntax: routine rows stay routine."""
    root, _db_path = extended
    out = nav.get_ast_slice.func("handler.py:handle_bulk_upload", limit=3,
                                 root=str(root))
    rows = _section(out.splitlines(), "guards (3 of 16)")
    assert [int(r.split(": ", 1)[0]) for r in rows] == [21, 24, 27]


def test_the_guard_section_comes_back_whole_when_the_cap_allows(extended):
    root, _db_path = extended
    out = nav.get_ast_slice.func("handler.py:handle_bulk_upload", limit=0,
                                 root=str(root))
    body = out.splitlines()
    assert "--- guards (16 of 16)" in body
    assert "capped at" not in out
    assert "… +" not in out


# ---------------------------------------------------------------------------
# 2. trace_interprocedural_hop
# ---------------------------------------------------------------------------

def test_a_calls_edge_reports_the_argument_that_crossed_it(repo):
    root, _db_path = repo
    payload = json.loads(nav.trace_interprocedural_hop.func(
        "app.py:login", "app.py:unsafe_query", root=str(root)))
    assert payload["edge_kind"] == "calls"
    assert payload["call_site"] == "app.py:10"
    assert payload["call_site_basis"] == "edge line/col"
    assert payload["provenance"] == "static"
    assert payload["synthesized_by"] is None
    assert payload["wiring_site"] is None
    assert payload["confidence"] == 0.9
    assert payload["edge_line_col"] == {"line": 10, "col": 12}
    assert payload["arg_to_param_map"] == [{
        "call_arg_index": 0,
        "call_expr": "\"SELECT * FROM users WHERE name = '%s'\" % username",
        "callee_param": "sql",
        "param_type": "",
        "keyword": None,
    }]
    window = payload["caller_window"].splitlines()
    assert window[0] == "7:     user = auth.verify_token(username)"
    assert "10:     return unsafe_query(\"SELECT * FROM users WHERE name = '%s'\" % username)" \
        in window
    assert len(window) == 7                     # radius 3 around line 10
    assert payload["notes"] == []


def test_a_cross_file_hop_locates_the_call_site_in_the_caller(extended):
    root, _db_path = extended
    payload = json.loads(nav.trace_interprocedural_hop.func(
        "worker.py:handle_export", "app.py:unsafe_query", root=str(root)))
    assert payload["call_site"] == "worker.py:13"
    assert payload["edge_kind"] == "references"
    assert payload["arg_to_param_map"][0] == {
        "call_arg_index": 0, "call_expr": "job.sql", "callee_param": "sql",
        "param_type": "", "keyword": None}
    assert payload["caller_window"].splitlines()[-1] == (
        "13:     return unsafe_query(job.sql)")


def test_a_receiver_is_not_an_argument(extended):
    root, _db_path = extended
    payload = json.loads(nav.trace_interprocedural_hop.func(
        "svc.py:run_export", "svc.py:Exporter.handle", root=str(root)))
    assert payload["call_site"] == "svc.py:10"
    assert payload["edge_line_col"] == {"line": 10, "col": 12}
    # `svc.handle(payload)`: one argument, one real parameter — no shift.
    assert payload["arg_to_param_map"] == [
        {"call_arg_index": 0, "call_expr": "payload", "callee_param": "payload",
         "param_type": "", "keyword": None}]
    assert any("receiver is implicit" in note for note in payload["notes"])
    assert not any("arity differs" in note for note in payload["notes"])


def test_a_synthesized_edge_resolves_its_wiring_site(repo):
    root, _db_path = repo
    payload = json.loads(nav.trace_interprocedural_hop.func(
        "worker.py:enqueue_export", "worker.py:handle_export", root=str(root)))
    assert payload["provenance"] == "heuristic"
    assert payload["synthesized_by"] == "queue-job"
    assert payload["wiring_site"] == "queues.py:28"
    # the edge's own line/col are a placeholder: the wiring site IS the site
    assert payload["call_site"] == "queues.py:28"
    assert "registeredAt" in payload["call_site_basis"]
    assert "suspect" in payload["call_site_basis"]
    assert payload["confidence"] == 0.85
    assert payload["edge_line_col"] == {"line": 9, "col": 5}
    assert payload["arg_to_param_map"] == []
    assert any("synthesized edge (queue-job)" in n for n in payload["notes"])
    assert any("no textual call to this target" in n for n in payload["notes"])
    assert any("caller_window is centred on the edge's own (suspect) line 9"
               in n for n in payload["notes"])


@pytest.mark.parametrize("source_id,target_id", [
    # provenance='heuristic' and nothing else: no wiring site anywhere
    ("app.py:login", "db.py:run_query"),
    # metadata.synthesizedBy, still no registeredAt to fall back on
    ("app.py:POST /login", "db.py:run_query"),
])
def test_a_synthesized_edge_without_registered_at_says_the_line_is_a_placeholder(
        extended, source_id, target_id):
    """T-1: the basis must not call a synthesizer's coordinate a call site."""
    root, _db_path = extended
    payload = json.loads(nav.trace_interprocedural_hop.func(
        source_id, target_id, root=str(root)))
    assert payload["wiring_site"] is None
    assert payload["call_site"] == "app.py:7"
    assert payload["call_site_basis"] == nav.SUSPECT_LINE_BASIS
    assert "suspect" in payload["call_site_basis"]
    assert "no registeredAt" in payload["call_site_basis"]
    assert "placeholder" in payload["call_site_basis"]
    # it is a statement about the edge, not a silent trust in the coordinate
    assert payload["edge_line_col"] == {"line": 7, "col": 12}
    assert payload["provenance"] == "heuristic"


def test_a_resolved_edge_still_reports_a_plain_line_basis(repo):
    root, _db_path = repo
    payload = json.loads(nav.trace_interprocedural_hop.func(
        "app.py:login", "app.py:unsafe_query", root=str(root)))
    assert payload["call_site_basis"] == "edge line/col"
    assert "suspect" not in payload["call_site_basis"]


def test_low_confidence_and_a_missing_calls_edge_are_both_flagged(extended):
    _root, _db_path = extended
    payload = json.loads(nav.trace_interprocedural_hop.func(
        "worker.py:handle_export", "app.py:unsafe_query", root=str(_root)))
    assert payload["confidence"] == 0.4
    assert any("UNCERTAIN_BELOW=0.6" in n for n in payload["notes"])
    assert any("falling back to kind='references'" in n for n in payload["notes"])
    # the call is still parsed locally, so the argument binding survives
    assert payload["arg_to_param_map"][0]["call_expr"] == "job.sql"


def test_a_missing_edge_points_at_the_blind_spot(extended):
    root, _db_path = extended
    out = nav.trace_interprocedural_hop.func("app.py:login", "auth.py:verify_token",
                                             root=str(root))
    assert out.startswith("# no edge from app.py:login to auth.py:verify_token")
    assert "unresolved ref: auth.verify_token at app.py:7 (kind call, status failed)" in out
    assert "the resolver saw this reference and failed on it" in out
    assert "hint: call resolve_blind_spot(node_id='app.py:login')" in out


def test_a_missing_edge_without_a_matching_ref_says_so(repo):
    root, _db_path = repo
    out = nav.trace_interprocedural_hop.func("app.py:login", "db.py:run_query",
                                             root=str(root))
    assert "no unresolved ref matching 'run_query' either" in out
    assert "genuinely unconnected" in out
    assert "resolve_blind_spot" in out


# ---------------------------------------------------------------------------
# 3. resolve_blind_spot
# ---------------------------------------------------------------------------

def test_a_failed_reference_is_ranked_with_reasons(extended):
    root, _db_path = extended
    out = nav.resolve_blind_spot.func("app.py:login", root=str(root))
    assert out.startswith("# blind spot recovery: app.py:login (app.py)")
    assert "1 unresolved reference(s) for this node" in out
    assert "## 1. auth.verify_token @ app.py:7" in out
    assert "reference_name: auth.verify_token  name_tail: verify_token" in out
    assert "kind: call  status: failed" in out
    assert "call-site arity: 1 (parsed from app.py:7)" in out

    body = out.splitlines()
    start = body.index("   candidates (2 of 2):")
    # exact qualified name beats a bare tail, and the arity near-miss costs a point
    assert "   1. score 7  auth.py:4  function verify_token" in body[start:start + 4]
    assert "   2. score 5  legacy.py:1  function verify_token" in body[start:start + 6]
    assert "why: exact qualified name; name_tail; same language; arity 1~2" in out
    assert "why: name_tail; same language; arity 1/1" in out
    assert "node_id: auth.py:verify_token" in out
    assert "node_id: legacy.py:verify_token" in out
    assert "hint: pick a candidate node_id and call trace_interprocedural_hop" in out


def test_a_polymorphic_interface_is_flagged(extended):
    root, _db_path = extended
    out = nav.resolve_blind_spot.func("payments.py:refund", root=str(root))
    assert "## 1. cache.get @ payments.py:48" in out
    assert "name_tail: get  kind: call  status: failed" in out
    assert "call-site arity: 2 (parsed from payments.py:48)" in out

    body = out.splitlines()
    start = body.index("   candidates (5 of 11):")
    assert "   1. score 8  payments.py:7  method get" in body[start:start + 4]
    assert ("why: name_tail; same file; same language; arity 2/2; 9 implementer(s) "
            "— polymorphic (dynamic dispatch decides)") in out
    assert "node_id: payments.py:RefundCache.get" in out
    # the implementers themselves rank below, with no implementer bonus of their own
    assert "   2. score 6  payments.py:11  method get" in body[start:start + 6]
    assert "why: name_tail; same file; same language; arity 2~1" in out
    # The dynamic-dispatch note rides the interface resolution alone: the
    # ranked implementers below it do not re-explain polymorphism per row.
    assert (len([l for l in out.splitlines()
                 if "why:" in l and "polymorphic" in l]) == 1)


def test_implementers_are_counted_for_class_and_method_kinds(extended):
    root, _db_path = extended
    conn = _db.connect(str(root))
    ref = {"reference_name": "cache.get", "name_tail": "get", "file_path": "payments.py",
           "language": "python"}
    for node_id in ("payments.py:RefundCache", "payments.py:RefundCache.get"):
        _score, why = nav._score_candidate(_db.get_node(conn, node_id), ref, 2,
                                           conn, str(root), {})
        assert "9 implementer(s) — polymorphic (dynamic dispatch decides)" in why, node_id


def test_the_reference_list_falls_back_to_the_file(repo):
    root, _db_path = repo
    # the variable node has no refs of its own, but its file does
    out = nav.resolve_blind_spot.func("worker.py:export_queue", root=str(root))
    assert out.startswith("# blind spot recovery: worker.py:export_queue (worker.py)")
    assert "file-level fallback" in out
    assert "references near this node, not necessarily inside it" in out
    assert "1 unresolved reference(s) for this node" in out
    assert "## 1. unsafe_query @ worker.py:13" in out
    assert "reference_name: unsafe_query  name_tail: unsafe_query" in out
    assert "kind: call  status: pending" in out
    assert "1. score 8  app.py:13  function unsafe_query" in out
    assert "why: exact name; name_tail; same language; arity 1/1" in out


def test_the_file_fallback_marker_is_absent_when_the_node_matched(repo):
    """R-1: the same count line, but only the fallback is labelled."""
    root, _db_path = repo
    direct = nav.resolve_blind_spot.func("app.py:login", root=str(root))
    assert "1 unresolved reference(s) for this node" in direct
    assert "file-level fallback" not in direct
    # ... while a node with nothing of its own and nothing in its file says so
    assert nav.resolve_blind_spot.func("db.py:run_query", root=str(root)) == (
        "# no unresolved references for db.py:run_query (db.py) "
        "— nothing to recover")


def test_the_reference_list_is_truncated_with_a_total(extended):
    root, db_path = extended
    refs = [("db.py:DB_PATH", f"zz_call_{n}", "call", n + 1, 1, None, "db.py",
             "python", "failed", f"zz_call_{n}") for n in range(25)]
    _insert(db_path, refs=refs)
    out = nav.resolve_blind_spot.func("db.py:DB_PATH", root=str(root))
    assert "25 unresolved reference(s) for this node" in out
    assert "## 20. zz_call_19 @ db.py:20" in out
    assert "## 21." not in out
    assert out.count("\n## ") == 20
    assert "… +5 more references (total 25" in out
    assert "candidates: none found for 'zz_call_0'" in out


def test_a_node_without_unresolved_references_has_nothing_to_recover(repo):
    root, _db_path = repo
    assert nav.resolve_blind_spot.func("db.py:run_query", root=str(root)) == (
        "# no unresolved references for db.py:run_query (db.py) "
        "— nothing to recover")


def test_a_reference_with_no_candidate_says_so(repo):
    root, _db_path = repo
    out = nav.resolve_blind_spot.func("app.py:login", root=str(root))
    assert "## 1. auth.verify_token @ app.py:7" in out
    assert "candidates: none found for 'verify_token'" in out
    assert "(vendor/node_modules are never indexed)" in out


# ---------------------------------------------------------------------------
# hostile input: every returned string is capped, and nothing raises
# ---------------------------------------------------------------------------

# What the audit bound into these tools: a node id the host cannot address
# (NUL byte, a component past NAME_MAX), one SQLite cannot store (a lone
# surrogate) and one simply too large to echo back verbatim.
HOSTILE_IDS = [
    pytest.param("z" * 200_000, id="200000-char-node-id"),
    pytest.param("app.py:log\ud800in", id="lone-surrogate"),
    pytest.param("a\x00b", id="nul-byte"),
    pytest.param("a" * 400, id="400-byte-component"),
]


def _calls_with(hostile: str, root: Path) -> list[str]:
    """Every navigation answer that echoes an agent-supplied id back."""
    return [
        nav.get_ast_slice.func(hostile, root=str(root)),
        nav.trace_interprocedural_hop.func(hostile, "app.py:login", root=str(root)),
        nav.trace_interprocedural_hop.func("app.py:login", hostile, root=str(root)),
        nav.trace_interprocedural_hop.func(hostile, "app.py:ghost",
                                           root=str(root)),
        nav.resolve_blind_spot.func(hostile, root=str(root)),
    ]


@pytest.mark.parametrize("hostile", HOSTILE_IDS)
def test_hostile_node_ids_never_raise_and_echo_nothing_back(extended, monkeypatch,
                                                            hostile):
    """X-common: an ERROR string is a string, so the char cap applies to it too."""
    root, _db_path = extended
    monkeypatch.setenv("CODEGRAPH_CHARS", "200")
    for out in _calls_with(hostile, root):
        assert isinstance(out, str)
        assert out.startswith(("ERROR:", "#")), out[:80]
        assert len(out) <= 200 + 64, len(out)
        if len(hostile) > 200:
            assert "more chars (total" in out, out[-80:]


def test_a_short_error_string_is_returned_verbatim(repo):
    """Capping a string that fits is a no-op, marker and all."""
    root, _db_path = repo
    out = nav.get_ast_slice.func("app.py:login", mode="nonsense", root=str(root))
    assert out == ("ERROR: unknown mode 'nonsense' (use one of full_or_window, "
                   "body, def_use_slice)")
    assert nav.get_ast_slice.func("app.py:ghost", root=str(root)) == (
        "ERROR: node not found: app.py:ghost")
    # a short id SQLite can never store is still just an error string
    assert nav.get_ast_slice.func("app.py:ghost\ud800", root=str(root)) == (
        "ERROR: node not found: app.py:ghost\ud800")
    assert nav.resolve_blind_spot.func("app.py:ghost\ud800", root=str(root)) == (
        "ERROR: node not found: app.py:ghost\ud800")


@pytest.mark.parametrize("hostile", HOSTILE_IDS)
def test_hostile_node_ids_are_capped_at_the_default_budget_too(extended, hostile):
    root, _db_path = extended
    for out in _calls_with(hostile, root):
        assert len(out) <= 20000 + 64, len(out)


def test_a_hostile_root_is_a_string_not_an_exception(extended):
    """X-common: a root the OS cannot address degrades, and is capped too."""
    root, _db_path = extended
    for bad_root in ("a\x00b", "/a\x00b", "a" * 400, "b" * 200_000):
        for out in (nav.get_ast_slice.func("app.py:login", root=bad_root),
                    nav.trace_interprocedural_hop.func("app.py:login",
                                                       "app.py:unsafe_query",
                                                       root=bad_root),
                    nav.resolve_blind_spot.func("app.py:login", root=bad_root)):
            assert isinstance(out, str)
            assert out.startswith(("ERROR:", "(no codegraph index"))
            assert len(out) <= 20000 + 64, len(out)


# ---------------------------------------------------------------------------
# fixture honesty: the extended rows agree with the files on disk
# ---------------------------------------------------------------------------

def test_extended_nodes_match_their_own_source(extended):
    root, _db_path = extended
    conn = _db.connect(str(root))
    for node in _db.find_nodes(conn, limit=0):
        if node["kind"] == "file" or node["file_path"] not in _EXTENDED_FILES:
            continue  # a file node spans the whole file by definition
        lines = (root / node["file_path"]).read_text().splitlines()
        first = lines[node["start_line"] - 1]
        assert node["end_line"] >= node["start_line"]
        assert node["name"] in first, f"{node['id']} at {node['start_line']}: {first!r}"
        if node["kind"] in ("method", "class"):
            assert first.lstrip().startswith(("def ", "class ")), first


def test_the_long_handler_really_is_longer_than_the_verbatim_threshold(extended):
    root, _db_path = extended
    node = _db.get_node(_db.connect(str(root)), "handler.py:handle_bulk_upload")
    assert (node["start_line"], node["end_line"]) == (HANDLER_START, HANDLER_END)
    assert HANDLER_SPAN > nav._SMALL_SPAN_LINES
    assert HANDLER_SPAN == 68

"""Tests for cerberus.codegraph.supply — egress and SSRF target inspection.

The fixture extends the shared mini index with four network calls: a dynamic
host, a constant literal, a one-hop identifier and a dynamic path/query.

Every node span is derived from the file text (:func:`_fn_span`) rather than
hard-coded, so a fixture edit cannot silently desynchronise graph from source.
"""
from __future__ import annotations

import sqlite3

import pytest
from _graphseed import GraphSeed
from cerberus.codegraph import _db, supply
from cerberus.config import reset_config
from codegraph_support import (
    _assert_finding_schema,
    _finding_blocks,
    _fn_span,
    close_cached,
    mini_index,
)
from test_codegraph_foundation import _EDGES_SQL, _NODES_SQL, NODE_COLUMNS, _node

# ---------------------------------------------------------------------------
# fixture source
# ---------------------------------------------------------------------------

EGRESS_PY = '''\
import requests


def fetch_dynamic_host(user_domain):
    return requests.get(f"https://{user_domain}/api")


def fetch_constant():
    return requests.get("https://api.example.com/v1/status")


def fetch_via_identifier():
    target = "https://api.example.com/v1/status"
    return requests.get(target)


def fetch_dynamic_path(resource):
    return requests.get(f"https://api.example.com/v1/{resource}")


def fetch_dynamic_query(term):
    return requests.get(f"https://api.example.com/v1/search?q={term}")


def identity(value):
    return value


def local_value():
    return identity("local")
'''

SOURCES = {
    "egress.py": EGRESS_PY,
}


# ---------------------------------------------------------------------------
# span helpers — the graph must agree with the files on disk
# ---------------------------------------------------------------------------

def _line_of(text: str, needle: str) -> int:
    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    raise AssertionError(f"no line containing {needle!r}")


# ---------------------------------------------------------------------------
# fixture
# ---------------------------------------------------------------------------

def _seed_rows(root, db_path) -> None:
    """Write the extra sources and the nodes/edges/refs rows they imply."""
    seed = GraphSeed(root, db_path, SOURCES, rel_paths=True)
    seed.write_sources()
    nodes, edges = seed.nodes, seed.edges
    file_node, contains = seed.file_node, seed.contains

    # ---- egress.py: network calls plus a non-network control ----------------
    egress = file_node("egress.py", EGRESS_PY, "python")
    for name in ("fetch_dynamic_host", "fetch_constant", "fetch_via_identifier",
                 "fetch_dynamic_path", "fetch_dynamic_query", "identity",
                 "local_value"):
        start, end = _fn_span(EGRESS_PY, name)
        nodes.append(_node(f"egress.py:{name}", "function", name, "egress.py",
                           "python", start, end, signature=f"def {name}():",
                           qualified_name=f"egress.{name}"))
        contains(egress, f"egress.py:{name}", start)
    # A wrapper node inside fetch_dynamic_host: the tool must fall back to the
    # enclosing function instead of scanning the one line this node spans.
    wrapper_line = _line_of(EGRESS_PY, "return requests.get(f\"https://{user_domain}")
    nodes.append(_node("egress.py:target_url", "variable", "target_url",
                       "egress.py", "python", wrapper_line, wrapper_line,
                       signature="target_url = f\"https://{user_domain}/api\""))

    seed.flush()


@pytest.fixture
def mini(tmp_path, monkeypatch):
    """The foundation's mini index, extended with egress fixture rows."""
    with mini_index(tmp_path, monkeypatch, _seed_rows,
                    unset_env=("CODEGRAPH_CHARS",)) as index:
        yield index


# ---------------------------------------------------------------------------
# 1. trace_egress_and_ssrf_targets
# ---------------------------------------------------------------------------

def test_ssrf_verdicts_from_one_file(mini):
    root, _db_path = mini
    dynamic = supply.trace_egress_and_ssrf_targets.func(
        "egress.py:fetch_dynamic_host", str(root))
    assert "# egress & ssrf: egress.py:fetch_dynamic_host" in dynamic
    assert "network: 1" in dynamic
    assert f"file: egress.py  line: " \
           f"{_line_of(EGRESS_PY, 'requests.get(f')}" in dynamic
    assert "call: requests.get" in dynamic
    assert "url_arg: f\"https://{user_domain}/api\"" in dynamic
    assert "host={} DYNAMIC" in dynamic
    assert "scheme=https CONSTANT" in dynamic
    assert "path=/api CONSTANT" in dynamic
    assert "verdict: HOST_DYNAMIC" in dynamic
    blocks = _finding_blocks(dynamic)
    assert len(blocks) == 1
    _assert_finding_schema(blocks[0])
    assert blocks[0]["cwe"] == "CWE-918"
    assert blocks[0]["severity"] == "high"

    constant = supply.trace_egress_and_ssrf_targets.func(
        "egress.py:fetch_constant", str(root))
    assert "verdict: FULLY_CONSTANT" in constant
    assert "host=api.example.com CONSTANT" in constant
    assert _finding_blocks(constant) == []
    assert "none: every network call in this span targets a" in constant

    path_dynamic = supply.trace_egress_and_ssrf_targets.func(
        "egress.py:fetch_dynamic_path", str(root))
    assert "path=/v1/{} DYNAMIC" in path_dynamic
    assert "host=api.example.com CONSTANT" in path_dynamic
    assert "verdict: PATH_DYNAMIC" in path_dynamic
    blocks = _finding_blocks(path_dynamic)
    assert len(blocks) == 1 and blocks[0]["severity"] == "high"

    query_dynamic = supply.trace_egress_and_ssrf_targets.func(
        "egress.py:fetch_dynamic_query", str(root))
    assert "query=q={} DYNAMIC" in query_dynamic
    assert "verdict: PARTIAL" in query_dynamic
    blocks = _finding_blocks(query_dynamic)
    assert len(blocks) == 1 and blocks[0]["severity"] == "medium"
    assert blocks[0]["cwe"] == "CWE-918"


def test_one_hop_identifier_resolution(mini):
    root, _db_path = mini
    out = supply.trace_egress_and_ssrf_targets.func(
        "egress.py:fetch_via_identifier", str(root))
    assert "url_arg: target" in out
    assert "resolved: one-hop assignment target = " \
           "\"https://api.example.com/v1/status\"" in out
    assert "host=api.example.com CONSTANT" in out
    assert "verdict: FULLY_CONSTANT" in out
    assert _finding_blocks(out) == []


def test_wrapper_node_falls_back_to_the_enclosing_function(mini):
    """A non-function node is scanned through its enclosing function."""
    root, _db_path = mini
    out = supply.trace_egress_and_ssrf_targets.func(
        "egress.py:target_url", str(root))
    assert "node: egress.py:5 (variable target_url, 5)" in out
    assert "span: egress.py:4-5" in out
    assert "verdict: HOST_DYNAMIC" in out


def test_no_network_call_in_span(mini):
    root, _db_path = mini
    out = supply.trace_egress_and_ssrf_targets.func(
        "egress.py:local_value", str(root))
    assert "no network call in this span" in out
    assert "calls in span: 1  network: 0" in out
    assert _finding_blocks(out) == []


def test_egress_limit_and_char_cap(mini, monkeypatch):
    root, _db_path = mini
    out = supply.trace_egress_and_ssrf_targets.func(
        "egress.py:fetch_dynamic_host", str(root), limit=0)
    assert "network: 1" in out
    monkeypatch.setenv("CODEGRAPH_CHARS", "400")
    reset_config()
    capped = supply.trace_egress_and_ssrf_targets.func(
        "egress.py:fetch_dynamic_host", str(root))
    assert len(capped) <= 500
    assert "more chars (total" in capped


def test_unresolvable_identifier_is_dynamic(mini):
    """A URL threaded in from the caller reads as dynamic, never as constant."""
    root, db_path = mini
    source = '''\
import requests


def fetch_remote(host):
    return requests.get(host)
'''
    (root / "remote.py").write_text(source)
    start, end = _fn_span(source, "fetch_remote")
    nodes = [
        _node("remote.py:remote.py", "file", "remote.py", "remote.py", "python",
              1, len(source.splitlines())),
        _node("remote.py:fetch_remote", "function", "fetch_remote", "remote.py",
              "python", start, end, signature="def fetch_remote(host):",
              qualified_name="remote.fetch_remote"),
    ]
    edges = [
        ("remote.py:remote.py", "remote.py:fetch_remote", "contains", None, start,
         1, "static"),
    ]
    handle = sqlite3.connect(str(db_path))
    try:
        handle.executemany(_NODES_SQL, nodes)
        handle.executemany(_EDGES_SQL, edges)
        handle.commit()
    finally:
        handle.close()
    close_cached()

    out = supply.trace_egress_and_ssrf_targets.func(
        "remote.py:fetch_remote", str(root))
    assert "url_arg: host" in out
    assert "unresolved local host" in out
    assert "host={} DYNAMIC" in out
    assert "verdict: HOST_DYNAMIC" in out
    blocks = _finding_blocks(out)
    assert len(blocks) == 1 and blocks[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# 2. pure helpers: URL skeleton and part classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("expression,skeleton", [
    ('"https://api.example.com/v1"', "https://api.example.com/v1"),
    ("'https://api.example.com/v1'", "https://api.example.com/v1"),
    ('f"https://{user_domain}/api"', "https://\x00/api"),
    ('"https://${host}/api"', "https://\x00/api"),
    ('f"https://api.example.com/v1/{resource}"',
     "https://api.example.com/v1/\x00"),
    ('"https://api.example.com/s?q=" + q', "https://api.example.com/s?q=\x00"),
    ('host + "/api"', "\x00/api"),
    ('"https://api.example.com:" + port + "/v1"',
     "https://api.example.com:\x00/v1"),
    ("", ""),
])
def test_url_skeleton_marks_the_dynamic_regions(expression, skeleton):
    assert supply._url_skeleton(expression) == skeleton


@pytest.mark.parametrize("expression,host,path,verdict", [
    # a plain literal: every part constant
    ('"https://api.example.com/v1/status"', "api.example.com", "/v1/status",
     "FULLY_CONSTANT"),
    # the host is interpolated: full SSRF
    ('f"https://{user_domain}/api"', "\x00", "/api", "HOST_DYNAMIC"),
    # the host is a bare identifier
    ("host", "\x00", "", "HOST_DYNAMIC"),
    # only the path is built
    ('f"https://api.example.com/v1/{resource}"', "api.example.com",
     "/v1/\x00", "PATH_DYNAMIC"),
    # only the query is built
    ('f"https://api.example.com/v1/search?q={term}"', "api.example.com",
     "/v1/search", "PARTIAL"),
    # only the port is built
    ('f"https://api.example.com:{port}/v1"', "api.example.com", "/v1",
     "PARTIAL"),
    # the scheme itself is built
    ('f"{scheme}://api.example.com/v1"', "api.example.com", "/v1", "PARTIAL"),
    # no authority at all, and the path is built: the whole target moves
    ('f"{base}/api"', "\x00", "/api", "HOST_DYNAMIC"),
])
def test_url_parts_and_verdicts(expression, host, path, verdict):
    parts = supply._url_parts(expression)
    assert parts["host"]["value"] == host
    assert parts["path"]["value"] == path
    got = supply._egress_verdict(parts)[0]
    assert got == verdict, (expression, got)


def test_url_parts_port_and_userinfo_and_ipv6():
    parts = supply._url_parts('"https://user:pw@api.example.com:8443/v1?a=b#frag"')
    assert parts["host"]["value"] == "api.example.com"
    assert parts["port"]["value"] == "8443"
    assert parts["port"]["kind"] == "CONSTANT"
    assert parts["path"]["value"] == "/v1"
    assert parts["query"]["value"] == "a=b#frag" or parts["query"]["value"] == "a=b"
    assert all(parts[k]["kind"] == "CONSTANT" for k in parts)

    ipv6 = supply._url_parts('"https://[2001:db8::1]:9000/v1"')
    assert ipv6["host"]["value"] == "[2001:db8::1]"
    assert ipv6["port"]["value"] == "9000"

    # a dynamic port is the PARTIAL shape
    dynamic_port = supply._url_parts('f"https://api.example.com:{port}/v1"')
    assert dynamic_port["port"]["kind"] == "DYNAMIC"
    assert supply._egress_verdict(dynamic_port)[0] == "PARTIAL"


def test_empty_expression_is_fully_dynamic_not_constant():
    parts = supply._url_parts("")
    assert all(parts[key]["kind"] == "DYNAMIC" for key in parts)
    assert supply._egress_verdict(parts)[0] == "HOST_DYNAMIC"


# ---------------------------------------------------------------------------
# 3. caps and truncation markers
# ---------------------------------------------------------------------------


def test_egress_site_cap(mini):
    root, _db_path = mini
    out = supply.trace_egress_and_ssrf_targets.func(
        "egress.py:fetch_dynamic_host", str(root), limit=1)
    assert "network: 1" in out
    assert "verdict: HOST_DYNAMIC" in out


def test_helpers_never_raise_on_odd_input():
    # The contract is a string, always; these are the shapes an agent sends.
    assert supply._url_parts(None) is not None
    assert supply._callee_tail("") == ""


def test_tool_schemas_are_parseable():
    """``parse_docstring`` must have read the docstring into a schema."""
    tool_fn = supply.trace_egress_and_ssrf_targets
    schema = tool_fn.args_schema
    assert schema is not None
    fields = set(schema.model_fields)
    assert {"root", "limit"} <= fields, (tool_fn.name, fields)
    assert tool_fn.description and len(tool_fn.description) > 100

# ---------------------------------------------------------------------------
# 4. egress regressions
# ---------------------------------------------------------------------------


def test_egress_keyword_url_argument_is_not_an_ssrf(mini):
    """S-2: ``url=`` must not reach the URL parser."""
    root, db_path = mini
    source = '''\
import requests


def fetch_constant():
    return requests.get(url="https://api.example.com/v1", timeout=5)


def fetch_reordered():
    return requests.get(timeout=5, url="https://api.example.com/v1")


def fetch_positional():
    return requests.get("https://api.example.com/v1", timeout=5)


def fetch_dynamic_host(host):
    return requests.get(url=f"https://{host}/api")
'''
    (root / "kw.py").write_text(source)
    nodes = [
        _node("kw.py:kw.py", "file", "kw.py", "kw.py", "python", 1,
              len(source.splitlines())),
    ]
    for name in ("fetch_constant", "fetch_reordered", "fetch_positional",
                 "fetch_dynamic_host"):
        start, end = _fn_span(source, name)
        nodes.append(_node(f"kw.py:{name}", "function", name, "kw.py", "python",
                           start, end, signature=f"def {name}():",
                           qualified_name=f"kw.{name}"))
    edges = [("kw.py:kw.py", f"kw.py:{name}", "contains", None, 1, 1, "static")
             for name in ("fetch_constant", "fetch_reordered",
                          "fetch_positional", "fetch_dynamic_host")]
    handle = sqlite3.connect(str(db_path))
    try:
        handle.executemany(_NODES_SQL, nodes)
        handle.executemany(_EDGES_SQL, edges)
        handle.commit()
    finally:
        handle.close()
    close_cached()

    for name in ("fetch_constant", "fetch_reordered", "fetch_positional"):
        out = supply.trace_egress_and_ssrf_targets.func(f"kw.py:{name}", str(root))
        assert "url_arg: " in out
        assert "host=api.example.com CONSTANT" in out, (name, out)
        assert "verdict: FULLY_CONSTANT" in out, (name, out)
        assert "scheme=https CONSTANT" in out, (name, out)
        assert _finding_blocks(out) == [], (name, out)

    # the keyword form still reports the argument as written ...
    constant = supply.trace_egress_and_ssrf_targets.func("kw.py:fetch_constant",
                                                         str(root))
    assert 'url_arg: url="https://api.example.com/v1"' in constant
    assert "url=\"https CONSTANT" not in constant

    # ... and a dynamic host behind a keyword is still the real finding
    dynamic = supply.trace_egress_and_ssrf_targets.func(
        "kw.py:fetch_dynamic_host", str(root))
    assert "host={} DYNAMIC" in dynamic
    assert "verdict: HOST_DYNAMIC" in dynamic
    assert len(_finding_blocks(dynamic)) == 1


def test_strip_keyword_prefix_helper():
    assert supply._strip_keyword_prefix('url="https://x/v1"', "url") == \
        '"https://x/v1"'
    assert supply._strip_keyword_prefix("url=f\"https://{d}/api\"", "url") == \
        'f"https://{d}/api"'
    assert supply._strip_keyword_prefix("https://x", "") == "https://x"
    assert supply._strip_keyword_prefix("target = 5", "target") == "5"
    # == is not a keyword assignment
    assert supply._strip_keyword_prefix("target == 5", "target") == "target == 5"
    assert supply._strip_keyword_prefix("", "url") == ""

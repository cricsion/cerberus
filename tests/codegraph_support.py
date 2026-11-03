"""Scaffolding shared by the ``test_codegraph_*`` modules.

Not a ``test_*`` module, so pytest never collects it: it is imported by name
from the seven CodeGraph test modules, which all live in a flat ``tests/``
directory (no ``__init__.py``).  Both the test modules themselves and pytest's
own importer therefore reach the sibling test modules through ``tests/`` on
``sys.path`` — the bare ``test_codegraph_foundation`` name — so
``build_mini_db``/``_node``/``NODE_COLUMNS`` and every fixture below are a
single object in ``sys.modules`` regardless of which test module imported
first.

Fixtures defined here (``conn``) resolve their dependencies — ``mini`` — in the
namespace of the module that imports them, so each test module's own seeded
index is what gets connected to.

Everything here was lifted verbatim from the copies the test modules carried;
the per-module source constants and ``_seed_rows`` seeding stay with their
tests, because they are test inputs rather than scaffolding.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest
from cerberus.codegraph import _db

# The literal nvm path the host CLI is installed under (a bare ``pytest`` may
# run with a PATH that lacks it) — used only to *find* a CLI; the build shells
# the absolute path.
_NVM_CLI = Path("/Users/critical/.nvm/versions/node/v23.6.1/bin/codegraph")


def live_cli() -> str:
    """Absolute path to a real codegraph CLI, or skip (the host may not carry one)."""
    found = os.environ.get("CODEGRAPH_CLI") or shutil.which("codegraph")
    if found:
        return found
    if _NVM_CLI.is_file():
        return str(_NVM_CLI)
    pytest.skip("codegraph CLI not installed")



# ---------------------------------------------------------------------------
# span helpers — the graph must agree with the files on disk
# ---------------------------------------------------------------------------

def _block_span(text: str, pattern: str) -> tuple[int, int]:
    """(start, end) of the ``pattern``-headed block, derived from the text.

    Brace/indent-agnostic: the block ends at the first same-or-lower indent
    line that is not a closer (``}``/``)``/``]``) or a comment, with trailing
    blank lines trimmed — one rule for the python, typescript and kotlin
    fixtures alike.
    """
    lines = text.splitlines()
    head = re.compile(pattern)
    start = None
    indent = 0
    for index, line in enumerate(lines, start=1):
        match = head.match(line)
        if match:
            start = index
            indent = len(match.group(1))
            break
    assert start is not None, f"no block matches {pattern!r}"
    end = start
    for index in range(start + 1, len(lines) + 1):
        line = lines[index - 1]
        if not line.strip():
            end = index
            continue
        current = len(line) - len(line.lstrip())
        if current <= indent and not line.lstrip().startswith(("#", ")", "]", "}")):
            end = index - 1
            break
        end = index
    while end > start and not lines[end - 1].strip():
        end -= 1
    return start, end


def _fn_span(text: str, name: str) -> tuple[int, int]:
    return _block_span(text, rf"^(\s*)(?:async\s+)?def\s+{re.escape(name)}\s*\(")


def _route_line(text: str, url_fragment: str) -> int:
    """The decorator line that registers a route — where CodeGraph puts the node."""
    for index, line in enumerate(text.splitlines(), start=1):
        if "@app.route(" in line and url_fragment in line:
            return index
    raise AssertionError(f"no route decorator for {url_fragment!r}")


def _route_node(node_id: str, name: str, file_path: str, language: str,
                start: int, end: int) -> tuple:
    from test_codegraph_foundation import _node

    return _node(node_id, "route", name, file_path, language, start, end,
                 qualified_name=f"{file_path}:{name}")


def _insert_rows(db_path, nodes, edges) -> None:
    """Append node/edge rows to an index the caller has already built."""
    from test_codegraph_foundation import _EDGES_SQL, _NODES_SQL

    handle = sqlite3.connect(str(db_path))
    try:
        handle.executemany(_NODES_SQL, nodes)
        handle.executemany(_EDGES_SQL, edges)
        handle.commit()
    finally:
        handle.close()


# ---------------------------------------------------------------------------
# test-support cache teardown
# ---------------------------------------------------------------------------

def close_cached() -> None:
    """Close all cached ``_db`` connections and reset the open-mode gate."""
    with _db._LOCK:
        for _key, (_mtime, _mode, conn) in _db._CONN_CACHE.items():
            if conn is not None:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
        _db._CONN_CACHE.clear()
        _db.last_open_mode = ""


# ---------------------------------------------------------------------------
# fixture scaffolding
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def mini_index(tmp_path, monkeypatch, seed=None, *,
               unset_env: tuple[str, ...] = ()) -> Iterator[tuple]:
    """The skeleton every module's ``mini``/``repo`` fixture is built from.

    The fixtures in these modules all did the same four things: build the mini
    index, write their own extra sources and rows (``seed``), point
    ``TARGET_REPO`` at the tmp root while clearing the env keys the module
    owns (``unset_env``), and keep ``_db``'s cached handle from leaking into
    the next test.  Yields ``(root, db_path)``.
    """
    from test_codegraph_foundation import build_mini_db

    db_path = build_mini_db(tmp_path)
    if seed is not None:
        seed(tmp_path, db_path)
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    for key in unset_env:
        monkeypatch.delenv(key, raising=False)
    close_cached()
    try:
        yield tmp_path, db_path
    finally:
        close_cached()


@pytest.fixture
def conn(mini):
    """A live handle into the index the importing module's ``mini`` seeded."""
    root, _db_path = mini
    handle = _db.connect(str(root))
    assert handle is not None
    return handle


# ---------------------------------------------------------------------------
# output helpers
# ---------------------------------------------------------------------------

def _finding_blocks(text: str) -> list[dict]:
    """Every candidate-finding JSON block a tool emitted, in order."""
    decoder = json.JSONDecoder()
    out: list[dict] = []
    cursor = 0
    while True:
        start = text.find("candidate finding", cursor)
        if start < 0:
            return out
        brace = text.find("{", start)
        if brace < 0:
            return out
        try:
            obj, _end = decoder.raw_decode(text[brace:])
        except ValueError:
            cursor = start + len("candidate finding")
            continue
        out.append(obj)
        cursor = brace + 1


FINDING_KEYS = {"path", "start_line", "end_line", "cwe", "severity", "confidence",
                "taint", "evidence"}


def _assert_finding_schema(finding: dict) -> None:
    assert FINDING_KEYS <= set(finding), sorted(FINDING_KEYS - set(finding))
    assert isinstance(finding["path"], str) and finding["path"]
    assert isinstance(finding["start_line"], int) and finding["start_line"] > 0
    assert isinstance(finding["end_line"], int)
    assert finding["cwe"].startswith("CWE-")
    assert finding["severity"] in ("critical", "high", "medium", "low", "info")
    assert 0.0 <= float(finding["confidence"]) <= 1.0
    taint = finding["taint"]
    assert set(taint) >= {"source", "sink", "path"}
    assert isinstance(taint["path"], list) and taint["path"]
    assert finding["evidence"]

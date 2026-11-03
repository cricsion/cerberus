"""Tests for cerberus.codegraph.contracts — declared type contracts.

The fixture is the foundation's mini index (``build_mini_db``: real source files
whose node spans match them, the ``/login`` route with its decorators, cross-file
call edges, a synthesized queue-job edge, unresolved refs, a generated file)
EXTENDED here with the rows the contract question needs:

- ``user.dto.ts`` — a class-validator DTO whose fields carry ``@IsUUID()``,
  ``@IsEmail()``, ``@Length(...)`` and ``@IsOptional()``, plus one bare field;
- ``schema.sql`` — the ``CREATE TABLE IF NOT EXISTS user_profiles`` those fields
  persist to, with a ``NOT NULL``, a ``DEFAULT`` and a table constraint that
  must not be mistaken for a column.

Every node span is derived from the file text (:func:`_block_span` /
:func:`_ts_field_span`) rather than hard-coded, so a fixture edit cannot
silently desynchronise the graph from the source on disk.
"""
from __future__ import annotations

import json
import re

import pytest
from _graphseed import GraphSeed
from cerberus.codegraph import _db, contracts
from cerberus.config import reset_config
from codegraph_support import _block_span, close_cached, mini_index
from test_codegraph_foundation import _node, build_mini_db

# ---------------------------------------------------------------------------
# fixture source
# ---------------------------------------------------------------------------

USER_DTO_TS = '''\
import { IsUUID, IsEmail, Length, IsOptional } from "class-validator";

export class UserProfile {
  @IsUUID()
  id: string;

  @IsEmail()
  @Length(5, 254)
  email: string;

  @IsOptional()
  @Length(0, 200)
  note: string;

  role: string;
}
'''

SCHEMA_SQL = '''\
-- the table UserProfile persists to
CREATE TABLE IF NOT EXISTS user_profiles (
    id UUID NOT NULL PRIMARY KEY,
    email VARCHAR(254) NOT NULL DEFAULT 'none',
    note TEXT,
    role VARCHAR(32) NOT NULL,
    UNIQUE (email)
);
'''

SOURCES = {
    "user.dto.ts": USER_DTO_TS,
    "schema.sql": SCHEMA_SQL,
}


# ---------------------------------------------------------------------------
# span helpers — the graph must agree with the files on disk
# ---------------------------------------------------------------------------

def _ts_class_span(text: str, name: str) -> tuple[int, int]:
    return _block_span(text, rf"^(\s*)(?:export\s+)?class\s+{re.escape(name)}\b")


def _ts_field_span(text: str, name: str) -> tuple[int, int]:
    """A TS field's span starts at its decorator, the way CodeGraph records it."""
    lines = text.splitlines()
    declaration = None
    for index, line in enumerate(lines, start=1):
        if re.match(rf"^\s*{re.escape(name)}\s*:", line):
            declaration = index
            break
    assert declaration is not None, f"no field {name!r}"
    start = declaration
    for index in range(declaration - 1, 0, -1):
        stripped = lines[index - 1].strip()
        if stripped.startswith("@"):
            start = index
            continue
        break
    return start, declaration


# ---------------------------------------------------------------------------
# fixture
# ---------------------------------------------------------------------------

def _seed_rows(root, db_path) -> None:
    """Write the extra sources and the nodes/edges/files rows they imply."""
    seed = GraphSeed(root, db_path, SOURCES)
    seed.write_sources()
    nodes, edges, files = seed.nodes, seed.edges, seed.files
    file_node, contains = seed.file_node, seed.contains

    # ---- user.dto.ts: a class-validator DTO -----------------------------
    dto_file = file_node("user.dto.ts", USER_DTO_TS, "typescript")
    class_start, class_end = _ts_class_span(USER_DTO_TS, "UserProfile")
    dto_id = "user.dto.ts:UserProfile"
    nodes.append(_node(dto_id, "class", "UserProfile", "user.dto.ts", "typescript",
                       class_start, class_end,
                       signature="class UserProfile", is_exported=1,
                       qualified_name="user.dto.UserProfile"))
    contains(dto_file, dto_id, class_start)
    # (field, decorators as CodeGraph stores them, validated?)
    fields = [
        ("id", ['@IsUUID()']),
        ("email", ['@IsEmail()', '@Length(5, 254)']),
        ("note", ['@IsOptional()', '@Length(0, 200)']),
        ("role", []),
    ]
    for field_name, decorators in fields:
        start, end = _ts_field_span(USER_DTO_TS, field_name)
        field_id = f"user.dto.ts:{field_name}"
        nodes.append(_node(field_id, "property", field_name, "user.dto.ts",
                           "typescript", start, end,
                           signature=f"{field_name}: string",
                           decorators=json.dumps(decorators) if decorators else None,
                           qualified_name=f"user.dto.UserProfile.{field_name}"))
        contains(dto_id, field_id, start)

    seed.flush()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """The mini index, extended, with TARGET_REPO pointed at it."""
    with mini_index(tmp_path, monkeypatch, _seed_rows,
                    unset_env=("SAST_SUMMARIES_DB",)) as index:
        yield index


# ---------------------------------------------------------------------------
# 1. inspect_type_contract
# ---------------------------------------------------------------------------

def test_dto_fields_decorators_and_validation_summary(repo):
    root, _db_path = repo
    out = contracts.inspect_type_contract.func("UserProfile", str(root))
    assert "ERROR" not in out
    # header: file:line, kind, node id
    assert "# type contract: user.dto.ts:3-16 (class UserProfile)" in out
    assert "node_id: user.dto.ts:UserProfile" in out
    assert "(resolved by exact name)" in out
    # fields with their types and decorators
    assert "--- fields (4 of 4)" in out
    assert "id  : string  @IsUUID()  <validated: IsUUID>" in out
    assert "email  : string  @IsEmail(), @Length(5, 254)" in out
    assert "<validated: IsEmail, Length>" in out
    assert "note  : string  @IsOptional(), @Length(0, 200)" in out
    # the bare field is rendered, and named as unvalidated
    assert "role  : string" in out
    assert "no validator decorator on: role" in out
    assert "--- validation summary (3 of 4" in out
    # the db sidecar: CREATE TABLE columns, constraints not columns
    assert "--- db columns (4 of 4; table UserProfile in schema.sql)" in out
    assert "id  UUID  [NOT NULL PRIMARY KEY]" in out
    assert "email  VARCHAR  [NOT NULL DEFAULT 'none']" in out
    assert "note  TEXT" in out
    assert "role  VARCHAR  [NOT NULL]" in out
    assert "UNIQUE" not in out.split("--- db columns")[1]


def test_resolution_by_node_id_and_by_name(repo):
    root, _db_path = repo
    by_id = contracts.inspect_type_contract.func("user.dto.ts:UserProfile", str(root))
    assert "# type contract: user.dto.ts:3-16 (class UserProfile)" in by_id
    assert "(resolved by node id)" in by_id
    # a function resolves too: its parameters come from nodes.signature when the
    # index carries no parameter children
    login = contracts.inspect_type_contract.func("login", str(root))
    assert "(function login)" in login
    assert "--- parameters (2 of 2)" in login
    assert "username" in login and "password" in login
    assert "--- validation summary: no framework validator decorators" in login
    # substring fallback, bounded
    like = contracts.inspect_type_contract.func("UserProf", str(root))
    assert "(resolved by name substring)" in like
    assert "UserProfile" in like
    # unknown symbol is an error, not a crash
    missing = contracts.inspect_type_contract.func("NoSuchThing", str(root))
    assert missing.startswith("ERROR: no type or function named")
    # a class-like node with no fields says so rather than inventing rows
    account = contracts.inspect_type_contract.func("app.py:login", str(root))
    assert "ERROR" not in account


def test_no_sql_sidecar_without_sql_files(tmp_path, monkeypatch):
    """A name that looks like a table, in a repo with no .sql files: no columns."""
    db_path = build_mini_db(tmp_path)
    _seed_rows(tmp_path, db_path)
    (tmp_path / "schema.sql").unlink()
    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    close_cached()
    out = contracts.inspect_type_contract.func("UserProfile", str(tmp_path))
    assert "# type contract: user.dto.ts:3-16 (class UserProfile)" in out
    assert "--- fields (4 of 4)" in out
    assert "--- db columns" not in out
    close_cached()


def test_field_limit_and_char_cap(repo, monkeypatch):
    """``limit`` caps what is RENDERED; every total names what was withheld."""
    root, _db_path = repo
    out = contracts.inspect_type_contract.func("UserProfile", str(root), 2)
    assert "--- fields (2 of 4)" in out
    assert "… +2 more fields (total 4)" in out
    # the withheld rows are counted rather than silently dropped, in the
    # validation summary and in the db sidecar alike
    assert "no validator decorator on: role" in out
    assert "… +1 more validated fields" in out
    assert "--- db columns (2 of 4; table UserProfile in schema.sql)" in out
    assert "… +2 more columns (total 4)" in out

    # the overall character budget, and a marker that says it was applied
    monkeypatch.setenv("CODEGRAPH_CHARS", "300")
    reset_config()
    capped = contracts.inspect_type_contract.func("UserProfile", str(root))
    assert capped.startswith("# type contract: user.dto.ts:3-16")
    assert "more chars (total " in capped
    assert len(capped) < 400          # 300 chars plus the marker
    assert "--- db columns" not in capped   # the truncation really cut


def test_declared_type_falls_back_to_type_parameters_and_return_type():
    """Grammars that keep the type outside ``signature`` still resolve a type.

    Java/C# field declarations and TS interfaces carry the declared type in
    ``type_parameters`` (or ``return_type``) with ``signature`` holding only the
    name, so the field row must not read "(untyped)" for them.
    """
    assert contracts._declared_type({"signature": "", "type_parameters": ["UUID"]}) \
        == "UUID"
    assert contracts._declared_type({"signature": None, "type_parameters": None,
                                     "return_type": "Promise<User>"}) == "Promise<User>"
    # the signature path still wins, and a call default is not mistaken for it
    assert contracts._declared_type({"signature": "id: UUID = Field(...)"}) == "UUID"
    assert contracts._declared_type({"signature": ""}) == ""


# ---------------------------------------------------------------------------
# 2. hostile input
# ---------------------------------------------------------------------------

HOSTILE_INPUTS = [
    pytest.param("z" * 200_000, id="200000-chars"),
    pytest.param("app.py:log\ud800in", id="lone-surrogate"),
    pytest.param("a\x00b", id="nul-byte"),
    pytest.param("b" * 500, id="500-byte-component"),
]


@pytest.mark.parametrize("hostile", HOSTILE_INPUTS)
def test_hostile_inputs_are_capped_and_never_raise(repo, monkeypatch, hostile):
    """X-common: an ERROR string is a string, so the char cap applies to it."""
    root, _db_path = repo
    monkeypatch.setenv("CODEGRAPH_CHARS", "200")
    out = contracts.inspect_type_contract.func(hostile, str(root))
    assert isinstance(out, str), type(out)
    assert out.startswith(("ERROR:", "#", "(no")), out[:80]
    assert len(out) <= 200 + 64, len(out)

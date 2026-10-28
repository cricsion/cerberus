"""Declared type contracts — the Taint & Injection boundary tool.

The hunter works at framework boundaries (DTO, request body, ORM entity),
which is also where its false positives live: an ``UUID`` field decorated
``@IsUUID()`` was never "an arbitrary attacker string". So
:func:`inspect_type_contract` renders declared fields/parameters plus matching
``CREATE TABLE`` columns.

Laws (each pinned by ``tests/test_codgraph_contracts.py``):

- LAW-1 — contracts are DECLARED, FOUND or RECORDED, never inferred: indexed
  structure only, and ``.sql`` columns only when a ``.sql`` file exists.
- LAW-2 — the ladder is closed: node id, exact name, name substring, echoed as
  ``(resolved by …)``; a miss is an ``ERROR:``/guidance string, never a raise.
- LAW-3 — sections are bounded: ``HARD_MAX_SECTION`` rows, ``---
  <section> (k of n)`` headers, and the ``CODEGRAPH_CHARS`` budget applied once
  at the end (see :class:`harness.codegraph._common.Report`).
- LAW-4 — the report never mutates the index: reads only.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from harness.codegraph import _common, _db, _ts, summaries
from harness.codegraph._common import (
    _as_int,
    _cap_chars,
    _cap_rows,
    _split_top_level,
)
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


class _ContractReport(_common.Report):
    """Keep the old fluent ``add(*lines)`` shape over the shared report API."""

    def add(self, *lines: str) -> "_ContractReport":
        """Append one or more already-rendered lines and keep the chain fluent."""
        self.lines.extend(lines)
        return self


# caps — env-key strings and values are frozen (MUST-NOT-CHANGE #2)

HARD_MAX_SECTION = 200   # per-section ceiling before _db.HARD_MAX_ROWS applies

ENV_FIELDS = "CODEGRAPH_FIELDS_LIMIT"
ENV_SQL_FILES = "CODEGRAPH_SQL_FILES_LIMIT"
ENV_COLUMNS = "CODEGRAPH_COLUMNS_LIMIT"

DEFAULT_FIELDS = 60      # fields / parameters rendered per type
DEFAULT_SQL_FILES = 40   # .sql files searched for a CREATE TABLE
DEFAULT_COLUMNS = 60     # columns rendered per matched table
MAX_DECORATORS = 12      # a node with 40 decorators is not an answer
MAX_SQL_BYTES = _ts.MAX_FILE_BYTES  # the indexer's own per-file cap


# shared primitives — bodies live in ``_common`` (or ``_ts``); the module-level
# names and signatures stay here so the published surface does not move

def _truncate_line(text: str, cap: int = 200) -> str:
    """Flatten whitespace and truncate at ``cap``; call sites state their cap."""
    return _common._truncate_line(text, cap)


# node-kind vocabularies (CodeGraph ``nodes.kind``, NOT tree-sitter node types)

# What :func:`inspect_type_contract` will resolve a bare symbol name to.
_TYPE_KINDS = ("class", "struct", "interface", "protocol", "trait", "enum",
               "type_alias", "component", "record", "union", "object", "mixin",
               "annotation", "function", "method", "constructor")

# The subset that carries FIELDS rather than parameters. Kept separate from
# ``_ts.CLASS_NODE_TYPES`` (tree-sitter node types) on purpose — the two
# vocabularies are not interchangeable and matching them silently never hits.
_CLASS_LIKE_KINDS = frozenset({
    "class", "struct", "interface", "protocol", "trait", "enum", "type_alias",
    "record", "union", "object", "mixin", "annotation", "component",
})

# The children a DTO's fields are stored as (a class's ``contains`` edges).
_FIELD_KINDS = ("property", "field", "variable", "constant")

# The kind a member row is EXPECTED to carry in each section, so an unexpected
# one is annotated instead of quietly looking like its neighbours. Keyed on the
# section title, NOT on its singular: ``"fields".rstrip("s")`` is ``"field"``,
# which never equals the ``property`` a TypeScript field is actually stored as.
_SECTION_CANONICAL_KIND = {"fields": "property", "parameters": "parameter"}


# Framework validation decorators, by name pattern. This is what lets an agent
# downgrade "arbitrary attacker string" on a DTO field: class-validator,
# pydantic, DRF and friends all spell their guarantees this way.
_VALIDATOR_NAMES = (
    "Is", "Max", "Min", "Length", "UUID", "Email", "Matches", "Validate",
    "Strict", "Positive", "Negative", "Int", "Float", "Decimal", "Enum",
    "Optional", "Json", "Array", "Nested", "Url", "URI", "Date", "Datetime",
    "Size", "Range", "Pattern", "NotBlank", "NotEmpty", "NotNull", "Email",
    "CreditCard", "IBAN", "Phone", "JSONField", "Slug", "Boolean", "Number",
)
# Compiled at import time (``re`` memoises it); ``re.escape``-dependent, so it is
# deliberately never hoisted behind a function call (audit A-F13 / B verdict e).
_VALIDATOR_RE = re.compile(r"\b(?:" + "|".join(_VALIDATOR_NAMES) + r")\w*\b",
                           re.IGNORECASE)

# A DTO/entity name that is worth looking for in a .sql file.
_TABLE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Column clauses that open a table constraint rather than a column.
_TABLE_CONSTRAINT_HEADS = frozenset({
    "PRIMARY", "FOREIGN", "CONSTRAINT", "UNIQUE", "CHECK", "INDEX", "KEY",
    "EXCLUDE", "PERIOD",
})
# Directories a .sql search never enters (CodeGraph's own index, vendored trees
# and build output).
_SQL_SKIP_DIRS = frozenset({
    ".codegraph", "node_modules", "vendor", "dist", "build", "target", ".git",
    "__pycache__", ".venv", "venv",
})


# 1. inspect_type_contract

def _looks_like_table(name: str) -> bool:
    """True when ``name`` could be a table name (not dotted, spaced or empty)."""
    return bool(_TABLE_NAME_RE.match(str(name or "")))


def _plural(stem: str) -> str:
    """The English plural of a table-name stem (``user_profile`` -> ``…s``)."""
    if not stem:
        return ""
    if stem.endswith(("s", "x", "z", "ch", "sh")):
        return stem + "es"
    if stem.endswith("y") and len(stem) > 1 and stem[-2] not in "aeiou":
        return stem[:-1] + "ies"
    return stem + "s"


def _table_name_variants(name: str) -> list[str]:
    """Try raw, lowercase, snake-case and squashed table spellings, then plurals."""
    raw = str(name or "").strip()
    if not raw:
        return []
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", raw).lower()
    squashed = snake.replace("_", "")
    out = list(dict.fromkeys(c for c in (raw, raw.lower(), snake, squashed) if c))
    for stem in (snake, squashed, raw.lower()):
        plural = _plural(stem)
        if plural and plural not in out:
            out.append(plural)
    return out


def _sql_files(root: str, cap: int) -> list[Path]:
    """Bounded, contained walk for ``*.sql`` files under ``root``."""
    try:
        base = _safe_path(str(root) if root is not None else ".")
        if base.is_file():
            base = base.parent
    except (OSError, ValueError):
        return []
    found: list[Path] = []
    stack = [base]
    while stack and len(found) < cap:
        try:
            entries = sorted(stack.pop().iterdir())
        except OSError:
            continue
        for entry in entries:
            if len(found) >= cap:
                break
            try:
                if entry.is_dir() and entry.name not in _SQL_SKIP_DIRS:
                    stack.append(entry)
                elif entry.is_file() and entry.suffix.lower() == ".sql":
                    found.append(entry)
            except OSError:
                continue
    return found


def _matching_paren(text: str, open_index: int) -> int:
    """Index of the ``)`` matching the ``(`` at ``open_index`` (-1 if unbalanced)."""
    depth, quote, i = 0, "", open_index
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            quote = "" if ch == quote else quote
        elif ch in "\"'`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _parse_create_table(name: str, text: str) -> list[dict]:
    """Return parsed CREATE TABLE columns, balancing quotes and nested parens."""
    pattern = re.compile(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"'`\[]?" + re.escape(name)
        + r"[\"'`\]]?\s*\(", re.IGNORECASE)
    for match in pattern.finditer(text):
        close = _matching_paren(text, match.end() - 1)
        if close < 0:
            continue
        columns: list[dict] = []
        for piece in _split_top_level(text[match.end():close]):
            piece = piece.strip()
            if not piece:
                continue
            head = re.match(r"^[\"'`\[]?([A-Za-z_]\w*)[\"'`\]]?\s*(.*)$", piece)
            if head is None:
                continue
            column, rest = head.group(1), head.group(2).strip().rstrip(";").strip()
            if column.upper() in _TABLE_CONSTRAINT_HEADS:
                continue  # a table constraint, not a column definition
            tokens = [t for t in rest.split() if t]
            # ``VARCHAR(254)`` is the length of a VARCHAR, not a second type —
            # dropped so the column type compares with the DTO field's.
            column_type = (tokens[0].split("(", 1)[0] if tokens else "").strip()
            default = re.search(
                r"\bDEFAULT\s+('(?:[^']|'')*'|\"[^\"]*\"|\([^)]*\)|[\w.+-]+)",
                rest, re.IGNORECASE)
            constraints: list[str] = []
            upper = rest.upper()
            for marker in ("NOT NULL", "PRIMARY KEY", "UNIQUE", "DEFAULT",
                           "REFERENCES", "AUTOINCREMENT", "AUTO_INCREMENT"):
                if marker == "DEFAULT" and default:
                    continue  # rendered as ``DEFAULT <value>``, not a bare flag
                if marker in upper and marker not in constraints:
                    constraints.append(marker)
            columns.append({
                "name": column,
                "type": column_type,
                "not_null": "NOT NULL" in upper or "PRIMARY KEY" in upper,
                "default": default.group(1) if default else "",
                "constraints": constraints,
            })
        if columns:
            return columns
    return []


def _sql_columns_for(root: str, name: str, cap_files: int) -> tuple[list[dict], str]:
    """``(columns, "relative/path.sql")`` for the first table named ``name``."""
    if not _looks_like_table(name):
        return [], ""
    try:
        base = _safe_path(str(root) if root is not None else ".").resolve()
    except (OSError, ValueError):
        return [], ""
    for path in _sql_files(root, cap_files):
        try:
            if path.stat().st_size > MAX_SQL_BYTES:
                continue
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for variant in _table_name_variants(name):
            columns = _parse_create_table(variant, text)
            if columns:
                try:
                    shown = str(path.relative_to(base))
                except ValueError:
                    shown = str(path)
                return columns, shown
    return [], ""


def _decorators_of(node: dict) -> list[str]:
    """A node's decorators as written, de-duplicated, in index order."""
    raw = node.get("decorators")
    if not raw:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            raw = [raw]
    if not isinstance(raw, (list, tuple)):
        raw = [raw]
    out: list[str] = []
    for item in raw:
        text = str(item or "").strip()
        if text and text not in out:
            out.append(text)
    return out


def _decorator_text(item) -> str:
    """Normalize mixed extractor spellings to exactly one leading ``@``."""
    flat = " ".join(str(item or "").split())
    if not flat:
        return ""
    return "@" + flat.lstrip("@").strip()


def _render_decorators(node: dict) -> str:
    """The ``@a(), @b()`` text for a node, capped at :data:`MAX_DECORATORS`."""
    decorators = [d for d in (_decorator_text(item) for item in _decorators_of(node))
                  if d]
    shown = decorators[:MAX_DECORATORS]
    text = ", ".join(shown)
    if len(decorators) > len(shown):
        text += f", … +{len(decorators) - len(shown)} more"
    return text


def _validator_hits(node: dict) -> list[str]:
    """The framework validator names written in a node's decorators."""
    hits: list[str] = []
    for decorator in _decorators_of(node):
        for found in _VALIDATOR_RE.findall(str(decorator)):
            if found not in hits:
                hits.append(found)
    return hits


def _declared_type(node: dict) -> str:
    """A field's or parameter's declared type, from whatever the index carries.

    ``nodes.signature`` is authoritative (``id: UUID = Field(…)``, ``email:
    string``, ``email TEXT NOT NULL``); ``type_parameters`` and ``return_type``
    are the fallbacks for grammars that put the type there instead.
    """
    signature = str(node.get("signature") or "").strip().rstrip(";").strip()
    if signature:
        head = signature.split("=", 1)[0].strip()
        if ":" in head:
            candidate = head.split(":", 1)[1].strip()
        else:
            tokens = [t for t in head.replace(",", " ").split() if t]
            candidate = tokens[1] if len(tokens) >= 2 else ""
        candidate = candidate.strip().strip("`").strip()
        # A call default survived the split (`= Field(...)`): keep the head.
        candidate = candidate.split("(")[0].strip()
        if candidate and re.fullmatch(r"[\w$.<>,\[\]|?: ]+", candidate):
            return candidate
    for column in ("type_parameters", "return_type"):
        raw = node.get(column)
        if isinstance(raw, (list, tuple)):
            joined = ", ".join(str(v) for v in raw if str(v).strip())
            if joined:
                return joined
        elif raw:
            return str(raw).strip()
    return ""


def _resolve_type_node(conn, symbol: str, cap: int) -> tuple[list[dict], str]:
    """``(matches, basis)`` — exact node id, then name, then ``name_like``."""
    direct = _db.get_node(conn, symbol)
    if direct is not None:
        return [direct], "node id"
    name = str(symbol or "").strip()
    if not name:
        return [], "no symbol given"
    exact = [n for n in _db.find_nodes(conn, name=name, limit=cap)
             if str(n.get("kind") or "") in _TYPE_KINDS]
    if exact:
        return exact, "exact name"
    like = [n for n in _db.find_nodes(conn, name_like=f"%{name}%", limit=cap)
            if str(n.get("kind") or "") in _TYPE_KINDS]
    if like:
        return like, "name substring"
    return [], "not found"


def _pick_type_node(matches: list[dict]) -> tuple[dict, list[dict]]:
    """The best match and the rest: class-like first, then non-test, then file."""
    def key(node: dict):
        return (0 if str(node.get("kind") or "") in _CLASS_LIKE_KINDS else 1,
                1 if _db.is_test_file(str(node.get("file_path") or "")) else 0,
                str(node.get("file_path") or ""),
                _as_int(node.get("start_line"), 0),
                str(node.get("id") or ""))
    ordered = sorted(matches, key=key)
    return ordered[0], ordered[1:]


@tool(parse_docstring=True)
def inspect_type_contract(symbol_name_or_node_id: str, root: str = ".",
                          limit: int | None = None) -> str:
    """Show declared DTO/entity fields, validators, and matching SQL columns.

    Use before assessing injection, mass-assignment, or BOLA on a boundary.
    This is indexed structure, not dataflow; an absent decorator does not prove
    there is no base-class or serializer validation.

    Args:
        symbol_name_or_node_id: A CodeGraph node id (content hash), or a symbol
            name such as ``CreateUserDto`` / ``User`` / ``login``.
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Cap on name-search candidates and on rendered fields/columns.
            0 = unlimited (hard-clamped at 500).

    Returns:
        A bounded contract view (header, fields/parameters, validation summary,
        db columns), or an ``ERROR:``/guidance string when the repo is not
        indexed or the symbol is unknown.
    """
    conn, _node, error = _common.tool_gate(root)
    if error:
        return error

    # Search and rendered-row caps differ; totals describe every indexed member.
    cap = _cap_rows(limit, ENV_FIELDS, DEFAULT_FIELDS)
    field_cap = min(cap, HARD_MAX_SECTION)
    column_cap = min(_cap_rows(limit, ENV_COLUMNS, DEFAULT_COLUMNS), HARD_MAX_SECTION)
    sql_cap = _cap_rows(None, ENV_SQL_FILES, DEFAULT_SQL_FILES)

    matches, basis = _resolve_type_node(conn, symbol_name_or_node_id, cap)
    if not matches:
        return _cap_chars(
            f"ERROR: no type or function named {symbol_name_or_node_id!r} in "
            f"the index (searched kinds: {', '.join(_TYPE_KINDS[:9])}…; "
            f"basis={basis})")
    node, others = _pick_type_node(matches)

    node_id = str(node.get("id") or "")
    kind = str(node.get("kind") or "node")
    name = str(node.get("name") or node_id)
    file_path = str(node.get("file_path") or "")
    try:
        start = int(node.get("start_line"))
        end = int(node.get("end_line"))
    except (TypeError, ValueError):
        start, end = 0, 0

    out = _ContractReport([
        f"# type contract: {file_path}:{start}"
        + (f"-{end}" if end and end != start else "")
        + f" ({kind} {name})",
        f"node_id: {node_id}  (resolved by {basis})"])
    hint = summaries.cache_hint(conn, node_id)
    if hint:
        out.add(hint)
    if others:
        shown = others[:5]
        rest = len(others) - len(shown)
        out.add(f"note: {len(matches)} symbols match this name — showing the "
                f"best; others: " + "; ".join(
                    f"{str(o.get('id'))} ({o.get('file_path')}:"
                    f"{_as_int(o.get('start_line'), 0)} {o.get('kind')})"
                    for o in shown)
                + (f", … +{rest} more" if rest > 0 else ""))

    qualified = str(node.get("qualified_name") or "")
    if qualified and qualified != name:
        out.add(f"qualified_name: {qualified}")
    language = str(node.get("language") or "")
    if language:
        out.add(f"language: {language}")
    type_decorators = _render_decorators(node)
    if type_decorators:
        out.add(f"type decorators: {type_decorators}")
    signature = str(node.get("signature") or "")
    if signature:
        out.add(f"signature: {_truncate_line(signature, 400)}")

    # ---- fields or parameters ------------------------------------------
    class_like = kind in _CLASS_LIKE_KINDS
    children = _db.node_children(
        conn, node_id,
        kinds=list(_FIELD_KINDS) if class_like else ["parameter"],
        limit=0)
    members: list[tuple[dict, str, list[str]]] = [
        (child, _declared_type(child), _validator_hits(child))
        for child in children]
    if not members and not class_like:
        # No parameter children in the index: nodes.signature is the fallback.
        for param in _ts.parse_signature_params(signature, language):
            members.append(({"name": param.get("name") or "",
                             "kind": "parameter",
                             "start_line": _as_int(node.get("start_line"), 0)},
                            str(param.get("type") or ""), []))

    title = "fields" if class_like else "parameters"
    shown_members = members[:field_cap]
    out.blank().section(title, len(shown_members), len(members))
    if not shown_members:
        out.add(f"  (no {title} recorded for this node: it may be a "
                f"type whose members are indexed as methods only)")
    for child, type_text, validators in shown_members:
        line = _as_int(child.get("start_line"), 0)
        child_kind = str(child.get("kind") or "")
        row = f"  {line or '-':>5}  {child.get('name') or '(anonymous)'}"
        if child_kind and child_kind != _SECTION_CANONICAL_KIND.get(title, ""):
            row += f"  [{child_kind}]"
        row += f"  : {type_text or '(untyped)'}"
        decorators = _render_decorators(child)
        if decorators:
            row += f"  {decorators}"
        if validators:
            row += f"  <validated: {', '.join(validators)}>"
        out.add(row)
    if len(members) > len(shown_members):
        out.more(len(members) - len(shown_members), title, len(members))

    # ---- validation summary --------------------------------------------
    out.blank()
    validated = [(str(c.get("name") or ""), v) for c, _t, v in members if v]
    unvalidated = [str(c.get("name") or "") for c, _t, v in members if not v]
    if validated:
        out.section("validation summary", len(validated), len(members),
                    " carry a framework validator")
        for member_name, validators in validated[:field_cap]:
            out.add(f"  {member_name or '(anonymous)'}: {', '.join(validators)}")
        if len(validated) > field_cap:
            out.add(f"  … +{len(validated) - field_cap} more validated {title}")
        if unvalidated:
            shown_unvalidated = unvalidated[:field_cap]
            out.add("  no validator decorator on: "
                    + ", ".join(shown_unvalidated)
                    + (f", … +{len(unvalidated) - len(shown_unvalidated)} more"
                       if len(unvalidated) > len(shown_unvalidated) else ""))
            out.add("  note: an undecorated field is only UNVALIDATED in this "
                    "index — a base-class or serializer-level guarantee is "
                    "invisible here")
    elif members:
        out.add("--- validation summary: no framework validator decorators on "
                "any member of this node",
                "  note: absence of a decorator is not proof of absence of "
                "validation — check the serializer/schema node too")
    else:
        out.add("--- validation summary: no members to summarise")

    # ---- SQL sidecar ----------------------------------------------------
    if _looks_like_table(name):
        columns, sql_path = _sql_columns_for(root, name, sql_cap)
        if columns:
            shown_columns = columns[:column_cap]
            out.blank().section("db columns", len(shown_columns), len(columns),
                                f"; table {name} in {sql_path}")
            for column in shown_columns:
                row = f"  {column['name']}  {column['type']}".rstrip()
                flags = list(column["constraints"])
                if column["default"] and "DEFAULT" not in flags:
                    flags.append(f"DEFAULT {column['default']}")
                if flags:
                    row += "  [" + " ".join(flags) + "]"
                out.add(row)
            if len(columns) > len(shown_columns):
                out.more(len(columns) - len(shown_columns), "columns", len(columns))
    return out.text()

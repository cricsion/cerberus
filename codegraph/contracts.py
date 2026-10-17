"""Type-contract, security-summary and patch-validation tools.

The Taint & Injection hunter lives at framework boundaries — the DTO, the
request body, the ORM entity — and that is exactly where its false positives
live too: a field typed ``UUID`` and decorated ``@IsUUID()`` was never an
"arbitrary attacker string", and a patch that looks safe may have broken every
caller or moved the sink instead of removing it. These four tools are the
answers to those three questions:

- :func:`inspect_type_contract` — **the false-positive killer at a boundary.**
  Fields and parameters of a DTO/request-body/entity, each with its declared
  type and its framework validation decorators, plus the matching
  ``CREATE TABLE`` columns when the repo ships SQL. A field carrying
  ``@IsUUID()`` is the reason an "arbitrary string" claim must be downgraded.
- :func:`record_function_security_summary` / :func:`get_function_security_summary`
  — **the neuro-symbolic memory.** The analyst's verdict about a function
  (``SANITIZER``, ``AUTH_GUARD``, …) is written once into the summary sidecar
  (:mod:`harness.codegraph.summaries`) and read back as the compact
  ``[CACHED SUMMARY: …]`` hint every other tool prepends, so the same function
  is not re-reasoned about on the next call.
- :func:`validate_remediation_patch` — **post-patch proof.** The patched code is
  parsed with the node's own grammar, its parameters are compared with the
  original's, every caller in the index is re-counted for arity, and the sink
  calls on both sides of the patch are classified with the same ported taxonomy
  the hunter used, so "eliminated / remaining / introduced" is a statement
  about the same rule set rather than about a second opinion.

Everything here is read-only against the target repo: the index is opened
``mode=ro`` by :func:`harness.codegraph._db.connect`, source is read through the
same containment check every harness tool uses, and the ONLY writable artifact
in the whole package is the summary sidecar's. No LLM, no network, no
subprocess, and no tool here raises: a missing index, an unreadable file, a
grammar that is not installed and a symbol the index never saw are all strings.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from harness.codegraph import _db, _ts, sinks, summaries
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


# ---------------------------------------------------------------------------
# caps — the same shape as _db's, navigation.py's and authz.py's, so one env
# idiom covers the whole package
# ---------------------------------------------------------------------------

HARD_MAX_SECTION = 200   # per-section ceiling before _db.HARD_MAX_ROWS applies
CHAR_CAP = 20000         # overall output cap (CODEGRAPH_CHARS, 0 = unlimited)
ENV_CHARS = "CODEGRAPH_CHARS"

ENV_FIELDS = "CODEGRAPH_FIELDS_LIMIT"
ENV_CALLERS = "CODEGRAPH_CALLERS_LIMIT"
ENV_SQL_FILES = "CODEGRAPH_SQL_FILES_LIMIT"
ENV_COLUMNS = "CODEGRAPH_COLUMNS_LIMIT"

DEFAULT_FIELDS = 60      # fields / parameters rendered per type
DEFAULT_CALLERS = 100    # callers checked for arity
DEFAULT_SQL_FILES = 40   # .sql files searched for a CREATE TABLE
DEFAULT_COLUMNS = 60     # columns rendered per matched table
MAX_DECORATORS = 12      # a node with 40 decorators is not an answer
MAX_ERROR_POSITIONS = 5  # parse errors reported before the list is marked
MAX_SQL_BYTES = _ts.MAX_FILE_BYTES  # the indexer's own per-file cap

# The summary sidecar is one row per node, and every row is injected back as
# the compact ``[CACHED SUMMARY: …]`` hint — so what goes in is capped here,
# before the write, rather than surfacing as a 100 KB hint on some later call.
MAX_CWE_SCOPE = 24       # CWE ids recorded for one verdict
MAX_CWE_ID = 64          # chars per CWE id
MAX_CWE_TEXT = 2000      # chars of a bare comma-separated CWE string
MAX_SUMMARY_NOTES = 4000 # chars of free-text justification


def _env_int(key: str, default: int) -> int:
    try:
        v = os.environ.get(key)
        if v is None or v == "":
            return default
        return int(v)
    except (TypeError, ValueError):
        return default


def _cap_rows(limit, env_key: str, default: int) -> int:
    """Explicit arg wins, then env, ``<=0`` means unlimited, hard-clamped.

    Mirrors ``_db._resolve_rows`` (private to the foundation module on purpose)
    so contracts.py does not reach into it; the clamp is still
    :data:`_db.HARD_MAX_ROWS`, the one ceiling the whole package shares.
    """
    if limit is None:
        n = _env_int(env_key, default)
    else:
        try:
            n = int(limit)
        except (TypeError, ValueError):
            n = default
    if n <= 0:
        return _db.HARD_MAX_ROWS
    return min(n, _db.HARD_MAX_ROWS)


def _section_cap(env_key: str, default: int) -> int:
    """A per-section cap that never outgrows the row ceiling."""
    return min(_env_int(env_key, default), HARD_MAX_SECTION)


def _cap_chars(text: str) -> str:
    """The overall character budget. ``CODEGRAPH_CHARS``, 0 = unlimited."""
    lim = _env_int(ENV_CHARS, CHAR_CAP)
    if lim <= 0 or len(text) <= lim:
        return text
    return text[:lim] + f"\n… +{len(text) - lim} more chars (total {len(text)})"


# ---------------------------------------------------------------------------
# source access
# ---------------------------------------------------------------------------

def _contained_file(root: str, file_path: str) -> Path | None:
    """Resolve a repo-relative ``nodes.file_path`` under ``root``.

    Returns ``None`` — never raises — when the path escapes the repo boundary,
    does not exist, is unreadable, or is above the 1 MB per-file cap the
    indexer applies (a file CodeGraph skipped has no symbols here either, so
    parsing one would invent spans the graph disagrees with).

    A path the host cannot even ADDRESS (a NUL byte, a component past NAME_MAX)
    raises ``OSError``/``ValueError`` out of ``resolve()`` rather than out of
    the containment check, so every step below guards for both.
    """
    rel = str(file_path or "").strip().replace("\\", "/")
    if not rel:
        return None
    try:
        base = _safe_path(str(root) if root is not None else ".")
        try:
            if base.is_file():
                base = base.parent  # a tool may point at one file, not a tree
        except (OSError, ValueError):
            return None
    except (OSError, ValueError):
        return None
    try:
        candidates = [(base / rel).resolve()]
    except (OSError, ValueError):
        return None
    if rel.startswith("/"):
        # A leading slash may be the repo's own virtual path ("/app.py").
        try:
            candidates.append(_safe_path(rel))
        except (OSError, ValueError):
            pass
    for cand in candidates:
        try:
            cand.relative_to(base)  # re-check after resolving symlinks
        except ValueError:
            continue
        try:
            if not cand.is_file():
                continue
        except (OSError, ValueError):
            continue
        try:
            if cand.stat().st_size > _ts.MAX_FILE_BYTES:
                continue
            cand.read_bytes()  # readability probe: an unreadable file is a miss
        except (OSError, ValueError):
            continue
        return cand
    return None


def _read_source(root: str, file_path: str):
    """``(source_bytes, path)`` for a node's file, or ``(None, None)``."""
    path = _contained_file(root, file_path)
    if path is None:
        return None, None
    try:
        return path.read_bytes(), path
    except OSError:
        return None, None


def _parse_node_file(root: str, node: dict, cache: dict):
    """``(tree, src)`` for a node's own file, memoised per file+language."""
    file_path = str(node.get("file_path") or "")
    language = str(node.get("language") or "")
    key = (file_path, language)
    if key not in cache:
        cache[key] = None
        src, _path = _read_source(root, file_path)
        if src is not None:
            tree = _ts.parse_source(src.decode("utf-8", errors="replace"), language)
            if tree is not None:
                cache[key] = (tree, src)
    return cache[key]


# ---------------------------------------------------------------------------
# tree-sitter walk helpers (same pre-order contract as _ts._walk)
# ---------------------------------------------------------------------------

def _walk(node):
    """Depth-first, parent before children."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        try:
            children = list(current.children)
        except Exception:
            continue
        stack.extend(reversed(children))


def _as_int(value, default: int = 0) -> int:
    """A DB column coerced to int without raising.

    ``nodes.start_line``/``edges.line`` are declared INTEGER, but SQLite column
    types are advisory and an index written by another producer can hold
    anything; a tool that promises never to raise cannot assume otherwise.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _truncate_line(text: str, cap: int = 200) -> str:
    flat = " ".join(str(text or "").split())
    if len(flat) <= cap:
        return flat
    return flat[:cap] + " …"


def _split_top_level(text: str, separators: str = ",") -> list[str]:
    """Split on separators that are not inside (), [], {}, <> or a string."""
    parts: list[str] = []
    depth = 0
    angle = 0
    quote = ""
    buf: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(text):
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "<":
            angle += 1
        elif ch == ">":
            angle = max(0, angle - 1)
        if ch in separators and depth == 0 and angle == 0:
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


# ---------------------------------------------------------------------------
# node-kind vocabularies (CodeGraph ``nodes.kind``, NOT tree-sitter node types)
# ---------------------------------------------------------------------------

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
# which never equals the ``property`` a TypeScript field is actually stored as,
# so that comparison flagged every single row of a fields section.
_SECTION_CANONICAL_KIND = {"fields": "property", "parameters": "parameter"}

# A caller of the patched function: an edge that means "this code reaches it".
_CALLER_EDGE_KINDS = ("calls", "references", "instantiates")

# Identifier leaves a parameter name is written as, per grammar.
_ID_LEAF_TYPES = frozenset({
    "identifier", "field_identifier", "property_identifier", "type_identifier",
    "shorthand_property_identifier", "simple_identifier", "word",
})

# Tree-sitter parameter node types whose NAME is the LAST identifier leaf
# (the ``Type name`` spellings of the C/JVM family).
_NAME_LAST_PARAM_TYPES = frozenset({
    "formal_parameter", "parameter", "parameter_spec", "fixed_parameter",
    "typed_parameter", "required_parameter", "optional_parameter",
})

_VARIADIC_PARAM_TYPES = frozenset({
    "list_splat_pattern", "dictionary_splat_pattern", "rest_parameter",
    "spread_parameter", "variadic_parameter", "rest_pattern", "splat_pattern",
})

# Parameter spellings the grammars use for "this one is OPTIONAL". Some carry
# no default expression at all (TypeScript's ``c?: number``), so the marker
# below is what marks them optional rather than the text.
_OPTIONAL_PARAM_TYPES = frozenset({
    "default_parameter", "typed_default_parameter", "optional_parameter",
    "optional_parameter_property", "default_formal_parameter",
    "parameter_with_default", "optional_parameter_declaration",
    "default_opt_parameter",
})

# What an optional parameter with no written expression reports as its default.
# Any truthy default means "a caller may omit this", which is what the
# minimum-arity comparison below keys on.
_OPTIONAL_MARKER = "?"

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
_VALIDATOR_RE = re.compile(r"\b(?:" + "|".join(_VALIDATOR_NAMES) + r")\w*\b",
                           re.IGNORECASE)

# A DTO/entity name that is worth looking for in a .sql file. A dotted or
# spaced name is not a table name, so the SQL sidecar is skipped for it.
_TABLE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Column clauses that open a table constraint rather than a column.
_TABLE_CONSTRAINT_HEADS = frozenset({
    "PRIMARY", "FOREIGN", "CONSTRAINT", "UNIQUE", "CHECK", "INDEX", "KEY",
    "EXCLUDE", "PERIOD",
})

# Directories a .sql search never enters: CodeGraph's own index, vendored
# trees and build output. Mirroring the indexer's own exclusions keeps the
# sidecar from paying for files the graph will never reference.
_SQL_SKIP_DIRS = frozenset({
    ".codegraph", "node_modules", "vendor", "dist", "build", "target", ".git",
    "__pycache__", ".venv", "venv",
})


# ---------------------------------------------------------------------------
# 1. inspect_type_contract
# ---------------------------------------------------------------------------

def _looks_like_table(name: str) -> bool:
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
    """``UserProfile`` -> ``["UserProfile", "userprofile", "user_profile", "user_profiles"]``.

    SQL is not case-sensitive and conventions disagree on underscores, so the
    raw, lower-cased and snake-cased spellings are all searched rather than
    only the class name as written — and so is the PLURAL, because an ORM
    entity ``UserProfile`` is persisted as ``user_profiles`` about as often as
    it is persisted as ``user_profile`` (Rails/Django/Sequelize pluralise,
    Hibernate/TypeORM do not). A search that only tried the singular missed the
    most common table name of all.
    """
    raw = str(name or "").strip()
    if not raw:
        return []
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", raw).lower()
    squashed = snake.replace("_", "")
    out: list[str] = []
    for candidate in (raw, raw.lower(), snake, squashed):
        if candidate and candidate not in out:
            out.append(candidate)
    for stem in (snake, squashed, raw.lower()):
        plural = _plural(stem)
        if plural and plural not in out:
            out.append(plural)
    return out


def _sql_files(root: str, cap: int) -> list[Path]:
    """Bounded, contained walk for ``*.sql`` files under ``root``."""
    try:
        base = _safe_path(str(root) if root is not None else ".")
        try:
            if base.is_file():
                base = base.parent
        except (OSError, ValueError):
            return []
    except (OSError, ValueError):
        return []
    found: list[Path] = []
    stack = [base]
    while stack and len(found) < cap:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if len(found) >= cap:
                break
            try:
                if entry.is_dir():
                    if entry.name not in _SQL_SKIP_DIRS:
                        stack.append(entry)
                elif entry.is_file() and entry.suffix.lower() == ".sql":
                    found.append(entry)
            except OSError:
                continue
    return found


def _matching_paren(text: str, open_index: int) -> int:
    """Index of the ')' matching the '(' at ``open_index`` (-1 when unbalanced)."""
    depth = 0
    quote = ""
    i = open_index
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "\"'`":
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
    """Columns of ``CREATE TABLE [IF NOT EXISTS] <name> (…)``, or ``[]``.

    The table body is found by paren-matching rather than a greedy regex,
    because a ``DEFAULT ('a,b')`` or a ``REFERENCES other(id)`` clause would
    otherwise terminate the column list early.
    """
    pattern = re.compile(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"'`\[]?" + re.escape(name)
        + r"[\"'`\]]?\s*\(", re.IGNORECASE)
    for match in pattern.finditer(text):
        open_index = match.end() - 1
        close_index = _matching_paren(text, open_index)
        if close_index < 0:
            continue
        body = text[open_index + 1:close_index]
        columns = []
        for piece in _split_top_level(body):
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
            # the parenthetical is dropped so the column's type compares with
            # the DTO field's, the way :func:`_declared_type` already does.
            column_type = (tokens[0].split("(", 1)[0] if tokens else "").strip()
            default = re.search(r"\bDEFAULT\s+('(?:[^']|'')*'|\"[^\"]*\"|\([^)]*\)|[\w.+-]+)",
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
    """One decorator with exactly one leading ``@``.

    ``nodes.decorators`` is written by several extractors and the spellings
    disagree: the TS/Java/Python paths keep the sigil (``@IsUUID()``), the Rust
    and Kotlin paths store a bare name (``tauri::command``). The ``@`` is
    therefore normalised once here instead of being prepended at each render
    site — prepending is what turned ``@IsUUID()`` into ``@@IsUUID()``, and a
    doubled sigil is noise an agent reads as a second decorator.
    """
    flat = " ".join(str(item or "").split())
    if not flat:
        return ""
    return "@" + flat.lstrip("@").strip()


def _render_decorators(node: dict) -> str:
    decorators = [d for d in (_decorator_text(item) for item in _decorators_of(node))
                  if d]
    if not decorators:
        return ""
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

    ``nodes.signature`` is the authoritative spelling (``id: UUID = Field(…)``,
    ``email: string``, ``email TEXT NOT NULL``); ``type_parameters`` and
    ``return_type`` are the fallbacks for the grammars that put the type there
    instead.
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
    """What does this DTO / request body / entity actually guarantee about its fields?

    Resolves a symbol (node id, exact name, then a capped substring search over
    class/struct/interface/protocol/trait/enum/type_alias/component/function
    kinds) and renders its field or parameter contract: every field's name, its
    declared type, and its decorators — with the framework VALIDATORS called out
    separately, because a field carrying ``@IsUUID()`` / ``@Length(8, 64)`` /
    ``field: EmailStr`` is precisely the reason an "arbitrary attacker string"
    claim must be downgraded at a boundary. When the node name looks like a
    table/entity and the repo ships ``.sql`` files, the matching
    ``CREATE TABLE`` column definitions (type, NOT NULL, DEFAULT) are appended
    as the persistence-side half of the same contract.

    Use this BEFORE claiming an injection, mass-assignment or BOLA false
    positive on a DTO, request body, ORM entity or handler parameter — it is
    the cheap check that separates "the framework already validated this" from
    "this really is unconstrained input". Do NOT use it as a taint tracer (it
    has no dataflow) and do NOT use it to prove a field is UNVALIDATED: absence
    of decorators here means absence in the index, and a validator applied by a
    base class or a serializer metaclass lives on another node.

    Args:
        symbol_name_or_node_id: A CodeGraph node id (content hash), or a symbol
            name such as ``CreateUserDto`` / ``User`` / ``login``.
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Cap on name-search candidates and on rendered fields/columns.
            0 = unlimited (hard-clamped at 500).

    Returns:
        A bounded contract view — type header (file:line, kind), fields or
        parameters with types and decorators, a validation summary naming the
        validators, and db columns when a matching table exists — or an
        ``ERROR:``/guidance string when the repo is not indexed or the symbol
        is unknown.
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return _cap_chars(_db.guidance_no_db(root))

    # `cap` bounds the name search (its candidate list); `field_cap` and
    # `column_cap` bound what is RENDERED. The member list itself is read in
    # full (bounded by ``_db.HARD_MAX_ROWS``) so that "--- fields (2 of 4)" and
    # its "… +2 more (total 4)" marker describe the NODE, not the render cap —
    # the same per-section totals ``get_ast_slice`` reports. Truncating the read
    # instead made the header claim a DTO had two fields when it had four.
    cap = _cap_rows(limit, ENV_FIELDS, DEFAULT_FIELDS)
    field_cap = min(_cap_rows(limit, ENV_FIELDS, DEFAULT_FIELDS), HARD_MAX_SECTION)
    column_cap = min(_cap_rows(limit, ENV_COLUMNS, DEFAULT_COLUMNS), HARD_MAX_SECTION)
    sql_cap = min(_cap_rows(None, ENV_SQL_FILES, DEFAULT_SQL_FILES),
                  _db.HARD_MAX_ROWS)

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

    out: list[str] = [f"# type contract: {file_path}:{start}"
                      + (f"-{end}" if end and end != start else "")
                      + f" ({kind} {name})",
                      f"node_id: {node_id}  (resolved by {basis})"]
    hint = summaries.cache_hint(conn, node_id)
    if hint:
        out.append(hint)
    if others:
        shown = others[:5]
        rest = len(others) - len(shown)
        out.append(f"note: {len(matches)} symbols match this name — showing the "
                   f"best; others: " + "; ".join(
                       f"{str(o.get('id'))} ({o.get('file_path')}:"
                       f"{_as_int(o.get('start_line'), 0)} {o.get('kind')})"
                       for o in shown)
                   + (f", … +{rest} more" if rest > 0 else ""))

    qualified = str(node.get("qualified_name") or "")
    if qualified and qualified != name:
        out.append(f"qualified_name: {qualified}")
    language = str(node.get("language") or "")
    if language:
        out.append(f"language: {language}")
    type_decorators = _render_decorators(node)
    if type_decorators:
        out.append(f"type decorators: {type_decorators}")
    signature = str(node.get("signature") or "")
    if signature:
        out.append(f"signature: {_truncate_line(signature, 400)}")

    # ---- fields or parameters ------------------------------------------
    class_like = kind in _CLASS_LIKE_KINDS
    # 0 = "every member the index holds" (hard-clamped by _db), so the totals
    # below count the node's members and not the render cap.
    children = _db.node_children(
        conn, node_id,
        kinds=list(_FIELD_KINDS) if class_like else ["parameter"],
        limit=0)
    members: list[tuple[dict, str, list[str]]] = []
    for child in children:
        members.append((child, _declared_type(child), _validator_hits(child)))
    if not members and not class_like:
        # No parameter children in the index: nodes.signature is the fallback.
        for param in _ts.parse_signature_params(signature, language):
            members.append(({"name": param.get("name") or "",
                             "kind": "parameter",
                             "start_line": _as_int(node.get("start_line"), 0),
                             "signature": (f"{param.get('name')}: {param.get('type')}"
                                           if param.get("type") else str(param.get("name") or ""))},
                            str(param.get("type") or ""), []))

    title = "fields" if class_like else "parameters"
    shown_members = members[:field_cap]
    out.append("")
    out.append(f"--- {title} ({len(shown_members)} of {len(members)})")
    if not shown_members:
        out.append(f"  (no {title} recorded for this node: it may be a "
                   f"type whose members are indexed as methods only)")
    for child, type_text, validators in shown_members:
        line = _as_int(child.get("start_line"), 0)
        child_kind = str(child.get("kind") or "")
        child_name = str(child.get("name") or "")
        decorators = _render_decorators(child)
        row = f"  {line or '-':>5}  {child_name or '(anonymous)'}"
        if child_kind and child_kind != _SECTION_CANONICAL_KIND.get(title, ""):
            row += f"  [{child_kind}]"
        row += f"  : {type_text}" if type_text else "  : (untyped)"
        if decorators:
            row += f"  {decorators}"
        if validators:
            row += f"  <validated: {', '.join(validators)}>"
        out.append(row)
    if len(members) > len(shown_members):
        out.append(f"… +{len(members) - len(shown_members)} more {title} "
                   f"(total {len(members)})")

    # ---- validation summary --------------------------------------------
    out.append("")
    validated = [(str(c.get("name") or ""), v) for c, _t, v in members if v]
    unvalidated = [str(c.get("name") or "") for c, _t, v in members if not v]
    if validated:
        out.append(f"--- validation summary ({len(validated)} of {len(members)} "
                   f"carry a framework validator)")
        for member_name, validators in validated[:field_cap]:
            out.append(f"  {member_name or '(anonymous)'}: {', '.join(validators)}")
        if len(validated) > field_cap:
            out.append(f"  … +{len(validated) - field_cap} more validated {title}")
        if unvalidated:
            shown_unvalidated = unvalidated[:field_cap]
            out.append(f"  no validator decorator on: "
                       + ", ".join(shown_unvalidated)
                       + (f", … +{len(unvalidated) - len(shown_unvalidated)} more"
                          if len(unvalidated) > len(shown_unvalidated) else ""))
            out.append("  note: an undecorated field is only UNVALIDATED in this "
                       "index — a base-class or serializer-level guarantee is "
                       "invisible here")
    elif members:
        out.append("--- validation summary: no framework validator decorators on "
                   "any member of this node")
        out.append("  note: absence of a decorator is not proof of absence of "
                   "validation — check the serializer/schema node too")
    else:
        out.append("--- validation summary: no members to summarise")

    # ---- SQL sidecar ----------------------------------------------------
    if _looks_like_table(name):
        columns, sql_path = _sql_columns_for(root, name, sql_cap)
        if columns:
            shown_columns = columns[:column_cap]
            out.append("")
            out.append(f"--- db columns ({len(shown_columns)} of {len(columns)}; "
                       f"table {name} in {sql_path})")
            for column in shown_columns:
                row = f"  {column['name']}  {column['type']}".rstrip()
                flags = list(column["constraints"])
                if column["default"] and "DEFAULT" not in flags:
                    flags.append(f"DEFAULT {column['default']}")
                if flags:
                    row += "  [" + " ".join(flags) + "]"
                out.append(row)
            if len(columns) > len(shown_columns):
                out.append(f"… +{len(columns) - len(shown_columns)} more columns "
                           f"(total {len(columns)})")
    return _cap_chars("\n".join(out))


# ---------------------------------------------------------------------------
# 2. record_function_security_summary
# ---------------------------------------------------------------------------

def _parse_summary_json(raw: str) -> tuple[dict, str]:
    """``(payload, error)`` for the ``summary_json`` argument.

    A JSON object is the documented shape (``{"cwe_scope": [...], "notes":
    "…"}``); a bare JSON list is read as the CWE scope and a comma-separated
    string as one — an agent that writes ``"79, 89"`` should not be failed for
    punctuation. Anything else is an error string, never an exception.
    """
    text = str(raw or "").strip()
    if not text:
        return {"cwe_scope": [], "notes": ""}, ""
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        # Tolerated: a bare comma-separated CWE list ("CWE-79, 89").
        if re.fullmatch(r"[\w\s,.;:'\"-]+", text):
            return {"cwe_scope": text, "notes": ""}, ""
        return {}, ("ERROR: summary_json must be a JSON object "
                    "({'cwe_scope': ['CWE-79'], 'notes': '…'}), a JSON list of "
                    "CWE ids, or a comma-separated CWE string")
    if isinstance(parsed, dict):
        scope = parsed.get("cwe_scope", parsed.get("cwe", parsed.get("cwes", [])))
        notes = parsed.get("notes", parsed.get("note", parsed.get("why", "")))
        return {"cwe_scope": scope if scope is not None else [],
                "notes": notes if notes is not None else ""}, ""
    if isinstance(parsed, list):
        return {"cwe_scope": parsed, "notes": ""}, ""
    if isinstance(parsed, str):
        return {"cwe_scope": parsed, "notes": ""}, ""
    return {}, ("ERROR: summary_json must be a JSON object "
                "({'cwe_scope': ['CWE-79'], 'notes': '…'}), a JSON list of "
                "CWE ids, or a comma-separated CWE string")


def _bounded_summary_payload(payload: dict) -> tuple[list[str] | str, str]:
    """``(cwe_scope, notes)`` length-bounded, ready for the sidecar.

    An agent may write anything into ``summary_json``; the sidecar is one row
    per node, and every later tool call injects that row back as the compact
    ``[CACHED SUMMARY: …]`` hint. So the payload is capped here — a bounded
    number of short CWE ids, and notes short enough to stay a hint — and a
    dict-shaped ``cwe_scope`` is rendered as its ids rather than left to be
    ``str()``-ed into one garbage CWE string.
    """
    scope = payload.get("cwe_scope")
    if isinstance(scope, dict):
        # ``{"79": "sql injection", "89": "sql injection"}``: a mapping of CWE
        # id to its reason. The keys are the scope; the values are not ids.
        scope = [str(k) for k in scope.keys()]
    if isinstance(scope, (list, tuple, set)):
        items: list[str] = []
        for item in list(scope)[:MAX_CWE_SCOPE]:
            text = _clip(str(item or ""), MAX_CWE_ID)
            if text:
                items.append(text)
        scope_out: list[str] | str = items
    elif scope is None:
        scope_out = []
    else:
        # A bare comma-separated string keeps its spelling: the sidecar splits
        # it exactly as an agent would have written "CWE-79, 89".
        scope_out = _clip(str(scope), MAX_CWE_TEXT)
    return scope_out, _clip(payload.get("notes"), MAX_SUMMARY_NOTES)


@tool(parse_docstring=True)
def record_function_security_summary(node_id: str, role: str, summary_json: str,
                                     root: str = ".") -> str:
    """Record the analyst's security verdict about one function, once.

    Neuro-symbolic specification mining: the reasoning is done by the agent, the
    result is persisted in the summary sidecar and injected back into later tool
    calls as the compact ``[CACHED SUMMARY: …]`` hint, so a function classified
    as a ``SANITIZER`` (or an ``AUTH_GUARD``) is not re-analysed on every hop of
    every future trace. ``role`` must be one of ``SANITIZER``, ``VALIDATOR``,
    ``AUTH_GUARD``, ``TAINT_PASSTHROUGH``, ``SAFE_WRAPPER``.

    Use this after you have decided what a function IS for a class of bugs, and
    before repeating that decision on the next call. Do NOT use it to record a
    finding (a verdict on a CWE/sink pair is triage memory) and do NOT use it as
    a cache of raw code: the sidecar is one upserted row per node, so a second
    record for the same node overwrites the first.

    Args:
        node_id: The function (or class) node id the verdict is about. It need
            not exist in the index — a cross-repo summary is recorded with a
            warning rather than refused.
        role: One of the taxonomy roles (case-insensitive): ``SANITIZER``,
            ``VALIDATOR``, ``AUTH_GUARD``, ``TAINT_PASSTHROUGH``, ``SAFE_WRAPPER``.
        summary_json: JSON object string. Recognised keys: ``cwe_scope`` (list
            of CWE ids, or a comma-separated string) and ``notes`` (free text
            explaining the verdict). A bare JSON list is read as ``cwe_scope``.
        root: Repo root holding ``.codegraph/codegraph.db``.

    Returns:
        The write confirmation plus the exact ``[CACHED SUMMARY: …]`` string
        future calls will inject, or an ``ERROR:`` string when the role is not
        in the taxonomy, the JSON is malformed, or the sidecar is unwritable.
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return f"ERROR: {e}"

    if not str(node_id or "").strip():
        return _cap_chars("ERROR: node_id is required")
    role_text = str(role or "").strip().upper().replace(" ", "_").replace("-", "_")
    if role_text not in summaries.ROLES:
        return _cap_chars(f"ERROR: unknown role {role!r} "
                          f"(use one of {', '.join(summaries.ROLES)})")

    payload, error = _parse_summary_json(summary_json)
    if error:
        return _cap_chars(error)

    # The sidecar is one upserted row per node, not a scratchpad: whatever
    # shape the agent wrote, the payload that reaches it is length-bounded and
    # list-shaped, so a 100 KB blob or a dict-shaped ``cwe_scope`` cannot turn
    # into one garbage CWE string.
    scope, notes = _bounded_summary_payload(payload)

    conn = _db.connect(root)
    known = conn is not None and _db.get_node(conn, node_id) is not None

    message = summaries.record_summary(root, str(node_id), role_text, scope,
                                       notes)
    if message.startswith("ERROR"):
        return _cap_chars(message)

    lines = [message]
    if conn is None:
        lines.append("[warning: no codegraph index for this root — recorded "
                     "without checking the node exists]")
    elif not known:
        # summaries.record_summary appends its own row-level warning ("node_id
        # not found in the nodes table") to the confirmation; this one states
        # the TOOL's policy about that miss — the verdict is recorded anyway —
        # so it must not be suppressed by the presence of the foundation's.
        lines.append(f"[warning: node_id {node_id} not found in the index — "
                     f"recording a cross-repo summary]")
    hint = summaries.cache_hint(root, node_id)
    if hint:
        lines.append(f"cache_hint injected by later calls: {hint}")
    lines.append(f"sidecar: {summaries.store_path(root)}")
    return _cap_chars("\n".join(lines))


# ---------------------------------------------------------------------------
# 3. get_function_security_summary
# ---------------------------------------------------------------------------

@tool(parse_docstring=True)
def get_function_security_summary(node_id: str, root: str = ".") -> str:
    """What has already been decided about this function, security-wise?

    The read side of the summary sidecar: every cached verdict recorded for one
    node — role, CWE scope, notes, and when it was recorded — plus the exact
    ``[CACHED SUMMARY: …]`` string later tool calls prepend.

    Use this at the start of a taint trace, before reasoning about a function
    from scratch: a ``SANITIZER`` or ``TAINT_PASSTHROUGH`` verdict changes what
    the hop means, and an ``AUTH_GUARD`` is the evidence an AuthZ check exists.
    Do NOT use it as a substitute for reading the code — a summary is a claim an
    analyst made, and the notes are the justification to re-check.

    Args:
        node_id: The node id whose cached summary to read.
        root: Repo root holding ``.codegraph/codegraph.db``.

    Returns:
        One block per cached summary (role, cwe_scope, notes, updated_at) and
        the cache-hint string, or ``(no cached security summary for {node_id})``
        when nothing was recorded.
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return f"ERROR: {e}"
    if not str(node_id or "").strip():
        return "ERROR: node_id is required"

    # The same degradation as every other tool in the package: an un-indexed
    # repo answers with the guidance string, not with an empty sidecar read
    # that reads like "nothing was ever decided about this function".
    conn = _db.connect(root)
    if conn is None:
        return _db.guidance_no_db(root)

    rows = summaries.get_summaries(root, str(node_id))
    if not rows:
        return _cap_chars(f"(no cached security summary for {node_id})")

    out: list[str] = [f"# cached security summary: {node_id} "
                      f"({len(rows)} record(s))"]
    node = _db.get_node(conn, node_id)
    if node is not None:
        out.append(f"node: {node.get('file_path')}:{_as_int(node.get('start_line'), 0)} "
                   f"({node.get('kind')} {node.get('name')})")
    else:
        out.append("note: this node id is not in the index (a cross-repo "
                   "summary, or a stale id after a re-index)")
    for row in rows:
        scope = ", ".join(row.get("cwe_scope") or []) or "any CWE"
        out.append("")
        out.append(f"--- {row.get('role')} for {scope}")
        out.append(f"  notes: {row.get('notes') or '(none)'}")
        out.append(f"  recorded_at: {row.get('updated_at')}")
    hint = summaries.cache_hint(root, node_id)
    if hint:
        out.append("")
        out.append(f"cache_hint: {hint}")
    out.append(f"sidecar: {summaries.store_path(root)}")
    return _cap_chars("\n".join(out))


# ---------------------------------------------------------------------------
# 4. validate_remediation_patch
# ---------------------------------------------------------------------------

# Argument shapes that mean "this value is built at runtime" rather than passed
# through: concatenation, template interpolation, an f-string, ``%``-formatting
# and ``.format()``. String contents are blanked first so a literal ``"a+b"``
# does not raise the flag.
_DYNAMIC_MARKERS = ("+", "${", ".format(", "%")
_FSTRING_RE = re.compile(r"\bf['\"]")
_PERCENT_RE = re.compile(r"%\s*[A-Za-z_(]")
_STRING_LITERAL_RE = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")


def _param_node_name(node, src: bytes) -> str:
    """A tree-sitter parameter node's NAME, whatever the grammar calls it."""
    for field in ("name", "pattern", "declarator"):
        child = node.child_by_field_name(field)
        if child is not None:
            text = _ts.node_text(child, src).strip()
            if text:
                return re.sub(r"^[*.$\s]+", "", text).strip()
    if node.type in _ID_LEAF_TYPES:
        return _ts.node_text(node, src).strip()
    leaves = [n for n in _walk(node) if n.type in _ID_LEAF_TYPES]
    if not leaves:
        return ""
    wanted = leaves[-1] if node.type in _NAME_LAST_PARAM_TYPES else leaves[0]
    return re.sub(r"^[*.$\s]+", "", _ts.node_text(wanted, src).strip()).strip()


def _param_default(child, src: bytes) -> str:
    """The default expression of a parameter node (``''`` when it has none).

    ``a=1``, ``c?: number`` and ``a: number = 1`` all make the parameter
    OPTIONAL, and that is the whole difference between "backwards-compatible
    patch" and "broke every caller": counting an optional parameter as required
    is what flagged both the 2-arg and the 1-arg callers of a patch that only
    added ``limit=100``. The ``value`` field is authoritative; the raw text is
    the fallback for the grammars that spell a default outside any named field.
    """
    if child is None:
        return ""
    for field in ("value", "default_value", "default", "initializer"):
        node = child.child_by_field_name(field)
        if node is None:
            continue
        text = _ts.node_text(node, src).strip()
        if text:
            return _clip(text, 120)
    if child.type in _OPTIONAL_PARAM_TYPES:
        # The grammar spells the parameter optional but carries no expression
        # at all (TypeScript's ``c?: number``).
        return _OPTIONAL_MARKER
    text = _ts.node_text(child, src) or ""
    if "=" in text:
        return _clip(text.split("=", 1)[1].strip(), 120)
    return ""


def _params_from_def(def_node, src: bytes) -> list[dict]:
    """Parameters of a parsed def: ``[{"name", "type", "default", "variadic"}]``.

    Extracted from the tree-sitter definition itself rather than from
    ``nodes.signature``, because the whole point of this tool is to compare what
    the PATCH declares with what callers already pass.
    """
    if def_node is None:
        return []
    params = None
    for field in ("parameters", "formal_parameters", "parameter_list",
                  "formal_parameter_list", "arguments"):
        params = def_node.child_by_field_name(field)
        if params is not None:
            break
    if params is None:
        for child in def_node.children:
            if child.type in ("parameters", "formal_parameters",
                              "parameter_list"):
                params = child
                break
    if params is None:
        return []
    out: list[dict] = []
    for child in params.named_children:
        if child.type in ("comment", "line_comment", "block_comment"):
            continue
        name = _param_node_name(child, src)
        if not name or name in ("self", "cls", "this"):
            continue  # a receiver is not an argument at a call site
        type_text = ""
        type_node = child.child_by_field_name("type")
        if type_node is not None:
            type_text = _ts.node_text(type_node, src).strip()
        elif len([n for n in _walk(child) if n.type in _ID_LEAF_TYPES]) > 1:
            leaves = [n for n in _walk(child) if n.type in _ID_LEAF_TYPES]
            type_text = _ts.node_text(leaves[-1], src).strip()
            if type_text == name:
                type_text = ""
        out.append({"name": name, "type": type_text,
                    "default": _param_default(child, src),
                    "variadic": child.type in _VARIADIC_PARAM_TYPES})
    return out


def _param_is_optional(param: dict) -> bool:
    """True when a caller may omit this parameter.

    A written default makes it optional; so does a grammar that spells the
    parameter itself optional. A ``*args``/``**kwargs`` is variadic rather than
    optional — it is handled by the upper bound being unlimited instead.
    """
    return bool(param.get("default")) or bool(param.get("optional"))


def _arity_bounds(params: list[dict]) -> tuple[int, int | None]:
    """``(min, max)`` arguments a caller must be able to pass; ``None`` = no max.

    A caller is compatible when ``min <= call_arity <= max``. Counting every
    parameter — the optional ones included — as required is what made a
    backwards-compatible patch (``def f(a, b, limit=100)``) look like it broke
    every caller of a two-argument function.
    """
    # A variadic parameter is not required either: ``def f(a, *rest)`` accepts
    # one argument just as well as five.
    required = [p for p in params
                if not _param_is_optional(p) and not p.get("variadic")]
    variadic = any(p.get("variadic") for p in params)
    return len(required), (None if variadic else len(params))


def _arity_label(minimum: int, maximum: int | None) -> str:
    """``2``, ``1-2`` or ``1+`` — the same bounds, rendered for a report row."""
    if maximum is None:
        return f"{minimum}+" if minimum else "0+ (variadic)"
    if maximum == minimum:
        return str(minimum)
    return f"{minimum}-{maximum}"


def _param_label(param: dict) -> str:
    """``name:type=default`` (``…`` for a variadic), for a parameter-list row."""
    label = str(param.get("name") or "")
    if param.get("type"):
        label += f":{param['type']}"
    if _param_is_optional(param):
        label += f"={param.get('default') or '?'}"
    if param.get("variadic"):
        label += "…"
    return label


def _clip(text, cap: int) -> str:
    """A length cap that keeps the text readable instead of replacing it."""
    text = str(text or "")
    return text if len(text) <= cap else text[:cap] + " …"


def _original_params(node: dict) -> tuple[list[dict], str]:
    """The node's own parameters: ``nodes.signature`` first, else children.

    ``_ts.parse_signature_params`` already returns a ``default`` per parameter
    (``def f(a, b = 100)`` -> ``b`` with ``default="100"``); it is kept here
    rather than dropped on the floor, because the arity comparison below needs
    to know which parameters a caller may omit.
    """
    language = str(node.get("language") or "")
    from_signature = _ts.parse_signature_params(str(node.get("signature") or ""),
                                                language)
    if from_signature:
        return [{"name": p.get("name") or "", "type": p.get("type") or "",
                 "default": p.get("default") or "",
                 "variadic": bool(p.get("variadic"))} for p in from_signature], \
            "nodes.signature"
    return [], "unavailable"


def _args_node(call_node):
    """The bracketed argument list of a call, whatever the grammar calls it."""
    for field in ("arguments", "argument_list", "arguments_list",
                  "parameter_list"):
        child = call_node.child_by_field_name(field)
        if child is not None:
            return child
    for child in reversed(list(call_node.children)):
        if child.is_named and "argument" in child.type:
            return child
    return None


def _call_arguments(call_node, src: bytes) -> list[str]:
    """Top-level argument expressions, exactly as written."""
    args = _args_node(call_node)
    if args is None:
        return []
    out: list[str] = []
    for child in args.named_children:
        if child.type in ("comment", "line_comment", "block_comment"):
            continue
        text = _ts.node_text(child, src).strip()
        if text:
            out.append(" ".join(text.split()))
    return out


def _callee_tail(text: str) -> str:
    """``db.run_query`` -> ``run_query`` — the segment a name match uses."""
    tail = str(text or "").strip().rsplit(".", 1)[-1]
    return tail.lstrip("?!").strip()


def _parse_errors(tree, cap: int = MAX_ERROR_POSITIONS) -> list[str]:
    """The first few error positions, so a bad patch is actionable."""
    out: list[str] = []
    try:
        root = tree.root_node
    except Exception:
        return out
    for node in _walk(root):
        is_missing = False
        try:
            is_missing = bool(node.is_missing)
        except Exception:
            is_missing = False
        if node.type != "ERROR" and not is_missing:
            continue
        try:
            line = int(node.start_point[0]) + 1
            col = int(node.start_point[1]) + 1
        except Exception:
            continue
        label = "missing token" if is_missing else "syntax error"
        out.append(f"line {line}, col {col} ({label})")
        if len(out) >= cap:
            break
    return out


def _patched_def(tree, src: bytes) -> tuple[object, str]:
    """``(def_node, defined_name)`` — the OUTERMOST def in the patched code."""
    if tree is None:
        return None, ""
    for node in _walk(tree.root_node):
        if node.type in _ts.FUNCTION_NODE_TYPES:
            name = ""
            child = node.child_by_field_name("name")
            if child is None:
                child = node.child_by_field_name("declarator")
            if child is not None:
                name = _ts.node_text(child, src).strip()
            if not name:
                for leaf in _walk(node):
                    if leaf.type in ("identifier", "property_identifier",
                                     "field_identifier", "simple_identifier"):
                        name = _ts.node_text(leaf, src).strip()
                        break
            return node, name
    return None, ""


def _sink_report(calls: list[dict], language: str) -> dict:
    """``{category: {"callees": [...], "dynamic": [...]}}`` for one code side.

    Every call in the span is classified through the SAME ported taxonomy the
    hunter used (:func:`sinks.classify_call`), keyed by category so "the
    database sink is gone" is a statement about one rule set rather than a
    second opinion. ``dynamic`` lists the callees whose argument text contains
    concatenation or interpolation — a remaining sink that still receives a
    built-at-runtime value.
    """
    report: dict[str, dict] = {}
    for call in calls:
        text = str(call.get("text") or "")
        categories = sinks.classify_call(text, language or None)
        if not categories:
            continue
        callee = sinks.normalise_call(text)
        args = " ".join(call.get("args") or [])
        blanked = _STRING_LITERAL_RE.sub('""', args)
        dynamic = ("+" in blanked or "${" in blanked or ".format(" in blanked
                   or bool(_FSTRING_RE.search(blanked))
                   or bool(_PERCENT_RE.search(blanked)))
        for category in categories:
            entry = report.setdefault(category, {"callees": [], "dynamic": []})
            if callee not in entry["callees"]:
                entry["callees"].append(callee)
            if dynamic and callee not in entry["dynamic"]:
                entry["dynamic"].append(callee)
    return report


def _span_calls(root: str, node: dict, cache: dict) -> list[dict]:
    """Every call inside a node's own span, with its argument text."""
    parsed = _parse_node_file(root, node, cache)
    if parsed is None:
        return []
    tree, src = parsed
    start = _as_int(node.get("start_line"), 0)
    end = _as_int(node.get("end_line"), 0)
    if not start or end < start:
        return []
    out: list[dict] = []
    for call in _ts.calls_in_span(tree, start, end, src):
        out.append({"line": call.get("line"), "text": call.get("text"),
                    "args": _call_arguments(call.get("node"), src)})
    return out


@tool(parse_docstring=True)
def validate_remediation_patch(node_id: str, patched_code: str, root: str = ".",
                               limit: int | None = None) -> str:
    """Does the proposed patch actually fix the sink without breaking the callers?

    Post-patch proof, three independent checks on the patched text:

    1. **parses** — the patch is parsed with the node's OWN grammar; a syntax
       error stops the report with the first error positions.
    2. **signature_compatible** — the patched def's parameters are compared with
       the original's, and every caller in the index (``calls`` /
       ``references`` / ``instantiates`` edges) is re-parsed and its call-site
       arity counted, so a patch that adds a REQUIRED parameter is reported
       together with every call site it breaks. The comparison is a MINIMUM
       arity: a caller is compatible when the arguments it passes fall between
       the patched def's required parameters and its declared parameters (no
       maximum for a variadic), so a patch that only ADDS an optional parameter
       — ``def find_order(name, region, limit=100)`` — is reported as
       compatible rather than as breaking every existing caller.
    3. **sinks** — the calls on both sides are classified with the same ported
       CodeGraph effects taxonomy (no semgrep dependency), yielding
       ``eliminated`` / ``remaining`` / ``introduced``; any REMAINING sink whose
       argument text contains concatenation, template interpolation or an
       f-string is flagged as still receiving a dynamic expression.

    Use this BEFORE proposing or applying a remediation, and before telling a
    user a fix is complete. Do NOT use it as a taint tracer: "sink eliminated"
    means the call no longer appears in this span, and the taxonomy is a curated
    effect table — a sink it does not name is not a sink it can clear.

    Args:
        node_id: The node being patched (its language, span and callers define
            every check below).
        patched_code: The FULL replacement text for that node — a complete def,
            not a diff hunk.
        root: Repo root holding ``.codegraph/codegraph.db``.
        limit: Cap on callers checked and on rows rendered per section.
            0 = unlimited (hard-clamped at 500).

    Returns:
        Compact sections — ``parses``, ``signature_compatible`` (plus the
        arity-incompatible callers as ``{caller, file:line, call_arity,
        expected_arity}``), ``sinks {eliminated, remaining, introduced}`` and a
        one-line verdict — or an ``ERROR:`` string when the repo is not indexed,
        the node is unknown, or the patch does not parse.

    Note:
        A patch with no ``def`` node in it is a BODY FRAGMENT: it declares no
        signature, so the signature comparison and the caller-arity check are
        both skipped (and the verdict never cites caller breakage) instead of
        being run against an empty parameter list.
    """
    try:
        _db.resolve_db_path(root)
    except ValueError as e:
        return _cap_chars(f"ERROR: {e}")
    conn = _db.connect(root)
    if conn is None:
        return _cap_chars(_db.guidance_no_db(root))

    node = _db.get_node(conn, node_id)
    if node is None:
        return _cap_chars(f"ERROR: node not found: {node_id}")

    language = str(node.get("language") or "")
    name = str(node.get("name") or node_id)
    file_path = str(node.get("file_path") or "")
    start = _as_int(node.get("start_line"), 0)
    end = _as_int(node.get("end_line"), 0)

    cap = _cap_rows(limit, ENV_CALLERS, DEFAULT_CALLERS)
    row_cap = _section_cap(ENV_CALLERS, DEFAULT_CALLERS)

    out: list[str] = [f"# patch validation: {name} ({node.get('kind')}) "
                      f"{file_path}:{start}" + (f"-{end}" if end > start else "")]
    out.append(f"node_id: {node_id}  language: {language or 'unknown'}")

    # ---- (a) the patch parses ------------------------------------------
    tree = _ts.parse_source(str(patched_code or ""), language)
    if tree is None:
        return _cap_chars(
            f"ERROR: patched code does not parse: no parser for language "
            f"{language!r} (grammar not installed, or the node's language is "
            f"unknown)")
    has_error = False
    try:
        has_error = bool(tree.root_node.has_error)
    except Exception:
        has_error = False
    if has_error:
        positions = _parse_errors(tree)
        detail = "; ".join(positions) if positions else "the grammar reported an ERROR node"
        return _cap_chars(
            f"ERROR: patched code does not parse ({language}): {detail}"
            + (f"; … more" if len(positions) >= MAX_ERROR_POSITIONS else ""))

    src = str(patched_code or "").encode("utf-8", errors="replace")
    def_node, defined_name = _patched_def(tree, src)
    patched_params = _params_from_def(def_node, src)
    # A body fragment declares no signature at all, so neither the parameter
    # comparison nor the caller-arity check below can say anything true about
    # it. Running them anyway scored ``expected_arity=0`` and reported every
    # caller as broken, which contradicted the note that followed.
    body_fragment = def_node is None
    out.append("")
    out.append(f"--- parses: yes ({language}, "
               f"{len(str(patched_code or '').splitlines())} lines)")
    if body_fragment:
        out.append("  note: no def/function node found in the patch — treated as "
                   "a body fragment, so the signature check and the "
                   "caller-arity check are both skipped")
    elif defined_name and defined_name != name:
        out.append(f"  [warning: the patch defines {defined_name!r} but the node "
                   f"is {name!r} — continuing, the checks below are name-agnostic]")
    elif not defined_name:
        out.append("  note: the patched def carries no name node; continuing")

    # ---- (b) signature compatibility ------------------------------------
    original_params, original_basis = _original_params(node)
    min_arity, max_arity = _arity_bounds(patched_params)
    variadic = max_arity is None
    out.append("")
    if body_fragment:
        out.append("--- signature_compatible: not checked "
                   "(the patch has no def — nothing to compare)")
    elif patched_params and original_params:
        added = [_param_label(p) for p in patched_params[len(original_params):]]
        removed = [_param_label(p)
                   for p in original_params[len(patched_params):]]
        if added or removed:
            out.append("--- signature_compatible: yes "
                       "(every existing caller still passes enough arguments)")
            out.append("  arity changes: "
                       + (f"+{', '.join(added)} " if added else "")
                       + (f"-{', '.join(removed)}" if removed else ""))
        else:
            out.append("--- signature_compatible: yes")
            out.append("  arity unchanged")
    else:
        out.append(f"--- signature_compatible: "
                   f"{'yes' if patched_params or not original_params else 'see below'}")
    out.append(f"  patched parameters ({len(patched_params)}): "
               + (", ".join(_param_label(p) for p in patched_params)
                  or "(none parsed)"))
    out.append(f"  original parameters ({len(original_params)}, {original_basis}): "
               + (", ".join(_param_label(p) for p in original_params)
                  or "(none parsed)"))
    if patched_params and not body_fragment:
        out.append(f"  arity rule: a caller is compatible when it passes between "
                   f"{min_arity} and {'unlimited' if variadic else max_arity} "
                   f"argument(s); an optional parameter may be omitted")

    # every caller, re-counted — skipped whole for a body fragment, which
    # declares no signature to compare a call site against
    seen_edges: set[tuple] = set()
    unique_edges: list[dict] = []
    if not body_fragment:
        edges = _db.incoming_edges(conn, node_id, kinds=list(_CALLER_EDGE_KINDS),
                                   limit=cap)
        for edge in edges:
            fingerprint = (str(edge.get("source") or ""),
                           str(edge.get("target") or ""),
                           str(edge.get("kind") or ""), _as_int(edge.get("line"), 0),
                           _as_int(edge.get("col"), 0))
            if fingerprint in seen_edges:
                continue  # idx_edges_identity may still admit duplicates after a sync
            seen_edges.add(fingerprint)
            unique_edges.append(edge)

    expected = min_arity
    caller_cache: dict[str, tuple] = {}
    checked = 0
    incompatible: list[str] = []
    unresolvable: list[str] = []
    if body_fragment:
        out.append("  callers checked: skipped — a body fragment declares no "
                   "signature, so there is no arity to compare a call site "
                   "against (nothing below reports a caller as broken)")
    for edge in unique_edges:
        source_id = str(edge.get("source") or "")
        caller = _db.get_node(conn, source_id)
        if caller is None:
            unresolvable.append(f"{source_id} (source node not in the index)")
            continue
        caller_file = str(caller.get("file_path") or "")
        parsed = _parse_node_file(root, caller, caller_cache)
        call_arity = None
        basis = ""
        if parsed is not None:
            caller_tree, caller_src = parsed
            line = _as_int(edge.get("line"), 0)
            candidates = _ts.calls_in_span(caller_tree, line, line, caller_src) \
                if line else []
            hit = next((c for c in candidates
                        if _callee_tail(c["text"]) in (name, name.rsplit(".", 1)[-1])),
                       None)
            basis = "edge line"
            if hit is None:
                lo = _as_int(caller.get("start_line"), 1) or 1
                hi = _as_int(caller.get("end_line"), 1) or 1
                wider = _ts.calls_in_span(caller_tree, lo, hi, caller_src)
                hit = next((c for c in wider
                            if _callee_tail(c["text"]) in (name, name.rsplit(".", 1)[-1])),
                           None)
                if hit is not None:
                    basis = "caller span"
            if hit is not None:
                call_arity = len(_call_arguments(hit.get("node"), caller_src))
        checked += 1
        if call_arity is None:
            unresolvable.append(
                f"{caller.get('name')} ({source_id}) {caller_file}:"
                f"{_as_int(edge.get('line'), 0)} — call site not parsed")
            continue
        # The required parameters are the floor, the declared parameter count
        # is the ceiling, and a variadic patch has no ceiling at all. A caller
        # that merely omits an optional parameter is still compatible, which is
        # what makes a patch adding ``limit=100`` backwards-compatible — while a
        # variadic patch still refuses a caller below its required minimum.
        upper = call_arity if max_arity is None else max_arity
        if min_arity <= call_arity <= upper:
            continue
        incompatible.append(
            f"  caller={caller.get('name')} ({source_id})  "
            f"{caller_file}:{_as_int(edge.get('line'), 0)}  "
            f"call_arity={call_arity}  expected_arity={expected}  [{basis}]"
            + ("" if max_arity is None else
               ("" if max_arity == min_arity else f"-{max_arity}")))

    if body_fragment:
        pass  # the skip note above is the whole of this section
    else:
        out.append(f"  callers checked: {checked} of {len(unique_edges)} "
                   f"incoming {', '.join(_CALLER_EDGE_KINDS)} edge(s)")
        if incompatible:
            shown = incompatible[:row_cap]
            out.append(f"  arity-INCOMPATIBLE callers ({len(incompatible)}):")
            out.extend(shown)
            if len(incompatible) > len(shown):
                out.append(f"  … +{len(incompatible) - len(shown)} more incompatible "
                           f"callers (total {len(incompatible)})")
        else:
            out.append(f"  arity-incompatible callers: none "
                       f"(all {checked} parsed call site(s) pass between "
                       f"{min_arity} and "
                       f"{'unlimited' if variadic else max_arity} argument(s))")
        if unresolvable:
            shown = unresolvable[:row_cap]
            out.append(f"  call sites not parsed ({len(unresolvable)}):")
            out.extend(f"    {u}" for u in shown)
            if len(unresolvable) > len(shown):
                out.append(f"    … +{len(unresolvable) - len(shown)} more "
                           f"(total {len(unresolvable)})")
            out.append("  note: an unparsed call site is NOT proof of compatibility")

    # ---- (c) sink elimination ------------------------------------------
    original_calls = _span_calls(root, node, caller_cache)
    patched_calls: list[dict] = []
    for call in _ts.calls_in_span(tree, 1, len(src.decode("utf-8", "replace").splitlines()), src):
        patched_calls.append({"line": call.get("line"), "text": call.get("text"),
                              "args": _call_arguments(call.get("node"), src)})

    before = _sink_report(original_calls, language)
    after = _sink_report(patched_calls, language)
    eliminated = sorted(set(before) - set(after))
    remaining = sorted(set(before) & set(after))
    introduced = sorted(set(after) - set(before))

    out.append("")
    out.append(f"--- sinks (taxonomy: the ported CodeGraph effects table)")
    out.append(f"  eliminated ({len(eliminated)}): "
               + (", ".join(eliminated) or "none"))
    out.append(f"  remaining ({len(remaining)}): "
               + (", ".join(remaining) or "none"))
    out.append(f"  introduced ({len(introduced)}): "
               + (", ".join(introduced) or "none"))
    for category in remaining:
        dynamic = after.get(category, {}).get("dynamic") or []
        callees = after.get(category, {}).get("callees") or []
        out.append(f"  remaining {category}: callees "
                   + (", ".join(callees) or "(unknown)"))
        if dynamic:
            out.append(f"  [warning: {category} sink still receives a dynamic "
                       f"expression: {', '.join(dynamic)}]")
    for category in introduced:
        out.append(f"  introduced {category}: callees "
                   + (", ".join(after.get(category, {}).get("callees") or [])))
    if not (eliminated or remaining or introduced):
        out.append("  (no effect-classified calls on either side of the patch)")

    # ---- verdict --------------------------------------------------------
    problems: list[str] = []
    # A body fragment never ran the caller check, so it must never be cited in
    # a "N callers break" verdict either — that claim had no evidence behind it.
    if incompatible:
        problems.append(f"{len(incompatible)} caller(s) break")
    dynamic_remaining = [c for c in remaining
                         if after.get(c, {}).get("dynamic")]
    if dynamic_remaining:
        problems.append(f"{len(dynamic_remaining)} sink(s) still take a dynamic "
                        f"argument")
    if not eliminated and before:
        problems.append("no sink eliminated")
    if problems:
        verdict = "verdict: patch is NOT clean — " + "; ".join(problems)
        if body_fragment:
            verdict += " (body fragment: no signature, so no caller-arity check ran)"
    elif body_fragment:
        verdict = ("verdict: patch parses as a body fragment — the signature and "
                   "caller-arity checks were skipped, so nothing here says a "
                   "caller broke")
    elif eliminated:
        verdict = (f"verdict: patch parses, keeps the signature, and eliminates "
                   f"{len(eliminated)} sink category(ies) "
                   f"({', '.join(eliminated)})")
    else:
        verdict = ("verdict: patch parses and breaks no caller, but eliminates "
                   "no sink")
    if introduced:
        verdict += f"; note it introduces {', '.join(introduced)}"
    out.append("")
    out.append(verdict)
    out.append(f"note: sink comparison is category-level over the patched span "
               f"and the node's original span ({file_path}:{start}-{end}); a sink "
               f"the taxonomy does not name is neither eliminated nor reported")
    return _cap_chars("\n".join(out))

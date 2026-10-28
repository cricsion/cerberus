"""The sidecar memory store — the only writable artifact this package makes.

Purpose
Per-node verdicts ("this function is a SANITIZER for CWE-79") live in
``<repo>/.codegraph/sast_summaries.db`` (or ``$SAST_SUMMARIES_DB``), beside the
index CodeGraph already owns and auto-gitignores.

Laws
- Every writer returns a confirmation or an ``ERROR: ...`` string; every reader
  returns ``[]``. No filesystem or SQLite failure raises into a tool loop.
- The sidecar is created on first write (``CREATE TABLE IF NOT EXISTS``) under
  a process-wide lock; ``check_same_thread=False`` because it outlives a call.
- Writes never touch the CodeGraph index, which is opened read-only elsewhere.
- Input is semantic, not just stored: roles are validated against their
  taxonomy and ``cwe_scope`` is normalised to ``CWE-<n>`` tokens.
- A summary is a claim an analyst can overwrite, never a finding.

Invariants
- The upsert key is the node id; re-recording refreshes rather than
  accumulates.
- ``SAST_SUMMARIES_DB`` wins over the default path and skips containment.

Format laws
- Table: ``summaries`` (see SCHEMA).
- Readers return lists of dicts carrying the schema columns; ``cache_hint``
  returns ``"[CACHED SUMMARY: ROLE for CWE-…] …"`` or ``""``.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from harness.codegraph._db import _safe_param

DEFAULT_DB_NAME = "sast_summaries.db"

# The verdict taxonomy: what a node IS, security-wise, for one CWE scope.
ROLES = ("SANITIZER", "VALIDATOR", "AUTH_GUARD", "TAINT_PASSTHROUGH", "SAFE_WRAPPER")


SCHEMA = """
CREATE TABLE IF NOT EXISTS summaries (
    node_id TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    cwe_scope TEXT,
    notes TEXT,
    updated_at INTEGER NOT NULL
);
"""

_LOCK = threading.Lock()

_OK_SUMMARY = "recorded {role} summary for {node_id} (cwe: {cwe})"
_UNWRITABLE = "ERROR: sidecar not writable at {path}: {reason}"


def _has_unboundable_text(value) -> bool:
    """True when a string carries characters SQLite could never store.

    Refusing on the write path beats silently rewriting the input.
    """
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return False


def store_path(root: str = ".") -> Path:
    """Absolute path of the sidecar DB.

    ``SAST_SUMMARIES_DB`` wins (deliberate placement, no containment check);
    otherwise ``<repo>/.codegraph/sast_summaries.db`` under the shared check.
    Raises ``ValueError`` for an escape or an OS-level refusal; callers convert.
    """
    override = (os.environ.get("SAST_SUMMARIES_DB") or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    from harness.tools.code import _safe_path
    try:
        base = _safe_path(str(root) if root is not None else ".")
        try:
            if base.is_file():
                base = base.parent
        except OSError:
            pass
        return (base / ".codegraph" / DEFAULT_DB_NAME).resolve()
    except OSError as e:
        raise ValueError(
            f"cannot resolve summary store path for {root!r}: {e}") from None


def _connect(path: Path):
    """``(connection, error_string)``; the connection is None when unusable."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return None, _UNWRITABLE.format(path=path, reason=e)
    try:
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        with _LOCK:
            conn.executescript(SCHEMA)
            conn.commit()
        return conn, ""
    except (sqlite3.Error, OSError, ValueError) as e:
        return None, _UNWRITABLE.format(path=path, reason=e)


def _close(conn) -> None:
    """Close a connection, swallowing a close-time SQLite error."""
    if conn is None:
        return
    try:
        conn.close()
    except sqlite3.Error:
        pass


def _now_ms() -> int:
    """Wall-clock milliseconds, the schema's ``updated_at`` unit."""
    return int(time.time() * 1000)


def _is_connection(candidate) -> bool:
    """True when the caller handed us a borrowed CodeGraph connection."""
    return isinstance(candidate, sqlite3.Connection)


def _sidecar_for(conn_or_root) -> Path:
    """Where the sidecar lives for either a CodeGraph connection or a root.

    A connection carries its own index path, so the sidecar sits beside THAT
    index (a monorepo may have several) without remembering the root.
    """
    if _is_connection(conn_or_root):
        try:
            rows = conn_or_root.execute("PRAGMA database_list").fetchall()
            for row in rows:
                name = row[1] if len(row) > 1 else ""
                if name == "main" and len(row) > 2 and row[2]:
                    return Path(row[2]).resolve().parent / DEFAULT_DB_NAME
        except (sqlite3.Error, OSError, ValueError):
            pass
        return store_path(".")
    if conn_or_root is None:
        return store_path(".")
    return store_path(str(conn_or_root))


def _node_exists(conn, node_id: str) -> bool:
    """True when ``node_id`` is in the borrowed index's ``nodes`` table."""
    if conn is None:
        return False
    try:
        row = conn.execute("SELECT 1 FROM nodes WHERE id = ? LIMIT 1",
                           (_safe_param(node_id),)).fetchone()
    except (sqlite3.Error, UnicodeEncodeError):
        return False
    return row is not None


def _normalise_cwe(value) -> list[str]:
    """``"79, CWE-89"``, ``["79"]``, ``"CWE-79 CWE-89"`` -> ``["CWE-79","CWE-89"]``.

    Bare numbers get the ``CWE-`` prefix; order is kept, duplicates dropped.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        parts: list[str] = []
        for item in value:
            parts.extend(_normalise_cwe(item))
        return parts
    text = str(value).strip()
    if not text:
        return []
    out: list[str] = []
    for token in text.replace(";", ",").replace(" ", ",").split(","):
        tok = token.strip().strip("\"'").upper()
        if not tok:
            continue
        if tok.isdigit():
            tok = f"CWE-{tok}"
        elif tok.startswith("CWE") and not tok.startswith("CWE-"):
            tok = f"CWE-{tok[3:]}"
        if tok and tok not in out:
            out.append(tok)
    return out


def _normalise_role(value) -> str:
    """Canonical taxonomy token: upper-case, spaces/dashes to underscores."""
    return str(value or "").strip().upper().replace(" ", "_").replace("-", "_")


def _text_error(text: str, label: str, limit: int) -> str:
    """Shared length/NUL/storability checks: an error string or ``""``."""
    if len(text) > limit:
        return f"ERROR: {label} too long ({len(text)} chars, max {limit})"
    if "\x00" in text:
        return f"ERROR: {label} contains a NUL byte"
    if _has_unboundable_text(text):
        # A lone surrogate cannot be stored: SQLite binds text as UTF-8.
        return f"ERROR: {label} contains unsupported characters"
    return ""


def _check_identifier(value, label: str, limit: int = 400) -> str:
    """Required, bounded, storable identifier: an error string or ``""``."""
    text = str(value or "").strip()
    if not text:
        return f"ERROR: {label} is required"
    return _text_error(text, label, limit)


def _check_free_text(value, label: str, limit: int = 20000) -> str:
    """Length-capped, NUL-free, storable — but never required (notes are)."""
    return _text_error(str(value or ""), label, limit)


def _safe_store_path(root):
    """``(path, error_string)``. Never raises: an escape becomes an error."""
    try:
        return store_path(root), ""
    except ValueError as e:
        return None, f"ERROR: {e}"
    except OSError as e:
        return None, f"ERROR: cannot resolve summary store path for {root!r}: {e}"


def record_summary(root, node_id: str, role: str, cwe_scope, notes: str) -> str:
    """Upsert one node's security verdict. Returns a confirmation or an error.

    ``node_id`` need not exist in the index — a miss is a WARNING in the
    returned string, not a refusal. Unstorable input is a refusal.
    """
    err = _check_identifier(node_id, "node_id")
    if err:
        return err
    err = _check_free_text(notes, "notes")
    if err:
        return err
    role_norm = _normalise_role(role)
    if role_norm not in ROLES:
        return (f"ERROR: unknown role {role!r} "
                f"(use one of {', '.join(sorted(ROLES))})")
    cwe = _normalise_cwe(cwe_scope)
    path, error = _safe_store_path(root)
    if path is None:
        return error
    conn, error = _connect(path)
    if conn is None:
        return error
    try:
        with _LOCK:
            conn.execute(
                "INSERT INTO summaries (node_id, role, cwe_scope, notes, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(node_id) DO UPDATE SET role = excluded.role, "
                "cwe_scope = excluded.cwe_scope, notes = excluded.notes, "
                "updated_at = excluded.updated_at",
                (_safe_param(node_id), role_norm, json.dumps(cwe),
                 _safe_param(notes or ""), _now_ms()),
            )
            conn.commit()
    except (sqlite3.Error, OSError, ValueError) as e:
        return _UNWRITABLE.format(path=path, reason=e)
    finally:
        _close(conn)
    message = _OK_SUMMARY.format(role=role_norm, node_id=_safe_param(node_id),
                                 cwe=", ".join(cwe) or "none")
    if not _is_connection(root):
        # A miss in the index is a warning: the node may not be indexed yet.
        try:
            codegraph = _codegraph_connect(root)
        except Exception:
            codegraph = None
        if codegraph is not None and not _node_exists(codegraph, str(node_id)):
            message += " [warning: node_id not found in the nodes table]"
    return message


def _codegraph_connect(root):
    """The read-only CodeGraph handle, or None. Never raises."""
    try:
        from harness.codegraph import _db
        return _db.connect(str(root))
    except Exception:
        return None


def _fetch(path: Path, sql: str, params: tuple = (), *, query_errors=(sqlite3.Error, OSError, ValueError)):
    """Rows for one sidecar query, or None when the DB cannot be opened/read."""
    try:
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
    except (sqlite3.Error, OSError, ValueError):
        return None
    try:
        return conn.execute(sql, params).fetchall()
    except query_errors:
        return None
    finally:
        _close(conn)


def get_summaries(conn_or_root, node_id: str) -> list[dict]:
    """Every summary recorded for a node — at most one row, but a list."""
    err = _check_identifier(node_id, "node_id")
    if err:
        return []
    try:
        path = _sidecar_for(conn_or_root)
    except (ValueError, OSError):
        return []
    rows = _fetch(
        path,
        "SELECT node_id, role, cwe_scope, notes, updated_at FROM summaries "
        "WHERE node_id = ? ORDER BY updated_at DESC, role",
        (_safe_param(node_id),),
    )
    return [_row_to_summary(r) for r in rows or []]


def _row_to_summary(row) -> dict:
    """One ``summaries`` row as the public dict shape (bad CWE JSON -> [])."""
    try:
        cwe = json.loads(row["cwe_scope"]) if row["cwe_scope"] else []
    except (ValueError, TypeError, KeyError, IndexError):
        cwe = []
    if not isinstance(cwe, list):
        cwe = [str(cwe)]
    return {
        "node_id": row["node_id"],
        "role": row["role"],
        "cwe_scope": [str(c) for c in cwe],
        "notes": row["notes"] or "",
        "updated_at": row["updated_at"],
    }


def cache_hint(conn_or_root, node_id: str) -> str:
    """``"[CACHED SUMMARY: SANITIZER for CWE-79] ..."`` — a compact reminder.

    Empty string when nothing is recorded, so a caller never checks first.
    """
    rows = get_summaries(conn_or_root, node_id)
    if not rows:
        return ""
    parts = []
    for row in rows:
        scope = ", ".join(row["cwe_scope"]) or "any CWE"
        body = row["notes"].strip()
        parts.append(f"[CACHED SUMMARY: {row['role']} for {scope}]"
                     + (f" {body}" if body else ""))
    return "; ".join(parts)[:600]



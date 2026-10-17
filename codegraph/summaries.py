"""The sidecar memory store — the only writable artifact this package makes.

A SAST agent that has reasoned about a node once should not reason about it
again. This module is that memory: per-node verdicts ("this function is a
SANITIZER for CWE-79"), per-(CWE, sink-signature) triage decisions ("this exact
pair was already called a FALSE_POSITIVE"), and the analyst's own variant rules.
It lives in ``<repo>/.codegraph/sast_summaries.db`` — the directory CodeGraph
already owns and auto-gitignores — so nothing new appears in the target repo's
tree, and ``SAST_SUMMARIES_DB`` can point it elsewhere (a shared scan dir, an
absolute path outside the repo).

What this gives that raw ``sqlite3`` does not:

- **A degradation contract.** Every writer returns a confirmation string or an
  ``"ERROR: ..."`` string; every reader returns ``[]``. A read-only filesystem,
  a missing directory, a corrupt file — none of them raise into an agent's tool
  loop. Writes never touch the CodeGraph index: that file is opened read-only
  everywhere else in this package, by design.
- **One schema, created on first write** (``CREATE TABLE IF NOT EXISTS``), with
  a process-wide lock around the write path so two tool calls in one thread
  pool cannot interleave. ``check_same_thread=False`` because the connection
  outlives the call that made it.
- **Semantics, not just storage.** ``role`` is validated against the taxonomy,
  ``decision`` against the four triage verdicts, ``cwe_scope`` is normalised so
  ``"79, 89"`` and ``["CWE-79"]`` are the same row, and the upsert is keyed on
  the node id so re-reading a function after a sync refreshes one row rather
  than accumulating a list.

Nothing here is a finding. A summary is a claim an analyst can act on and, when
it is wrong, overwrite.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path

DEFAULT_DB_NAME = "sast_summaries.db"

# The verdict taxonomy: what a node IS, security-wise, for one CWE scope.
ROLES = ("SANITIZER", "VALIDATOR", "AUTH_GUARD", "TAINT_PASSTHROUGH", "SAFE_WRAPPER")

# The triage verdicts.
DECISIONS = ("TRUE_POSITIVE", "FALSE_POSITIVE", "SUPPRESSED", "NEEDS_REVIEW")

SCHEMA = """
CREATE TABLE IF NOT EXISTS summaries (
    node_id TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    cwe_scope TEXT,
    notes TEXT,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS triage_memory (
    cwe_id TEXT NOT NULL,
    sink_signature TEXT NOT NULL,
    decision TEXT NOT NULL,
    notes TEXT,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (cwe_id, sink_signature)
);
CREATE TABLE IF NOT EXISTS variant_rules (
    name TEXT PRIMARY KEY,
    tree_sitter_query TEXT NOT NULL,
    cwe_id TEXT,
    updated_at INTEGER NOT NULL
);
"""

_LOCK = threading.Lock()

_OK_SUMMARY = "recorded {role} summary for {node_id} (cwe: {cwe})"
_UNWRITABLE = "ERROR: sidecar not writable at {path}: {reason}"


# ---------------------------------------------------------------------------
# bindable text
# ---------------------------------------------------------------------------

def _safe_param(value) -> str:
    """Text SQLite can bind, whatever the agent handed us.

    Python's ``str`` admits lone surrogates; SQLite binds text as UTF-8 and
    raises ``UnicodeEncodeError`` from inside ``execute`` for them. Every
    query below binds agent-controlled strings, so every one of them passes
    through here first: a hostile value simply matches/updates nothing.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-8", "replace").decode("utf-8", "replace")
    return text


def _has_unboundable_text(value) -> bool:
    """True when a string carries characters SQLite could never store.

    Used on the WRITE paths, where silently rewriting the analyst's input would
    be worse than refusing it: a tree-sitter query or a sink signature altered
    by a replacement character is no longer the thing that was written.
    """
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return False


# ---------------------------------------------------------------------------
# path
# ---------------------------------------------------------------------------

def store_path(root: str = ".") -> Path:
    """Absolute path of the sidecar DB.

    ``SAST_SUMMARIES_DB`` wins when set (absolute path, no containment check:
    the operator is placing the memory deliberately, e.g. on a scan-scoped
    volume). Otherwise it is ``<repo>/.codegraph/sast_summaries.db``, resolved
    under the same containment check every other tool here uses.

    Raises ``ValueError`` for a containment escape and for an OS-level refusal
    (a path component past NAME_MAX) — both become ``ERROR: ...`` strings at
    the callers that convert them, so no ``OSError`` escapes this module.
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
    """(connection, error_string). The connection is None when unusable."""
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
    if conn is None:
        return
    try:
        conn.close()
    except sqlite3.Error:
        pass


def _now_ms() -> int:
    return int(time.time() * 1000)


def _is_connection(candidate) -> bool:
    return isinstance(candidate, sqlite3.Connection)


def _sidecar_for(conn_or_root) -> Path:
    """Where the sidecar lives for either a CodeGraph connection or a root.

    A CodeGraph connection carries its own file path, so a caller holding one
    gets the sidecar beside THAT index (a monorepo may have several) without
    having to remember the root it opened it from.
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
    if conn is None:
        return False
    try:
        row = conn.execute("SELECT 1 FROM nodes WHERE id = ? LIMIT 1",
                           (_safe_param(node_id),)).fetchone()
    except (sqlite3.Error, UnicodeEncodeError):
        return False
    return row is not None


# ---------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------

def _normalise_cwe(value) -> list[str]:
    """``"79, CWE-89"``, ``["79"]``, ``"CWE-79 CWE-89"`` -> ``["CWE-79","CWE-89"]``.

    Bare numbers are given the ``CWE-`` prefix so a scope written either way
    lands in the same row, and the order is preserved with duplicates dropped.
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
    return str(value or "").strip().upper().replace(" ", "_").replace("-", "_")


def _normalise_decision(value) -> str:
    return str(value or "").strip().upper().replace(" ", "_").replace("-", "_")


def _check_identifier(value, label: str, limit: int = 400) -> str:
    text = str(value or "").strip()
    if not text:
        return f"ERROR: {label} is required"
    if len(text) > limit:
        return f"ERROR: {label} too long ({len(text)} chars, max {limit})"
    if "\x00" in text:
        return f"ERROR: {label} contains a NUL byte"
    if _has_unboundable_text(text):
        # A lone surrogate cannot be stored: SQLite binds text as UTF-8, so
        # this write could never have been recorded. Refuse, never raise.
        return f"ERROR: {label} contains unsupported characters"
    return ""


def _check_free_text(value, label: str, limit: int = 20000) -> str:
    """Length-capped, NUL-free, storable — but never required (notes are)."""
    text = str(value or "")
    if len(text) > limit:
        return f"ERROR: {label} too long ({len(text)} chars, max {limit})"
    if "\x00" in text:
        return f"ERROR: {label} contains a NUL byte"
    if _has_unboundable_text(text):
        return f"ERROR: {label} contains unsupported characters"
    return ""


# ---------------------------------------------------------------------------
# per-node summaries
# ---------------------------------------------------------------------------

def _safe_store_path(root):
    """(path, error_string). Never raises: containment escape becomes an error."""
    try:
        return store_path(root), ""
    except ValueError as e:
        return None, f"ERROR: {e}"
    except OSError as e:
        return None, f"ERROR: cannot resolve summary store path for {root!r}: {e}"


def record_summary(root, node_id: str, role: str, cwe_scope, notes: str) -> str:
    """Upsert one node's security verdict. Returns a confirmation or an error.

    ``node_id`` need not exist in the index — an agent may summarise a symbol
    whose file has not been indexed yet — so a miss is a WARNING in the
    returned string, not a refusal. Input that SQLite could not store at all
    (a lone surrogate) is a refusal, for the same reason: a row the store can
    never hold is not a verdict.
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
        # A miss in the index is a WARNING, not a refusal: the node may simply
        # not be indexed yet. The connection is the shared read-only cache's,
        # so it is borrowed, never closed here.
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


def get_summaries(conn_or_root, node_id: str) -> list[dict]:
    """Every summary recorded for a node — one after the upsert, but a list.

    Keyed on the node id, so the list holds at most one row; it is a list
    anyway because the shape is what a caller iterates.
    """
    err = _check_identifier(node_id, "node_id")
    if err:
        return []
    try:
        path = _sidecar_for(conn_or_root)
    except (ValueError, OSError):
        return []
    try:
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
    except (sqlite3.Error, OSError, ValueError):
        return []
    try:
        rows = conn.execute(
            "SELECT node_id, role, cwe_scope, notes, updated_at FROM summaries "
            "WHERE node_id = ? ORDER BY updated_at DESC, role",
            (_safe_param(node_id),),
        ).fetchall()
    except (sqlite3.Error, OSError, ValueError):
        return []
    finally:
        _close(conn)
    return [_row_to_summary(r) for r in rows]


def _row_to_summary(row) -> dict:
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

    Empty string when nothing is recorded: a caller that appends this to its
    context never has to check for a header first.
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


# ---------------------------------------------------------------------------
# triage memory
# ---------------------------------------------------------------------------

def record_triage(root, cwe_id: str, sink_signature: str, decision: str,
                  notes: str = "") -> str:
    """Remember what an analyst decided about one (CWE, sink) pair.

    Keyed on the pair so the same sink reached through two different call
    chains keeps one verdict, and the four allowed decisions are enforced:
    a tyoed verdict would surface later as a filter nothing matches.
    """
    err = _check_identifier(cwe_id, "cwe_id", 40)
    if err:
        return err
    err = _check_identifier(sink_signature, "sink_signature", 400)
    if err:
        return err
    err = _check_free_text(notes, "notes")
    if err:
        return err
    decision_norm = _normalise_decision(decision)
    if decision_norm not in DECISIONS:
        return (f"ERROR: unknown decision {decision!r} "
                f"(use one of {', '.join(sorted(DECISIONS))})")
    cwe = _normalise_cwe(cwe_id)
    cwe_text = cwe[0] if cwe else str(cwe_id).strip().upper()
    path, error = _safe_store_path(root)
    if path is None:
        return error
    conn, error = _connect(path)
    if conn is None:
        return error
    try:
        with _LOCK:
            conn.execute(
                "INSERT INTO triage_memory (cwe_id, sink_signature, decision, notes, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(cwe_id, sink_signature) DO UPDATE SET "
                "decision = excluded.decision, notes = excluded.notes, "
                "updated_at = excluded.updated_at",
                (_safe_param(cwe_text), _safe_param(sink_signature), decision_norm,
                 _safe_param(notes or ""), _now_ms()),
            )
            conn.commit()
    except (sqlite3.Error, OSError, ValueError) as e:
        return _UNWRITABLE.format(path=path, reason=e)
    finally:
        _close(conn)
    return f"recorded triage: {cwe_text} @ {sink_signature} = {decision_norm}"


def query_triage(root, cwe_id: str = "", sink_signature: str = "") -> list[dict]:
    """The remembered verdicts, newest first. Both filters are optional.

    Filters are equality (after normalisation), so a caller sees every pair
    recorded for one CWE, or the one verdict for one exact sink signature.
    """
    try:
        path = store_path(root)
    except (ValueError, OSError):
        return []
    try:
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
    except (sqlite3.Error, OSError, ValueError):
        return []
    clause: list[str] = []
    params: list = []
    cwe = _normalise_cwe(cwe_id)
    if cwe:
        clause.append("cwe_id = ?")
        params.append(_safe_param(cwe[0]))
    sig = str(sink_signature or "").strip()
    if sig:
        clause.append("sink_signature = ?")
        params.append(_safe_param(sig))
    where = f"WHERE {' AND '.join(clause)}" if clause else ""
    try:
        rows = conn.execute(
            f"SELECT cwe_id, sink_signature, decision, notes, updated_at "
            f"FROM triage_memory {where} ORDER BY updated_at DESC, cwe_id LIMIT 500",
            tuple(params),
        ).fetchall()
    except (sqlite3.Error, OSError, ValueError):
        return []
    finally:
        _close(conn)
    return [{"cwe_id": r["cwe_id"], "sink_signature": r["sink_signature"],
             "decision": r["decision"], "notes": r["notes"] or "",
             "updated_at": r["updated_at"]} for r in rows]


# ---------------------------------------------------------------------------
# variant rules
# ---------------------------------------------------------------------------

def record_variant_rule(root, rule_name: str, pattern: str, cwe_id: str = "") -> str:
    """Save a tree-sitter query the analyst wrote for a variant of a sink.

    The pattern is stored verbatim — a query is only meaningful against the
    grammar it was written for, and re-writing it here would silently change
    what it matches. Only emptiness and a NUL byte are rejected.
    """
    err = _check_identifier(rule_name, "rule_name", 200)
    if err:
        return err
    err = _check_identifier(pattern, "pattern", 20000)
    if err:
        return err
    cwe = _normalise_cwe(cwe_id)
    cwe_text = cwe[0] if cwe else ""
    path, error = _safe_store_path(root)
    if path is None:
        return error
    conn, error = _connect(path)
    if conn is None:
        return error
    try:
        with _LOCK:
            conn.execute(
                "INSERT INTO variant_rules (name, tree_sitter_query, cwe_id, updated_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET tree_sitter_query = excluded.tree_sitter_query, "
                "cwe_id = excluded.cwe_id, updated_at = excluded.updated_at",
                (_safe_param(rule_name), _safe_param(pattern),
                 _safe_param(cwe_text), _now_ms()),
            )
            conn.commit()
    except (sqlite3.Error, OSError, ValueError) as e:
        return _UNWRITABLE.format(path=path, reason=e)
    finally:
        _close(conn)
    return f"recorded variant rule: {rule_name}" + (f" ({cwe_text})" if cwe_text else "")


def list_variant_rules(root) -> list[dict]:
    """Every saved variant rule, newest first."""
    try:
        path = store_path(root)
    except (ValueError, OSError):
        return []
    try:
        conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
    except (sqlite3.Error, OSError, ValueError):
        return []
    try:
        rows = conn.execute(
            "SELECT name, tree_sitter_query, cwe_id, updated_at FROM variant_rules "
            "ORDER BY updated_at DESC, name LIMIT 500"
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        _close(conn)
    return [{"name": r["name"], "tree_sitter_query": r["tree_sitter_query"],
             "cwe_id": r["cwe_id"] or "", "updated_at": r["updated_at"]} for r in rows]

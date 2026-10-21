"""CodeGraph index lifecycle for the scan's target root.

The scan's indexer stage owns the CLI (``init``/``index``/``sync``/``status``);
everything downstream of the hunt reads the index through
:mod:`harness.codegraph._db` — read-only SQL, no CLI (D1). This module is the
writable half of that split. Every public function returns a value instead of
raising: when the CLI is missing, slow, or refuses the target, the scan
continues unindexed (tools fall back to grep, the partitioner to dirs).

Three containment gates, each live-verified against codegraph 1.6.2:

1. **Gate reads are root-pinned.** ``status -j`` walks UP to the nearest
   ``.codegraph`` ("similar to how git finds .git/"): run against a target
   nested under an already-indexed tree it reports the ANCESTOR's
   ``projectPath``/``indexPath``. :func:`index_status` therefore rejects — and
   logs — any payload whose paths are not the requested root, and
   :func:`_gate_ok` additionally requires ``<root>/.codegraph`` and its DB to
   exist at exactly the path :func:`harness.codegraph._db.resolve_db_path`
   joins, so the CLI is never the authority on where the DB is.
2. **A fresh root is initialized first.** ``index <root>`` REFUSES a root with
   no ``.codegraph`` ("CodeGraph not initialized in <root>") and does not walk
   up, so :func:`index_build` runs ``codegraph init -y <root>`` whenever
   ``<root>/.codegraph`` is missing (``init`` builds the index itself).
3. **``sync`` runs only on a confirmed own-root index.** ``sync <nested>`` reads
   AND WRITES the ancestor's index (verified: syncing a subdirectory updated the
   parent's DB and created no ``.codegraph`` of its own), so the status payload
   must first prove ``indexPath == <root>/.codegraph``; when it cannot, the
   root-pinned full ``index -q`` path runs instead.

Payload shape (1.6.2 — one JSON object on stdout): ``{"initialized":…,
"version":…, "projectPath":…, "indexPath":…, "fileCount":…, "nodeCount":…,
"edgeCount":…, "languages":[…], "pendingChanges":{"added":…,"modified":…,
"removed":…}, "index":{"state":"complete"|…, "pendingRefs":…,
"reindexRecommended":…, "builtWithVersion":…}}``. Gate predicate:
``index.state == "complete" AND index.pendingRefs == 0 AND NOT
index.reindexRecommended``. Freshness (⇒ nothing to do): the gate plus all three
``pendingChanges`` counters at 0. An unknown shape, an absent key, or an
uncontained payload is "not ready" — never a crash, never an ancestor's index.

``index.pendingRefs`` is NOT the ``unresolved_refs`` table (whose rows are 100%
``status='failed'``): the former is the CLI's own work queue, the latter is
CodeGraph's "an edge may be missing here" marker read by
:mod:`harness.codegraph._db`. Do not conflate the two counts.

D9 hygiene invariant: every CLI execution here carries :data:`SCAN_ENV`
(no daemon, no telemetry, no update check) on top of the shared scrubbed env.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from subprocess import TimeoutExpired

from harness.codegraph import _db

logger = logging.getLogger(__name__)

CLI_NAME = "codegraph"

# Per-call wall clocks: `status` is bookkeeping, a cold `init`/`index` over a
# large repo is the slow one (the indexer stage bounds it, not this module).
STATUS_TIMEOUT = 60
DEFAULT_BUILD_TIMEOUT = 600

# The D9 invariant, on top of the shared scrubbed env (which strips provider
# keys): a daemon would outlive the scan, and the update check / telemetry would
# phone home from a security tool.
SCAN_ENV = {
    "PYTHONDONTWRITEBYTECODE": "1",
    "CODEGRAPH_NO_DAEMON": "1",
    "CODEGRAPH_TELEMETRY": "0",
    "CODEGRAPH_NO_UPDATE_CHECK": "1",
    "DO_NOT_TRACK": "1",
}


# ---------------------------------------------------------------------------
# process plumbing (never raises)
# ---------------------------------------------------------------------------

def _cli_path() -> str | None:
    """Absolute path to the CLI, or None when the image/host has none."""
    return shutil.which(CLI_NAME)


def _scan_env() -> dict[str, str]:
    """The single env every CLI call in this module uses (D9 + scrub)."""
    from harness.tools._compat import scrubbed_env

    env = scrubbed_env()
    env.update(SCAN_ENV)
    return env


def _run(cli: str, args: list[str], timeout: int) -> tuple[int, str, str]:
    """Run the CLI once: ``(returncode, stdout, stderr)``, never raising.

    ``-1`` marks an infra failure (timeout, vanished/ unexecutable binary) —
    callers treat it exactly like a non-zero exit.
    """
    try:
        proc = subprocess.run([cli, *args], capture_output=True, text=True,
                              errors="replace", timeout=timeout, env=_scan_env())
    except TimeoutExpired:
        logger.warning("codegraph %s timed out after %ss", " ".join(args), timeout)
        return -1, "", "timeout"
    except OSError as e:
        logger.warning("codegraph %s could not run: %s", " ".join(args), e)
        return -1, "", str(e)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


# ---------------------------------------------------------------------------
# paths + payload parsing
# ---------------------------------------------------------------------------

def _paths(root: str) -> tuple[Path, Path, Path]:
    """``(root, <root>/.codegraph, <root>/.codegraph/codegraph.db)``.

    The DB path is :func:`harness.codegraph._db.resolve_db_path`'s own answer —
    the file ``_db`` will later open — so the gate asserts against the exact
    path the read side uses, not against a path this module invented.
    """
    root_path = Path(root).expanduser().resolve()
    db_path = _db.resolve_db_path(str(root_path))
    return root_path, db_path.parent, db_path


def _parse_payload(raw: str) -> dict | None:
    """The single JSON object on ``status -j`` stdout, or None."""
    text = (raw or "").strip()
    if not text:
        return None
    try:
        payload = json.loads(text)
    except ValueError:
        # Tolerate trailing noise by decoding the leading object only.
        try:
            payload, _end = json.JSONDecoder().raw_decode(text)
        except ValueError:
            return None
    return payload if isinstance(payload, dict) else None


def _same_path(a: object, b: object) -> bool:
    if not a or not b:
        return False
    try:
        return os.path.realpath(str(a)) == os.path.realpath(str(b))
    except (OSError, ValueError):
        return False


def _contained(payload: dict, root_path: Path, cg_dir: Path) -> bool:
    """Gate (a): the payload describes THIS root and THIS ``.codegraph``."""
    if not payload:
        return False
    return (_same_path(payload.get("projectPath"), root_path)
            and _same_path(payload.get("indexPath"), cg_dir))


def _gate_ok(payload: dict, cg_dir: Path, db_path: Path) -> bool:
    """§2.4 gate + the files existing where :func:`_db.resolve_db_path` says.

    Missing keys, wrong types, any other state, or an absent ``.codegraph`` are
    all "not ready": only this exact shape authorizes serving the index (or
    skipping the build).
    """
    index = payload.get("index") if isinstance(payload, dict) else None
    if not isinstance(index, dict):
        return False
    state = index.get("state")
    pending_refs = index.get("pendingRefs")
    reindex = index.get("reindexRecommended")
    if not (isinstance(state, str) and state == "complete"):
        return False
    if isinstance(pending_refs, bool) or not isinstance(pending_refs, int):
        return False
    if pending_refs != 0 or reindex is not False:
        return False
    try:
        return cg_dir.is_dir() and db_path.is_file()
    except OSError:
        return False


def _pending_changes(payload: dict) -> int | None:
    """Sum of ``pendingChanges`` added+modified+removed; None when unknown."""
    changes = payload.get("pendingChanges") if isinstance(payload, dict) else None
    if not isinstance(changes, dict):
        return None
    total = 0
    for key in ("added", "modified", "removed"):
        value = changes.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return None
        total += value
    return total


def _fresh(payload: dict, cg_dir: Path, db_path: Path) -> bool:
    """Gate passes AND no pending work ⇒ ``sync``/``index`` would be a no-op."""
    return _gate_ok(payload, cg_dir, db_path) and _pending_changes(payload) == 0


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def index_status(root: str = ".") -> dict:
    """This root's ``status -j`` payload, or ``{}`` when there is no usable one.

    ``{}`` means: no CLI, no stdout, malformed JSON, an unaddressable root, or —
    the case this function exists for — a payload describing a DIFFERENT root
    (the CLI walks up to the nearest ``.codegraph``, so a nested target's status
    is its ancestor's). Rejections are logged, never raised; callers treat ``{}``
    as not-ready. An uninitialized-but-contained payload (``initialized:false``,
    no ``index`` block) IS returned: it is this root's honest answer, and
    :func:`_gate_ok` rejects it on shape.
    """
    try:
        root_path, cg_dir, _db_path = _paths(root)
    except (ValueError, OSError) as e:
        logger.debug("codegraph status: unusable root %r: %s", root, e)
        return {}
    cli = _cli_path()
    if cli is None:
        return {}
    _rc, out, _err = _run(cli, ["status", "-j", str(root_path)], STATUS_TIMEOUT)
    payload = _parse_payload(out)
    if payload is None:
        return {}
    if not _contained(payload, root_path, cg_dir):
        logger.warning(
            "codegraph status for %s answered for projectPath=%r indexPath=%r — "
            "refusing an index that is not this root's (the CLI walks up to the "
            "nearest .codegraph)", root_path, payload.get("projectPath"),
            payload.get("indexPath"))
        return {}
    return payload


def index_needed(root: str = ".") -> bool:
    """True when this root's own index is missing, stale, or has pending work."""
    try:
        _root_path, cg_dir, db_path = _paths(root)
    except (ValueError, OSError):
        return True
    payload = index_status(root)
    if not _gate_ok(payload, cg_dir, db_path):
        return True
    pending = _pending_changes(payload)
    return pending is None or pending != 0


def index_build(root: str = ".", timeout: int = DEFAULT_BUILD_TIMEOUT) -> str:
    """Build/gate ``<root>``'s OWN index; return the DB path, or ``""``.

    Order (D2 + the three gates): fresh index ⇒ nothing to do; missing
    ``.codegraph`` ⇒ ``init`` FIRST; an own-root DB ⇒ ``sync -q`` then re-gate;
    otherwise ``index -q``. The path is returned only after a re-gate proves the
    payload describes this root, so an ancestor's index can never be authorized
    for a db-less target. Never raises: ``""`` means "continue unindexed".
    """
    try:
        return _index_build(root, timeout)
    except Exception as e:  # fail-open by contract (D2/D6); a scan never dies here
        logger.warning("codegraph index build failed for %r; continuing "
                       "unindexed: %s: %s", root, type(e).__name__, e)
        return ""


def _index_build(root: str, timeout: int) -> str:
    root_path, cg_dir, db_path = _paths(root)
    if not root_path.is_dir():
        # `init` would happily create the missing path; never invent a root.
        logger.debug("codegraph index: %s is not a directory; nothing to build",
                     root_path)
        return ""
    payload = index_status(root)
    if _fresh(payload, cg_dir, db_path):
        logger.info("codegraph index for %s is fresh (gate complete, "
                    "pendingChanges 0) — skipping build", root_path)
        return str(db_path)
    cli = _cli_path()
    if cli is None:
        logger.info("codegraph CLI not found; %s stays unindexed (tools fall "
                    "back to grep)", root_path)
        return ""
    if not cg_dir.is_dir():
        # Gate (b): `index <path>` refuses an un-initialized root and does not
        # walk up; `init` builds the index itself.
        _run(cli, ["init", "-y", str(root_path)], timeout)
        payload = index_status(root)
        if _fresh(payload, cg_dir, db_path):
            return str(db_path)
    if db_path.is_file() and _contained(payload, root_path, cg_dir):
        # Gate (c): sync only against an index the payload proves is this
        # root's — a walk-up sync reads AND WRITES the ancestor's index.
        _run(cli, ["sync", "-q", str(root_path)], timeout)
        payload = index_status(root)
        if _fresh(payload, cg_dir, db_path):
            return str(db_path)
    _run(cli, ["index", "-q", str(root_path)], timeout)
    payload = index_status(root)
    if _gate_ok(payload, cg_dir, db_path):
        return str(db_path)
    logger.warning("codegraph index for %s did not reach the gate after a full "
                   "build; continuing unindexed", root_path)
    return ""


def index_summary(root: str = ".") -> str:
    """One bounded prose line about this root's index (for the info candidate)."""
    payload = index_status(root)
    if not payload:
        return "codegraph index: unavailable for this root"
    try:
        _root_path, cg_dir, db_path = _paths(root)
        ready = _gate_ok(payload, cg_dir, db_path)
    except (ValueError, OSError):
        ready = False
    index = payload.get("index") if isinstance(payload.get("index"), dict) else {}
    raw_langs = payload.get("languages")
    langs = ", ".join(str(x) for x in raw_langs) if isinstance(raw_langs, list) else ""
    pending = _pending_changes(payload)
    pending_refs = index.get("pendingRefs")
    text = (f"codegraph index: {payload.get('nodeCount')} nodes, "
            f"{payload.get('edgeCount')} edges in {payload.get('fileCount')} files; "
            f"state {index.get('state') or 'unknown'}; "
            f"pendingRefs {pending_refs if pending_refs is not None else '?'}; "
            f"pendingChanges {pending if pending is not None else '?'}; "
            f"gate {'ready' if ready else 'not ready'}; "
            f"languages {langs or 'none'}")
    return text[:600]

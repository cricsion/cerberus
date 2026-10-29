"""CodeGraph index lifecycle for the scan's target root.

Purpose
Manage the target root's own index without authorizing an ancestor's index.

The indexer stage owns the CLI (``init``/``index``/``sync``/``status``); the
hunt reads the index through :mod:`harness.codegraph._db` (read-only SQL, D1).
This is the writable half; every public function returns instead of raising.

Laws
- Gate reads are root-pinned: the payload must name this root's ``projectPath``
  and ``indexPath`` (via ``realpath``); a foreign payload is refused.
- A fresh root is initialized first (``init -y``) because ``index`` refuses an
  uninitialized root; ``sync`` runs only on a confirmed own-root index.

Invariants
- The gate is ``state == "complete"``, ``pendingRefs == 0``,
  ``reindexRecommended is False``, and ``.codegraph`` plus the DB exist at
  ``_db.resolve_db_path``'s exact path.
- ``pendingRefs`` is the CLI queue, not the ``unresolved_refs`` table.
- Every CLI call carries :data:`SCAN_ENV` over the scrubbed env.

Format laws
- CodeGraph 1.6.2 status -j is one JSON object with projectPath, indexPath,
  counts, languages, pendingChanges and an index block (state, pendingRefs,
  reindexRecommended, builtWithVersion).
- The gate requires state complete, pendingRefs zero and reindexRecommended
  false; freshness also requires added, modified and removed counts all zero.
- pendingRefs is the CLI queue, distinct from unresolved_refs rows in the
  read-only DB. Unknown shapes are not ready; index_build returns a DB path or
  an empty string.
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
STATUS_TIMEOUT = 60
DEFAULT_BUILD_TIMEOUT = 600

# D9: a daemon would outlive the scan; telemetry/update checks would phone home.
SCAN_ENV = {
    "PYTHONDONTWRITEBYTECODE": "1",
    "CODEGRAPH_NO_DAEMON": "1",
    "CODEGRAPH_TELEMETRY": "0",
    "CODEGRAPH_NO_UPDATE_CHECK": "1",
    "DO_NOT_TRACK": "1",
}


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

    ``-1`` marks an infra failure, treated like a non-zero exit by callers.
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


def _paths(root: str) -> tuple[Path, Path, Path]:
    """``(root, .codegraph dir, DB path)`` via :func:`_db.resolve_db_path`."""
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
        try:  # tolerate trailing noise: decode the leading object only
            payload, _end = json.JSONDecoder().raw_decode(text)
        except ValueError:
            return None
    return payload if isinstance(payload, dict) else None


def _same_path(a: object, b: object) -> bool:
    """True when two spellings resolve to the same path (never raises)."""
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


def index_status(root: str = ".") -> dict:
    """This root's ``status -j`` payload, or ``{}`` when there is no usable one.

    ``{}`` covers no CLI, bad JSON, an unaddressable or foreign root. A
    contained ``initialized:false`` payload IS returned; the gate rejects it.
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
    """Build/gate this root's OWN index; return the DB path, or ``""``.

    Order: fresh ⇒ nothing; else ``init -y`` then ``sync -q``.
    The path is returned only after a re-gate proves the payload is this root's.
    Never raises (D2/D6).
    """
    try:
        return _index_build(root, timeout)
    except Exception as e:  # a scan never dies here
        logger.warning("codegraph index build failed for %r; continuing "
                       "unindexed: %s: %s", root, type(e).__name__, e)
        return ""


def _index_build(root: str, timeout: int) -> str:
    """The raising core of :func:`index_build`; see its order contract."""
    root_path, cg_dir, db_path = _paths(root)
    if not root_path.is_dir():
        # `init` would create the missing path; never invent a root.
        logger.debug("codegraph index: %s is not a directory; nothing to build",
                     root_path)
        return ""
    if not index_needed(str(root_path)):
        logger.info("codegraph index for %s is fresh (gate complete, "
                    "pendingChanges 0) — skipping build", root_path)
        return str(db_path)
    cli = _cli_path()
    if cli is None:
        logger.info("codegraph CLI not found; %s stays unindexed (tools fall "
                    "back to grep)", root_path)
        return ""

    _run(cli, ["init", "-y", str(root_path)], timeout)
    _run(cli, ["sync", "-q", str(root_path)], timeout)
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

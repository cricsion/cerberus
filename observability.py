"""Fail-open Langfuse observability for scans.

Langfuse tracing is enabled iff ``LANGFUSE_PUBLIC_KEY``, ``LANGFUSE_SECRET_KEY``
and ``LANGFUSE_BASE_URL`` are all present; ``observability.enabled`` in the
harness config can override that gate with ``true``/``false``.
Everything here fails open: a missing or unusable SDK is a no-op,
and a failed init/auth/export logs one ``[observability]`` stderr line instead
of sinking a scan.

The ``langfuse`` package is
imported lazily inside functions only, never at module import time.
``finish_scan()`` flushes but never calls ``shutdown()``
"""
from __future__ import annotations

import atexit
import os
import re
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

# D2: all three must be non-empty for auto-enable.
_ENV_KEYS = ("LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_BASE_URL")
_FALSE_VALUES = frozenset({"false", "0", "no", "off"})
_TRUE_VALUES = frozenset({"true", "1", "yes", "on"})

# Stable role vocabulary. Trace names are a stable API:
# dynamic values (unit, group, batch) go to tags/metadata, never into names.
_IDENTITY_ROLES = frozenset({
    "triage",
    "threat",
    "partitioner",
    "system-pass",
    "poc_generator",
    "threat:researcher",
    "threat:historian",
    "threat:synthesizer",
    "threat:interviewer",
})
_PREFIX_ROLES = (("hunter", "hunter"), ("validator", "validator"))

_LOCK = threading.RLock()
_STATE: dict[str, Any] = {"scan_id": None, "handler": None}


def _log(msg: str) -> None:
    """One ``[observability]`` stderr line. Never logs env/key values."""
    try:
        print(f"[observability] {msg}", file=sys.stderr)
    except Exception:
        pass


def _load_env_files() -> None:
    """Load the single shared dotenv

    ``config._load_dotenv`` is ``Path(__file__)``-anchored, missing-only, and
    never overrides already-set vars, so this works from any cwd.
    """
    try:
        from cerberus.config import _load_dotenv

        _load_dotenv()
    except Exception:
        pass


def _keys_present() -> bool:
    """True iff all three Langfuse env keys are non-empty."""
    return all(bool(os.environ.get(key)) for key in _ENV_KEYS)


def enabled(cfg: dict | None = None) -> bool:
    """Enable gate. Never raises — fail-open to ``False``."""
    try:
        _load_env_files()
        from cerberus.config import get_config

        if not cfg:
            cfg = get_config()
        obs = cfg.get("observability", {}) if isinstance(cfg, dict) else {}
        if not isinstance(obs, dict):
            obs = {}
        fallback = get_config().get("observability", {}).get("enabled", "auto")
        raw = str(obs.get("enabled", fallback)).strip().lower()
        keys_ok = _keys_present()
        if raw in _FALSE_VALUES:
            return False
        if raw in _TRUE_VALUES:
            if keys_ok:
                return True
            _log(
                "observability.enabled=true but Langfuse env keys are "
                "incomplete; disabling"
            )
            return False
        return keys_ok  # "auto" (default) and anything unrecognized
    except Exception as exc:
        _log(f"enable check failed ({type(exc).__name__}: {exc}); disabling")
        return False


def start_scan(repo: str | Path, *, cfg: dict | None = None) -> str | None:
    """Start one scan session; returns the sanitized scan id or ``None``.

    Idempotent under the lock: a second call while a scan is active returns the
    existing scan id. On failure logs one line and leaves state untouched.
    """
    try:
        if not enabled(cfg):
            return None
        with _LOCK:
            existing = _STATE.get("scan_id")
            if existing:
                return str(existing)
            from langfuse import Langfuse
            from langfuse.langchain import CallbackHandler

            try:
                ok = bool(Langfuse().auth_check())
            except Exception:
                ok = False
            if not ok:
                _log("auth_check failed; Langfuse stays disabled for this scan")
                return None
            repo_name = re.sub(
                r"[^A-Za-z0-9._-]", "-", Path(str(repo)).name or "scan"
            )[:120]
            scan_id = (
                f"{repo_name}-{datetime.now():%Y%m%d-%H%M%S}-{os.urandom(3).hex()}"
            )
            handler = CallbackHandler()
            _STATE["scan_id"] = scan_id
            _STATE["handler"] = handler
            atexit.register(finish_scan)
            _log(
                f"enabled → {os.environ.get('LANGFUSE_BASE_URL', '?')} "
                f"(session {scan_id})"
            )
            return scan_id
    except Exception as exc:
        _log(f"start_scan failed ({type(exc).__name__}: {exc}); tracing disabled")
        return None


def get_handler() -> object | None:
    """The singleton ``CallbackHandler`` while a scan is active, else ``None``."""
    try:
        with _LOCK:
            return _STATE.get("handler")
    except Exception:
        return None


def stable_role(name: str) -> str:
    """Map a caller-provided agent name to the stable role vocabulary (D6).

    Exact map for the fixed roles, prefix map for ``hunter-*``/``validator-*``
    (dynamic suffix dropped), empty/``None`` → ``""``, unknown → as-is.
    Pure function; no I/O.
    """
    text = "" if name is None else str(name)
    if not text.strip():
        return ""
    if text in _IDENTITY_ROLES:
        return text
    for prefix, role in _PREFIX_ROLES:
        if text == prefix or text.startswith(prefix + "-"):
            return role
    return text


def scope_path(text: str | None) -> str:
    """Sanitize a colon-joined dynamic scope (``unit:cell:vote``) for a run name.

    Per-segment ``[A-Za-z0-9._-]`` only, ≤40 chars; structural colons survive,
    empty segments drop. Pure function.
    """
    try:
        segments: list[str] = []
        for seg in str(text or "").split(":"):
            seg = re.sub(r"[^A-Za-z0-9._-]", "-", seg).strip("-._")[:40]
            if seg:
                segments.append(seg)
        return ":".join(segments)
    except Exception:
        return ""


def scan_metadata(*, role: str = "", stage: str = "", unit: str = "",
                  extra: dict | None = None) -> dict:
    """Session/tags metadata for an invoke; ``{}`` when no scan is active (D5).

    Tags are the non-empty ``(stage, role)`` stable identifiers, deduplicated
    in order; ``unit``/``extra`` are dynamic and stay in metadata only (D6).
    """
    try:
        with _LOCK:
            scan_id = _STATE.get("scan_id")
        if not scan_id:
            return {}
        tags: list[str] = []
        for value in (stage, role):
            text = "" if value is None else str(value)
            if text and text not in tags:
                tags.append(text)
        meta: dict[str, Any] = {
            "langfuse_session_id": scan_id,
            "langfuse_tags": tags,
            "stage": stage,
            "unit": unit,
        }
        for key, value in (extra or {}).items():
            entry = "" if value is None else str(value)
            if str(key).strip() and entry:
                meta[str(key)] = entry
        return meta
    except Exception:
        return {}


def run_config(cfg: dict, *, name: str | None = None,
               role: str | None = None, stage: str | None = None,
               unit: str | None = None, extra: dict | None = None,
               trace_suffix: str | None = None) -> dict:
    """The per-call runtime config assembled here once (mutable ``cfg``).

    Adds the singleton langfuse callback, then the stage/role metadata and a
    run name that nests the sanitized trace scope when one is given. Non-
    tracing keys (``recursion_limit``, ``max_concurrency``) are seeded by the
    caller. With ``name`` the role defaults to ``stable_role(name)`` and the
    stage to that role; explicit ``role``/``stage``/``unit`` override for the
    hunters shape. Never raises.
    """
    try:
        handler = get_handler()
        if handler is not None:
            cfg.setdefault("callbacks", []).append(handler)
        resolved = role or (stable_role(name) if name else "")
        if resolved:
            meta = scan_metadata(stage=stage or resolved, role=resolved,
                                 unit=unit or "", extra=extra)
            if meta:
                cfg["metadata"] = meta
                scope = scope_path(trace_suffix)
                cfg["run_name"] = f"{resolved}:{scope}" if scope else resolved
    except Exception:
        pass
    return cfg


def finish_scan() -> None:
    """Durable-export flush only (D10); idempotent, no-op when inactive.

    Never calls ``shutdown()`` and never raises (it is registered with atexit
    and also called from the pipeline).
    """
    try:
        with _LOCK:
            if not _STATE.get("scan_id"):
                return
            _STATE["scan_id"] = None
            _STATE["handler"] = None
        try:
            from langfuse import get_client

            get_client().flush()
        except Exception as exc:
            _log(f"flush failed ({type(exc).__name__}: {exc})")
    except Exception:
        pass


__all__ = [
    "enabled",
    "finish_scan",
    "get_handler",
    "run_config",
    "scan_metadata",
    "scope_path",
    "stable_role",
    "start_scan",
]

"""Fail-open helpers for LLM/tool boundary code: re-raise on `is_fatal_error`
(config error or harness bug), else fall back to empty."""
from __future__ import annotations

import logging
from typing import Any, Callable

_logger = logging.getLogger(__name__)

EMPTY_STRUCTURED: tuple[None, str] = (None, "")


def needs_review_verdicts(items: list[dict], note: str) -> list[dict]:
    """One needs-review verdict per item, to fail open a batch/round; omitted ids
    would otherwise become false consensus downstream."""
    out: list[dict] = []
    for f in items or []:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("id", ""))
        if not fid:
            continue
        out.append({
            "id": fid,
            "status": "needs-review",
            "fallback_note": note,
        })
    return out


def is_config_error(exc: BaseException) -> bool:
    """Provider-config failure (operator error), not fail-open noise."""
    from harness.agents.deep import is_config_error as _is_config_error

    return _is_config_error(exc)


def is_fatal_error(exc: BaseException) -> bool:
    """Config error or harness bug: re-raise. Model, parse, and transport
    failures are the fail-open cases."""
    from harness.agents.deep import is_fatal_error as _is_fatal_error

    return _is_fatal_error(exc)


def run_fail_open(action: str, fn: Callable[[], Any], *,
                  default: Any = None,
                  logger: logging.Logger | None = None) -> Any:
    """Run ``fn``; non-fatal exceptions fail open, fatal-class ones (bad key, wrong
    model, harness defect) re-raise."""
    try:
        return fn()
    except Exception as exc:
        if is_fatal_error(exc):
            raise
        if logger is not None:
            logger.debug("%s failed; failing open: %s: %s",
                         action, type(exc).__name__, exc)
        return default

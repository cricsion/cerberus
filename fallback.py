"""Shared fail-open helpers for LLM/tool boundary code.

The scan pipeline deliberately fails open around model calls and external
tools, but the pattern used to be hand-rolled at every call site:

    try:
        ...
    except Exception as e:
        if is_fatal_error(e):   # config error OR harness bug
            raise
        ...
        parsed, raw_text = None, ""

That duplicated both the fatal-error decision and the "empty structured
result" fallback. Keep the broad boundary here, not at every agent stage.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

_logger = logging.getLogger(__name__)

EMPTY_STRUCTURED: tuple[None, str] = (None, "")


def needs_review_verdicts(items: list[dict], note: str) -> list[dict]:
    """One needs-review verdict per item, used to fail open a batch/round.

    Keeps failed/abstaining rounds counted as a conservative ballot instead
    of omitted ids becoming false consensus later.
    """
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
    """Provider-config failures are the operator's problem, not noise."""
    from harness.agents.deep import is_config_error as _is_config_error

    return _is_config_error(exc)


def is_fatal_error(exc: BaseException) -> bool:
    """Config error or harness bug: re-raise instead of failing open.

    Model, parse, and transport failures are the fail-open cases; operator
    misconfiguration and programming errors both stop the stage loudly
    (docs: "let unexpected errors bubble up").
    """
    from harness.agents.deep import is_fatal_error as _is_fatal_error

    return _is_fatal_error(exc)


def run_fail_open(action: str, fn: Callable[[], Any], *,
                  default: Any = None,
                  logger: logging.Logger | None = None) -> Any:
    """Run ``fn`` and fail open on non-fatal exceptions.

    Fatal-class errors are re-raised: a bad key or wrong model (operator
    config) and a harness defect (programming error) must stop the scan
    loudly instead of becoming a needs-review verdict.
    """
    try:
        return fn()
    except Exception as exc:
        if is_fatal_error(exc):
            raise
        if logger is not None:
            logger.debug("%s failed; failing open: %s: %s",
                         action, type(exc).__name__, exc)
        return default

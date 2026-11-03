"""Per-scan signal storage: raw tool outputs under ``.cerberus/<run_id>/signals/``.

The indexer's fast deterministic tools (gitleaks, osv-scanner, checkov, route
discovery, regex prefilter) used to be packed into info-severity finding
candidates, which made them march through aggregation, validation.

Run scoping mirrors the agent-scratch convention (``agents/deep.py``):
``$RUN_ID`` sanitized, else ``"latest"``.
"""
from __future__ import annotations

import json as _json
import os
import re as _re
from pathlib import Path

RUN_ID_ENV = "RUN_ID"
DEFAULT_RUN_ID = "latest"
_SIGNALS_DIRNAME = "signals"


def sanitize_run_id(rid: str) -> str:
    safe = _re.sub(r"[^A-Za-z0-9._-]", "_", str(rid or "").strip())[:80]
    safe = _re.sub(r"\.{2,}", "_", safe)
    safe = safe.lstrip(".").lstrip("-")
    return safe


def resolve_run_id() -> str:
    """The run identifier used for signal storage, mirroring the scratchpad."""
    return sanitize_run_id(os.environ.get(RUN_ID_ENV) or "") or DEFAULT_RUN_ID


def signals_dir(repo: str) -> Path:
    """The (mkdir'd) per-run signals directory inside the repo root."""
    root = Path(repo).resolve()
    out = root / ".cerberus" / resolve_run_id() / _SIGNALS_DIRNAME
    out.mkdir(parents=True, exist_ok=True)
    return out


def signal_stats(body: str) -> tuple[int, str]:
    """``(count, one-line summary)`` for a raw tool output.

    Count is the parsed JSON list length when the body is one, else the number
    of non-empty lines; the summary is the first non-empty line.
    """
    text = str(body or "").strip()
    if not text:
        return 0, ""
    first = ""
    for ln in text.splitlines():
        if ln.strip():
            first = ln.strip()[:200]
            break
    try:
        data = _json.loads(text)
    except ValueError:
        return sum(1 for ln in text.splitlines() if ln.strip()), first
    if isinstance(data, list):
        return len(data), first
    if isinstance(data, dict):
        for key in ("results", "findings", "failed_checks"):
            rows = data.get(key)
            if isinstance(rows, list):
                return len(rows), first
    return sum(1 for ln in text.splitlines() if ln.strip()), first


def write_signal(repo: str, name: str, body: str) -> str:
    """Write one raw tool output under the run's signals dir.

    Returns the repo-relative path (openable by repo-rooted agents and true
    for the persisted threat model), or ``""`` when the write fails — a
    signal storage failure never fails a scan.
    """
    try:
        root = Path(repo).resolve()
        sniff = str(body or "").lstrip()[:1]
        fname = f"{name}.json" if sniff in ("{", "[") else f"{name}.txt"
        path = signals_dir(str(root)) / fname
        path.write_text(str(body or ""), encoding="utf-8")
        return path.relative_to(root).as_posix()
    except (OSError, ValueError):
        return ""

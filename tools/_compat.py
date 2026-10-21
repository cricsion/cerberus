"""Shared fallbacks for the tool modules: langchain `tool`, env-int caps, and
the which/timeout/capture CLI runner the scanner wrappers share."""
from __future__ import annotations

import os
import shutil
import subprocess

from harness.config import get_default_config

SAST_MAX_BYTES = int(get_default_config("sandbox.max_output_bytes"))

try:
    from langchain_core.tools import tool
except ImportError:  # pragma: no cover - allow import without langchain installed
    def tool(*dargs, **dkwargs):  # type: ignore
        def deco(fn):
            return fn
        if dargs and callable(dargs[0]):
            return dargs[0]
        return deco


def env_int(name: str, default: int) -> int:
    """Env override for caps. 0 = unlimited."""
    try:
        v = os.environ.get(name)
        if v is None or v == "":
            return default
        return int(v)
    except (TypeError, ValueError):
        return default

_SECRET_ENV = frozenset({
    "API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
})

_SECRET_SUFFIXES = ("_API_KEY", "_APIKEY", "_SECRET_KEY", "_PRIVATE_KEY")


def _is_secret_key(name: str) -> bool:
    return name in _SECRET_ENV or name.endswith(_SECRET_SUFFIXES)


def scrubbed_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not _is_secret_key(k)}


def run_cli(cmd: list[str], timeout: int = 300, max_bytes: int | None = None) -> dict:
    """Run a scanner CLI, always returning a dict (never raising).

    A missing binary degrades to ``{"skipped": True}`` rather than crashing the
    scan: the SAST phase is defined by which binaries the image carries.
    """
    if max_bytes is None:
        max_bytes = env_int("SAST_BYTES", SAST_MAX_BYTES)
    if shutil.which(cmd[0]) is None:
        return {"tool": cmd[0], "skipped": True, "reason": f"binary not found: {cmd[0]}"}
    env = scrubbed_env()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        out = proc.stdout if max_bytes <= 0 else proc.stdout[:max_bytes]
        return {"tool": cmd[0], "returncode": proc.returncode,
                "stdout": out, "stderr": proc.stderr[:20000],
                "truncated": bool(max_bytes > 0 and len(proc.stdout) > max_bytes)}
    except subprocess.TimeoutExpired:
        return {"tool": cmd[0], "skipped": True, "reason": "timeout"}
    except OSError as e:
        return {"tool": cmd[0], "skipped": True, "reason": str(e)}

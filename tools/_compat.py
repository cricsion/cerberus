"""Shared fallbacks for the tool modules: langchain `tool` and env-int caps."""
from __future__ import annotations

import os

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

"""Partitioning policy knobs (env-overridable, read at call time).

Every tunable lives here so the algorithm reads its policy from one place.
Functions (not import-time constants) so tests can monkeypatch the environment
without reloading the module.
"""
from __future__ import annotations

import os as _os
from typing import Any


def _int_env(key: str, default: int) -> int:
    try:
        v = _os.environ.get(key)
        if v is None or v == "":
            return default
        return int(v)
    except (TypeError, ValueError):
        return default


def _env_flag(key: str, default: str = "0") -> str:
    v = _os.environ.get(key)
    return default if v is None or v == "" else str(v).lower()


def _flag_on(key: str, default: str = "0") -> bool:
    return _env_flag(key, default) in ("1", "true", "yes", "on")


def _cfg_value(cfg: dict | None, key: str) -> Any:
    """``partition.<key>`` from cfg, or None when cfg has no such value.

    Callers that already loaded a config pass it; callers without one pass
    None and fall back to the environment, which keeps the policy functions
    monkeypatch-friendly and import-free.
    """
    section = cfg.get("partition") if isinstance(cfg, dict) else None
    if not isinstance(section, dict):
        return None
    value = section.get(key)
    return None if value in (None, "") else value


def _loaded_cfg(cfg: dict | None) -> dict | None:
    """Lazily load the scan config so config-backed knobs stay authoritative
    even from code paths that never threaded a cfg through."""
    if cfg is not None:
        return cfg
    try:
        from harness.config import load_config
        return load_config()
    except Exception:
        return None


# --- core budget knobs (pre-existing behavior) ------------------------------

def max_units(cfg: dict | None = None) -> int:
    """Cap on unit count; 0 means unlimited.

    ``partition.max_units`` wins when a caller (or the lazy config load) has
    it; otherwise MAX_UNITS is read from the environment, so env-driven runs
    and monkeypatched tests behave the same either way.
    """
    value = _cfg_value(_loaded_cfg(cfg), "max_units")
    if value is None:
        value = _int_env("MAX_UNITS", 20)
    try:
        v = int(value)
    except (TypeError, ValueError):
        v = 20
    return 10**9 if v <= 0 else v


def min_files() -> int:
    v = _int_env("MIN_FILES", 10)
    return max(0, v)


# --- P0.1 vendor isolation ---------------------------------------------------

def vendor_unit_enabled() -> bool:
    return _flag_on("PARTITION_VENDOR_UNIT")


VENDOR_UNIT_NAME = "vendor"

VENDOR_DIR_SEGMENTS = frozenset({
    "node_modules", ".venv", "venv", "env", "vendor", "third_party",
    "third-party", "bower_components", "jspm_packages", "site-packages",
    "dist", "build", ".tox", "__pycache__", "pods", "godeps",
})

VENDOR_FILE_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".chunk.js",
                        ".min.js.map")

# --- P0.2 small-repo single unit --------------------------------------------

def single_unit_enabled() -> bool:
    """Permanently enabled: small repos whose app files fit the budget become one unit."""
    return True


def single_unit_max_files() -> int:
    """0 disables the small-repo rule; otherwise a repo whose app files fit
    the byte budget AND this file count becomes ONE unit."""
    return _int_env("PARTITION_SINGLE_UNIT_MAX_FILES", 50)


# --- P1.3 misc policy --------------------------------------------------------

def misc_code_merge_enabled() -> bool:
    """On: tiny CODE units merge into their most-coupled neighbour or stay
    singletons; only non-code lands in misc. This is the default; explicitly
    set PARTITION_MISC_CODE_MERGE=0 for legacy misc-absorbs-all behavior."""
    return _flag_on("PARTITION_MISC_CODE_MERGE", default="1")


NON_CODE_EXTS = frozenset({
    ".md", ".rst", ".txt", ".cfg", ".ini", ".lock",
})

NON_CODE_NAMES = frozenset({
    "dockerfile", "LICENSE", "LICENCE", "COPYING", "AUTHORS", "CONTRIBUTORS",
    "CHANGELOG", "NOTICE", "makefile", ".editorconfig", ".gitignore",
    ".pre-commit-config.yaml", ".pre-commit-config.yml",
})

# --- P2 framework edges ------------------------------------------------------

def framework_edges_enabled() -> bool:
    return _flag_on("PARTITION_FRAMEWORK_EDGES", default="1")


def edge_max_file_bytes() -> int:
    return _int_env("PARTITION_EDGE_MAX_FILE_BYTES", 262_144)


def edge_read_cap_bytes() -> int:
    return _int_env("PARTITION_EDGE_READ_CAP_BYTES", 20_000_000)


def same_dir_soft_edges() -> bool:
    v = _os.environ.get("PARTITION_SAME_DIR_EDGES")
    if v is None or v == "":
        return True
    return _flag_on("PARTITION_SAME_DIR_EDGES")

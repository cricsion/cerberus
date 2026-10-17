"""Partitioning policy knobs (env-overridable, read at call time; functions, not
import-time constants, so tests can monkeypatch the environment)."""
from __future__ import annotations

import logging
import os as _os
from typing import Any

_logger = logging.getLogger(__name__)


def _coerce_int(value: Any, default: int) -> int:
    """int(value) or default: a malformed operator value degrades, never blocks."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _int_env(key: str, default: int) -> int:
    v = _os.environ.get(key)
    if v is None or v == "":
        return default
    return _coerce_int(v, default)


def _env_flag(key: str, default: str = "0") -> str:
    v = _os.environ.get(key)
    return default if v is None or v == "" else str(v).lower()


def _flag_on(key: str, default: str = "0") -> bool:
    return _env_flag(key, default) in ("1", "true", "yes", "on")


def _cfg_value(cfg: dict | None, key: str) -> Any:
    """``partition.<key>`` from cfg, or None when unset (callers fall back to env)."""
    section = cfg.get("partition") if isinstance(cfg, dict) else None
    if not isinstance(section, dict):
        return None
    value = section.get(key)
    return None if value in (None, "") else value


def _loaded_cfg(cfg: dict | None) -> dict | None:
    """Lazily load the scan config when cfg is None (config beats env).

    An unreadable config is operator input, not noise: it is logged at
    warning and degrades to None (env defaults) — never silently swallowed.
    A fatal-class harness defect re-raises."""
    if cfg is not None:
        return cfg
    from harness.config import load_config_safe

    cfg, err = load_config_safe()
    if err is None:
        return cfg
    from harness.fallback import is_fatal_error

    if is_fatal_error(err):
        raise err
    _logger.warning("scan config unreadable, partition policy falls back to "
                    "env defaults: %s: %s", type(err).__name__, err)
    return None


# --- core budget knobs (pre-existing behavior) ------------------------------

def max_units(cfg: dict | None = None) -> int:
    """Cap on unit count; 0 means unlimited. Config wins, else MAX_UNITS from env."""
    value = _cfg_value(_loaded_cfg(cfg), "max_units")
    if value is None:
        value = _int_env("MAX_UNITS", 20)
    v = _coerce_int(value, 20)
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
    """Permanently on: a small repo fitting the budget becomes one unit."""
    return True


def single_unit_max_files() -> int:
    """0 disables the small-repo rule; else app files must fit this count AND the
    byte budget for a single unit."""
    return _int_env("PARTITION_SINGLE_UNIT_MAX_FILES", 50)


# --- P1.3 misc policy --------------------------------------------------------

def misc_code_merge_enabled() -> bool:
    """On by default: tiny code units couple or stay singletons, only non-code
    lands in misc; =0 restores legacy misc-absorbs-all."""
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

"""Partitioning policy knobs (env-overridable, read at call time; functions, not
import-time constants, so tests can monkeypatch the environment)."""
from __future__ import annotations

import logging
import os as _os
from typing import Any

_logger = logging.getLogger(__name__)


def _num(value: Any, default: int) -> int:
    """int(value) or default: a malformed operator value degrades, never blocks."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _section_value(cfg: dict | None, key: str, section: str = "partition") -> Any:
    """``<section>.<key>`` from cfg, or None when unset (callers fall back to env)."""
    node: Any = cfg if isinstance(cfg, dict) else None
    for part in section.split("."):
        node = node.get(part) if isinstance(node, dict) else None
    if not isinstance(node, dict):
        return None
    value = node.get(key)
    return None if value in (None, "") else value


def _yaml_default(path: str) -> Any:
    """The default for a path, from harness/config/default.yaml only."""
    from harness.config import config_default

    return config_default(path)


def _policy_value(cfg: dict | None, key: str, *, section: str = "partition",
                  env: str | None = None) -> Any:
    """Resolve ``<section>.<key>``: scan cfg wins, then an env override, then
    the YAML default.

    The env override defaults to ``PARTITION_<KEY>`` (``PARTITION_MAX_UNITS``,
    ``PARTITION_MIN_FILES``, ...). Those two are the legacy raw-env knobs and
    match the YAML ``${MAX_UNITS:-}`` / ``${MIN_FILES:-}`` placeholders, so
    both spellings reach the same value; pass ``env=`` explicitly anywhere the
    documented name differs.
    """
    value = _section_value(_loaded_cfg(cfg), key, section)
    if value is not None:
        return value
    env_value = _os.environ.get(env or f"PARTITION_{key.upper()}")
    return env_value if env_value not in (None, "") else _yaml_default(f"{section}.{key}")


def _as_flag(value: Any, default: bool) -> bool:
    from harness.config import as_bool

    return as_bool(value, default)


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
    value = _num(_policy_value(cfg, "max_units"),
                 int(_yaml_default("partition.max_units")))
    return 10**9 if value <= 0 else value


def min_files(cfg: dict | None = None) -> int:
    """Minimum files for a group to stand alone; smaller groups merge upward."""
    return max(0, _num(_policy_value(cfg, "min_files"),
                       int(_yaml_default("partition.min_files"))))


# --- P0.1 vendor isolation ---------------------------------------------------

def vendor_unit_enabled(cfg: dict | None = None) -> bool:
    return _as_flag(_policy_value(cfg, "vendor_unit"), False)


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


def single_unit_max_files(cfg: dict | None = None) -> int:
    """0 disables the small-repo rule; else app files must fit this count AND the
    byte budget for a single unit."""
    return _num(_policy_value(cfg, "single_unit_max_files"),
                int(_yaml_default("partition.single_unit_max_files")))


# --- P1.3 misc policy --------------------------------------------------------

def misc_code_merge_enabled(cfg: dict | None = None) -> bool:
    """On by default: tiny code units couple or stay singletons, only non-code
    lands in misc; =0 restores legacy misc-absorbs-all."""
    return _as_flag(_policy_value(cfg, "misc_code_merge"), True)


NON_CODE_EXTS = frozenset({
    ".md", ".rst", ".txt", ".cfg", ".ini", ".lock",
})

NON_CODE_NAMES = frozenset({
    "dockerfile", "LICENSE", "LICENCE", "COPYING", "AUTHORS", "CONTRIBUTORS",
    "CHANGELOG", "NOTICE", "makefile", ".editorconfig", ".gitignore",
    ".pre-commit-config.yaml", ".pre-commit-config.yml",
})

# --- P2 framework edges ------------------------------------------------------

def framework_edges_enabled(cfg: dict | None = None) -> bool:
    return _as_flag(_policy_value(cfg, "framework_edges"), True)


def edge_max_file_bytes(cfg: dict | None = None) -> int:
    return _num(_policy_value(cfg, "edge_max_file_bytes"),
                int(_yaml_default("partition.edge_max_file_bytes")))


def edge_read_cap_bytes(cfg: dict | None = None) -> int:
    return _num(_policy_value(cfg, "edge_read_cap_bytes"),
                int(_yaml_default("partition.edge_read_cap_bytes")))


# --- codegraph partition source ----------------------------------------------
#
# Read at call time from ``codegraph.partition.mode`` in the scan config
# (config beats env), else the env var, else the documented default.

PARTITION_MODES = ("off", "primary")


def partition_mode(cfg: dict | None = None) -> str:
    """``codegraph.partition.mode`` — one of off|primary.

    An unrecognized value degrades to the
    default, so a stale config can never select a mode that does not exist.
    """
    value = _policy_value(cfg, "mode", section="codegraph.partition",
                          env="CODEGRAPH_PARTITION_MODE")
    mode = str(value or "").strip().lower()
    if mode in PARTITION_MODES:
        return mode
    fallback = str(_yaml_default("codegraph.partition.mode")).strip().lower()
    return fallback if fallback in PARTITION_MODES else "primary"

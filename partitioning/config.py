"""Partitioning constants: policy values live in the one cfg.

Every tunable (``partition.*``, ``codegraph.partition.mode``) is normalized at
load in :mod:`harness.config`; callers read it from ``cfg``.
"""
from __future__ import annotations

# --- P0.1 vendor isolation ---------------------------------------------------

VENDOR_UNIT_NAME = "vendor"

VENDOR_DIR_SEGMENTS = frozenset({
    "node_modules", ".venv", "venv", "env", "vendor", "third_party",
    "third-party", "bower_components", "jspm_packages", "site-packages",
    "dist", "build", ".tox", "__pycache__", "pods", "godeps",
})

VENDOR_FILE_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".chunk.js",
                        ".min.js.map")

# --- P1.3 misc policy --------------------------------------------------------

NON_CODE_EXTS = frozenset({
    ".md", ".rst", ".txt", ".cfg", ".ini", ".lock",
})

NON_CODE_NAMES = frozenset({
    "dockerfile", "LICENSE", "LICENCE", "COPYING", "AUTHORS", "CONTRIBUTORS",
    "CHANGELOG", "NOTICE", "makefile", ".editorconfig", ".gitignore",
    ".pre-commit-config.yaml", ".pre-commit-config.yml",
})

# --- codegraph partition source ----------------------------------------------

PARTITION_MODES = ("off", "primary")

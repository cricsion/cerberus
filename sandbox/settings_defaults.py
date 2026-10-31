"""Sandbox default settings, read once from harness/config/default.yaml.

Leaf module: it imports only :mod:`harness.config`, so every sandbox backend may
depend on it without a cycle. The YAML file is the single source of these
values; the runtime settings builders still override them per scan.
"""
from __future__ import annotations

from harness.config import get_config

_SANDBOX = get_config()["sandbox"]

IMAGE = str(_SANDBOX["image"])
COMMAND_TIMEOUT = int(_SANDBOX["command_timeout"])
MAX_OUTPUT_BYTES = int(_SANDBOX["max_output_bytes"])
MEMORY = str(_SANDBOX["memory"])
CPUS = str(_SANDBOX["cpus"])
PIDS_LIMIT = int(_SANDBOX["pids_limit"])
NETWORK = str(_SANDBOX["network"])
DOCKER_BIN = str(_SANDBOX["docker_bin"])
RULES_DIR = str(_SANDBOX["rules_dir"])

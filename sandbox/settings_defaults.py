"""Sandbox default settings, read once from harness/config/default.yaml.

Leaf module: it imports only :mod:`harness.config`, so every sandbox backend may
depend on it without a cycle. The YAML file is the single source of these
values; the runtime settings builders still override them per scan.
"""
from __future__ import annotations

from harness.config import get_default_config

IMAGE = str(get_default_config("sandbox.image"))
COMMAND_TIMEOUT = int(get_default_config("sandbox.command_timeout"))
MAX_OUTPUT_BYTES = int(get_default_config("sandbox.max_output_bytes"))
MEMORY = str(get_default_config("sandbox.memory"))
CPUS = str(get_default_config("sandbox.cpus"))
PIDS_LIMIT = int(get_default_config("sandbox.pids_limit"))
NETWORK = str(get_default_config("sandbox.network"))
DOCKER_BIN = str(get_default_config("sandbox.docker_bin"))
RULES_DIR = str(get_default_config("sandbox.rules_dir"))

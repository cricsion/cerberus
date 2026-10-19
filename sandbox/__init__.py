from __future__ import annotations

import importlib
import os
from pathlib import Path
from typing import Any, Iterator

from harness.sandbox.local_backend import RepoLocalBackend
from harness.sandbox.run_base import (DEFAULT_COMMAND_TIMEOUT,
                                      DEFAULT_MAX_OUTPUT_BYTES,
                                      DEFAULT_MEMORY, DEFAULT_RULES_DIR)
from harness.sandbox.validation import DEFAULT_NETWORK

__all__ = [
    "RepoLocalBackend",
    "resolve_backend",
    "close_backend",
    "shutdown_run_sandbox",
    "reset_agent_scratch",
    "sweep_orphans",
]

def close_backend(backend: Any) -> None:
    # Backend close paths are fail-safe by construction (run teardown swallows,
    # cleanup uses ignore_errors): only a harness bug could raise, and a bug
    # must surface instead of silently skipping the next backend's teardown.
    close = getattr(backend, "close", None)
    if callable(close):
        close()

def _sandbox_section(cfg: dict | None) -> dict:
    section = (cfg if isinstance(cfg, dict) else {}).get("sandbox")
    return section if isinstance(section, dict) else {}

def _sandbox_setting(cfg: dict | None, key: str, default: Any) -> Any:
    value = _sandbox_section(cfg).get(key)
    if value in (None, ""):
        env_value = os.environ.get(f"SANDBOX_{key.upper()}")
        return env_value if env_value not in (None, "") else default
    return value

def _host_list(raw: Any) -> list[str]:
    # Config hosts arrive as list, comma/semicolon string, or a single value.
    if isinstance(raw, str):
        raw = [raw]
    hosts: list[str] = []
    for entry in raw if isinstance(raw, (list, tuple)) else [str(raw)]:
        for host in str(entry).replace(";", ",").split(","):
            if host.strip():
                hosts.append(host.strip())
    return hosts

def _coerce_int(key: str, value: Any) -> int:
    """A garbage sandbox setting fails the resolve (callers degrade to the
    local backend), matching validation.py's raise-at-construction contract."""
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid sandbox {key}: {value!r}") from exc

def _docker_settings(cfg: dict | None, repo: str | Path) -> dict:
    from .docker_backend import DEFAULT_IMAGE as _IMAGE
    from .credentials import find_credential_files
    # No guard on purpose: find_credential_files is fail-soft; a catch-all could only fail OPEN (mask_paths = []).
    mask_paths: list[str] = find_credential_files(repo)

    def _int(key: str, default: int) -> int:
        return _coerce_int(key, _sandbox_setting(cfg, key, default))

    return {
        "image": str(_sandbox_setting(cfg, "image", _IMAGE)),
        "command_timeout": _int("command_timeout", DEFAULT_COMMAND_TIMEOUT),
        "max_output_bytes": _int("max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES),
        "memory": str(_sandbox_setting(cfg, "memory", DEFAULT_MEMORY)),
        "cpus": str(_sandbox_setting(cfg, "cpus", "2")),
        "pids_limit": _int("pids_limit", 512),
        "network": str(_sandbox_setting(cfg, "network", DEFAULT_NETWORK)),
        # In-image rules dir for offline scans: read via `execute` (file tools are repo-confined). Scanner skills need no setting: the image bakes them and the agent is served them by the skills route -- harness/agents/deep.py.
        "rules_dir": str(_sandbox_setting(cfg, "rules_dir", DEFAULT_RULES_DIR)),
        "mask_paths": mask_paths,
    }

def _sbx_settings(cfg: dict | None, repo: str | Path | None = None) -> dict:
    section = _sandbox_section(cfg).get("sbx") or {}
    if not isinstance(section, dict):
        section = {}

    def _shared(key: str, default: Any) -> Any:
        value = _sandbox_setting(cfg, key, default)
        return section.get(key, value)

    def _int(key: str, default: int) -> int:
        return _coerce_int(key, _shared(key, default))

    hosts = _host_list(section.get("deny_network") or "")

    # Per-sandbox egress allow rules (never global); default: the OSV API (the image no longer bundles the vuln DB).
    raw_allowed = section.get("allow_network")
    if raw_allowed in (None, ""):
        raw_allowed = os.environ.get("SBX_ALLOW_NETWORK",
                                     "osv.dev,api.osv.dev")
    allowed = _host_list(raw_allowed)

    raw_telem = section.get("disable_telemetry", True)
    disable_telemetry = str(raw_telem).strip().lower() not in ("0", "false", "no", "off")

    from .sbx_backend import DEFAULT_IMAGE as _SBX_IMAGE

    return {
        "image": str(section.get("image")
                     or _sandbox_setting(cfg, "image", _SBX_IMAGE)),
        "cpus": str(section.get("cpus", "0")),
        "memory": str(section.get("memory", DEFAULT_MEMORY)),
        "skills": str(section.get("skills", "off")),
        "pull": str(section.get("pull", "never")),
        "deny_network": hosts,
        "allow_network": allowed,
        "disable_telemetry": disable_telemetry,
        "primary_dir": section.get("primary_dir") or None,
        "command_timeout": _int("command_timeout", DEFAULT_COMMAND_TIMEOUT),
        "max_output_bytes": _int("max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES),
        "sbx_bin": str(section.get("bin", "sbx")),
        # Same in-image rules dir as the docker settings above (read via `execute`); scanner skills need no setting (image-baked + served by the route).
        "rules_dir": str(_shared("rules_dir", DEFAULT_RULES_DIR)),
    }

# One row per backend: name, `sandbox.backend` aliases, settings builder
# (called as (cfg, repo) for every backend), and the module members the facade
# drives it through (backend class, run getter, shutdown). A backend lives
# entirely in its module; this table is the only place the facade names one.
_BACKENDS: tuple[tuple[Any, ...], ...] = (
    ("docker", ("docker", "container"), _docker_settings,
     "DockerSandboxBackend", "get_run_sandbox", "shutdown_run_sandbox"),
    ("sbx", ("sbx", "microvm", "docker-sandbox", "docker_sandbox"),
     _sbx_settings, "SbxBackend", "get_sbx_run", "shutdown_sbx"),
)

def _backend_module(name: str) -> Any:
    return importlib.import_module(f"{__name__}.{name}_backend")

def _iter_backends() -> Iterator[tuple[tuple[Any, ...], Any]]:
    # A module that fails to import drops only itself: the old shared
    # try/except silently dropped every backend that came after it too.
    for row in _BACKENDS:
        try:
            yield row, _backend_module(row[0])
        except Exception:
            continue

def resolve_backend(cfg: dict | None, repo: str | Path,
                    *, agent_id: str | None = None) -> RepoLocalBackend:
    which = str(_sandbox_setting(cfg, "backend", "local")).strip().lower()
    for name, aliases, build_settings, cls_name, getter, _shutdown in _BACKENDS:
        if which not in aliases:
            continue
        module = _backend_module(name)
        settings = build_settings(cfg, repo)
        run = getattr(module, getter)(repo, settings)
        return getattr(module, cls_name)(
            repo_path=repo, run=run, agent_id=agent_id, **settings)
    return RepoLocalBackend(repo_path=repo)

def shutdown_run_sandbox(repo: str | Path | None = None) -> None:
    # Every backend reaps on every exit path; teardown never raises by
    # construction (run_base.remove swallows, cleanup is ignore_errors), so a
    # raise here can only be a harness bug and must surface.
    for row, module in _iter_backends():
        getattr(module, row[-1])(repo)

def reset_agent_scratch(repo: str | Path) -> list[str]:
    errors: list[str] = []
    # Each backend's registry owns the reset, incl. the never-started case;
    # the registry converts reset failures to error strings, so an exception
    # here could only be a harness bug and must surface.
    for row, module in _iter_backends():
        for err in module.RUNS.reset_agent_scratch(repo):
            errors.append(f"{row[0]} sandbox: {err}")
    return errors

def sweep_orphans() -> list[str]:
    # Backends are fail-soft by contract (each returns [] on infra failure);
    # the scan-start gate in harness/pipeline.py is the real boundary.
    removed: list[str] = []
    for _row, module in _iter_backends():
        removed.extend(module.sweep_orphans())
    return removed

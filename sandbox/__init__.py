from __future__ import annotations

import importlib
import logging
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from cerberus.sandbox.local_backend import RepoLocalBackend

__all__ = [
    "RepoLocalBackend",
    "resolve_backend",
    "acquired_backend",
    "close_backend",
    "shutdown_run_sandbox",
    "reset_agent_scratch",
    "sweep_orphans",
]

_logger = logging.getLogger(__name__)

def close_backend(backend: Any) -> None:
    # Backend close paths are fail-safe by construction (run teardown swallows,
    # cleanup uses ignore_errors): only a harness bug could raise, and a bug
    # must surface instead of silently skipping the next backend's teardown.
    close = getattr(backend, "close", None)
    if callable(close):
        close()

def _acquire_backend(cfg: dict | None, root: str | Path, *, label: str,
                     fallback: str = "none",
                     refused_msg: str | None = None,
                     agent_id: str | None = None) -> Any:
    """Resolve a backend with the harness's one fail-open ladder.
    """
    from cerberus.fallback import is_fatal_error

    try:
        return resolve_backend(
            cfg, root,
            agent_id=agent_id or f"{label[:36]}-{uuid.uuid4().hex[:8]}")
    except Exception as exc:
        if is_fatal_error(exc):
            raise
        if refused_msg:
            print(refused_msg.format(exc=exc), file=sys.stderr)
        else:
            _logger.debug("%s backend refused (%s); falling back to %s",
                          label, exc, fallback)
        if fallback == "local":
            return RepoLocalBackend(repo_path=root)
        return None


@contextmanager
def acquired_backend(cfg: dict | None, root: str | Path, *, label: str,
                     fallback: str = "none",
                     refused_msg: str | None = None,
                     agent_id: str | None = None) -> Iterator[Any]:
    """``resolve_backend`` + fail-open ladder + ``close_backend`` on exit.

    One implementation for the per-session copy every LLM stage used to
    hand-roll. ``close_backend`` is None-safe, so no caller needs a guard.
    """
    backend = _acquire_backend(cfg, root, label=label, fallback=fallback,
                               refused_msg=refused_msg, agent_id=agent_id)
    try:
        yield backend
    finally:
        close_backend(backend)

def _sandbox_section(cfg: dict | None) -> dict:
    section = (cfg if isinstance(cfg, dict) else {}).get("sandbox")
    return section if isinstance(section, dict) else {}

def _sandbox_setting(cfg: dict | None, key: str, default: Any) -> Any:
    value = _sandbox_section(cfg).get(key)
    return default if value in (None, "") else value


def _sandbox_defaults(*path: str) -> dict:
    """The ``sandbox`` section of the one cfg."""
    from cerberus.config import get_config

    node: Any = get_config()
    for part in path:
        node = node.get(part) if isinstance(node, dict) else None
    return node if isinstance(node, dict) else {}


def _coerce_int(key: str, value: Any) -> int:
    """A garbage sandbox setting fails the resolve (callers degrade to the
    local backend), matching validation.py's raise-at-construction contract."""
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid sandbox {key}: {value!r}") from exc

def _coerce_bool(key: str, value: Any) -> bool:
    """Same raise-on-garbage contract as ``_coerce_int``: "1/true/yes/on" is
    True, "0/false/no/off" or empty is False, anything else fails the resolve
    (callers degrade to the local backend)."""
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"invalid sandbox {key}: {value!r}")

def _docker_settings(cfg: dict | None, repo: str | Path) -> dict:
    defaults = _sandbox_defaults("sandbox")

    def _int(key: str) -> int:
        return _coerce_int(key, _sandbox_setting(cfg, key, defaults[key]))

    def _bool(key: str) -> bool:
        return _coerce_bool(key, _sandbox_setting(cfg, key, defaults[key]))

    return {
        "image": str(_sandbox_setting(cfg, "image", defaults["image"])),
        "command_timeout": _int("command_timeout"),
        "max_output_bytes": _int("max_output_bytes"),
        "memory": str(_sandbox_setting(cfg, "memory", defaults["memory"])),
        "cpus": str(_sandbox_setting(cfg, "cpus", defaults["cpus"])),
        "pids_limit": _int("pids_limit"),
        "network": str(_sandbox_setting(cfg, "network", defaults["network"])),
        "docker_bin": str(_sandbox_setting(cfg, "docker_bin",
                                           defaults["docker_bin"])),
        # In-image rules dir for offline scans: read via `execute` (file tools are repo-confined). Scanner skills need no setting: the image bakes them and the agent is served them by the skills route -- cerberus/agents/deep.py.
        "rules_dir": str(_sandbox_setting(cfg, "rules_dir",
                                          defaults["rules_dir"])),
        # Opt-in SDK-lane pull-on-missing-image (docker_backend.RunSandbox);
        # default 0 from default.yaml keeps the CLI lane's fail-fast.
        "pull_image": _bool("pull_image"),
    }

# One row per backend: name, settings builder (called as (cfg, repo) for every
# backend), and the module members the facade drives it through (backend
# class, run getter, shutdown). `sandbox.backend` must equal the name exactly;
# anything else falls back to the local backend (resolve_backend). A backend
# lives entirely in its module; this table is the only place the facade names
# one.
_BACKENDS: tuple[tuple[Any, ...], ...] = (
    ("docker", _docker_settings,
     "DockerSandboxBackend", "get_run_sandbox", "shutdown_run_sandbox"),
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
    from cerberus.config import effective_config

    which = str(effective_config(cfg)["sandbox"]["backend"])
    for name, build_settings, cls_name, getter, _shutdown in _BACKENDS:
        if which != name:
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
    # the scan-start gate in cerberus/pipeline.py is the real boundary.
    removed: list[str] = []
    for _row, module in _iter_backends():
        removed.extend(module.sweep_orphans())
    return removed

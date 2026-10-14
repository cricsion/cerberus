"""Sandbox confinement for scan agents (Docker is the app-config default).

In local mode, agents use in-process filesystem tools confined to the target
repo and get no shell tool. Docker and sbx add a shell inside their respective
runtime; the filesystem tools remain repo-confined in every mode.

``sandbox.backend`` picks one of three:

* ``local`` -- confined file tools, no shell (the resolver fallback when no
  backend setting is supplied).
* ``docker`` (:class:`~harness.sandbox.docker_backend.DockerSandboxBackend`)
  and ``sbx`` (:class:`~harness.sandbox.sbx_backend.SbxBackend`) -- adds a
  shell that runs inside the run's ONE shared sandbox, the repo mounted
  read-only. Both backends are thin CLI adapters over the shared
  :class:`~harness.sandbox.run_base.RunSandboxBase` lifecycle and
  :class:`~harness.sandbox.backend_base.SandboxShellBackend` agent session,
  so a lifecycle fix lands in both. Path confinement and the shell live in
  different places on purpose: file tools stay in-process checks, the shell
  is contained by the sandbox, not by any path policy.

ONE sandbox per scan run, shared by every agent (hunter units, validators,
triage, the partitioner). Each agent gets distinct ``HOME``/``TMPDIR`` paths
to reduce accidental collisions; agents still share a container and runtime
identity, and the package download caches are shared. The optional phase
reset clears those conventional scratch paths as hygiene, not as an isolation
boundary. ``close_backend()`` ends a single agent's session;
``shutdown_run_sandbox()`` removes the shared sandbox at scan teardown
(also run by the CLI's ``finally``, an atexit hook, and a SIGTERM handler).

"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from harness.sandbox.local_backend import RepoLocalBackend

__all__ = [
    "RepoLocalBackend",
    "resolve_backend",
    "close_backend",
    "shutdown_run_sandbox",
    "reset_agent_scratch",
    "sweep_orphans",
]


def close_backend(backend: Any) -> None:
    """End one agent's sandbox session (container stays for the run).

    For a docker-mode backend this only marks the agent done -- the shared
    run container is removed by :func:`shutdown_run_sandbox` at scan
    teardown. Never raises: teardown must not fail a scan that already
    finished.
    """
    close = getattr(backend, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


def shutdown_run_sandbox(repo: str | Path | None = None) -> None:
    """Remove the run's shared sandbox container (idempotent, never raises).

    One container is shared by the whole run, so teardown is run-level, not
    per-agent: call it once at scan end (the CLI does) or with a repo path
    when only that scan is over. Shuts down whichever backend the run used
    (docker container or Docker Sandbox microVM).
    """
    from .docker_backend import shutdown_run_sandbox as _shutdown_docker

    _shutdown_docker(repo)
    try:
        from .sbx_backend import shutdown_sbx as _shutdown_sbx

        _shutdown_sbx(repo)
    except Exception:
        pass


def reset_agent_scratch(repo: str | Path) -> list[str]:
    """Clear conventional per-agent scratch paths between scan phases.

    Best-effort hygiene only: agents share a runtime identity, and this does
    not stop background processes or writes elsewhere. Shared package caches
    are kept. No-op in local mode (no sandbox). Never raises.
    """
    errors: list[str] = []
    try:
        # Each backend's public registry knows the run's sandbox for this
        # repo (one per repo per process) and owns the reset, including the
        # "never started, so there is nothing to remove" case.
        from . import docker_backend, sbx_backend

        for module, label in ((docker_backend, "docker"),
                              (sbx_backend, "sbx")):
            for err in module.RUNS.reset_agent_scratch(repo):
                errors.append(f"{label} sandbox: {err}")
    except Exception:
        pass
    return errors

def _sandbox_setting(cfg: dict | None, key: str, default: Any) -> Any:
    """Read sandbox.<key> from config, falling back to the env var.

    Defensive about malformed config: a non-dict cfg or `sandbox` section
    (a stray list or string in yaml) degrades to defaults, never crashes.
    """
    cfg = cfg if isinstance(cfg, dict) else {}
    section = cfg.get("sandbox") or {}
    if not isinstance(section, dict):
        section = {}
    value = section.get(key)
    if value in (None, ""):
        env_value = os.environ.get(f"SANDBOX_{key.upper()}")
        return env_value if env_value not in (None, "") else default
    return value


def _coerce_int(value: Any, default: int) -> int:
    """A setting that must be an int; a bad value falls back, never raises.

    Config comes from yaml and env, so "abc" or 2.5 are operator typos, not
    bugs -- a scan should start on the default rather than crash.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _docker_settings(cfg: dict | None, repo: str | Path) -> dict:
    """docker-mode container settings (shared keys under ``sandbox``).

    ``mask_paths`` is computed from the live tree: the container can hide a
    credential file (a read-only /dev/null bind over it) where sbx cannot, so
    the docker backend is the one that actually removes the read path.
    """
    from .docker_backend import DEFAULT_IMAGE as _IMAGE
    from .credentials import find_credential_files
    # No guard on purpose: find_credential_files is already fail-soft (it
    # catches OSError and returns []), the credentials module is loaded by
    # this package's own import chain so the import cannot fail, and a
    # repo_path bad enough to raise TypeError from Path() raises the same
    # TypeError from the unconditional _validate_mask_paths call in
    # RunSandbox. A catch-all here was dead code that could only ever fail
    # OPEN (mask_paths = []).
    mask_paths: list[str] = find_credential_files(repo)

    def _int(key: str, default: int) -> int:
        return _coerce_int(_sandbox_setting(cfg, key, default), default)

    return {
        "image": str(_sandbox_setting(cfg, "image", _IMAGE)),
        "command_timeout": _int("command_timeout", 120),
        "max_output_bytes": _int("max_output_bytes", 200_000),
        "memory": str(_sandbox_setting(cfg, "memory", "2g")),
        "cpus": str(_sandbox_setting(cfg, "cpus", "2")),
        "pids_limit": _int("pids_limit", 512),
        "network": str(_sandbox_setting(cfg, "network", "bridge")),
        # In-image locations the prompt points the model at (rules for
        # offline scans, skills for scanner usage). Read via `execute`,
        # since the file tools are repo-confined.
        "rules_dir": str(_sandbox_setting(cfg, "rules_dir", "/opt/scan-rules/harness")),
        "skills_dir": str(_sandbox_setting(cfg, "skills_dir", "/opt/harness-skills")),
        "mask_paths": mask_paths,
    }


def _sbx_settings(cfg: dict | None) -> dict:
    """sbx-mode settings (nested ``sandbox.sbx``; shared caps stay on ``sandbox``)."""
    cfg = cfg if isinstance(cfg, dict) else {}
    sandbox = cfg.get("sandbox")
    sandbox = sandbox if isinstance(sandbox, dict) else {}
    section = sandbox.get("sbx") or {}
    if not isinstance(section, dict):
        section = {}

    def _shared(key: str, default: Any) -> Any:
        value = _sandbox_setting(cfg, key, default)
        return section.get(key, value)

    def _int(key: str, default: int) -> int:
        return _coerce_int(_shared(key, default), default)

    raw_hosts = section.get("deny_network") or ""
    if isinstance(raw_hosts, str):
        raw_hosts = [raw_hosts]
    hosts: list[str] = []
    for entry in raw_hosts if isinstance(raw_hosts, (list, tuple)) else [str(raw_hosts)]:
        for host in str(entry).replace(";", ",").split(","):
            if host.strip():
                hosts.append(host.strip())

    # Egress allow rules for this sandbox (per-sandbox, never global). Default:
    # the OSV API, because the image no longer bundles the vulnerability DB.
    raw_allowed = section.get("allow_network")
    if raw_allowed in (None, ""):
        raw_allowed = os.environ.get("SBX_ALLOW_NETWORK",
                                     "osv.dev,api.osv.dev")
    if isinstance(raw_allowed, str):
        raw_allowed = [raw_allowed]
    allowed: list[str] = []
    for entry in (raw_allowed if isinstance(raw_allowed, (list, tuple))
                  else [str(raw_allowed)]):
        for host in str(entry).replace(";", ",").split(","):
            if host.strip():
                allowed.append(host.strip())

    raw_telem = section.get("disable_telemetry", True)
    disable_telemetry = str(raw_telem).strip().lower() not in ("0", "false", "no", "off")

    from .sbx_backend import DEFAULT_IMAGE as _SBX_IMAGE

    return {
        "image": str(section.get("image")
                     or _sandbox_setting(cfg, "image", _SBX_IMAGE)),
        "cpus": str(section.get("cpus", "0")),
        "memory": str(section.get("memory", "2g")),
        "skills": str(section.get("skills", "off")),
        "pull": str(section.get("pull", "never")),
        "deny_network": hosts,
        "allow_network": allowed,
        "disable_telemetry": disable_telemetry,
        "primary_dir": section.get("primary_dir") or None,
        "command_timeout": _int("command_timeout", 120),
        "max_output_bytes": _int("max_output_bytes", 200_000),
        "sbx_bin": str(section.get("bin", "sbx")),
        # In-image locations the prompt points the model at (rules for
        # offline scans, skills for scanner usage). Read via `execute`,
        # since the file tools are repo-confined.
        "rules_dir": str(_shared("rules_dir", "/opt/scan-rules/harness")),
        "skills_dir": str(_shared("skills_dir", "/opt/harness-skills")),
    }


def resolve_backend(cfg: dict | None, repo: str | Path,
                    *, agent_id: str | None = None) -> RepoLocalBackend:
    """Backend for one agent: local (confined, no shell), docker or sbx.

    ``docker`` and ``sbx`` are the same design in two runtimes: thin CLI
    adapters over the shared
    :class:`~harness.sandbox.run_base.RunSandboxBase` lifecycle and
    :class:`~harness.sandbox.backend_base.SandboxShellBackend` agent session.
    Both connect to the run's ONE shared sandbox -- every agent of the run
    executes in it, each with its own scratch state -- started on the first
    ``execute()``. The caller ends the agent's session with
    ``close_backend()`` and removes the sandbox with
    ``shutdown_run_sandbox()`` at scan teardown.

    ``agent_id`` names the agent's scratch dir inside the sandbox; it defaults
    to a random id (safe for one-shot agents).
    """
    which = str(_sandbox_setting(cfg, "backend", "local")).strip().lower()
    if which in ("sbx", "microvm", "docker-sandbox", "docker_sandbox"):
        from .sbx_backend import SbxBackend, get_sbx_run

        settings = _sbx_settings(cfg)
        run = get_sbx_run(repo, settings)
        return SbxBackend(repo_path=repo, run=run, agent_id=agent_id,
                          denied_globs=_deny_globs(repo), **settings)
    if which in ("docker", "container"):
        from .docker_backend import DockerSandboxBackend, get_run_sandbox

        settings = _docker_settings(cfg, repo)
        run = get_run_sandbox(repo, settings)
        return DockerSandboxBackend(repo_path=repo, run=run, agent_id=agent_id,
                                    denied_globs=_deny_globs(repo), **settings)
    return RepoLocalBackend(repo_path=repo, denied_globs=_deny_globs(repo))


def _deny_globs(repo: str | Path) -> tuple[str, ...]:
    """Credential-file globs the file tools refuse (finding: egress allows exfil)."""
    # blocked_paths() returns the constant CREDENTIAL_GLOBS: it cannot raise,
    # and the module is already loaded by this package's import chain.
    from harness.sandbox.credentials import blocked_paths
    return blocked_paths()


def sweep_orphans() -> list[str]:
    """Reap sandboxes a killed run left behind (runs at scan start).

    A SIGKILL'd harness runs no teardown: atexit never fires and the SIGTERM
    handler never sees the signal, so its sandbox outlives it -- a container
    nobody uses, or an idle microVM costing host CPU.

    Each backend sweeps with what its daemon publishes (sbx's `last_used_at`,
    docker's `exec_start` events), so there is no harness-side liveness state
    to lose when a run is killed. Only sandboxes this harness created are
    candidates, a run of THIS process is excluded outright, and anything the
    daemon can no longer account for is left alone. Never raises; returns what
    it removed.
    """
    removed: list[str] = []
    try:
        from . import docker_backend, sbx_backend

        for module in (docker_backend, sbx_backend):
            try:
                removed.extend(module.sweep_orphans())
            except Exception:
                pass
    except Exception:
        pass
    return removed

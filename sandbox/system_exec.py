"""System-lane execution: harness-owned commands run in the repo sandbox.

The deterministic pipeline stages (SAST scanners, the codegraph CLI, the
compute runner behind the graph tools and partitioning) used to fork host
subprocesses that read or parse the target tree. They now execute INSIDE the
per-repo run container on the shared exec channel (D1: one container per repo,
zero additional containers; the host runs only the orchestrator and its store
reads). This module is that single seam.

It rides the SAME exec channel, exec markers and pkill hygiene as agent shells
(``RunSandboxBase.exec``) with a reserved ``system`` agent id, and mirrors
``SandboxShellBackend.execute``'s error mapping: a missing client is an infra
error, a client hang kills ONLY this exec's tagged shell via pkill, and the
in-sandbox ``timeout`` yields exit 124. It deliberately skips the backend's
``command_timeout`` clamp so a 600 s index build is bounded by its own timeout
argument, not agent policy.

The environment crosses as an ``export`` prefix INSIDE the command (docker
``-e`` equivalents): inline ``K=V cmd`` assignment would apply to one simple
command only, while these stages run multi-statement shell strings. System
scratch dirs live under ``/work/_system`` / ``/tmp/_system`` — outside the
``agent-*`` reset glob, so caches survive phase cleanup.

``SANDBOX_BACKEND=local`` keeps a host-subprocess lane (cwd=repo, scrubbed
env) so dev scans without docker behave exactly as before.
"""
from __future__ import annotations

import logging
import os
import re
import shlex
import subprocess
import uuid
from dataclasses import dataclass

from .cli_utils import run_bounded
from .run_base import DEFAULT_MAX_OUTPUT_BYTES

__all__ = ["ExecResult", "ShellResult", "sandbox_lane", "system_execute",
           "system_shell"]

_logger = logging.getLogger(__name__)

_SYSTEM_AGENT_ID = "system"
_ENV_KEY_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# System scratch: a stable HOME for CLI config/cache, outside the
# agent-<id>-prefixed dirs that reset_agent_scratch wipes between phases.
_SYSTEM_ENV = {
    "HOME": "/work/_system",
    "TMPDIR": "/tmp/_system",
    "PYTHONPYCACHEPREFIX": "/work/_system/.pyc",
}

# Sentinel exit for the ``command -v`` probe: absent binary in the lane.
_MISSING_OK = re.compile(r"^[A-Za-z0-9_.+/-]+$")

_BYTE_CAP_FACTOR = 4  # keep in line with run_base._BYTE_CAP_FACTOR


@dataclass(frozen=True)
class ExecResult:
    """One lane primitive result.

    ``error`` non-empty marks an INFRA failure (no client, no container, a
    create timeout, or a client hang) — stages treat it like a non-zero exit
    and fail open, exactly like the backend does.
    """
    out: str = ""
    exit_code: int | None = None
    truncated: bool = False
    error: str = ""


@dataclass(frozen=True)
class ShellResult:
    """``system_shell`` result with stdout/stderr separated (like
    ``subprocess.run(capture_output=True)`` had produced it)."""
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False
    error: str = ""


def sandbox_lane() -> str:
    """The configured execution lane: ``docker`` (in-container) or ``local``.

    Same ladder as the facade's ``resolve_backend``: the scan cfg's
    ``sandbox.backend`` (env escape ``SANDBOX_BACKEND`` included) over the
    packaged default. A config LOAD failure is the same operator-facing
    degrade deep.py applies — the local lane, never a silent ``{}`` resolve
    that could still pick docker via env interpolation behind a broken cfg.
    """
    from harness.config import load_config_safe

    cfg, cfg_err = load_config_safe()
    if cfg_err is not None:
        _logger.debug("sandbox lane degraded to local: config load failed: "
                      "%s: %s", type(cfg_err).__name__, cfg_err)
        return "local"
    from . import _sandbox_defaults, _sandbox_setting

    defaults = _sandbox_defaults("sandbox")
    return str(_sandbox_setting(cfg, "backend",
                                defaults["backend"])).strip().lower()


def _env_exports(env: dict[str, str] | None) -> str:
    """``export`` prefix persisting for the whole shell string."""
    if not env:
        return ""
    parts: list[str] = []
    for key, value in env.items():
        if not _ENV_KEY_OK.match(str(key)):
            raise ValueError(f"system env key not exportable: {key!r}")
        parts.append(f"{key}={shlex.quote(str(value))}")
    return "export " + " ".join(parts) + "; "


def _run_for(repo: str):
    from harness.config import load_config_safe
    from . import _docker_settings
    from .docker_backend import get_run_sandbox

    # The SAME cfg the agent lane resolves with, so the registry's one
    # container per repo carries one settings set (image, network, limits)
    # whichever lane constructs it first. A config failure degrades to {}
    # here (defaults + env ladder) exactly as sandbox_lane degrades to local.
    cfg, _cfg_err = load_config_safe()
    return get_run_sandbox(repo, _docker_settings(cfg, repo))


def system_execute(repo: str, command: str, *, timeout: int = 300,
                   max_bytes: int | None = None,
                   env: dict[str, str] | None = None) -> ExecResult:
    """Run one shell command in the configured lane; never raises.

    Local lane: ``/bin/bash -c`` as a host subprocess with cwd=repo and a
    scrubbed environment. Docker lane: the per-repo run container's exec
    channel, with system scratch exports prepended.
    """
    if sandbox_lane() != "docker":
        return _local_exec(repo, command, timeout, max_bytes, env)
    return _docker_exec(repo, command, timeout, max_bytes, env)


def _local_exec(repo: str, command: str, timeout: int, max_bytes: int | None,
                env: dict[str, str] | None) -> ExecResult:
    from harness.tools._compat import scrubbed_env

    merged = {**scrubbed_env(), **(env or {})}
    cap = max(1, int(max_bytes or DEFAULT_MAX_OUTPUT_BYTES))
    try:
        out, exit_code, truncated = run_bounded(
            ["/bin/bash", "-c", _env_exports(env) + command],
            timeout=float(timeout), byte_cap=cap * _BYTE_CAP_FACTOR,
            env=merged,
            # cwd=repo: relative targets resolve against the repo, matching
            # the in-container exec workdir (-w <repo>). No in-container
            # `timeout` wrapper here, so the client deadline IS the cap.
            cwd=repo)
    except subprocess.TimeoutExpired:
        return ExecResult(error=f"command timed out after {timeout}s",
                          exit_code=124)
    return ExecResult(out=out, exit_code=exit_code, truncated=truncated)


def _docker_exec(repo: str, command: str, timeout: int, max_bytes: int | None,
                 env: dict[str, str] | None) -> ExecResult:
    run = _run_for(repo)
    try:
        err = run.ensure_started()
    except FileNotFoundError:
        run.mark_dead()
        return ExecResult(error=f"refused: {run.cli_bin!r} not found on PATH; "
                                "system lane needs a container runtime")
    except subprocess.TimeoutExpired:
        return ExecResult(error=f"sandbox create timed out after "
                                f"{int(run.CREATE_TIMEOUT)}s")
    if err:
        return ExecResult(error=err)

    command = (_env_exports({**_SYSTEM_ENV, **(env or {})})
               + 'mkdir -p "$HOME" "$TMPDIR" 2>/dev/null; ' + command)
    marker = f"{_SYSTEM_AGENT_ID}-{uuid.uuid4().hex[:8]}"
    try:
        out, exit_code, truncated = run.exec(
            agent_id=_SYSTEM_AGENT_ID, command=command, marker=marker,
            timeout=max(1, int(timeout)),
            max_output_bytes=max(1, int(max_bytes or DEFAULT_MAX_OUTPUT_BYTES)))
    except subprocess.TimeoutExpired:
        # A hung client: kill ONLY this exec's tagged shell.
        try:
            run.kill_exec(marker)
        except Exception:
            pass
        return ExecResult(error=f"command timed out after {timeout}s "
                                "(exec client hang)", exit_code=124)
    except FileNotFoundError:
        run.mark_dead()
        return ExecResult(error=f"refused: {run.cli_bin!r} not found on PATH; "
                                "system lane needs a container runtime")
    return ExecResult(out=out, exit_code=exit_code, truncated=truncated)


# --------------------------------------------------------------------------
# Capture composition: argv → probe → run → separated stdout/stderr/rc.
# --------------------------------------------------------------------------

def _quote_argv(argv) -> str:
    return " ".join(shlex.quote(str(a)) for a in argv)


def system_shell(argv, *, repo: str | None = None, timeout: int = 300,
                 max_bytes: int | None = None,
                 env: dict[str, str] | None = None) -> ShellResult:
    """Run argv inside the lane with stdout/stderr/rc separated; never raises.

    ``repo`` keys the run sandbox (docker lane) and is the subprocess cwd
    (local lane); default is the scan's ``TARGET_REPO``. A ``command -v``
    probe up front catches an absent binary (exit 91) and folds it into
    ``error`` as ``binary not found: <argv0>`` — the same skip-if-absent
    semantics the host ``shutil.which`` path provided. Not for agent input:
    argv strings are fixed harness literals, quoted defensively.
    """
    if not _MISSING_OK.match(str(argv[0])):
        return ShellResult(error=f"refused: unusable argv[0]: {argv[0]!r}")
    if repo is None:
        from harness.paths import canonical_repo

        repo = str(canonical_repo(os.environ.get("TARGET_REPO") or "."))

    tag = uuid.uuid4().hex[:12]
    outcap = max(1, int(max_bytes or DEFAULT_MAX_OUTPUT_BYTES))
    # exec cap is the backstop over stdout cap + stderr slack; the composite
    # cost (stdout cap + separately-killed stderr + rc) must fit.
    cap = outcap + (1 << 16)

    command = (
        f'command -v {_quote_argv([argv[0]])} >/dev/null 2>&1 '
        f'|| exit 91; '
        f'd=$TMPDIR/.sys-run-{tag} && mkdir -p "$d"; '
        f'{{ {_quote_argv(argv)}; }} >"$d/out" 2>"$d/err"; rc=$?; '
        f'printf %s "$rc" >"$d/rc"; '
        f'cat "$d/out"; printf "{tag}|0|"; cat "$d/err"; '
        f'printf "{tag}|1|"; cat "$d/rc"; rm -rf "$d" 2>/dev/null'
    )
    res = system_execute(repo, command, timeout=timeout, max_bytes=cap, env=env)
    if str(res.exit_code) == "91" and f"{tag}|" not in res.out:
        # The probe refused before the composition ran (binary absent here).
        return ShellResult(error=f"binary not found: {argv[0]}")
    if res.error:
        if res.error.startswith("command timed out"):
            return ShellResult(error="timeout")
        return ShellResult(stdout=res.out, truncated=res.truncated,
                           error=res.error)

    parts = res.out.split(f"{tag}|0|", 1)
    if len(parts) != 2:
        # Either the backstop cap ate the composition (stdout alone exceeded
        # it) or the in-container timeout killed the shell mid-run (exit 124).
        if res.exit_code == 124:
            return ShellResult(error="timeout")
        return ShellResult(stdout=res.out, truncated=True,
                           error="system exec output cap exceeded")
    stdout, rest = parts
    tail = rest.split(f"{tag}|1|", 1)
    stderr = tail[0] if len(tail) == 2 else rest
    rc = tail[1].strip() if len(tail) == 2 else ""
    try:
        exit_code = int(rc) if rc else None
    except ValueError:
        exit_code = None
    if res.exit_code == 124 and exit_code in (None, 124):
        return ShellResult(error="timeout")
    return ShellResult(exit_code=exit_code, stdout=stdout,
                       stderr=stderr, truncated=res.truncated)

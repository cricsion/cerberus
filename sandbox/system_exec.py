"""System-lane execution: harness-owned commands run in the repo sandbox.

The deterministic pipeline stages (SAST scanners, the codegraph CLI, the
compute runner behind the graph tools and partitioning) execute INSIDE the
per-repo run container on the shared exec channel — one container per repo,
zero additional containers; the host runs only the orchestrator and its store
reads. This module is that single seam.

It rides the SAME exec channel, exec markers and pkill hygiene as agent
shells (the channel's ``exec_core`` path, via ``RunSandbox.exec_streams``)
with a reserved ``system`` agent id, and mirrors
``SandboxShellBackend.execute``'s error mapping: a missing client is an infra
error, a client hang kills ONLY this exec's tagged shell via pkill (the
channel's watchdog), and the deadline surfaces as exit 124. It deliberately
skips the backend's ``command_timeout`` clamp so a 600 s index build is
bounded by its own timeout argument, not agent policy.

The environment crosses as an ``export`` prefix INSIDE the command (docker
``-e`` equivalents): inline ``K=V cmd`` assignment would apply to one simple
command only, while these stages run multi-statement shell strings. System
scratch dirs live under ``/work/_system`` / ``/tmp/_system`` — outside the
``agent-*`` reset glob, so caches survive phase cleanup.

``SANDBOX_BACKEND=local`` keeps a host-subprocess lane (cwd=repo, scrubbed
env) so dev scans without docker behave exactly as before. Both lanes capture
stdout/stderr separately (demuxed) — the scanner seam (:func:`system_shell`,
cerberus/tools/sast.py) parses stdout JSON, so stderr noise must never touch
that stream; there is no merged shape.
"""
from __future__ import annotations

import logging
import os
import re
import shlex
import subprocess
import uuid
from dataclasses import dataclass, replace

from .cli_utils import BYTE_CAP_FACTOR, run_bounded_streams
from .docker_channel import ExecResult
from .run_base import DEFAULT_MAX_OUTPUT_BYTES

__all__ = ["ShellResult", "sandbox_lane", "system_execute", "system_shell"]

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

# Probe-failure marker: echoed to stderr by the probe's exit branch, so a
# tool that itself exits 91 is distinguishable from a binary that is absent.
_PROBE_ABSENT = "cerberus-sys-absent"


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
    from cerberus.config import get_config

    try:
        cfg = get_config()
    except Exception as cfg_err:
        _logger.debug("sandbox lane degraded to local: config load failed: "
                      "%s: %s", type(cfg_err).__name__, cfg_err)
        return "local"
    return str(cfg["sandbox"]["backend"])


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
    from cerberus.config import get_config

    from . import _docker_settings
    from .docker_backend import get_run_sandbox

    # The SAME cfg the agent lane resolves with, so the registry's one
    # container per repo carries one settings set (image, network, limits)
    # whichever lane constructs it first.
    return get_run_sandbox(repo, _docker_settings(get_config(), repo))


def system_execute(repo: str, command: str, *, timeout: int = 300,
                   max_bytes: int | None = None,
                   env: dict[str, str] | None = None) -> ExecResult:
    """Run one shell command in the configured lane; never raises.

    Local lane: ``/bin/bash -c`` as a host subprocess with cwd=repo and a
    scrubbed environment. Docker lane: the per-repo run container's exec
    channel, with system scratch exports prepended. Output is demuxed:
    ``stdout`` carries stdout, ``stderr`` carries stderr.
    """
    if sandbox_lane() != "docker":
        return _local_exec(repo, command, timeout, max_bytes, env)
    return _docker_exec(repo, command, timeout, max_bytes, env)


def _local_exec(repo: str, command: str, timeout: int, max_bytes: int | None,
                env: dict[str, str] | None) -> ExecResult:
    from cerberus.tools._compat import scrubbed_env

    merged = {**scrubbed_env(), **(env or {})}
    cap = max(1, int(max_bytes or DEFAULT_MAX_OUTPUT_BYTES)) * BYTE_CAP_FACTOR
    argv = ["/bin/bash", "-c", _env_exports(env) + command]
    try:
        stdout, stderr, exit_code, truncated = run_bounded_streams(
            argv, timeout=float(timeout), byte_cap=cap, env=merged,
            # cwd=repo: relative targets resolve against the repo, matching
            # the in-container exec workdir (-w <repo>). No client-side
            # deadline slack: run_bounded_streams IS the deadline.
            cwd=repo)
    except subprocess.TimeoutExpired:
        return ExecResult(error=f"command timed out after {timeout}s",
                          exit_code=124)
    return ExecResult(stdout=stdout, stderr=stderr, exit_code=exit_code,
                      truncated=truncated)


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
    # exec_core never raises for infra; the hang arrives as ``error`` with
    # the partial tail it kept.
    res = run.exec_streams(
        agent_id=_SYSTEM_AGENT_ID, command=command, marker=marker,
        timeout=max(1, int(timeout)),
        max_output_bytes=max(1, int(max_bytes or DEFAULT_MAX_OUTPUT_BYTES)))
    if res.error.startswith("command timed out after"):
        return replace(res, exit_code=124, truncated=True)
    return res


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
    (local lane); default is the scan's ``TARGET_REPO``. Both lanes capture
    the streams separately — docker via the exec channel's demuxed frames,
    local via :func:`run_bounded_streams` — so scanner JSON on stdout is
    never polluted by stderr noise, and the rc comes from the runner (the
    file-and-marker composition the merged stream required is gone). A
    ``command -v`` probe up front catches an absent binary (exit 91 with
    the probe marker on stderr) and folds it into ``error`` as ``binary
    not found: <argv0>`` — the same skip-if-absent semantics the host
    ``shutil.which`` path provided. Not for agent input: argv strings are
    fixed harness literals, quoted defensively.
    """
    if not _MISSING_OK.match(str(argv[0])):
        return ShellResult(error=f"refused: unusable argv[0]: {argv[0]!r}")
    if repo is None:
        from cerberus.paths import canonical_repo

        repo = str(canonical_repo(os.environ.get("TARGET_REPO") or "."))

    outcap = max(1, int(max_bytes or DEFAULT_MAX_OUTPUT_BYTES))
    # exec cap is the backstop over stdout cap + stderr slack; the composite
    # cost (stdout cap + separately-captured stderr + rc) must fit.
    cap = outcap + (1 << 16)

    command = (f'command -v {_quote_argv([argv[0]])} >/dev/null 2>&1 '
               f'|| {{ echo {_PROBE_ABSENT} >&2; exit 91; }}; '
               f'{{ {_quote_argv(argv)}; }}')
    res = system_execute(repo, command, timeout=timeout, max_bytes=cap,
                         env=env)
    if res.error.startswith("command timed out"):
        return ShellResult(error="timeout")
    if res.error:
        return ShellResult(stdout=res.stdout, stderr=res.stderr,
                           truncated=res.truncated, error=res.error)
    if res.exit_code == 91 and _PROBE_ABSENT in (res.stderr or ""):
        # The probe refused before the composition ran (binary absent here).
        return ShellResult(error=f"binary not found: {argv[0]}")
    return ShellResult(exit_code=res.exit_code, stdout=res.stdout,
                       stderr=res.stderr, truncated=res.truncated)

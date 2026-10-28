"""System-lane execution: harness-owned commands run in the repo sandbox.

The deterministic pipeline stages (SAST scanners, the codegraph CLI, the
compute runner behind the graph tools and partitioning) used to fork host
subprocesses that read or parse the target tree. They now execute INSIDE the
per-repo run container on the shared exec channel (D1: one container per repo,
zero additional containers; the host runs only the orchestrator and its store
reads). This module is that single seam.

It rides the SAME exec channel, exec markers and pkill hygiene as agent shells
with a reserved ``system`` marker prefix (``system-<hex8>``), and mirrors the
backend's hang mapping: an in-container timeout surfaces as the channel's
``command timed out after Ns (exec client hang)`` result with exit 124 (the
CLI-era synthetic TimeoutExpired was practice for this and is gone). The
stream separation is the channel's NATIVE demux — stdout/stderr/rc arrive
separated by construction, no tempdir re-split, no sentinel tags. The system
environment (``_SYSTEM_ENV`` scratch, under ``/work/_system`` /
``/tmp/_system`` — outside the ``agent-*`` reset glob) crosses as exec
``environment`` instead of an ``export`` prefix; caller keys are still
validated exportable-style. It deliberately skips the backend's
``command_timeout`` clamp so a 600 s index build is bounded by its own
timeout argument, not agent policy.

``SANDBOX_BACKEND=local`` keeps a host-subprocess lane (cwd=repo, scrubbed
env, split pipes) so dev scans without docker behave exactly as before.
"""
from __future__ import annotations

import logging
import os
import re
import shlex
import subprocess
import uuid
from dataclasses import dataclass

from .cli_utils import BYTE_CAP_FACTOR, run_bounded_streams
from .docker_channel import ExecResult
from .run_base import DEFAULT_MAX_OUTPUT_BYTES

__all__ = ["ShellResult", "sandbox_lane", "system_execute", "system_shell"]

_logger = logging.getLogger(__name__)

_SYSTEM_AGENT_ID = "system"
_ENV_KEY_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# System scratch: a stable HOME for CLI config/cache, outside the
# agent-<id>-prefixed dirs that reset_agent_scratch wipes between phases.
# Applied natively as the exec environment on the docker lane (the local lane
# keeps the host environment — unchanged).
_SYSTEM_ENV = {
    "HOME": "/work/_system",
    "TMPDIR": "/tmp/_system",
    "PYTHONPYCACHEPREFIX": "/work/_system/.pyc",
}

# Sentinel exit for the ``command -v`` probe: absent binary in the lane.
_MISSING_OK = re.compile(r"^[A-Za-z0-9_.+/-]+$")


@dataclass(frozen=True)
class ShellResult:
    """``system_shell`` result: stdout/stderr/rc separated by the exec
    channel's native demux (docker lane) or Popen pipes (local lane)."""
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


def _first_line(e: Exception) -> str:
    text = str(e).strip() or repr(e)
    return text.splitlines()[0][:200]


def _validate_env_keys(env: dict[str, str] | None) -> None:
    """Caller env crosses as exec ``environment`` on the docker lane — its
    keys must be exportable-style (the CLI-era ``export`` prefix's contract,
    kept as this one boundary check)."""
    for key in env or {}:
        if not _ENV_KEY_OK.match(str(key)):
            raise ValueError(f"system env key not exportable: {key!r}")


def system_execute(repo: str, command: str, *, timeout: int = 300,
                   max_bytes: int | None = None,
                   env: dict[str, str] | None = None) -> ExecResult:
    """INTERNAL exec primitive — every system-lane consumer funnels through
    :func:`system_shell`; never raises (infra is an ``ExecResult.error``)."""
    _validate_env_keys(env)
    if sandbox_lane() != "docker":
        return _local_exec(repo, command, timeout, max_bytes, env)
    return _docker_exec(repo, command, timeout, max_bytes, env)


def _local_exec(repo: str, command: str, timeout: int, max_bytes: int | None,
                env: dict[str, str] | None) -> ExecResult:
    from harness.tools._compat import scrubbed_env

    merged = {**scrubbed_env(), **(env or {})}
    cap = max(1, int(max_bytes or DEFAULT_MAX_OUTPUT_BYTES)) * BYTE_CAP_FACTOR
    try:
        out, err, exit_code, truncated = run_bounded_streams(
            ["/bin/bash", "-c", command],
            timeout=float(timeout), byte_cap=cap, env=merged,
            # cwd=repo: relative targets resolve against the repo, matching
            # the in-container exec workdir (-w <repo>).
            cwd=repo)
    except subprocess.TimeoutExpired:
        # The host deadline is the only local-lane cap; same timeout shape,
        # without an exec client to hang.
        return ExecResult(error=f"command timed out after {timeout}s",
                          exit_code=124)
    return ExecResult(stdout=out, stderr=err, exit_code=exit_code,
                      truncated=truncated)


def _docker_exec(repo: str, command: str, timeout: int, max_bytes: int | None,
                 env: dict[str, str] | None) -> ExecResult:
    try:
        run = _run_for(repo)
    except Exception as e:
        # A garbage sandbox setting failing the resolve (run construction)
        # degrades here exactly like the agent lane does.
        return ExecResult(
            error=f"system lane needs a container runtime: {_first_line(e)}")
    try:
        err = run.ensure_started()
    except Exception as e:
        return ExecResult(
            error=f"system lane needs a container runtime: {_first_line(e)}")
    if err:
        return ExecResult(error=err)
    marker = f"{_SYSTEM_AGENT_ID}-{uuid.uuid4().hex[:8]}"
    # The exec env IS the system env (native, no shell exports): system
    # scratch first, caller overrides last.
    exec_env = list({**_SYSTEM_ENV, **(env or {})}.items())
    return run.exec(command=command, marker=marker,
                    timeout=max(1, int(timeout)),
                    max_output_bytes=max(1, int(max_bytes
                                                or DEFAULT_MAX_OUTPUT_BYTES)),
                    env=exec_env)


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
    probe up front exits 91 when the binary is absent, folding into
    ``error`` as ``binary not found: <argv0>`` — the same skip-if-absent
    semantics the host ``shutil.which`` path provided. Not for agent input:
    argv strings are fixed harness literals, quoted defensively.
    """
    if not _MISSING_OK.match(str(argv[0])):
        return ShellResult(error=f"refused: unusable argv[0]: {argv[0]!r}")
    if repo is None:
        from harness.paths import canonical_repo

        repo = str(canonical_repo(os.environ.get("TARGET_REPO") or "."))

    outcap = max(1, int(max_bytes or DEFAULT_MAX_OUTPUT_BYTES))
    # exec cap is the backstop over stdout cap + stderr slack (one combined
    # bytes budget through the channel; per-stream trimming is the caller's).
    cap = outcap + (1 << 16)

    command = (f'command -v {_quote_argv([argv[0]])} >/dev/null 2>&1 '
               f'|| exit 91; {_quote_argv(argv)}')
    res = system_execute(repo, command, timeout=timeout, max_bytes=cap, env=env)
    if res.error.startswith("command timed out"):
        return ShellResult(error="timeout")
    if res.error:
        return ShellResult(stdout=res.stdout, stderr=res.stderr,
                           truncated=res.truncated, error=res.error)
    if res.exit_code == 91:
        # The probe refused before the command ran (binary absent here).
        return ShellResult(error=f"binary not found: {argv[0]}")
    return ShellResult(exit_code=res.exit_code, stdout=res.stdout,
                       stderr=res.stderr, truncated=res.truncated)

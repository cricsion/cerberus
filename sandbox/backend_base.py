"""The agent-facing shell backend: file tools plus one shell tool.

A backend instance lives for ONE agent: its file tools are the inherited
read-only, repo-confined :class:`RepoLocalBackend`, and its single ``execute``
tool runs a command inside the run's ONE shared sandbox with the repo mounted
read-only.

What is shared here (and was written twice, once per backend, before):

* the session contract -- ``close()`` ends this agent's session only; the
  run's sandbox is removed by its registry's ``shutdown()``, never by an
  agent's teardown;
* the ``execute`` contract -- strip, refuse when closed, deny-list pre-filter,
  clamp the timeout, start on demand, run bounded, truncate to the allowance,
  and never raise: the model gets a result object it can act on;
* the two recovery hooks that genuinely differ per CLI: a vanished sandbox
  (sbx recreates and retries once) and a corpse that holds the name (docker
  removes it), plus the "your binary is not on PATH" advice.

The command deny-list is a cheap prefilter, not the boundary: the sandbox is
the boundary.
"""
from __future__ import annotations

import subprocess
import threading
import uuid
from typing import Callable

from deepagents.backends.protocol import ExecuteResponse, SandboxBackendProtocol

from . import cli_utils, command_policy
from .local_backend import RepoLocalBackend
from .run_base import RunSandboxBase


class SandboxShellBackend(SandboxBackendProtocol, RepoLocalBackend):
    """Base for the sandbox-backed (shell-carrying) repo backends.

    Because the class also inherits :class:`SandboxBackendProtocol`,
    deepagents detects it per model call and gives the agent the ``execute``
    tool (and only then) -- so a local-mode run still has no shell at all.

    ``network`` is the posture the prompts describe to the model. It means
    different things per backend (a docker mode we set, versus the operator's
    machine policy for sbx), so it is data the subclass supplies, never a
    behaviour override.
    """

    # How a client-side hang is reported to the model ("exec client hang").
    HANG_NOTE = "exec client hang"

    def __init__(self, *, repo_path: str | Path, run_factory: Callable[[], RunSandboxBase],
                 run: RunSandboxBase | None = None, agent_id: str | None = None,
                 denied_globs: tuple[str, ...] | list[str] | None = None,
                 command_timeout: int = 120, max_output_bytes: int = 200_000,
                 rules_dir: str = "/opt/scan-rules/harness",
                 skills_dir: str = "/opt/harness-skills",
                 network: str = "") -> None:
        super().__init__(repo_path=repo_path, denied_globs=denied_globs)
        self.agent_id = cli_utils.safe_slug(agent_id or uuid.uuid4().hex[:12])
        self.command_timeout = max(1, int(command_timeout))
        self.max_output_bytes = max(0, int(max_output_bytes))
        # Where the image bakes the harness's custom rules; the hunter
        # prompt points the model here (offline rule scans).
        self.rules_dir = str(rules_dir or "/opt/scan-rules/harness")
        # Where the image bakes the scanner skill docs. Read via `execute`
        # (`cat`), never the file tools: those are repo-confined, so the
        # skills middleware path cannot serve them from inside the sandbox.
        self.skills_dir = str(skills_dir or "/opt/harness-skills")
        # Shared run sandbox unless this backend was built standalone.
        # `run_factory` is only called when there is no shared run, which is
        # what keeps the run's settings where they belong: in the backend
        # that validates them, not in this base.
        self._owns_run = run is None
        self._run = run or run_factory()
        self._name = self._run.name
        self._network = str(network or "")
        self._lock = threading.Lock()
        self._closed = False

    # -- identity ------------------------------------------------------------

    @property
    def id(self) -> str:
        """Live backend identity (the shared sandbox's current run name).

        The run registry can rename a shared sandbox after a failed exec
        recovery, so this must reflect the live name rather than the value
        cached at construction.
        """
        return self._run.name

    @property
    def network(self) -> str:
        """Egress posture as prompts describe it."""
        return self._network

    # -- command deny-list prefilter ----------------------------------------

    def _policy_error(self, command: str) -> str | None:
        """Fail fast on obvious host/runtime tools. Not the boundary."""
        return command_policy.policy_error(command)

    # -- agent session lifecycle ---------------------------------------------

    def close(self) -> None:
        """End this agent's session. Never removes the shared run sandbox
        (that is the registry's ``shutdown()`` at scan teardown), unless the
        backend was built standalone, without a shared run sandbox.
        Idempotent, never raises.
        """
        with self._lock:
            already = self._closed
            self._closed = True
        if already:
            return
        if self._owns_run:
            self._run.close()

    def __del__(self) -> None:  # best-effort reaping on interpreter GC
        try:
            if self._owns_run and self._run.started:
                self._run.close()
        except Exception:
            pass

    # -- shell ---------------------------------------------------------------

    def execute(self, command: str, *, timeout: int | None = None) -> ExecuteResponse:
        """Run one shell command inside the run's shared sandbox.

        Returns a result object (never raises for command failure or
        policy denial) so the model can recover and continue.
        """
        command = (command or "").strip()
        if not command:
            return ExecuteResponse(output="(empty command)", exit_code=126)
        if self._closed:
            return ExecuteResponse(
                output="refused: this agent's sandbox is closed", exit_code=126)
        denial = self._policy_error(command)
        if denial:
            return ExecuteResponse(output=denial, exit_code=126)
        t = (self.command_timeout if timeout is None
             else max(1, min(int(timeout), self.command_timeout * 4)))

        err = self._run.ensure_started()
        if err:
            return ExecuteResponse(output=err, exit_code=None)

        # Tags this exec's command line so a hung client can be cleaned up
        # without touching a concurrent agent's shell.
        marker = f"{self.agent_id}-{uuid.uuid4().hex[:8]}"
        try:
            result = self._run.exec(
                agent_id=self.agent_id, command=command,
                marker=marker, timeout=t,
                max_output_bytes=self.max_output_bytes)
        except subprocess.TimeoutExpired:
            # The in-sandbox `timeout` fires at t; this is the CLI client
            # itself hanging. Kill ONLY this exec's tagged shell -- the
            # sandbox is shared, so a blanket pkill would take down every
            # other agent's running command -- then report.
            try:
                cli_utils.run_cli(self._run.pkill_argv(self._run.name, marker),
                                  timeout=30)
            except Exception:
                pass
            return ExecuteResponse(
                output=f"command timed out after {t}s ({self.HANG_NOTE})",
                exit_code=124)
        except FileNotFoundError:
            # The binary disappeared: mark the sandbox for a restart on the
            # next call and tell the model how to fix its environment.
            self._run.mark_dead()
            return ExecuteResponse(output=self._missing_binary_message(),
                                   exit_code=None)
        out, exit_code, truncated = self._truncate(result)
        recovered = self._recover_sandbox(command=command, marker=marker,
                                          t=t, out=out, exit_code=exit_code,
                                          truncated=truncated)
        if recovered is not None:
            out, exit_code, truncated = recovered
        return ExecuteResponse(output=out, exit_code=exit_code,
                               truncated=truncated)

    # aexecute inherits SandboxBackendProtocol's sync-delegating default.

    def _truncate(self, result: tuple[str, int | None, bool]
                  ) -> tuple[str, int | None, bool]:
        """Clamp command output to the agent's allowance, saying how much.
        """
        out, exit_code, truncated = result
        if self.max_output_bytes and len(out) > self.max_output_bytes:
            out = out[: self.max_output_bytes] + (
                f"\n... +{len(out) - self.max_output_bytes} more bytes "
                f"(total {len(out)})")
            truncated = True
        return out, exit_code, truncated

    # -- per-CLI hooks -------------------------------------------------------

    def _missing_binary_message(self) -> str:
        """Agent-visible advice when the CLI binary is not on PATH."""
        return (f"refused: {self._run.cli_bin!r} not found on PATH")

    def _recover_sandbox(self, *, command: str, marker: str, t: int,
                         out: str, exit_code: int | None, truncated: bool
                         ) -> tuple[str, int | None, bool] | None:
        """React to output that says the sandbox itself went away.

        Returns the (possibly re-run) result to report instead, or None to
        keep the original unchanged. Runs only after truncation, so the
        result handed back here is already within the output allowance.
        """
        return None

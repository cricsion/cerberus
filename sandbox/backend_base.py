from __future__ import annotations

import threading
import uuid
from pathlib import Path
from typing import Callable

from deepagents.backends.protocol import ExecuteResponse, SandboxBackendProtocol

from .cli_utils import safe_slug
from .docker_channel import ExecResult, HANG_NOTE
from .run_base import (DEFAULT_COMMAND_TIMEOUT, DEFAULT_MAX_OUTPUT_BYTES,
                       DEFAULT_RULES_DIR, agent_env)


def exec_merge(res: ExecResult) -> str:
    """Merged exec output exactly as every agent has always received it:
    stdout, stderr on the next line, infra error last (today's, byte-identical
    composition)."""
    out = res.stdout + (f"\n{res.stderr}" if res.stderr else "")
    if res.error:
        out = f"{out}\n{res.error}" if out else res.error
    return out


class SandboxShellBackend(SandboxBackendProtocol):
    """Run-backed shell lane for a :class:`BaseSandbox` adapter.

    Owns a run sandbox (or shares one from the run registry), implements the
    protocol's ``execute`` primitive against that run's exec channel, and
    carries the per-agent bookkeeping (agent id, timeouts, byte caps, rules
    dir). The filesystem protocol surface comes from the ``BaseSandbox`` base
    beside it — with same-path mounts those FS ops run inside the container,
    not in this process. Repo-confined HOST filesystem reads remain the job
    of ``RepoLocalBackend`` (SANDBOX_BACKEND=local); this class no longer
    inherits it.
    """

    # The hang marker the (shared) exec channel stamps onto a timed-out
    # command ("command timed out after Ns (exec client hang)").
    HANG_NOTE = HANG_NOTE

    def __init__(self, *, repo_path: str | Path,
                 run_factory: Callable[[], object],
                 run: object | None = None, agent_id: str | None = None,
                 command_timeout: int = DEFAULT_COMMAND_TIMEOUT,
                 max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
                 rules_dir: str = DEFAULT_RULES_DIR,
                 network: str = "") -> None:
        self.repo_path = Path(repo_path).resolve()
        self.agent_id = safe_slug(agent_id or uuid.uuid4().hex[:12])
        self.command_timeout = max(1, int(command_timeout))
        self.max_output_bytes = max(0, int(max_output_bytes))
        self.rules_dir = str(rules_dir or DEFAULT_RULES_DIR)
        # `run_factory` is only called when there is no shared run, keeping the run's validated settings in the backend that checked them.
        self._owns_run = run is None
        self._run = run if run is not None else run_factory()
        self._name = self._run.name
        self._network = str(network or "")
        self._lock = threading.Lock()
        self._closed = False
        # Cooperative MRO: the BaseSandbox base beside this mixin (and ABC
        # under it) takes no arguments.
        super().__init__()

    @property
    def id(self) -> str:
        return self._run.name

    @property
    def network(self) -> str:
        return self._network

    def close(self) -> None:
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

    def execute(self, command: str, *, timeout: int | None = None
                ) -> ExecuteResponse:
        command = (command or "").strip()
        if not command:
            return ExecuteResponse(output="(empty command)", exit_code=126)
        if self._closed:
            return ExecuteResponse(
                output="refused: this agent's sandbox is closed", exit_code=126)
        t = (self.command_timeout if timeout is None
             else max(1, min(int(timeout), self.command_timeout * 4)))

        # Start failures are tool errors at this ONE boundary: the run's
        # create path funnels every refusal into a string, so a raise from
        # here could only be a harness bug and must surface.
        err = self._run.ensure_started()
        if err:
            return ExecuteResponse(output=err, exit_code=None)

        # Tags this exec's command line so a hung command can be killed without touching a concurrent agent's shell.
        marker = f"{self.agent_id}-{uuid.uuid4().hex[:8]}"
        res = self._run.exec(command=command, marker=marker, timeout=t,
                             max_output_bytes=self.max_output_bytes,
                             env=agent_env(self.agent_id))
        if res.error.startswith("command timed out"):
            # The bound fired (in-container timeout, or the channel's own
            # never-EOF backstop): the message already carries HANG_NOTE.
            return ExecuteResponse(output=res.error, exit_code=124)
        out = exec_merge(res)
        exit_code, truncated = res.exit_code, res.truncated
        if self.max_output_bytes and len(out) > self.max_output_bytes:
            out = out[: self.max_output_bytes] + (
                f"\n... +{len(out) - self.max_output_bytes} more bytes "
                f"(total {len(out)})")
            truncated = True
        recovered = self._recover_sandbox(res=res, out=out,
                                          exit_code=exit_code,
                                          truncated=truncated)
        if recovered is not None:
            out, exit_code, truncated = recovered
        return ExecuteResponse(output=out, exit_code=exit_code,
                               truncated=truncated)

    def _recover_sandbox(self, *, res: ExecResult, out: str,
                         exit_code: int | None, truncated: bool
                         ) -> tuple[str, int | None, bool] | None:
        return None

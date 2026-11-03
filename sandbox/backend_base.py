from __future__ import annotations

import subprocess
import threading
import uuid
from collections.abc import Callable
from pathlib import Path

from deepagents.backends.protocol import ExecuteResponse, SandboxBackendProtocol

from .cli_utils import safe_slug
from .run_base import (
    DEFAULT_COMMAND_TIMEOUT,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_RULES_DIR,
    RunSandboxBase,
)

# The hang response's note, shared by every lane that reports a hung client.
HANG_NOTE = "exec client hang"

class SandboxShellBackend(SandboxBackendProtocol):
    """Run-backed shell lane for a :class:`BaseSandbox` adapter.

    Owns a :class:`RunSandboxBase` (or shares one from the run registry),
    implements the protocol's ``execute`` primitive against that run's exec
    channel, and carries the per-agent bookkeeping (agent id, timeouts, byte
    caps, rules dir). The filesystem protocol surface comes from the
    ``BaseSandbox`` base beside it — with same-path mounts those FS ops run
    inside the container, not in this process. Repo-confined HOST filesystem
    reads remain the job of ``RepoLocalBackend`` (SANDBOX_BACKEND=local); this
    class does not inherit it.
    """

    HANG_NOTE = HANG_NOTE

    def __init__(self, *, repo_path: str | Path, run_factory: Callable[[], RunSandboxBase],
                 run: RunSandboxBase | None = None, agent_id: str | None = None,
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
        self._run = run or run_factory()
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

    def execute(self, command: str, *, timeout: int | None = None) -> ExecuteResponse:
        command = (command or "").strip()
        if not command:
            return ExecuteResponse(output="(empty command)", exit_code=126)
        if self._closed:
            return ExecuteResponse(
                output="refused: this agent's sandbox is closed", exit_code=126)
        t = (min(self.command_timeout, 600) if timeout is None
             else max(1, min(int(timeout), 600)))

        # Start failures are tool errors at this ONE boundary: a missing CLI
        # client and a timed-out create both reach the agent as an actionable
        # response, keeping backend _start_locked implementations catch-free.
        try:
            err = self._run.ensure_started()
        except FileNotFoundError:
            self._run.mark_dead()
            return ExecuteResponse(output=self._missing_binary_message(),
                                   exit_code=None)
        except subprocess.TimeoutExpired:
            return ExecuteResponse(
                output=(f"sandbox create timed out after "
                        f"{int(self._run.CREATE_TIMEOUT)}s"), exit_code=None)
        if err:
            return ExecuteResponse(output=err, exit_code=None)

        # Tags this exec's command line so a hung client can be killed without touching a concurrent agent's shell.
        marker = f"{self.agent_id}-{uuid.uuid4().hex[:8]}"
        result = self._run.exec(
            agent_id=self.agent_id, command=command,
            marker=marker, timeout=t,
            max_output_bytes=self.max_output_bytes)
        out, exit_code, truncated = self._truncate(result)
        recovered = self._recover_sandbox(command=command, marker=marker,
                                          t=t, out=out, exit_code=exit_code,
                                          truncated=truncated)
        if recovered is not None:
            out, exit_code, truncated = recovered
        return ExecuteResponse(output=out, exit_code=exit_code,
                               truncated=truncated)

    def _truncate(self, result: tuple[str, int | None, bool]
                  ) -> tuple[str, int | None, bool]:
        out, exit_code, truncated = result
        if self.max_output_bytes and len(out) > self.max_output_bytes:
            out = out[: self.max_output_bytes] + (
                f"\n... +{len(out) - self.max_output_bytes} more bytes "
                f"(total {len(out)})")
            truncated = True
        return out, exit_code, truncated

    def _missing_binary_message(self) -> str:
        return (f"refused: {self._run.cli_bin!r} not found on PATH")

    def _recover_sandbox(self, *, command: str, marker: str, t: int,
                         out: str, exit_code: int | None, truncated: bool
                         ) -> tuple[str, int | None, bool] | None:
        return None

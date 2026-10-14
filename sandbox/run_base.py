"""The ONE sandbox a scan run executes in: shared state machine + registry.

docker and sbx differ in WHICH CLI is invoked -- ``docker run`` vs
``sbx create shell``, ``docker exec`` vs ``sbx exec`` -- and in almost
nothing else, so everything else lives here: create-once-then-reuse, the
per-agent environment, the phase-boundary scratch reset, mark-dead and
recreate, removal, and the per-run registry. A backend supplies only argv
builders, which keeps the two backends honest about one rule: a bug fixed
in the lifecycle is fixed for both.

A subclass supplies (and nothing else):

* ``cli_bin`` / ``cli_label`` -- the binary and how it is named in messages
* ``_workdir_args()`` -- how an exec names the working dir (``-w`` vs
  ``--workdir``); the whole exec argv head derives from this
* ``_start_locked()`` -- the create procedure and its error mapping
* ``destroy_argv()`` / ``DESTROY_TIMEOUT`` -- how the sandbox is removed

Contract, relied on by :mod:`harness.sandbox.backend_base` and by the tests:
``exec``/``reset_agent_scratch`` return the same tuple shape and never raise
for a failed command; ``close`` is idempotent and never raises;
``ensure_started`` returns an error STRING or None, never raises.
"""
from __future__ import annotations

import atexit
import re
import signal
import sys
import threading
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Iterable

from . import cli_utils
from .validation import validate_image

__all__ = ["RunSandboxBase", "RunRegistry", "install_crash_hooks",
           "AGENT_SCRATCH_PREFIX", "RESET_COMMAND", "DEFAULT_IMAGE",
           "agent_env"]

# The pinned scan toolchain image: one image, both runtimes. Docker runs it
# directly; sbx loads it into its template store once (`sbx template load`).
DEFAULT_IMAGE = "cyber-sandbox:local"

# Every per-agent scratch dir under the sandbox's writable scratch carries
# this prefix, and the phase-boundary reset removes exactly these -- never the
# shared package caches (/work/_shared), which hold wheels, not reasoning.
# Keeping the prefix and the reset glob in ONE module is what stops them from
# drifting apart.
AGENT_SCRATCH_PREFIX = "agent-"

# Shared package-manager download caches: agents avoid duplicate downloads,
# at the cost of sharing writable cache contents. They survive phase cleanup.
SHARED_CACHE_DIRS = ("/work/_shared/pip", "/work/_shared/npm")

# Best-effort phase cleanup, run inside the sandbox. It removes only these
# conventional scratch paths; it is not process or agent isolation.
RESET_COMMAND = "rm -rf /work/agent-* /tmp/agent-* 2>/dev/null; exit 0"

# Exec output is read through run_bounded, whose byte cap is the command's
# own output allowance times this: the model-facing number stays the
# contract, the multiplier only keeps the read loop from stopping mid-line.
_BYTE_CAP_FACTOR = 4


def agent_env(agent_id: str) -> list[tuple[str, str]]:
    """The per-agent environment every exec() carries, in order.

    HOME/TMPDIR/pycache point to per-agent paths (prefixed ``agent-`` so the
    phase cleanup can remove them). They are path separation only: commands
    run as the same identity in the shared sandbox. The two cache vars point
    to writable caches shared by all agents and retained across cleanup.

    There is deliberately no other ``-e``: the sandbox environment is the
    image environment plus this list, never the host's -- so an API key in
    the operator's ``.env`` is not inherited by any agent command.
    """
    home = f"/work/{AGENT_SCRATCH_PREFIX}{agent_id}"
    return [
        ("HOME", home),
        ("TMPDIR", f"/tmp/{AGENT_SCRATCH_PREFIX}{agent_id}"),
        ("PYTHONPYCACHEPREFIX", f"{home}/.pyc"),
        ("PIP_CACHE_DIR", SHARED_CACHE_DIRS[0]),
        ("npm_config_cache", SHARED_CACHE_DIRS[1]),
    ]


class RunSandboxBase(ABC):
    """The one sandbox every agent of a run executes in.

    Shared by hunter units, validators, triage and the partitioner. Each
    ``exec()`` gets separate ``HOME``/``TMPDIR`` paths to reduce accidental
    collisions, but every command runs in the same filesystem and runtime
    identity; these paths are not an access-control boundary.

    The deliberate cost of sharing: a runaway agent (memory, pids, a stray
    ``rm -rf`` in the shared scratch) degrades the whole run instead of one
    unit.

    Thread-safe: the first ``ensure_started()`` creates the sandbox, later
    callers reuse it. ``close()`` removes it (idempotent).
    """

    # Extra dirs every exec mkdir -p's beyond the agent's own scratch (sbx
    # creates the shared cache dirs explicitly; the docker container mounts
    # /work already).
    EXTRA_EXEC_MKDIR_DIRS: tuple[str, ...] = ()
    # How long removing the sandbox may take (sbx rm is a VM teardown).
    DESTROY_TIMEOUT: float = 60
    # How long a create may take (sbx boots a microVM).
    CREATE_TIMEOUT: float = 120
    # How the backend names itself in an agent-visible message.
    cli_label: str = ""

    def __init__(self, *, repo_path: str | Path, image: str = DEFAULT_IMAGE,
                 command_timeout: int = 120,
                 max_output_bytes: int = 200_000,
                 name_prefix: str = "cyber-sandbox") -> None:
        self.repo_path = Path(repo_path).resolve()
        self.image = validate_image(str(image or DEFAULT_IMAGE))
        self.command_timeout = max(1, int(command_timeout))
        self.max_output_bytes = max(0, int(max_output_bytes))
        # Random name: two runs of the same repo in one process must never
        # collide, and a stale sandbox from a crashed run must not be adopted.
        self._name = f"{name_prefix}-{uuid.uuid4().hex[:12]}"
        self._lock = threading.Lock()
        self._started = False
        self._closed = False

    # -- identity / state ----------------------------------------------------

    @property
    def name(self) -> str:
        return self._name

    @property
    def started(self) -> bool:
        return self._started

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    @abstractmethod
    def cli_bin(self) -> str:
        """The binary this sandbox is driven with ("docker", "sbx")."""

    @abstractmethod
    def _workdir_args(self) -> list[str]:
        """How an exec names the working dir inside the sandbox."""

    # -- lifecycle -----------------------------------------------------------

    def ensure_started(self) -> str | None:
        """Create the sandbox once. Returns an error string or None."""
        with self._lock:
            if self._closed:
                return "sandbox is closed"
            if self._started:
                return None
            return self._start_locked()

    @abstractmethod
    def _start_locked(self) -> str | None:
        """Create the sandbox (lock held), mapping CLI failures to advice."""

    def mark_dead(self) -> None:
        """The sandbox is gone: recreate it on the next command."""
        self._on_death()
        with self._lock:
            self._started = False

    def _on_death(self) -> None:
        """Hook: state to reset before recreation (docker frees its name)."""

    def close(self) -> None:
        """Remove the sandbox. Idempotent; never raises."""
        with self._lock:
            already = self._closed
            was_started = self._started
            self._closed = True
            self._started = False
        if already:
            return
        if was_started:
            # Never started: there is nothing to remove (sbx still cleans up
            # its throwaway primary workspace via _after_close).
            self.remove()
        self._after_close()

    def _after_close(self) -> None:
        """Hook: extra cleanup once the sandbox is gone."""

    @abstractmethod
    def destroy_argv(self) -> list[str]:
        """The argv that force-removes this sandbox."""

    def remove(self, timeout: float | None = None) -> None:
        """Force-remove the sandbox. Idempotent; never raises.

        Best-effort on purpose: removal also runs from teardown and crash
        paths, and failing to remove a container must never fail a scan that
        already finished. A sandbox removed elsewhere just leaves the next
        `rm` an error.
        """
        try:
            cli_utils.run_cli(self.destroy_argv(),
                              timeout=(self.DESTROY_TIMEOUT
                                       if timeout is None else timeout))
        except Exception:
            pass

    # -- per-agent scratch ---------------------------------------------------

    def reset_agent_scratch(self) -> str | None:
        """Remove the per-agent scratchpads between scan phases.

        This is best-effort hygiene for the conventional per-agent scratch
        directories. It reduces accidental carryover, but does not stop
        background processes or prevent writes elsewhere in the shared
        sandbox. Strong phase separation requires a fresh sandbox.

        Only ``/work/agent-*`` and ``/tmp/agent-*`` are removed (see
        :data:`AGENT_SCRATCH_PREFIX`). Shared package caches under
        ``/work/_shared`` are preserved to avoid re-downloading packages;
        agents can access those caches, so they are not a trust boundary.
        """
        with self._lock:
            started, closed = self._started, self._closed
        if not started or closed:
            return None
        argv = [*self._exec_prefix(), self._name,
                "/bin/bash", "-c", RESET_COMMAND]
        try:
            proc = cli_utils.run_cli(argv, timeout=120)
        except Exception as e:
            return f"{self.cli_label} agent-scratch reset failed: {e}"
        if proc.returncode != 0:
            return (f"{self.cli_label} agent-scratch reset failed: "
                    f"{(proc.stdout or '').strip()[:160]}")
        return None

    # -- execution -----------------------------------------------------------

    def _exec_prefix(self) -> list[str]:
        """The argv head every exec shares: the binary, "exec", the workdir."""
        return [self.cli_bin, "exec", *self._workdir_args()]

    def _exec_mkdir_dirs(self) -> str:
        """The mkdir list every exec runs first (idempotent, no setup step)."""
        return " ".join(['"$HOME"', '"$TMPDIR"',
                         *(f'"{d}"' for d in self.EXTRA_EXEC_MKDIR_DIRS)])

    def exec(self, *, agent_id: str, command: str, marker: str, timeout: int,
             max_output_bytes: int) -> tuple[str, int | None, bool]:
        """Run one command inside the shared sandbox as ``agent_id``.

        The agent's scratch dirs are created inside the same exec (an
        idempotent ``mkdir -p``), so there is no setup step and no race with
        a parallel agent. ``marker`` tags this exec's command line so a hung
        CLI client can be cleaned up without touching other agents'
        processes.
        """
        argv = [*self._exec_prefix(),
                *(a for key, value in agent_env(agent_id)
                  for a in ("-e", f"{key}={value}")),
                self._name,
                # No -i: stdin is /dev/null so a stray pager/read exits at
                # once instead of hanging to the timeout.
                "timeout", "-k", "5", str(timeout),
                "/bin/bash", "-c",
                f"{cli_utils.EXEC_TAG}={marker}; "
                f"mkdir -p {self._exec_mkdir_dirs()}; {command}"]
        byte_cap = (max_output_bytes or 200_000) * _BYTE_CAP_FACTOR
        return cli_utils.run_bounded(argv, timeout=timeout + 15,
                                     byte_cap=byte_cap)

    def pkill_argv(self, name: str, marker: str) -> list[str]:
        """Kill ONLY this exec's tagged shell (the sandbox is shared)."""
        return [self.cli_bin, "exec", name,
                "pkill", "-KILL", "-f", f"{cli_utils.EXEC_TAG}={marker}"]


class RunRegistry:
    """One run sandbox per resolved repo path, per process.

    Keyed by the resolved repo path, so a second scan of another repo gets
    its own sandbox while every scan of the same repo in one process shares
    ONE -- which is the point: hunters, validators, triage and the
    partitioner all run in the same sandbox.

    Settings are applied at CREATION only: the first agent of the run
    configures the sandbox every later agent reuses.
    """

    def __init__(self, factory: Callable[[str, dict], RunSandboxBase]) -> None:
        self._factory = factory
        self._runs: dict[str, RunSandboxBase] = {}
        self._lock = threading.Lock()

    def get(self, repo: str | Path,
            settings: dict | None = None) -> RunSandboxBase:
        """The shared run sandbox for ``repo`` (created on first use)."""
        key = str(Path(repo).resolve())
        with self._lock:
            run = self._runs.get(key)
            if run is None or run.closed:
                run = self._factory(key, settings or {})
                self._runs[key] = run
            return run

    def shutdown(self, repo: str | Path | None = None) -> None:
        """Remove the run's sandbox(s) (default: all). Idempotent."""
        with self._lock:
            if repo is None:
                runs = list(self._runs.values())
                self._runs.clear()
            else:
                run = self._runs.pop(str(Path(repo).resolve()), None)
                runs = [run] if run is not None else []
        for run in runs:
            run.close()

    def reset_agent_scratch(self, repo: str | Path) -> list[str]:
        """Wipe the run sandbox's per-agent scratchpads; errors as strings.

        Never started means the agent scratch was never created, so there is
        nothing to remove (and the sandbox itself resets as a no-op anyway).
        """
        key = str(Path(repo).resolve())
        with self._lock:
            run = self._runs.get(key)
        if run is None or not run.started:
            return []
        try:
            err = run.reset_agent_scratch()
        except Exception as e:  # backends are fail-safe by contract
            err = f"{type(e).__name__}: {e}"
        return [err] if err else []

    def live_names(self) -> list[str]:
        """The sandbox names this process is still using (never sweep those)."""
        with self._lock:
            return [run.name for run in self._runs.values() if not run.closed]


# -- orphan sweep ------------------------------------------------------------
#
# A SIGKILL'd harness (kill -9, host OOM-kill, power loss) runs no teardown:
# atexit does not fire and the SIGTERM handler never sees the signal. Its
# sandbox then lingers -- a container nobody uses, or an idle microVM costing
# host CPU. Something has to reap it, and that something runs at the START of
# the next scan.
#
# Both backends ask their daemon the same question -- "when was this last
# used?" -- because both publish the answer:
#
# * sbx: `sbx ls --json` reports `last_used_at`, which advances on every exec.
# * docker: `docker events --filter container=NAME` reports `exec_start` for
#   every command the daemon ran, with a unix timestamp.
#
# So there is no harness-side liveness state anywhere: nothing to write,
# nothing to forge, and nothing to lose when the harness is killed -- which is
# the whole point, since the process that would have maintained it is exactly
# the one that died. Neither signal is a security boundary: the name pattern
# below is what keeps the sweep from touching a sandbox this harness did not
# create.

# A run quiet for longer than this is an orphan candidate. The sweep only
# runs at scan start, and a live run's agents exec constantly, so this only
# has to exceed a scan's quietest gap (a long model turn, or a run someone
# paused) -- comfortably past any of those, and comfortably under "leaked VM
# for days". A false positive is survivable anyway: the sandbox is recreated
# on the next command.
ORPHAN_IDLE_SECONDS = 6 * 3600

# The names this harness creates. Deliberately narrow: the sweep matches ours
# and nothing else, whatever the runtime calls it or anyone else has.
RUN_NAME_RE = re.compile(r"^cyber-(?:sandbox-run|sbx)-[0-9a-f]{12}$")


def orphan_targets(listed: Iterable[str], *,
                   live: Iterable[str] = ()) -> list[str]:
    """Names in ``listed`` that are ours and not in use by this process.

    The liveness question is deliberately NOT answered here: each backend
    answers it with what its runtime publishes (see the comment above), and
    passes the result through this filter.
    """
    live_set = {str(n) for n in live}
    targets: list[str] = []
    for raw in listed:
        name = str(raw).strip()
        if not name or name in live_set or not RUN_NAME_RE.match(name):
            continue
        targets.append(name)
    return targets


# Crash-path shutdowns, one per backend module that registers. atexit chains
# its callbacks, so per-shutdown registration there is enough — but
# signal.signal() REPLACES the installed handler, so "each backend installs
# its own SIGTERM handler" meant the LAST import won and the other backend's
# registries were never reaped on SIGTERM wherever atexit could not run
# (interpreter shutdown blocked at a non-daemon thread join). One handler
# reaps all of them; installing is idempotent.
_CRASH_SHUTDOWNS: list[Callable[[], None]] = []
_CRASH_HANDLER_INSTALLED = False


def install_crash_hooks(shutdown: Callable[[], None]) -> None:
    """Reap run sandboxes on interpreter exit AND on SIGTERM.

    atexit alone is not enough: a SIGTERM'd (killed, not exited) harness
    would leave its sandbox running -- a leaked container, or a leaked
    microVM burning host CPU. Signal handlers can only be installed from the
    main thread, which is why this is an explicit call and not an import
    side effect: a worker thread importing a backend module stays silent
    (its shutdown is still registered here, and a later main-thread caller
    installs the shared handler).
    """
    global _CRASH_HANDLER_INSTALLED
    atexit.register(shutdown)
    _CRASH_SHUTDOWNS.append(shutdown)

    if _CRASH_HANDLER_INSTALLED:
        return

    def _handler(signum: int, frame: Any) -> None:
        try:
            for reap in list(_CRASH_SHUTDOWNS):
                try:
                    reap()
                except Exception:
                    pass  # one registry's failure must not strand another's
        finally:
            sys.exit(128 + signum)

    try:
        signal.signal(signal.SIGTERM, _handler)
    except (ValueError, OSError):  # not the main thread, or no SIGTERM here
        pass
    else:
        _CRASH_HANDLER_INSTALLED = True

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
from .settings_defaults import (COMMAND_TIMEOUT, IMAGE, MAX_OUTPUT_BYTES,
                                MEMORY, RULES_DIR)
from .validation import validate_image

__all__ = ["RunSandboxBase", "RunRegistry", "install_crash_hooks",
           "AGENT_SCRATCH_PREFIX", "RESET_COMMAND", "DEFAULT_IMAGE",
           "agent_env", "orphan_targets", "sweep_orphans_via"]

DEFAULT_IMAGE = IMAGE

DEFAULT_COMMAND_TIMEOUT = COMMAND_TIMEOUT
DEFAULT_MAX_OUTPUT_BYTES = MAX_OUTPUT_BYTES
DEFAULT_MEMORY = MEMORY
DEFAULT_RULES_DIR = RULES_DIR

# Keep this prefix in sync with RESET_COMMAND's glob (they cannot drift).
AGENT_SCRATCH_PREFIX = "agent-"

# Shared writable caches (agents see each other's contents); survive phase cleanup.
SHARED_CACHE_DIRS = ("/work/_shared/pip", "/work/_shared/npm")

# Best-effort phase cleanup inside the sandbox only; not isolation.
RESET_COMMAND = "rm -rf /work/agent-* /tmp/agent-* 2>/dev/null; exit 0"

# Multiplier >1 keeps run_bounded's read loop from stopping mid-line.
_BYTE_CAP_FACTOR = 4


# Per-agent HOME/TMPDIR are hygiene, not an access-control boundary.
def agent_env(agent_id: str) -> list[tuple[str, str]]:
    home = f"/work/{AGENT_SCRATCH_PREFIX}{agent_id}"
    return [
        ("HOME", home),
        ("TMPDIR", f"/tmp/{AGENT_SCRATCH_PREFIX}{agent_id}"),
        ("PYTHONPYCACHEPREFIX", f"{home}/.pyc"),
        ("PIP_CACHE_DIR", SHARED_CACHE_DIRS[0]),
        ("npm_config_cache", SHARED_CACHE_DIRS[1]),
    ]


class RunSandboxBase(ABC):
    # How long removing the sandbox may take (docker rm -f).
    DESTROY_TIMEOUT: float = 60
    # How long a create may take (docker run).
    CREATE_TIMEOUT: float = 120
    cli_label: str = ""

    def __init__(self, *, repo_path: str | Path, image: str = DEFAULT_IMAGE,
                 command_timeout: int = DEFAULT_COMMAND_TIMEOUT,
                 max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
                 name_prefix: str = "cyber-sandbox") -> None:
        self.repo_path = Path(repo_path).resolve()
        self.image = validate_image(str(image or DEFAULT_IMAGE))
        self.command_timeout = max(1, int(command_timeout))
        self.max_output_bytes = max(0, int(max_output_bytes))
        # Random name: same-repo runs must not collide; a stale sandbox
        # from a crashed run must not be adopted.
        self._name = f"{name_prefix}-{uuid.uuid4().hex[:12]}"
        self._lock = threading.Lock()
        self._started = False
        self._closed = False

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
        ...

    def _child_env(self) -> dict[str, str] | None:
        return None

    @abstractmethod
    def _workdir_args(self) -> list[str]:
        ...

    def ensure_started(self) -> str | None:
        with self._lock:
            if self._closed:
                return "sandbox is closed"
            if self._started:
                return None
            return self._start_locked()

    @abstractmethod
    def _start_locked(self) -> str | None:
        ...

    def mark_dead(self) -> None:
        self._on_death()
        with self._lock:
            self._started = False

    def _on_death(self) -> None:
        ...

    def close(self) -> None:
        with self._lock:
            already = self._closed
            was_started = self._started
            self._closed = True
            self._started = False
        if already:
            return
        if was_started:
            self.remove()

    @abstractmethod
    def destroy_argv(self) -> list[str]:
        ...

    def remove(self, timeout: float | None = None) -> None:
        try:
            cli_utils.run_cli(self.destroy_argv(),
                              timeout=(self.DESTROY_TIMEOUT
                                        if timeout is None else timeout),
                              env=self._child_env())
        except Exception:
            # Also runs on teardown/crash paths: never fail a scan.
            pass

    def reset_agent_scratch(self) -> str | None:
        with self._lock:
            started, closed = self._started, self._closed
        if not started or closed:
            return None
        argv = [*self._exec_prefix(), self._name,
                "/bin/bash", "-c", RESET_COMMAND]
        try:
            proc = cli_utils.run_cli(argv, timeout=120, env=self._child_env())
        except Exception as e:
            return f"{self.cli_label} agent-scratch reset failed: {e}"
        if proc.returncode != 0:
            return (f"{self.cli_label} agent-scratch reset failed: "
                    f"{(proc.stdout or '').strip()[:160]}")
        return None

    def _exec_prefix(self) -> list[str]:
        return [self.cli_bin, "exec", *self._workdir_args()]

    def exec(self, *, agent_id: str, command: str, marker: str, timeout: int,
             max_output_bytes: int) -> tuple[str, int | None, bool]:
        argv = [*self._exec_prefix(),
                *(a for key, value in agent_env(agent_id)
                  for a in ("-e", f"{key}={value}")),
                self._name,
                # No -i: stdin is /dev/null so a stray pager/read exits at once.
                "timeout", "-k", "5", str(timeout),
                "/bin/bash", "-c",
                f"{cli_utils.EXEC_TAG}={marker}; "
                f"mkdir -p \"$HOME\" \"$TMPDIR\"; {command}"]
        byte_cap = (max_output_bytes or DEFAULT_MAX_OUTPUT_BYTES) * _BYTE_CAP_FACTOR
        return cli_utils.run_bounded(argv, timeout=timeout + 15,
                                     byte_cap=byte_cap, env=self._child_env())

    def pkill_argv(self, name: str, marker: str) -> list[str]:
        # Kill ONLY this exec's tagged shell (the sandbox is shared).
        return [self.cli_bin, "exec", name,
                "pkill", "-KILL", "-f", f"{cli_utils.EXEC_TAG}={marker}"]


class RunRegistry:
    def __init__(self, run_cls: type[RunSandboxBase],
                 setting_keys: frozenset[str]) -> None:
        # setting_keys: the run constructor's surface. A settings dict also
        # carries backend/agent-level keys (e.g. rules_dir) that must never
        # reach the run class (TypeError).
        self._run_cls = run_cls
        self._setting_keys = setting_keys
        self._runs: dict[str, RunSandboxBase] = {}
        self._lock = threading.Lock()

    def get(self, repo: str | Path,
            settings: dict | None = None) -> RunSandboxBase:
        # Settings apply at CREATION only; later agents reuse the first sandbox.
        key = str(Path(repo).resolve())
        with self._lock:
            run = self._runs.get(key)
            if run is None or run.closed:
                run = self._run_cls(repo_path=key, **{
                    k: v for k, v in (settings or {}).items()
                    if k in self._setting_keys})
                self._runs[key] = run
            return run

    def shutdown(self, repo: str | Path | None = None) -> None:
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
        key = str(Path(repo).resolve())
        with self._lock:
            run = self._runs.get(key)
        if run is None or not run.started:
            return []
        # run.reset_agent_scratch() never raises for infra: the backend
        # converts failures to strings (the reset boundary in the subclass
        # methods), so a raise from here is a harness bug and must surface.
        err = run.reset_agent_scratch()
        return [err] if err else []

    def live_names(self) -> list[str]:
        with self._lock:
            return [run.name for run in self._runs.values() if not run.closed]


# A SIGKILLed harness runs no teardown: the next scan sweeps it (daemon liveness).

# Sweeps run only at scan start; a false positive self-heals on next use.
ORPHAN_IDLE_SECONDS = 6 * 3600

# Deliberately narrow: the sweep must match only sandboxes this harness created.
RUN_NAME_RE = re.compile(r"^cyber-sandbox-run-[0-9a-f]{12}$")


def orphan_targets(listed: Iterable[str], *,
                   live: Iterable[str] = ()) -> list[str]:
    live_set = {str(n) for n in live}
    targets: list[str] = []
    for raw in listed:
        name = str(raw).strip()
        if not name or name in live_set or not RUN_NAME_RE.match(name):
            continue
        targets.append(name)
    return targets


def sweep_orphans_via(*, registry: RunRegistry,
                      list_names: Callable[[], list[str]],
                      idle_age: Callable[[str], float | None],
                      remove: Callable[[list[str]], bool],
                      live: Iterable[str] | None = None,
                      idle_seconds: float = ORPHAN_IDLE_SECONDS) -> list[str]:
    """The sweep rule, implemented once for every backend.

    Order: name pattern -> not a live run of this process -> idle past the
    threshold -> remove. A backend supplies only its liveness source: how to
    list candidates, how to age one, and how to remove a batch. An entry whose
    age cannot be measured is never removed.
    """
    try:
        listed = list_names()
    except Exception:
        return []
    if live is None:
        live = registry.live_names()
    targets = [name for name in orphan_targets(listed, live=live)
               if (age := idle_age(name)) is not None and age > idle_seconds]
    if not targets:
        return []
    try:
        removed = remove(targets)
    except Exception:
        return []
    return targets if removed else []


# signal.signal() replaces installed handlers; one handler reaps all backends.
_CRASH_SHUTDOWNS: list[Callable[[], None]] = []
_CRASH_HANDLER_INSTALLED = False


def install_crash_hooks(shutdown: Callable[[], None]) -> None:
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

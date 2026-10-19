from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Iterable

from . import cli_utils
from .backend_base import SandboxShellBackend
from .run_base import (DEFAULT_COMMAND_TIMEOUT, DEFAULT_IMAGE,
                       DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_MEMORY,
                       DEFAULT_RULES_DIR, ORPHAN_IDLE_SECONDS, RunRegistry,
                       RunSandboxBase, install_crash_hooks, sweep_orphans_via)
from .validation import (DEFAULT_NETWORK, validate_image, validate_network)

__all__ = ["DockerSandboxBackend", "RunSandbox", "DEFAULT_IMAGE",
           "get_run_sandbox", "shutdown_run_sandbox", "reap_orphans",
           "sweep_orphans"]

# Sweep hook for a container orphaned by a SIGKILLed harness (no atexit or SIGTERM then).
_RUN_LABEL = "cyber.agent.sandbox=run"

# `exec_start` timestamps are the only liveness source; keep no harness-side state.
def _last_exec_age(name: str, *, docker_bin: str = "docker") -> float | None:
    try:
        proc = cli_utils.run_cli(
            [docker_bin, "events", "--since", "0", "--until", "0s",
             "--filter", f"container={name}",
             "--filter", "event=exec_start",
             "--format", "json"], timeout=60)
    except Exception:
        return None
    newest = 0.0
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if str(event.get("Action", "")).startswith("exec_start"):
            newest = max(newest, float(event.get("time") or 0))
    if not newest:
        return None
    return max(0.0, time.time() - newest)


def _validate_mask_paths(*, repo_path: str | Path,
                         mask_paths: tuple[str, ...] | list[str] | None
                         ) -> list[str]:
    repo = Path(repo_path).resolve()
    out: list[str] = []
    seen: set[str] = set()
    for rel in mask_paths or ():
        rel = str(rel).strip().replace("\\", "/")
        if not rel or rel.startswith("/") or ".." in rel.split("/"):
            continue
        try:
            target = (repo / rel).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        try:
            target_rel = target.relative_to(repo).as_posix()
        except ValueError:
            continue
        if not target.is_file() or target_rel in seen:
            continue
        # Mount over the resolved file, not the symlink: a `.env -> settings.txt` alias must mask the destination bytes too.
        out.append(target_rel)
        seen.add(target_rel)
    return out

class RunSandbox(RunSandboxBase):
    cli_label = "docker"
    # A corpse must be removed in seconds, not minutes: an agent is waiting.
    DESTROY_TIMEOUT: float = 30

    def __init__(self, *, repo_path: str | Path, image: str = DEFAULT_IMAGE,
                 user: str = "1000:1000",
                 command_timeout: int = DEFAULT_COMMAND_TIMEOUT,
                 max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
                 memory: str = DEFAULT_MEMORY, cpus: str = "2",
                 pids_limit: int = 512,
                 network: str = DEFAULT_NETWORK,
                 docker_bin: str = "docker",
                 mask_paths: tuple[str, ...] | list[str] | None = None) -> None:
        self.user = str(user)
        self.memory = str(memory)
        self.cpus = str(cpus)
        self.pids_limit = max(16, int(pids_limit))
        # Egress: bridge = full egress (Docker NAT), none = none; host is refused (host netns). Validated here: a bad sandbox.network fails first.
        self.network = validate_network(network)
        self.docker_bin = str(docker_bin or "docker")
        # Credential files to hide from the shell (egress is live, so a key must not be readable): each gets a read-only /dev/null bind.
        if mask_paths is None:
            # No guard on purpose: find_credential_files is already fail-soft and a catch-all could only fail OPEN (mask_paths = ()).
            from harness.sandbox.credentials import find_credential_files
            mask_paths = find_credential_files(repo_path)
        self.mask_paths = tuple(_validate_mask_paths(repo_path=repo_path,
                                                     mask_paths=mask_paths))
        super().__init__(repo_path=repo_path, image=image,
                         command_timeout=command_timeout,
                         max_output_bytes=max_output_bytes,
                         name_prefix="cyber-sandbox-run")

    @property
    def cli_bin(self) -> str:
        return self.docker_bin

    def _workdir_args(self) -> list[str]:
        return ["-w", str(self.repo_path)]

    def _run_args(self) -> list[str]:
        repo = str(self.repo_path)
        return [
            self.docker_bin, "run", "-d", "--rm", "--name", self._name,
            "--label", _RUN_LABEL,
            "--network", self.network,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(self.pids_limit),
            "--memory", self.memory,
            "--memory-swap", self.memory,
            "--cpus", self.cpus,
            "--read-only",
            "--tmpfs", "/tmp:rw,size=1g,mode=1777",
            "--tmpfs", "/work:rw,size=2g,mode=1777",
            "--mount", f"type=bind,source={repo},target={repo},readonly",
            # Masked credential files: reads return EOF and writes fail. Docker fails the container ("not a directory") if a tmpfs covers a file.
            *[arg for rel in self.mask_paths
              for arg in ("--mount", f"type=bind,source={os.devnull},"
                                     f"target={repo}/{rel},readonly")],
            "--user", self.user,
            "-e", "HOME=/work",
            "-e", "TMPDIR=/tmp",
            "-e", "PYTHONPYCACHEPREFIX=/work/.pyc",
            "-e", "GIT_PAGER=cat",
            "-e", "PAGER=cat",
            "-e", "TERM=dumb",
            self.image,
            "sleep", "infinity",
        ]

    def _start_locked(self) -> str | None:
        proc = cli_utils.run_cli(self._run_args(), timeout=self.CREATE_TIMEOUT)
        if proc.returncode != 0:
            out = (proc.stdout or "").strip()
            if "not shared" in out:
                return (f"docker refused the repo mount ({self.repo_path}): "
                        "add it to Docker Desktop > Settings > Resources > "
                        "File Sharing, or use a repo path under a shared "
                        f"directory. docker said: {out[:200]}")
            return f"docker run failed ({self.image}): {out[:300]}"
        self._started = True
        return None

    def _on_death(self) -> None:
        # Free the name for the recreation that follows: the corpse holds it until removed, and the best-effort removal may not have run.
        with self._lock:
            self._name = f"cyber-sandbox-run-{uuid.uuid4().hex[:12]}"

    def destroy_argv(self) -> list[str]:
        return [self.docker_bin, "rm", "-f", self._name]

class DockerSandboxBackend(SandboxShellBackend):
    def __init__(self, *, repo_path: str | Path, image: str = DEFAULT_IMAGE,
                 user: str = "1000:1000",
                 command_timeout: int = DEFAULT_COMMAND_TIMEOUT,
                 max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
                 memory: str = DEFAULT_MEMORY, cpus: str = "2",
                 pids_limit: int = 512,
                 network: str = DEFAULT_NETWORK,
                 docker_bin: str = "docker",
                 rules_dir: str = DEFAULT_RULES_DIR,
                 run: RunSandbox | None = None, agent_id: str | None = None,
                 mask_paths: tuple[str, ...] | list[str] | None = None) -> None:
        # Validated before super(): a bad image or network must fail at construction, not inside `docker run`; mask_paths None keeps discovery.
        self.mask_paths = None if mask_paths is None else tuple(mask_paths)
        self.image = validate_image(str(image or DEFAULT_IMAGE))
        self.user = str(user)
        self.memory = str(memory)
        self.cpus = str(cpus)
        self.pids_limit = max(16, int(pids_limit))
        # Egress: bridge = full egress, none = none; host refused (host netns).
        network_mode = validate_network(network)
        self.docker_bin = str(docker_bin or "docker")
        super().__init__(
            repo_path=repo_path,
            run_factory=lambda: RunSandbox(
                repo_path=repo_path, image=self.image, user=self.user,
                command_timeout=command_timeout,
                max_output_bytes=max_output_bytes, memory=self.memory,
                cpus=self.cpus, pids_limit=self.pids_limit,
                network=network_mode, docker_bin=self.docker_bin,
                mask_paths=self.mask_paths),
            run=run, agent_id=agent_id,
            command_timeout=command_timeout,
            max_output_bytes=max_output_bytes,
            rules_dir=rules_dir,
            network=network_mode)

    def _missing_binary_message(self) -> str:
        return (f"refused: {self.docker_bin!r} not found on PATH; "
                "sandbox backend needs a container runtime")

    def _recover_sandbox(self, *, command: str, marker: str, t: int,
                         out: str, exit_code: int | None, truncated: bool
                         ) -> tuple[str, int | None, bool] | None:
        if exit_code == 126 and "exec failed" in out:
            # The shared container died: mark it for restart on the next exec and remove the corpse so the fresh name is free.
            self._run.mark_dead()
            self._run.remove()
        return None

# Run-level slice of a sandbox settings dict: rules_dir is PER-AGENT and must
# never reach the container constructor (TypeError).
_RUN_SETTING_KEYS = frozenset({
    "image", "user", "command_timeout", "max_output_bytes", "memory", "cpus",
    "pids_limit", "network", "docker_bin", "mask_paths",
})

RUNS = RunRegistry(RunSandbox, _RUN_SETTING_KEYS)

def get_run_sandbox(repo: str | Path, settings: dict | None = None) -> RunSandbox:
    return RUNS.get(repo, settings)

def shutdown_run_sandbox(repo: str | Path | None = None) -> None:
    RUNS.shutdown(repo)

def sweep_orphans(*, docker_bin: str = "docker",
                  live: Iterable[str] | None = None,
                  idle_seconds: float = ORPHAN_IDLE_SECONDS) -> list[str]:
    def list_names() -> list[str]:
        proc = cli_utils.run_cli(
            [docker_bin, "ps", "-a", "--filter", f"label={_RUN_LABEL}",
             "--format", "{{.Names}}"], timeout=60)
        return (proc.stdout or "").splitlines()

    def remove(targets: list[str]) -> bool:
        return cli_utils.run_cli([docker_bin, "rm", "-f", *targets],
                                 timeout=120).returncode == 0

    return sweep_orphans_via(
        registry=RUNS, list_names=list_names,
        idle_age=lambda name: _last_exec_age(name, docker_bin=docker_bin),
        remove=remove, live=live, idle_seconds=idle_seconds)

def reap_orphans() -> None:
    RUNS.shutdown()

install_crash_hooks(RUNS.shutdown)

"""Docker sandbox backend: adds shell access that cannot escape the container.

The local backend (:class:`RepoLocalBackend`) is repo-confined but has no
shell. This backend keeps all of its in-process, resolve-then-check
contained file operations and adds :meth:`execute`, which runs commands
inside a container. Because the class also inherits
:class:`SandboxBackendProtocol`, deepagents detects it per model call and
gives the agent the ``execute`` tool (and only then).

Containment is by construction, not by path checks -- the properties a
shell would otherwise use to escape do not exist inside the container:

* network: ``--network none`` or ``--network bridge``, set by
  ``sandbox.network``. Default is bridge (FULL EGRESS: pip/git/curl
  reach the internet, so the container can fetch tooling at scan time);
  ``none`` is the network-less posture for runs that do not need it.
* filesystem: the repo is bind-mounted **read-only** at its absolute host
  path, and nothing else from the host is mounted; the rootfs is
  ``--read-only`` with explicit tmpfs for ``/tmp`` and ``/work`` only
* secrets: no ``-e`` is ever passed except the fixed per-agent scratch env
  (see :func:`~harness.sandbox.run_base.agent_env`), so the container env
  is exactly the image env plus it; host env (API keys in ``.env``) is
  never inherited. Credential files inside the tree are additionally
  shadowed, so the shell cannot read them either (docker can mask a path;
  sbx cannot).
* escalation: ``--cap-drop ALL --security-opt no-new-privileges`` and a
  non-root ``--user``

Egress is a CONFIG decision, never a policy one: with bridge networking,
anything the agent reads inside the container (the repo, including a
``.env`` with credentials when the target IS the harness checkout) can be
sent anywhere on the internet, and any payload can be pulled and run. The
command policy below cannot hold that boundary -- it strings-matches a
command line, and ``python -c 'import socket...'`` is never in it -- so it
only fails fast on host/container-escape tooling. Operate with egress on
only when that exfiltration path is acceptable (or run ``none``).

Known limits (accepted by design):
* agent code IS arbitrary inside the container (context injection owns it);
  the shell's blast radius is the container, which is why it must stay
  host-file-less and resource-bounded (memory, pids, cpus, caps).
* background processes (nohup/setsid) can outlive their command until the
  run container is removed at :func:`shutdown_run_sandbox`; the exec stream
  does not hang.
* a repo that is itself the harness checkout exposes its own ``.env`` to
  the container via the read-only mount -- with egress on, that key is
  exfiltrable, not just readable.
* a small deny-only check in :meth:`_policy_error` fails fast on obvious
  host/container tools. It is not a boundary; the flags above provide
  containment.

Lifecycle: ONE container per scan run, shared by every agent -- hunter
units, validators, triage, the partitioner -- via :class:`RunSandbox`
(which is a :class:`~harness.sandbox.run_base.RunSandboxBase`: the create
/ exec / reset / remove state machine is shared with the sbx backend). It
starts lazily on the first ``execute()`` of any agent and is reused by
every later command of every agent for the rest of the run
(``close()`` on a per-agent backend ends that agent's session only).
``shutdown_run_sandbox()`` force-removes it at scan teardown, and an atexit
+ SIGTERM hook reaps it from a crashed process.

The container has one ``--memory``/``--pids-limit``/``--cpus`` budget, image
start and teardown. Each agent gets different ``HOME``/``TMPDIR`` paths to
reduce accidental collisions, but commands share the same filesystem and
runtime identity; this is not per-agent isolation. A runaway process or a
write elsewhere in the shared tmpfs can affect the whole run.

The image (``harness/sandbox/docker/Dockerfile``) carries the scan
toolchain -- python, git, semgrep, opengrep, gitleaks, osv-scanner,
checkov -- so the agent rarely needs egress; whatever ``sandbox.network``
allows is available for the rest (registry rules, installing the target's
own dependencies). Build the image once per tag (pins live in
versions.env)::

    ./harness/sandbox/docker/build.sh cyber-sandbox:local
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Iterable

from . import cli_utils
from .backend_base import SandboxShellBackend
from .run_base import (DEFAULT_IMAGE, ORPHAN_IDLE_SECONDS, RunRegistry,
                       RunSandboxBase, install_crash_hooks, orphan_targets)
from .validation import validate_image, validate_network

__all__ = ["DockerSandboxBackend", "RunSandbox", "DEFAULT_IMAGE",
           "get_run_sandbox", "shutdown_run_sandbox", "reap_orphans",
           "sweep_orphans"]

# Operator sweep hook for a container orphaned by a SIGKILLed harness
# (neither atexit nor SIGTERM runs then): docker ps --filter
# label=cyber.agent.sandbox=run
_RUN_LABEL = "cyber.agent.sandbox=run"


# -- liveness (docker's own record) -------------------------------------------
#
# The daemon records every command it runs: `docker events` reports
# `exec_start: <command>` for each exec, with a unix timestamp. That is the
# liveness signal for a container, exactly as `last_used_at` is for an sbx
# sandbox -- so, as with sbx, there is no harness-side state to maintain and
# nothing to forge, and a SIGKILL'd run leaves the daemon's account intact
# (which is the whole point: the process that would have cleaned up is gone).


def _last_exec_age(name: str, *, docker_bin: str = "docker") -> float | None:
    """Seconds since the container's last exec, or None if not established.

    None means "the daemon cannot tell us": a container that never served a
    command, or one whose events have rotated out of the daemon's log. Both
    are left alone rather than removed (never remove what you cannot measure).
    """
    try:
        proc = cli_utils.run_cli(
            [docker_bin, "events", "--since", "0", "--until", "0s",
             "--filter", f"container={name}", "--format", "json"], timeout=60)
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


def _idle_orphans(listed: list[str], *, docker_bin: str,
                  idle_seconds: float) -> list[str]:
    """Our containers whose last exec is older than the threshold."""
    orphans: list[str] = []
    for name in listed:
        age = _last_exec_age(name, docker_bin=docker_bin)
        if age is not None and age > idle_seconds:
            orphans.append(name)
    return orphans


def _validate_mask_paths(*, repo_path: str | Path,
                         mask_paths: tuple[str, ...] | list[str] | None
                         ) -> list[str]:
    """Mounted-path sanitisation for the credential masks.

    A mask is repo-relative and must resolve to a file inside the repo.
    Absolute and escaping (``..``) paths are refused. Symlinks to in-repo
    files are resolved so the mount covers the file bytes, not the link name.
    """
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
        # Mount over the resolved file, not a symlink mount point. A
        # credential-named alias such as `.env -> settings.txt` must mask the
        # destination bytes, and Docker must not follow a symlink target path.
        out.append(target_rel)
        seen.add(target_rel)
    return out


class RunSandbox(RunSandboxBase):
    """The ONE container a whole scan run executes in (docker CLI).

    The whole lifecycle -- create once, exec per agent with its own scratch
    env, reset per-agent scratch at the phase boundary, mark dead and
    recreate, remove -- comes from :class:`RunSandboxBase`. What lives here
    is only what is docker's: the argv, and the advice for its failures.
    """

    cli_label = "docker"
    # A corpse must be removed in seconds, not minutes: an agent is waiting.
    DESTROY_TIMEOUT: float = 30

    def __init__(self, *, repo_path: str | Path, image: str = DEFAULT_IMAGE,
                 user: str = "1000:1000", command_timeout: int = 120,
                 max_output_bytes: int = 200_000, memory: str = "2g",
                 cpus: str = "2", pids_limit: int = 512,
                 network: str = "bridge",
                 docker_bin: str = "docker",
                 mask_paths: tuple[str, ...] | list[str] | None = None) -> None:
        self.user = str(user)
        self.memory = str(memory)
        self.cpus = str(cpus)
        self.pids_limit = max(16, int(pids_limit))
        # Egress posture. bridge = full egress (Docker default NAT); none =
        # no egress at all. host would join the host network namespace, so it
        # is refused. Validated here so a bad sandbox.network fails before any
        # container exists.
        self.network = validate_network(network)
        self.docker_bin = str(docker_bin or "docker")
        # Credential files to hide inside the container: egress is allowed, so
        # a live key in the scanned tree must not be readable by the shell
        # either. Each path gets a read-only /dev/null bind over it (see
        # _run_args: a tmpfs cannot mask a plain file).
        if mask_paths is None:
            # No guard here on purpose: find_credential_files is already
            # fail-soft (it catches OSError and returns []), the credentials
            # module is loaded by this package's own import chain (backend_base
            # -> local_backend -> .credentials) so the import cannot fail, and
            # a repo_path bad enough to raise TypeError from Path() raises the
            # same TypeError from the unconditional _validate_mask_paths call
            # below. A catch-all here was dead code that could only ever
            # fail OPEN (mask_paths = ()) on an unreadable tree.
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
            # Egress posture (bridge = full egress; none = no egress).
            "--network", self.network,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(self.pids_limit),
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--read-only",
            "--tmpfs", "/tmp:rw,size=1g,mode=1777",
            "--tmpfs", "/work:rw,size=2g,mode=1777",
            "--mount", f"type=bind,source={repo},target={repo},readonly",
            # Credential files: /dev/null is bound read-only over each one,
            # so reads return EOF and writes fail. A tmpfs cannot be used
            # here: it only mounts onto a directory, and
            # docker fails the whole container with "not a directory" the
            # moment a credential file (a plain file) is in the tree.
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
        # Free the name for the recreation that follows: the corpse still
        # holds it until removed, and the best-effort removal in
        # _recover_sandbox may not have run.
        with self._lock:
            self._name = f"cyber-sandbox-run-{uuid.uuid4().hex[:12]}"

    def destroy_argv(self) -> list[str]:
        return [self.docker_bin, "rm", "-f", self._name]


class DockerSandboxBackend(SandboxShellBackend):
    """Repo-confined file tools (in-process) plus shared-container shell.

    One backend per agent, all sharing one :class:`RunSandbox`: ``close()``
    ends this agent's session (it does NOT remove the container unless the
    backend was built standalone, without a shared run sandbox).
    """

    def __init__(self, *, repo_path: str | Path, image: str = DEFAULT_IMAGE,
                 user: str = "1000:1000",
                 command_timeout: int = 120, max_output_bytes: int = 200_000,
                 memory: str = "2g", cpus: str = "2", pids_limit: int = 512,
                 network: str = "bridge",
                 docker_bin: str = "docker",
                 rules_dir: str = "/opt/scan-rules/harness",
                 skills_dir: str = "/opt/harness-skills",
                 run: RunSandbox | None = None, agent_id: str | None = None,
                 denied_globs=None,
                 mask_paths: tuple[str, ...] | list[str] | None = None) -> None:
        # Validated before anything exists, and before super(): a bad image
        # or network must fail at construction, not inside a `docker run`.
        # Preserve None so RunSandbox can discover credential paths when this
        # backend is constructed directly, outside resolve_backend().
        self.mask_paths = None if mask_paths is None else tuple(mask_paths)
        self.image = validate_image(str(image or DEFAULT_IMAGE))
        self.user = str(user)
        self.memory = str(memory)
        self.cpus = str(cpus)
        self.pids_limit = max(16, int(pids_limit))
        # Egress posture. bridge = full egress; none = no egress; host would
        # join the host network namespace, so it is refused.
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
            run=run, agent_id=agent_id, denied_globs=denied_globs,
            command_timeout=command_timeout,
            max_output_bytes=max_output_bytes,
            rules_dir=rules_dir, skills_dir=skills_dir,
            network=network_mode)

    def _missing_binary_message(self) -> str:
        return (f"refused: {self.docker_bin!r} not found on PATH; "
                "sandbox backend needs a container runtime")

    def _recover_sandbox(self, *, command: str, marker: str, t: int,
                         out: str, exit_code: int | None, truncated: bool
                         ) -> tuple[str, int | None, bool] | None:
        if exit_code == 126 and "exec failed" in out:
            # The shared container died: mark it so the next agent's exec
            # restarts it, and remove the corpse so the fresh name is free
            # (a corpse holds its name until it is gone).
            self._run.mark_dead()
            self._run.remove()
        return None


# The run-level slice of a sandbox settings dict. The rest of the settings
# (rules_dir, skills_dir) are the PER-AGENT session's -- the hunter prompt
# reads them off the backend -- and must never reach the container
# constructor, or the first agent's run creation dies with a TypeError.
# test_run_settings_reach_the_run_sandbox asserts this still covers every
# RunSandbox parameter, so a new run setting cannot be silently dropped.
_RUN_SETTING_KEYS = frozenset({
    "image", "user", "command_timeout", "max_output_bytes", "memory", "cpus",
    "pids_limit", "network", "docker_bin", "mask_paths",
})


def _run_settings(settings: dict | None) -> dict:
    """The run-level slice of a sandbox settings dict (see above)."""
    return {k: v for k, v in (settings or {}).items() if k in _RUN_SETTING_KEYS}


# Run-scoped sandbox registry: one container per repo per process.
RUNS = RunRegistry(lambda repo, settings: RunSandbox(
    repo_path=repo, **_run_settings(settings)))


def get_run_sandbox(repo: str | Path, settings: dict | None = None) -> RunSandbox:
    """The shared run sandbox for ``repo`` (created on first use)."""
    return RUNS.get(repo, settings)


def shutdown_run_sandbox(repo: str | Path | None = None) -> None:
    """Remove the run container for ``repo`` (default: all). Idempotent."""
    RUNS.shutdown(repo)


def sweep_orphans(*, docker_bin: str = "docker",
                  live: Iterable[str] | None = None,
                  idle_seconds: float = ORPHAN_IDLE_SECONDS) -> list[str]:
    """Force-remove run containers a killed harness left behind.

    The label is the operator-facing handle (``docker ps --filter
    label=cyber.agent.sandbox=run``) and this is the same sweep in-process:
    it runs at scan start, because a SIGKILL'd harness cannot run its own
    teardown (no atexit, no signal handler) and nothing else will remove its
    container.

    A container is an orphan when it is ours (the label), it is not one this
    process is using (the registry), and the daemon reports it idle past
    ``idle_seconds`` -- its own ``exec_start`` events, so a live run never
    looks idle and no harness-side state exists. Idempotent; never raises.
    Returns the names it removed.
    """
    try:
        proc = cli_utils.run_cli(
            [docker_bin, "ps", "-a", "--filter", f"label={_RUN_LABEL}",
             "--format", "{{.Names}}"], timeout=60)
    except Exception:
        return []
    if live is None:
        live = RUNS.live_names()
    listed = orphan_targets((proc.stdout or "").splitlines(), live=live)
    targets = _idle_orphans(listed, docker_bin=docker_bin,
                            idle_seconds=idle_seconds)
    if not targets:
        return []
    try:
        removal = cli_utils.run_cli([docker_bin, "rm", "-f", *targets],
                                    timeout=120)
    except Exception:
        return []
    return targets if removal.returncode == 0 else []


def reap_orphans() -> None:
    """Close every run sandbox (crash-path cleanup via atexit, tests)."""
    RUNS.shutdown()


install_crash_hooks(RUNS.shutdown)

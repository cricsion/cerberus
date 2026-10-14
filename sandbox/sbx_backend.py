"""Docker Sandboxes backend: the run's agents execute inside one microVM.

Docker Sandboxes (the ``sbx`` CLI) run each sandbox as a microVM with its own
kernel, its own Docker Engine, and its own network: the VM boundary is the
isolation control, not in-VM privilege separation (the agent runs as a non-root
user *with sudo* inside the VM). See ``sbx-sandbox-design.md`` for the full
design and the **validated** CLI facts behind this module -- the read-only
workspace shape (``<repo>:ro`` as an extra workspace, ``--workdir <repo>``),
the per-agent env overrides, the shared caches, and the <1 s idle restart were
all proven against a real microVM before this code was written.

How the harness maps onto it:

* ONE sandbox per scan run (per repo), shared by every agent -- exactly like
  :class:`~harness.sandbox.docker_backend.RunSandbox`, and for the same
  reason: both are :class:`~harness.sandbox.run_base.RunSandboxBase`, so the
  create / exec / phase-reset / remove lifecycle is shared code. Agents
  ``sbx exec`` into it; the run-level teardown (``shutdown_sbx()``, the CLI's
  ``finally``, and an atexit + SIGTERM hook) removes it.
* **Read-only repo**: ``sbx`` refuses ``:ro`` on the primary workspace
  ("primary workspace must be read/write"), so the target repo is mounted as
  an *additional* ``<repo>:ro`` workspace and every exec runs with
  ``--workdir <repo>``. The primary workspace is a throwaway read-write
  directory (a temp dir per run, or ``sandbox.sbx.primary_dir``), because a
  primary is required. Reads work; writes to the repo path fail.
* **Egress is policy, not a flag**: the operator's machine-level policy
  (Balanced in our posture) governs destinations through the host-side proxy.
  This backend NEVER mutates global policy -- no ``sbx policy init/reset``.
  The only rules it writes are per-sandbox ``--deny-network`` hosts from
  ``sandbox.sbx.deny_network`` (the safe direction: deny can only narrow).
* **Per-agent scratch**: each exec carries ``HOME``/``TMPDIR``/pycache/env
  overrides so a ``pip install`` or test cache in one agent's session cannot
  touch another's; package-manager *download* caches are shared under
  ``/work/_shared`` so parallel agents do not re-download the same wheels.
* The template image is the pinned scan toolchain, loaded into the sandbox
  runtime once by the operator (``docker image save ... | sbx template load``)
  and used with ``--pull never`` so no registry round-trip happens at scan
  time.

What this backend does NOT provide (by design of sbx): ``--cap-drop``,
seccomp, ``--read-only`` and ``--pids-limit`` have no sbx equivalent here --
the microVM replaces them. Do not claim them for this mode anywhere.

Lifecycle: ``ensure_started()`` runs ``sbx create`` once; every later command
is ``sbx exec`` (which also starts a stopped sandbox). ``close()`` ends one
agent's session; ``shutdown_sbx()`` removes the run's sandbox and its
throwaway primary workspace.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from . import cli_utils
from .backend_base import SandboxShellBackend
from .run_base import (DEFAULT_IMAGE, ORPHAN_IDLE_SECONDS, SHARED_CACHE_DIRS,
                       RunRegistry, RunSandboxBase, install_crash_hooks,
                       orphan_targets)
from .validation import (validate_cpus, validate_image, validate_memory,
                         validate_pull, validate_skills)

__all__ = ["SbxBackend", "SbxRun", "get_sbx_run", "shutdown_sbx",
           "sweep_orphans", "DEFAULT_IMAGE"]

# The operator's own telemetry preference, captured before we ever touch it,
# so "disable_telemetry: 0" restores their value instead of erasing it.
_TELEMETRY_PREEXISTING = os.environ.get("SBX_NO_TELEMETRY")


def _dedupe(hosts) -> tuple[str, ...]:
    """Trim, drop empties, keep order, drop repeats."""
    return tuple(dict.fromkeys(str(h).strip() for h in (hosts or [])
                               if str(h).strip()))


class SbxRun(RunSandboxBase):
    """The ONE microVM sandbox a whole scan run executes in.

    Shared by every agent of the run; per-exec ``HOME``/``TMPDIR`` overrides
    reduce accidental path collisions but do not isolate commands sharing
    the VM. What lives here is only what is sbx's: the argv, the name-collision
    retry, the per-sandbox egress rules, and the throwaway primary workspace.
    """

    cli_label = "sbx"
    # Booting and tearing down a microVM is not a docker run.
    DESTROY_TIMEOUT: float = 120
    CREATE_TIMEOUT: float = 600
    # sbx has no tmpfs mounts to create the shared cache dirs for us.
    EXTRA_EXEC_MKDIR_DIRS: tuple[str, ...] = SHARED_CACHE_DIRS

    def __init__(self, *, repo_path: str | Path, image: str = DEFAULT_IMAGE,
                 cpus: str = "0", memory: str = "2g", skills: str = "off",
                 pull: str = "never",
                 deny_network: tuple[str, ...] | list[str] = (),
                 allow_network: tuple[str, ...] | list[str] = (),
                 disable_telemetry: bool = True,
                 primary_dir: str | Path | None = None,
                 command_timeout: int = 120, max_output_bytes: int = 200_000,
                 sbx_bin: str = "sbx") -> None:
        self.cpus = validate_cpus(cpus)
        self.memory = validate_memory(memory)
        self.skills = validate_skills(skills)
        self.pull = validate_pull(pull)
        self.deny_network = _dedupe(deny_network)
        self.allow_network = _dedupe(allow_network)
        # Each `sbx` invocation makes ~2 HTTPS round-trips (Docker Hub session
        # refresh + one more), so on a high-latency link every agent command
        # pays seconds. The telemetry call is one of them and is the only one
        # we can decline: SBX_NO_TELEMETRY removes it from every sbx child
        # process we spawn (~0.9s/exec measured on a 1.7s-RTT link).
        self.disable_telemetry = bool(disable_telemetry)
        # Authoritative for the child processes we spawn: an explicit config
        # value wins over whatever the operator's shell exported, and turning
        # it back off restores the operator's own value rather than deleting
        # it (deterministic per backend, no leakage between configurations).
        if self.disable_telemetry:
            os.environ["SBX_NO_TELEMETRY"] = "1"
        elif _TELEMETRY_PREEXISTING is not None:
            os.environ["SBX_NO_TELEMETRY"] = _TELEMETRY_PREEXISTING
        self.sbx_bin = str(sbx_bin or "sbx")
        # The throwaway read-write primary workspace sbx requires. Created
        # lazily (first ensure_started) so constructing a backend has no
        # filesystem side effects.
        self._primary_dir: Path | None = (
            Path(primary_dir).expanduser() if primary_dir else None)
        self._owns_primary = primary_dir is None
        # Name rules: >=2 chars, letters/digits/hyphens/periods, not 'default'.
        super().__init__(repo_path=repo_path, image=image,
                         command_timeout=command_timeout,
                         max_output_bytes=max_output_bytes,
                         name_prefix="cyber-sbx")

    @property
    def cli_bin(self) -> str:
        return self.sbx_bin

    def _workdir_args(self) -> list[str]:
        return ["--workdir", str(self.repo_path)]

    def _primary(self) -> Path:
        if self._primary_dir is None:
            # Named after the sandbox on purpose: a SIGKILL'd run leaves BOTH
            # behind (`sbx rm` does not delete a host workspace), and the
            # sweep needs to pair a dead sandbox with its throwaway workspace.
            # The sandbox name is uuid-unique, so so is this path, and it is
            # cached: a recreated sandbox keeps the workspace it already has.
            self._primary_dir = _primary_path(self._name)
            try:
                self._primary_dir.mkdir(parents=True, exist_ok=False)
            except FileExistsError:  # a killed run's leftover, same uuid: reuse
                pass
            self._owns_primary = True
        return self._primary_dir

    def _cleanup_primary(self) -> None:
        if self._owns_primary and self._primary_dir is not None:
            shutil.rmtree(self._primary_dir, ignore_errors=True)

    def _create_args(self) -> list[str]:
        argv = [self.sbx_bin, "create", "shell",
                "--name", self._name,
                "--template", self.image,
                "--pull", self.pull,
                "--skills", self.skills]
        if self.cpus != "0":
            argv += ["--cpus", self.cpus]
        argv += ["--memory", self.memory]
        for host in self.deny_network:
            argv += ["--deny-network", host]
        # primary (RW, throwaway) + the target repo, read-only.
        argv += [str(self._primary()), f"{self.repo_path}:ro"]
        return argv

    def _apply_allow_network(self) -> str | None:
        """Grant this sandbox's extra allow rules (scoped to it, never global).

        Verified syntax (v0.47): `sbx policy allow network --sandbox NAME
        "host1,host2"` -- one comma-separated RESOURCES argument. Local
        sandboxes have no create-time allow flag (that is --cloud only), so the
        rules are added right after create and vanish with the sandbox.
        """
        if not self.allow_network:
            return None
        argv = [self.sbx_bin, "policy", "allow", "network",
                "--sandbox", self._name, ",".join(self.allow_network)]
        try:
            proc = cli_utils.run_cli(argv, timeout=60)
        except Exception as e:  # never fail the run over a policy add
            return f"could not add egress allow rules: {e}"
        if proc.returncode != 0:
            return (f"could not allow {', '.join(self.allow_network)} "
                    f"({(proc.stdout or '').strip()[:160]})")
        return None

    def _start_locked(self) -> str | None:
        for attempt in (0, 1):
            try:
                proc = cli_utils.run_cli(self._create_args(),
                                         timeout=self.CREATE_TIMEOUT)
            except FileNotFoundError:
                return (f"{self.sbx_bin!r} not found on PATH: install Docker "
                        "Sandboxes (brew install docker/tap/sbx) or set "
                        "sandbox.backend: docker")
            out = (proc.stdout or "").strip()
            if proc.returncode == 0:
                self._started = True
                # Egress allow rules are per-sandbox: they die with the
                # sandbox and never touch the operator's global policy.
                allow_err = self._apply_allow_network()
                if allow_err:
                    print(f"[sbx] {allow_err}", file=sys.stderr, flush=True)
                return None
            low = out.lower()
            if attempt == 0 and ("exist" in low or "in use" in low):
                # A stale sandbox holds our name: clear it, take a fresh
                # name and retry once (also the path after a dead VM).
                self.remove(timeout=60)
                self._name = f"cyber-sbx-{uuid.uuid4().hex[:12]}"
                continue
            if "not signed in" in low:
                return (f"{self.sbx_bin} needs Docker authentication: run "
                        f"'sbx login' (or set sandbox.backend: docker). "
                        f"sbx said: {out[:200]}")
            if "has not been initialized" in low:
                return ("the machine's global network policy is "
                        "uninitialized; the operator sets it once with "
                        f"'sbx policy init balanced' (we never mutate it). "
                        f"sbx said: {out[:200]}")
            if "primary workspace must be read/write" in low:
                return (f"sbx refused the read-only repo mount "
                        f"({self.repo_path}): {out[:200]}")
            if "template" in low and ("not found" in low or "unknown" in low
                                      or "no such" in low
                                      or "not loaded" in low):
                return ("the sandbox template image is not loaded in sbx's "
                        "template store (sbx does not share your host Docker "
                        "image store): load it once with 'docker image save "
                        f"{self.image} -o /tmp/template.tar && sbx template "
                        f"load /tmp/template.tar'. sbx said: {out[:200]}")
            return f"sbx create failed: {out[:300]}"

    def _after_close(self) -> None:
        # The primary workspace is ours (a temp dir per run): remove it even
        # when the sandbox was never created, or every failed run leaks one.
        self._cleanup_primary()

    def destroy_argv(self) -> list[str]:
        return [self.sbx_bin, "rm", "--force", self._name]


class SbxBackend(SandboxShellBackend):
    """Repo-confined file tools (in-process) plus microVM shell access.

    One backend per agent, all sharing one :class:`SbxRun`: ``close()`` ends
    this agent's session only -- the run's sandbox is removed by
    :func:`shutdown_sbx` at scan teardown.
    """

    HANG_NOTE = "sbx exec client hang"

    def __init__(self, *, repo_path: str | Path, image: str = DEFAULT_IMAGE,
                 cpus: str = "0", memory: str = "2g", skills: str = "off",
                 pull: str = "never",
                 deny_network: tuple[str, ...] | list[str] = (),
                 allow_network: tuple[str, ...] | list[str] = (),
                 disable_telemetry: bool = True,
                 primary_dir: str | Path | None = None,
                 command_timeout: int = 120, max_output_bytes: int = 200_000,
                 sbx_bin: str = "sbx", rules_dir: str = "/opt/scan-rules/harness",
                 skills_dir: str = "/opt/harness-skills",
                 run: SbxRun | None = None, agent_id: str | None = None,
                 denied_globs=None) -> None:
        # Validated before anything exists, and before super(): a bad setting
        # must fail at construction, not inside a `sbx create`.
        self.image = validate_image(str(image or DEFAULT_IMAGE))
        self.cpus = validate_cpus(cpus)
        self.memory = validate_memory(memory)
        self.skills = validate_skills(skills)
        self.pull = validate_pull(pull)
        self.deny_network = _dedupe(deny_network)
        self.allow_network = _dedupe(allow_network)
        self.disable_telemetry = bool(disable_telemetry)
        self.sbx_bin = str(sbx_bin or "sbx")
        self._primary_dir = (Path(primary_dir).expanduser()
                             if primary_dir else None)
        super().__init__(
            repo_path=repo_path,
            run_factory=lambda: SbxRun(
                repo_path=repo_path, image=self.image, cpus=self.cpus,
                memory=self.memory, skills=self.skills, pull=self.pull,
                deny_network=self.deny_network,
                allow_network=self.allow_network,
                disable_telemetry=self.disable_telemetry,
                primary_dir=self._primary_dir,
                command_timeout=command_timeout,
                max_output_bytes=max_output_bytes,
                sbx_bin=self.sbx_bin),
            run=run, agent_id=agent_id, denied_globs=denied_globs,
            command_timeout=command_timeout,
            max_output_bytes=max_output_bytes,
            rules_dir=rules_dir, skills_dir=skills_dir,
            # The machine's Balanced policy is what actually governs egress
            # here (we never mutate it), so that is what the prompts say.
            network="balanced")

    def _missing_binary_message(self) -> str:
        return (f"refused: {self.sbx_bin!r} not found on PATH: install "
                "Docker Sandboxes or set sandbox.backend: docker")

    def _recover_sandbox(self, *, command: str, marker: str, t: int,
                         out: str, exit_code: int | None, truncated: bool
                         ) -> tuple[str, int | None, bool] | None:
        low = out.lower()
        if exit_code not in (0, None) and ("no such sandbox" in low
                                           or "not found" in low):
            # The sandbox vanished (removed elsewhere, `sbx reset`): recreate
            # it and retry the command ONCE so the agent keeps working.
            self._run.mark_dead()
            retry_err = self._run.ensure_started()
            if retry_err is None:
                try:
                    retry_out, retry_code, retry_trunc = self._run.exec(
                        agent_id=self.agent_id, command=command,
                        marker=marker, timeout=t,
                        max_output_bytes=self.max_output_bytes)
                except Exception:
                    return None  # the original result stands
                if retry_code == 0:
                    retry_out += ("\n[sandbox was recreated after it had been "
                                  "removed]")
                return self._truncate((retry_out, retry_code, retry_trunc))
            out += f"\n[sandbox could not be recreated: {retry_err}]"
            return (out, exit_code, truncated)
        return None


# The run-level slice of a sandbox settings dict. The rest (rules_dir,
# skills_dir) are the PER-AGENT session's -- the hunter prompt reads them off
# the backend -- and must never reach the sandbox constructor, or the first
# agent's run creation dies with a TypeError. A guard test asserts this still
# covers every SbxRun parameter.
_RUN_SETTING_KEYS = frozenset({
    "image", "cpus", "memory", "skills", "pull", "deny_network",
    "allow_network", "disable_telemetry", "primary_dir", "command_timeout",
    "max_output_bytes", "sbx_bin",
})


def _run_settings(settings: dict | None) -> dict:
    """The run-level slice of a sandbox settings dict (see above)."""
    return {k: v for k, v in (settings or {}).items() if k in _RUN_SETTING_KEYS}


# Run-scoped registry: one sandbox per repo per process.
RUNS = RunRegistry(lambda repo, settings: SbxRun(
    repo_path=repo, **_run_settings(settings)))


def get_sbx_run(repo: str | Path, settings: dict | None = None) -> SbxRun:
    """The shared run sandbox for ``repo`` (created on first use)."""
    return RUNS.get(repo, settings)


def shutdown_sbx(repo: str | Path | None = None) -> None:
    """Remove the run sandbox(s) for ``repo`` (default: all). Idempotent."""
    RUNS.shutdown(repo)


# ORPHAN_IDLE_SECONDS is imported from run_base: one meaning of "idle" for
# both backends, and the reason for its value is documented there.


# The throwaway workspace a sandbox's run creates for it. Named after the
# sandbox, so the sweep can pair a dead sandbox with the workspace left on the
# host: `sbx rm` deletes the sandbox's state, its Git worktrees and its scoped
# secrets, but never this directory -- so a SIGKILL'd run leaks it, and only
# the sweep can take it back.
_PRIMARY_PREFIX = "cyber-sbx-primary-"


def _primary_path(sandbox_name: str) -> Path:
    """The host workspace belonging to `sandbox_name`."""
    return (Path(tempfile.gettempdir())
            / f"{_PRIMARY_PREFIX}{sandbox_name.removeprefix('cyber-sbx-')}")


def _remove_primary(sandbox_name: str) -> None:
    """Delete a dead sandbox's workspace. Never raises, never touches another."""
    shutil.rmtree(_primary_path(sandbox_name), ignore_errors=True)


def _idle_seconds(entry: dict, *, now: datetime) -> float | None:
    """Seconds since the sandbox's last exec, or None if not established.

    The daemon reports `last_used_at` in RFC 3339; a sandbox whose stamp is
    missing or unparseable yields None and is left alone (never remove what
    you cannot measure).
    """
    raw = str(entry.get("last_used_at") or "").strip()
    if not raw:
        return None
    try:
        stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return (now - stamp).total_seconds()


def _idle_orphans(entries: dict[str, dict], *, live: Iterable[str],
                  idle_seconds: float, now: datetime) -> list[str]:
    """Our sandboxes, not ours right now, and idle past the threshold.

    Liveness here is the daemon's own `last_used_at` -- there is no
    harness-side state, and the operator's habitual cleanup stays `sbx
    prune`, which the CLI documents as safe to run whenever.
    """
    orphans: list[str] = []
    for name in orphan_targets(list(entries), live=live):
        age = _idle_seconds(entries[name], now=now)
        if age is not None and age > idle_seconds:
            orphans.append(name)
    return orphans


def sweep_orphans(*, sbx_bin: str = "sbx",
                  live: Iterable[str] | None = None,
                  idle_seconds: float = ORPHAN_IDLE_SECONDS) -> list[str]:
    """Remove run sandboxes a killed harness left behind.

    Runs at scan start: a SIGKILL'd harness cannot run its own teardown, and
    a local sandbox never expires on its own (`sbx settings list` has no TTL;
    TTL is cloud-only), so an idle microVM would cost host CPU until someone
    acts. This is the harness's half of that; the operator's documented
    habitual cleanup is `sbx prune`, which only ever touches stopped
    sandboxes.

    A sandbox is an orphan when its name is ours, it is not one this process
    is using, and the daemon reports it idle past `idle_seconds` (its
    `last_used_at` advances on every exec, so a live run never looks idle).
    Each sandbox removed takes its throwaway host workspace with it, since
    `sbx rm` leaves that behind and a SIGKILL'd run leaked exactly that pair.
    Idempotent; never raises. Returns the names it removed.
    """
    try:
        proc = cli_utils.run_cli([sbx_bin, "ls", "--json"], timeout=120)
    except Exception:
        return []
    try:
        payload = json.loads(proc.stdout or "{}")
    except (TypeError, ValueError):
        # The CLI prints its own warnings before the JSON (e.g. the Docker
        # Hub refresh lock); take the object out of the output and retry once.
        raw = proc.stdout or ""
        try:
            payload = json.loads(raw[raw.index("{"):raw.rindex("}") + 1])
        except (TypeError, ValueError):
            return []
    entries = payload.get("sandboxes") if isinstance(payload, dict) else payload
    if not isinstance(entries, list):
        return []
    by_name = {str(e.get("name") or "").strip(): e
               for e in entries if isinstance(e, dict)}
    by_name.pop("", None)
    if live is None:
        live = RUNS.live_names()
    targets = _idle_orphans(by_name, live=live, idle_seconds=idle_seconds,
                            now=datetime.now(timezone.utc))
    if not targets:
        return []
    try:
        removal = cli_utils.run_cli([sbx_bin, "rm", "--force", *targets],
                                    timeout=300)
    except Exception:
        return []
    if removal.returncode != 0:
        return []
    for name in targets:
        _remove_primary(name)
    return targets


install_crash_hooks(RUNS.shutdown)

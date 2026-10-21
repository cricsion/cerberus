from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from harness.config import config_default

from . import cli_utils
from .backend_base import SandboxShellBackend
from .run_base import (DEFAULT_COMMAND_TIMEOUT, DEFAULT_IMAGE,
                       DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_RULES_DIR,
                       ORPHAN_IDLE_SECONDS, SHARED_CACHE_DIRS, RunRegistry,
                       RunSandboxBase, install_crash_hooks, sweep_orphans_via)
from .settings_defaults import (SBX_BIN, SBX_CPUS, SBX_IMAGE, SBX_MEMORY)
from .validation import (DEFAULT_PULL, DEFAULT_SKILLS, validate_cpus,
                         validate_image, validate_memory, validate_pull,
                         validate_skills)

DEFAULT_SBX_IMAGE = SBX_IMAGE
DEFAULT_SBX_CPUS = SBX_CPUS
DEFAULT_SBX_MEMORY = SBX_MEMORY
DEFAULT_SBX_BIN = SBX_BIN

__all__ = ["SbxBackend", "SbxRun", "get_sbx_run", "shutdown_sbx",
           "sweep_orphans", "DEFAULT_IMAGE"]


def _sbx_bin(value: str | None = None) -> str:
    return str(value or config_default("sandbox.sbx.bin") or DEFAULT_SBX_BIN)


def _dedupe(hosts) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(h).strip() for h in (hosts or [])
                               if str(h).strip()))

class SbxRun(RunSandboxBase):
    cli_label = "sbx"
    # Booting/tearing down a microVM is not a docker run.
    DESTROY_TIMEOUT: float = 120
    CREATE_TIMEOUT: float = 600
    # sbx has no tmpfs: every exec must mkdir the shared cache dirs itself.
    EXTRA_EXEC_MKDIR_DIRS: tuple[str, ...] = SHARED_CACHE_DIRS

    def __init__(self, *, repo_path: str | Path, image: str = DEFAULT_SBX_IMAGE,
                 cpus: str = DEFAULT_SBX_CPUS, memory: str = DEFAULT_SBX_MEMORY,
                 skills: str = DEFAULT_SKILLS,
                 pull: str = DEFAULT_PULL,
                 deny_network: tuple[str, ...] | list[str] = (),
                 allow_network: tuple[str, ...] | list[str] = (),
                 disable_telemetry: bool = True,
                 primary_dir: str | Path | None = None,
                 command_timeout: int = DEFAULT_COMMAND_TIMEOUT,
                 max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
                 sbx_bin: str = DEFAULT_SBX_BIN) -> None:
        self.cpus = validate_cpus(cpus)
        self.memory = validate_memory(memory)
        self.skills = validate_skills(skills)
        self.pull = validate_pull(pull)
        self.deny_network = _dedupe(deny_network)
        self.allow_network = _dedupe(allow_network)
        self.disable_telemetry = bool(disable_telemetry)
        self.sbx_bin = _sbx_bin(sbx_bin)
        # The throwaway read-write primary workspace sbx requires; created lazily (first ensure_started) so constructing has no fs side effects.
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

    def _child_env(self) -> dict[str, str]:
        if not self.disable_telemetry:
            return dict(os.environ)
        env = dict(os.environ)
        env["SBX_NO_TELEMETRY"] = "1"
        return env

    def _workdir_args(self) -> list[str]:
        return ["--workdir", str(self.repo_path)]

    def _primary(self) -> Path:
        if self._primary_dir is None:
            # Named after the sandbox so the sweep can pair it (`sbx rm` does not delete it); uuid-unique and cached across recreation.
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
        argv += [str(self._primary()), f"{self.repo_path}:ro"]
        return argv

    def _apply_allow_network(self) -> str | None:
        if not self.allow_network:
            return None
        argv = [self.sbx_bin, "policy", "allow", "network",
                "--sandbox", self._name, ",".join(self.allow_network)]
        try:
            proc = cli_utils.run_cli(argv, timeout=60, env=self._child_env())
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            # never fail the run over a policy add; these are run_cli's only
            # raises (a non-zero exit is handled just below)
            return f"could not add egress allow rules: {e}"
        if proc.returncode != 0:
            return (f"could not allow {', '.join(self.allow_network)} "
                    f"({(proc.stdout or '').strip()[:160]})")
        return None

    def _start_locked(self) -> str | None:
        for attempt in (0, 1):
            # A missing CLI binary raises past here: the execute() boundary in
            # backend_base converts it once for every backend.
            proc = cli_utils.run_cli(self._create_args(),
                                     timeout=self.CREATE_TIMEOUT,
                                     env=self._child_env())
            out = (proc.stdout or "").strip()
            if proc.returncode == 0:
                self._started = True
                # Allow rules are per-sandbox: they die with it and never touch the operator's global policy.
                allow_err = self._apply_allow_network()
                if allow_err:
                    print(f"[sbx] {allow_err}", file=sys.stderr, flush=True)
                return None
            low = out.lower()
            if attempt == 0 and ("exist" in low or "in use" in low):
                # A stale sandbox holds our name: clear it and retry once with a fresh name (also the path after a dead VM).
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
        # Remove our temp primary workspace even when the sandbox was never created, or every failed run leaks one.
        self._cleanup_primary()

    def destroy_argv(self) -> list[str]:
        return [self.sbx_bin, "rm", "--force", self._name]

class SbxBackend(SandboxShellBackend):
    HANG_NOTE = "sbx exec client hang"

    def __init__(self, *, repo_path: str | Path, image: str = DEFAULT_SBX_IMAGE,
                 cpus: str = DEFAULT_SBX_CPUS, memory: str = DEFAULT_SBX_MEMORY,
                 skills: str = DEFAULT_SKILLS,
                 pull: str = DEFAULT_PULL,
                 deny_network: tuple[str, ...] | list[str] = (),
                 allow_network: tuple[str, ...] | list[str] = (),
                 disable_telemetry: bool = True,
                 primary_dir: str | Path | None = None,
                 command_timeout: int = DEFAULT_COMMAND_TIMEOUT,
                 max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
                 sbx_bin: str = DEFAULT_SBX_BIN, rules_dir: str = DEFAULT_RULES_DIR,
                 run: SbxRun | None = None, agent_id: str | None = None) -> None:
        # Validated before super(): a bad setting must fail at construction, not inside a `sbx create`.
        self.image = validate_image(str(image or DEFAULT_SBX_IMAGE))
        self.cpus = validate_cpus(cpus)
        self.memory = validate_memory(memory)
        self.skills = validate_skills(skills)
        self.pull = validate_pull(pull)
        self.deny_network = _dedupe(deny_network)
        self.allow_network = _dedupe(allow_network)
        self.disable_telemetry = bool(disable_telemetry)
        self.sbx_bin = _sbx_bin(sbx_bin)
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
            run=run, agent_id=agent_id,
            command_timeout=command_timeout,
            max_output_bytes=max_output_bytes,
            rules_dir=rules_dir,
            # The machine's Balanced policy governs egress here (never mutated), so that is what the prompts say.
            network="balanced")

    def _missing_binary_message(self) -> str:
        return (f"refused: {self.sbx_bin!r} not found on PATH: install "
                "Docker Sandboxes (brew install docker/tap/sbx) or set "
                "sandbox.backend: docker")

    def _recover_sandbox(self, *, command: str, marker: str, t: int,
                         out: str, exit_code: int | None, truncated: bool
                         ) -> tuple[str, int | None, bool] | None:
        low = out.lower()
        if exit_code not in (0, None) and ("no such sandbox" in low
                                           or "not found" in low):
            # Sandbox vanished (removed elsewhere, `sbx reset`): recreate and retry the command ONCE so the agent keeps working.
            self._run.mark_dead()
            try:
                retry_err = self._run.ensure_started()
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                out += f"\n[sandbox could not be recreated: {e}]"
                return (out, exit_code, truncated)
            if retry_err is None:
                try:
                    retry_out, retry_code, retry_trunc = self._run.exec(
                        agent_id=self.agent_id, command=command,
                        marker=marker, timeout=t,
                        max_output_bytes=self.max_output_bytes)
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    return None  # the original result stands
                if retry_code == 0:
                    retry_out += ("\n[sandbox was recreated after it had been "
                                  "removed]")
                return self._truncate((retry_out, retry_code, retry_trunc))
            out += f"\n[sandbox could not be recreated: {retry_err}]"
            return (out, exit_code, truncated)
        return None

# Run-level slice of a sandbox settings dict: rules_dir is PER-AGENT and must
# never reach the run constructor (TypeError, before super()).
_RUN_SETTING_KEYS = frozenset({
    "image", "cpus", "memory", "skills", "pull", "deny_network",
    "allow_network", "disable_telemetry", "primary_dir", "command_timeout",
    "max_output_bytes", "sbx_bin",
})

RUNS = RunRegistry(SbxRun, _RUN_SETTING_KEYS)

def get_sbx_run(repo: str | Path, settings: dict | None = None) -> SbxRun:
    return RUNS.get(repo, settings)

def shutdown_sbx(repo: str | Path | None = None) -> None:
    RUNS.shutdown(repo)

# Throwaway run workspace: `sbx rm` never deletes it, so the sweep pairs by name.
_PRIMARY_PREFIX = "cyber-sbx-primary-"

def _primary_path(sandbox_name: str) -> Path:
    return (Path(tempfile.gettempdir())
            / f"{_PRIMARY_PREFIX}{sandbox_name.removeprefix('cyber-sbx-')}")

def _remove_primary(sandbox_name: str) -> None:
    shutil.rmtree(_primary_path(sandbox_name), ignore_errors=True)

def _idle_seconds(entry: dict, *, now: datetime) -> float | None:
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

def _ls_payload(raw: str):
    """`sbx ls --json` output -> payload. The CLI prints WARN lines before the
    object (e.g. the Docker Hub refresh lock), so retry on the {...} substring."""
    try:
        return json.loads(raw or "{}")
    except (TypeError, ValueError):
        try:
            return json.loads(raw[raw.index("{"):raw.rindex("}") + 1])
        except (TypeError, ValueError):
            return None

def _admin_env() -> dict[str, str]:
    env = dict(os.environ)
    env["SBX_NO_TELEMETRY"] = "1"
    return env

def sweep_orphans(*, sbx_bin: str | None = None,
                  live: Iterable[str] | None = None,
                  idle_seconds: float = ORPHAN_IDLE_SECONDS) -> list[str]:
    if sbx_bin is None:
        sbx_bin = _sbx_bin()
    entries: dict[str, dict] = {}

    def list_names() -> list[str]:
        proc = cli_utils.run_cli([sbx_bin, "ls", "--json"], timeout=120,
                                 env=_admin_env())
        payload = _ls_payload(proc.stdout or "")
        if payload is None:
            return []
        listed = payload.get("sandboxes") if isinstance(payload, dict) else payload
        if not isinstance(listed, list):
            return []
        entries.clear()
        entries.update({str(e.get("name") or "").strip(): e
                        for e in listed if isinstance(e, dict)})
        entries.pop("", None)
        return list(entries)

    def idle_age(name: str) -> float | None:
        entry = entries.get(name)
        if entry is None:
            return None
        return _idle_seconds(entry, now=datetime.now(timezone.utc))

    def remove(targets: list[str]) -> bool:
        proc = cli_utils.run_cli([sbx_bin, "rm", "--force", *targets],
                                 timeout=300, env=_admin_env())
        if proc.returncode != 0:
            return False
        for name in targets:
            _remove_primary(name)
        return True

    return sweep_orphans_via(
        registry=RUNS, list_names=list_names, idle_age=idle_age,
        remove=remove, live=live, idle_seconds=idle_seconds)

install_crash_hooks(RUNS.shutdown)

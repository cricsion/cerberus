from __future__ import annotations

import io
import posixpath
import shlex
import tarfile
import threading
import uuid
from pathlib import Path
from typing import Iterable

from deepagents.backends.protocol import (DeleteResult, EditResult,
                                          FileDownloadResponse,
                                          FileUploadResponse, GlobResult,
                                          GrepResult, LsResult, ReadResult,
                                          WriteResult)
from deepagents.backends.sandbox import BaseSandbox

from . import docker_channel
from .backend_base import SandboxShellBackend
from .docker_channel import ExecResult
from .run_base import (RunRegistry, install_crash_hooks, sweep_orphans_via)
from .run_base import (DEFAULT_COMMAND_TIMEOUT, DEFAULT_IMAGE,
                       DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_MEMORY,
                       DEFAULT_RULES_DIR, ORPHAN_IDLE_SECONDS, RESET_COMMAND)
from .settings_defaults import (CPUS as DEFAULT_CPUS,
                                PIDS_LIMIT as DEFAULT_PIDS_LIMIT)
from .validation import (DEFAULT_NETWORK, validate_cpus, validate_image,
                         validate_network)

__all__ = ["DockerSandboxBackend", "RunSandbox", "DEFAULT_IMAGE",
           "get_run_sandbox", "shutdown_run_sandbox", "reap_orphans",
           "sweep_orphans"]


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


def _tar_uid_gid(user: str) -> tuple[int, int]:
    """Tar-stream member owner derived from the container ``user`` so an
    extracted file is writable by the agent user. Numeric ``uid[:gid]``
    only; a named owner falls back to the image default."""
    uid_text, _, gid_text = str(user).partition(":")
    try:
        uid = int(uid_text)
    except ValueError:
        return _IMAGE_UID_GID
    try:
        gid = int(gid_text) if gid_text else uid
    except ValueError:
        gid = _IMAGE_UID_GID
    return uid, gid


# Image user (uid/gid) of the run container for non-numeric owners: tar-stream
# members carry it so an extracted file stays writable by the agent user.
_IMAGE_UID_GID = 1000


def _tar_bytes(name: str, data: bytes, *, uid: int = _IMAGE_UID_GID,
               gid: int = _IMAGE_UID_GID) -> bytes:
    """One in-memory tar member for :func:`docker_channel.put_archive`."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        info.mode = 0o644
        info.mtime = 0
        info.uid = info.gid = int(uid)
        info.uname = info.gname = ""
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _untar_first(tar_bytes: bytes):
    """First member of a ``get_archive`` stream, as raw bytes.

    ``None`` when the stream holds no regular file (a directory pull returns a
    dir node first) — the adapter maps that to the docs' ``is_directory``.
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
            member = next((m for m in tar.getmembers() if m.isfile()), None)
            if member is None:
                return None
            inner = tar.extractfile(member)
            return None if inner is None else inner.read()
    except (OSError, tarfile.TarError):
        return None


def _transfer_error_text(text: str, fallback: str = "") -> str:
    """Map a docker API message to the docs' file-operation literals
    (``file_not_found``/``permission_denied``/``is_directory``); a
    backend-specific first line is the unreachable catch-all, ``fallback``
    when nothing was said."""
    text = (text or "").strip()
    low = text.lower()
    if "permission denied" in low or "read-only" in low:
        return "permission_denied"
    if ("no such file" in low or "could not find the file" in low
            or "does not exist" in low or "not found" in low):
        return "file_not_found"
    if "is a directory" in low:
        return "is_directory"
    return text.splitlines()[0][:200] if text else fallback


def _transfer_error(e: Exception) -> str:
    """Normalize a docker API failure to the docs' file-operation literals
    ('On failure, error is one of file_not_found, permission_denied,
    is_directory, or invalid_path')."""
    return _transfer_error_text(str(getattr(e, "explanation", "") or e),
                                fallback=type(e).__name__)


class RunSandbox:
    """The per-repo run container, on the docker-py channel.

    ONE container per repo shared by every agent of the run (the registry in
    :mod:`harness.sandbox.run_base` holds it). Confinement is composed at
    creation (:func:`docker_channel.create_sandbox`); execution is one
    bounded exec channel (:func:`docker_channel.exec_core`), demuxed.
    """

    cli_label = "docker"

    def __init__(self, *, repo_path: str | Path, image: str = DEFAULT_IMAGE,
                 user: str = "1000:1000",
                 command_timeout: int = DEFAULT_COMMAND_TIMEOUT,
                 max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
                 memory: str = DEFAULT_MEMORY,
                 cpus: str = DEFAULT_CPUS,
                 pids_limit: int = DEFAULT_PIDS_LIMIT,
                 network: str = DEFAULT_NETWORK,
                 mask_paths: tuple[str, ...] | list[str] | None = None) -> None:
        # Re-start-after-death flag: a name a corpse may still hold is never
        # reused; the next start allocates a fresh one (id stays the dead
        # name until then).
        self._fresh_name_needed = False
        self.user = str(user)
        self.memory = str(memory)
        self.cpus = str(cpus)
        # Construction-time conversion: garbage fails the resolve (callers
        # degrade to the local backend) instead of silently running 1 CPU —
        # every other numeric sandbox setting has the same raise contract.
        self._nano_cpus = validate_cpus(cpus)
        self.pids_limit = max(16, int(pids_limit))
        # Egress: bridge = full egress (Docker NAT), none = none; host is refused (host netns). Validated here: a bad sandbox.network fails first.
        self.network = validate_network(network)
        # Credential files to hide from the shell (egress is live, so a key must not be readable): each gets a read-only /dev/null bind.
        if mask_paths is None:
            # No guard on purpose: find_credential_files is already fail-soft and a catch-all could only fail OPEN (mask_paths = ()).
            from harness.sandbox.credentials import find_credential_files
            mask_paths = find_credential_files(repo_path)
        self.mask_paths = tuple(_validate_mask_paths(repo_path=repo_path,
                                                     mask_paths=mask_paths))
        # Validated here rather than in the channel: a bad image must fail
        # the resolve, not the first exec.
        self.image = validate_image(str(image or DEFAULT_IMAGE))
        self.repo_path = Path(repo_path).resolve()
        self.command_timeout = max(1, int(command_timeout))
        self.max_output_bytes = max(0, int(max_output_bytes))
        # Random name: same-repo runs must not collide; a stale sandbox
        # from a crashed run must not be adopted.
        self._name = f"cyber-sandbox-run-{uuid.uuid4().hex[:12]}"
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

    def ensure_started(self) -> str | None:
        with self._lock:
            if self._closed:
                return "sandbox is closed"
            if self._started:
                return None
            return self._start_locked()

    def exec(self, *, command: str, marker: str, timeout: int,
             max_output_bytes: int,
             env: list[tuple[str, str]] | None = None) -> ExecResult:
        """One demuxed exec on the run's channel (agent or system lane)."""
        return docker_channel.exec_core(
            self._name, command=command, marker=marker, timeout=timeout,
            max_output_bytes=max_output_bytes, env=env,
            workdir=str(self.repo_path))

    def mark_dead(self) -> None:
        self._on_death()
        with self._lock:
            self._started = False

    def _on_death(self) -> None:
        # The corpse may still hold the name (the best-effort removal on the
        # recover path can fail): the recreation picks a fresh one at start.
        self._fresh_name_needed = True

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

    def remove(self) -> None:
        # Teardown runs on crash paths too: the channel variant swallows
        # everything (absent/gone is success), so a raise here can only be a
        # harness bug and must surface.
        docker_channel.remove_container(self._name)

    def reset_agent_scratch(self) -> str | None:
        with self._lock:
            started, closed = self._started, self._closed
        if not started or closed:
            return None
        res = docker_channel.exec_core(
            self._name, command=RESET_COMMAND,
            marker=f"reset-{uuid.uuid4().hex[:8]}", timeout=120,
            max_output_bytes=4096, env=(), workdir=str(self.repo_path))
        if res.error:
            return (f"{self.cli_label} agent-scratch reset failed: "
                    f"{res.error[:160]}")
        if res.exit_code not in (0, None):
            return (f"{self.cli_label} agent-scratch reset failed: "
                    f"{(res.stdout or res.error or '').strip()[:160]}")
        return None

    def _codegraph_shadow(self) -> str:
        """Host path of the RW ``<repo>/.codegraph`` shadow dir, or ``""``.

        Fail-soft by contract: an un-creatable dir just omits the shadow; the
        index build then fails open ("continuing unindexed") at its own gate.
        """
        cg = Path(str(self.repo_path)).resolve() / ".codegraph"
        try:
            cg.mkdir(parents=True, exist_ok=True)
        except OSError:
            return ""
        return str(cg)

    def _start_locked(self) -> str | None:
        if self._fresh_name_needed:
            # Re-start after death: a name a corpse may still hold is never
            # reused — create under a fresh one.
            self._fresh_name_needed = False
            self._name = f"cyber-sandbox-run-{uuid.uuid4().hex[:12]}"
        try:
            name = docker_channel.create_sandbox(
                name=self._name, image=self.image, repo=str(self.repo_path),
                network=self.network, nano_cpus=self._nano_cpus,
                pids_limit=self.pids_limit, memory=self.memory,
                user=self.user, mask_paths=self.mask_paths,
                codegraph_shadow=self._codegraph_shadow())
            docker_channel.start_sandbox(name)
        except Exception as e:
            # create-then-start: a start failure (or a name conflict on
            # create) leaves a corpse holding self._name. Remove it now and
            # never reuse the name — otherwise the next start collides with
            # it forever. Removal is fail-soft: a create failure left no
            # corpse, and a refused rm is re-swept at the next scan start.
            docker_channel.remove_container(self._name)
            self._fresh_name_needed = True
            # Probe AFTER the corpse removal (the probe must not skip it):
            # DockerClient.ping separates a REFUSING daemon — mount/image
            # advice below is accurate — from an UNREACHABLE one, where the
            # run container advice would be invented ("is Docker Desktop
            # running / DOCKER_HOST wrong / SDK missing" is the truth).
            unreachable = docker_channel.daemon_unreachable_reason()
            if unreachable is not None:
                return (f"docker daemon unreachable (is Docker Desktop "
                        f"running / DOCKER_HOST set correctly?): "
                        f"{unreachable[:200]}")
            text = (str(getattr(e, "explanation", "") or e) or "").strip()
            if "not shared" in text:
                return (f"docker refused the repo mount ({self.repo_path}): "
                        "add it to Docker Desktop > Settings > Resources > "
                        "File Sharing, or use a repo path under a shared "
                        f"directory. docker said: {text[:200]}")
            return f"docker run failed ({self.image}): {text[:300]}"
        self._started = True
        return None


class DockerSandboxBackend(SandboxShellBackend, BaseSandbox):
    """deepagents ``BaseSandbox`` adapter over the per-repo run container.

    Primitives: ``id`` → the run's container name; ``execute()`` → the shared
    shell lane (the agent's execute tool, scanner runners, and every
    library-generated FS script ride this one bounded channel);
    ``upload_files()``/``download_files()`` → the tar transfer plane, as
    ordered per-file responses (one failure is reported in its response,
    never aborts the batch). Every other FS op is DERIVED by ``BaseSandbox``
    from those and therefore runs INSIDE the container; before delegating,
    each op confines its path through :func:`~harness.paths.resolve_tool_path`
    — an escaping path resolves onto a never-created in-repo sentinel, so the
    refusal reads as the sandbox's own not-found and no path outside the repo
    is ever addressed. The repo bind is read-only, so in-repo writes surface
    as container-side permission errors and never mutate the target tree.
    """

    def __init__(self, *, repo_path: str | Path, image: str = DEFAULT_IMAGE,
                 user: str = "1000:1000",
                 command_timeout: int = DEFAULT_COMMAND_TIMEOUT,
                 max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
                 memory: str = DEFAULT_MEMORY,
                 cpus: str = DEFAULT_CPUS,
                 pids_limit: int = DEFAULT_PIDS_LIMIT,
                 network: str = DEFAULT_NETWORK,
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
        super().__init__(
            repo_path=repo_path,
            run_factory=lambda: RunSandbox(
                repo_path=repo_path, image=self.image, user=self.user,
                command_timeout=command_timeout,
                max_output_bytes=max_output_bytes, memory=self.memory,
                cpus=self.cpus, pids_limit=self.pids_limit,
                network=network_mode,
                mask_paths=self.mask_paths),
            run=run, agent_id=agent_id,
            command_timeout=command_timeout,
            max_output_bytes=max_output_bytes,
            rules_dir=rules_dir,
            network=network_mode)
        # Denial target for the confining FS overrides below: an in-repo path
        # that is never created (the repo bind is RO), so a denied op returns
        # the base's structured not-found instead of raising.
        self._sentinel = self.repo_path / f".denied-{uuid.uuid4().hex[:16]}"

    # -- path confinement -----------------------------------------------------

    def _confine(self, path: str) -> str:
        """One contract for every accepted spelling (RepoLocalBackend parity).

        ``resolve_tool_path`` accepts repo-relative, host-absolute-under-root,
        and virtual leading-slash spellings; anything that escapes resolves to
        the denial sentinel — never followed, never created. Same-path mounts
        make the resolved host form valid at the identical container path.
        """
        from harness.paths import resolve_tool_path

        resolved = resolve_tool_path(path, self.repo_path)
        return str(self._sentinel if resolved is None else resolved)

    def ls(self, path: str) -> LsResult:
        return super().ls(self._confine(path))

    def read(self, file_path: str, offset: int = 0,
             limit: int = 2000) -> ReadResult:
        return super().read(self._confine(file_path), offset=offset,
                            limit=limit)

    def write(self, file_path: str, content: str) -> WriteResult:
        # Repo writes cannot succeed (RO bind) — the container refuses them.
        return super().write(self._confine(file_path), content)

    def edit(self, file_path: str, old_string: str, new_string: str,
             replace_all: bool = False) -> EditResult:
        return super().edit(self._confine(file_path), old_string, new_string,
                            replace_all=replace_all)

    def delete(self, file_path: str) -> DeleteResult:
        return super().delete(self._confine(file_path))

    def glob(self, pattern: str, path: str | None = None) -> GlobResult:
        return super().glob(pattern, self._confine(path or ""))

    def grep(self, pattern: str, path: str | None = None,
             glob: str | None = None, *,
             max_count: int | None = None) -> GrepResult:
        return super().grep(pattern, self._confine(path or ""), glob,
                            max_count=max_count)

    # -- transfer plane (BaseSandbox's fourth primitive) -----------------------

    def upload_files(self,
                     files: list[tuple[str, bytes]]) -> list[FileUploadResponse]:
        """App-level transfer plane: one tar ``put_archive`` per file. Parent
        dirs are ensured per-parent first (put_archive requires the
        extraction directory to exist), and a bad parent fails only its own
        files. Neither this nor ``download_files`` routes through
        ``_confine``: they need container-absolute paths, and the residual
        reach is the container's own RW tmpfs — no agent surface calls this
        plane."""
        started = self._run.ensure_started()
        if started:
            return [FileUploadResponse(path=path,
                                       error=f"sandbox unavailable: {started}")
                    for path, _ in files]
        parents = sorted({posixpath.dirname(path) for path, _ in files
                          if path.startswith("/")})
        # One mkdir per parent, never one combined `mkdir -p a b c`: a single
        # bad operand (an existing file at that name, a transient exec
        # failure) fails a combined call's exit code for the whole list even
        # when the other parents were created fine — and the partner contract
        # is "one failure is reported in its response, never aborts the
        # batch".
        parent_error: dict[str, str] = {}
        for parent in parents:
            mkdir = self.execute(f"mkdir -p {shlex.quote(parent)}", timeout=120)
            if mkdir.exit_code != 0:
                parent_error[parent] = _transfer_error_text(
                    mkdir.output, fallback="parent directory creation failed")
        out: list[FileUploadResponse] = []
        for path, content in files:
            if not path or not path.startswith("/") or not posixpath.basename(path):
                out.append(FileUploadResponse(path=path, error="invalid_path"))
            else:
                reason = parent_error.get(posixpath.dirname(path))
                if reason:
                    out.append(FileUploadResponse(path=path, error=reason))
                    continue
                uid, gid = _tar_uid_gid(self._run.user)
                try:
                    docker_channel.put_archive(
                        self._run.name, posixpath.dirname(path),
                        _tar_bytes(posixpath.basename(path), content,
                                   uid=uid, gid=gid))
                except Exception as e:
                    out.append(FileUploadResponse(path=path,
                                                  error=_transfer_error(e)))
                else:
                    out.append(FileUploadResponse(path=path, error=None))
        return out

    def download_files(self, paths: list[str]) -> list[FileDownloadResponse]:
        """App-level transfer plane: per-path ``get_archive`` stream, untarred
        to the single regular-file member (directories and non-regular nodes
        report ``is_directory`` per the docs' normalized literals)."""
        started = self._run.ensure_started()
        if started:
            return [FileDownloadResponse(path=path, content=None,
                                         error=f"sandbox unavailable: {started}")
                    for path in paths]
        out: list[FileDownloadResponse] = []
        for path in paths:
            if not path or not path.startswith("/"):
                out.append(FileDownloadResponse(path=path, content=None,
                                                error="invalid_path"))
                continue
            try:
                tar_bytes = docker_channel.get_archive(self._run.name, path)
            except Exception as e:
                out.append(FileDownloadResponse(path=path, content=None,
                                                error=_transfer_error(e)))
                continue
            content = _untar_first(tar_bytes)
            if content is None:
                out.append(FileDownloadResponse(path=path, content=None,
                                                error="is_directory"))
            else:
                out.append(FileDownloadResponse(path=path, content=content,
                                                error=None))
        return out

    def _recover_sandbox(self, *, res: ExecResult, out: str,
                         exit_code: int | None, truncated: bool
                         ) -> tuple[str, int | None, bool] | None:
        if res.exit_code == 126 and "exec failed" in out:
            # "exec failed" reports the exec, not the container: an exec can
            # lose its race with a transient daemon hiccup while the shared
            # container is alive and mid-run. Ask the daemon (inspect →
            # State.Running) before tearing anything down; only a genuinely
            # dead/stopped container is removed and marked for recreation.
            if docker_channel.container_alive(self._run.name):
                return None
            # Dead: remove the corpse (by its current name — mark_dead only
            # flags it), then mark the run dead so the next exec recreates
            # under a fresh name.
            self._run.remove()
            self._run.mark_dead()
        return None


# Run-level slice of a sandbox settings dict: rules_dir is PER-AGENT and must
# never reach the container constructor (TypeError).
_RUN_SETTING_KEYS = frozenset({
    "image", "user", "command_timeout", "max_output_bytes", "memory", "cpus",
    "pids_limit", "network", "mask_paths",
})

RUNS = RunRegistry(RunSandbox, _RUN_SETTING_KEYS)


def get_run_sandbox(repo: str | Path, settings: dict | None = None) -> RunSandbox:
    return RUNS.get(repo, settings)


def shutdown_run_sandbox(repo: str | Path | None = None) -> None:
    RUNS.shutdown(repo)


def sweep_orphans(*, live: Iterable[str] | None = None,
                  idle_seconds: float = ORPHAN_IDLE_SECONDS) -> list[str]:
    # NOT client.containers.prune(filters={"label": RUN_LABEL}) (md 910-928;
    # v1.56.yaml ContainerPrune 9739): the docs say prune deletes STOPPED
    # containers — our orphan corpses are RUNNING, so prune would miss them
    # even apart from its delete-what-matches contract, which cannot express
    # this sweep's inverse: never remove what it cannot measure. The loop
    # (list wire rows → per-container age evidence → remove-by-name) decides
    # KEEP vs REMOVE per container from daemon-published facts.
    return sweep_orphans_via(
        registry=RUNS, list_names=docker_channel.list_sandbox_names,
        idle_age=docker_channel.last_exec_event_age,
        # Fail-soft + honest by channel contract: absent/gone is success (a
        # corpse that vanished between list and rm must not fail the sweep),
        # a REFUSAL is reported as not-removed.
        remove_one=docker_channel.remove_container,
        live=live, idle_seconds=idle_seconds)


def reap_orphans() -> None:
    RUNS.shutdown()


install_crash_hooks(RUNS.shutdown)

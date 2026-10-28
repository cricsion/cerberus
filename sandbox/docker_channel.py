"""docker-py channel: one transport for every docker-lane sandbox action.

Doc-verified against docker-py 7.1.0 (api.html / containers.html / client.html):

- ``exec_start(stream=True, demux=True)`` yields (stdout, stderr) frames —
  exactly one side is bytes per frame, the other None — and
  ``exec_inspect()`` gives the exit code.
- ``put_archive``/``get_archive`` are the tar transfer plane.
- ``containers.create`` expresses the confinement contract; ``init=True``
  gives the daemon's init to reap SIGKILLed exec processes (PID 1 here is
  ``sleep infinity`` and would not).
- Sweep recon rides the LOW-LEVEL ``api.containers`` / ``inspect_container``
  / ``events`` — ``docker ps`` wire dicts (``Names``/``Created``); the
  high-level sparse list yields ``None`` names because the list endpoint
  never sends ``Name``.
- ``docker.from_env()`` honors DOCKER_HOST / Docker Desktop contexts.
- ``DockerClient.ping`` separates a refusing daemon from an unreachable one
  on the start-failure path.

ONE lazily-built client (600s socket read deadline) serves every call site.
Lazy ``docker`` imports keep local mode free of the SDK; tests inject
through ``client_for``.
"""
from __future__ import annotations

import shlex
import threading
import time
from dataclasses import dataclass

from .cli_utils import BYTE_CAP_FACTOR, EXEC_TAG

__all__ = ["ExecResult", "HANG_NOTE", "client_for", "create_sandbox",
           "daemon_unreachable_reason", "exec_core", "kill_exec_marker",
           "remove_container", "list_sandbox_names", "container_alive",
           "put_archive", "get_archive", "last_exec_event_age",
           "DOCKER_LABEL_KEY", "DOCKER_LABEL_VALUE", "RUN_LABEL"]

DOCKER_LABEL_KEY = "cyber.agent.sandbox"
DOCKER_LABEL_VALUE = "run"
RUN_LABEL = f"{DOCKER_LABEL_KEY}={DOCKER_LABEL_VALUE}"

HANG_NOTE = "exec client hang"


@dataclass(frozen=True)
class ExecResult:
    """One exec result. ``error`` non-empty marks INFRA (setup failure,
    container gone, daemon unreachable) — never the command's own exit."""
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    truncated: bool = False
    error: str = ""


# ONE cached client per process (its 600s socket read deadline is the
# last-resort bound for a read that never returns). Tests patch this seam.
_client = None
_client_lock = threading.Lock()


def client_for():
    """The process's ``DockerClient``, built on first use. Lazy import:
    local mode and the in-container compute pack never import the SDK."""
    global _client
    with _client_lock:
        if _client is None:
            try:
                import docker
            except ImportError as e:
                raise RuntimeError(
                    "the docker SDK is not installed: pip install docker") from e
            _client = docker.from_env(timeout=600)
        return _client


def create_sandbox(*, name: str, image: str, repo: str, network: str,
                   nano_cpus: int, pids_limit: int, memory: str, user: str,
                   mask_paths: tuple[str, ...] | list[str] = (),
                   codegraph_shadow: str = "") -> str:
    """Create (not start) the confined per-repo container; returns ``name``.

    Raises the SDK's own exceptions (image bad, mount refused, name taken).
    The ``create`` return value is discarded and the passed name is
    returned: every downstream caller is str-addressed (a ``Container``
    object into the low-level API raises "Expected a string but found
    <Container ...>").
    """
    from docker.types import Mount

    mounts = [Mount(target=repo, source=repo, type="bind", read_only=True)]
    if codegraph_shadow:
        mounts.append(Mount(target=codegraph_shadow,
                            source=codegraph_shadow, type="bind"))
    for rel in mask_paths:
        mounts.append(Mount(target=f"{repo}/{rel}", source="/dev/null",
                            type="bind", read_only=True))

    client = client_for()
    client.containers.create(
        image, ["sleep", "infinity"], name=name, detach=True,
        user=str(user), network_mode=network,
        cap_drop=["ALL"], security_opt=["no-new-privileges"],
        pids_limit=max(16, int(pids_limit)), mem_limit=str(memory),
        memswap_limit=str(memory), nano_cpus=int(nano_cpus),
        read_only=True,
        tmpfs={"/tmp": "rw,size=1g,mode=1777",
               "/work": "rw,size=2g,mode=1777"},
        mounts=mounts,
        environment={"HOME": "/work", "TMPDIR": "/tmp",
                     "PYTHONPYCACHEPREFIX": "/work/.pyc",
                     "GIT_PAGER": "cat", "PAGER": "cat", "TERM": "dumb"},
        labels={DOCKER_LABEL_KEY: DOCKER_LABEL_VALUE},
        init=True,
    )
    return name


def daemon_unreachable_reason() -> str | None:
    """Why no daemon will answer right now, or ``None`` when one will.

    Runs on the START-FAILURE path only: a refusing daemon (mount/image
    advice applies) returns ``None``; an unreachable one (Desktop down,
    DOCKER_HOST wrong, SDK missing) returns the reason to show. Not a
    happy-path preflight — a working daemon pays no extra round-trip.
    """
    try:
        client_for().ping()
    except RuntimeError as e:
        # ``client_for`` itself: the SDK is not installed.
        return str(e)
    except Exception as e:  # ping: "an exception if the server isn't reachable"
        return _first_line(e)
    return None


def start_sandbox(name: str) -> None:
    """Start a created container. Deliberately create-then-start, not
    ``containers.run(detach=True)``: run() auto-pulls a missing image and
    retries instead of failing fast. A start failure still names its corpse
    for the caller's force-remove."""
    client_for().api.start(name)


def exec_core(name: str, *, command: str, marker: str, timeout: int,
              max_output_bytes: int,
              env: list[tuple[str, str]] | None = None,
              workdir: str | None = None) -> ExecResult:
    """One bounded exec: demuxed frames, in-container ``timeout -k 5`` as THE
    timeout, marker pkill on cap exceed or a past-deadline read failure.
    Never raises infra.

    Name-addressed, low-level on purpose: ``Container.exec_run`` streaming
    returns ``exit_code=None`` and no exec id, and the byte-cap path needs
    ``exec_inspect`` for the true rc.
    """
    # The wrapper bounds the command itself (timeout's TERM, then -k 5 KILL)
    # and creates the per-agent scratch dirs the env points at — one exec,
    # no setup call. Quoted so the command is parsed ONCE, by the inner bash.
    script = (f"{EXEC_TAG}={marker}; "
              f'mkdir -p "$HOME" "$TMPDIR"; '
              f"timeout -k 5 {int(timeout)} /bin/bash -c {shlex.quote(command)}")
    api = client_for().api
    try:
        created = api.exec_create(
            name, ["/bin/bash", "-c", script],
            environment=[f"{k}={v}" for k, v in (env or ())],
            workdir=workdir)
    except Exception as e:
        return ExecResult(exit_code=126, error=_child_gone(e))
    exec_id = created["Id"]

    stdout: list[bytes] = []
    stderr: list[bytes] = []
    total = 0
    cap = max(1, int(max_output_bytes)) * BYTE_CAP_FACTOR
    # Past-deadline checks live in the except branch only: a silent hang
    # blocks IN next() (the client's socket deadline raises there); a
    # chatty-but-EOFing stream is the byte cap's job below.
    deadline = time.monotonic() + timeout

    def partial() -> tuple[str, str]:
        return (b"".join(stdout).decode("utf-8", errors="replace"),
                b"".join(stderr).decode("utf-8", errors="replace"))

    def hang() -> ExecResult:
        # Deadline exceeded: pkill THIS exec's shell, keep what it emitted.
        kill_exec_marker(name, marker)
        out, err = partial()
        return ExecResult(stdout=out, stderr=err, exit_code=None,
                          truncated=True,
                          error=f"command timed out after {timeout}s "
                                f"({HANG_NOTE})")

    try:
        stream = api.exec_start(exec_id, stream=True, demux=True)
    except Exception as e:
        return ExecResult(exit_code=126, error=_child_gone(e))

    while True:
        if total > cap:
            # Over-budget: stop reading so a chatty command cannot drive
            # harness memory up, keep the tail emitted so far, and kill the
            # marked shell (the byte cap is not enforced in-container).
            kill_exec_marker(name, marker)
            out, err = partial()
            return ExecResult(stdout=out, stderr=err, exit_code=_inspect_rc(
                api, exec_id), truncated=True)
        try:
            frame = next(stream)
        except StopIteration:
            break
        except Exception as e:
            if time.monotonic() > deadline:
                return hang()
            return ExecResult(exit_code=126, error=_child_gone(e))
        # docker-py demuxes into (stdout, stderr) frames with EXACTLY one
        # side bytes and the other None (utils/socket.py demux_adaptor).
        out_chunk, err_chunk = frame
        if out_chunk is not None:
            total += len(out_chunk)
            stdout.append(out_chunk)
        if err_chunk is not None:
            total += len(err_chunk)
            stderr.append(err_chunk)

    rc = _inspect_rc(api, exec_id)
    if rc == 124:
        # The in-container timeout killed the command (124 is timeout's own
        # exit code): the bound fired exactly as designed — same agent shape
        # the client-hang path reports, without the client-side pkill.
        out, err = partial()
        return ExecResult(stdout=out, stderr=err, exit_code=124,
                          truncated=True,
                          error=f"command timed out after {timeout}s "
                                f"({HANG_NOTE})")
    return ExecResult(stdout=partial()[0], stderr=partial()[1], exit_code=rc)


def kill_exec_marker(name: str, marker: str) -> None:
    """Kill ONLY this exec's tagged shell and its children (the sandbox is shared).
    Fail-soft by contract: dead shells and dead containers never raise here."""
    try:
        api = client_for().api
        kill_cmd = (
            f"pids=$(pgrep -f {EXEC_TAG}={marker} 2>/dev/null); "
            f"for p in $pids; do pkill -KILL -P $p 2>/dev/null; kill -9 $p 2>/dev/null; done"
        )
        created = api.exec_create(name, ["/bin/sh", "-c", kill_cmd])
        api.exec_start(created["Id"], stream=False, demux=False)
    except Exception:
        pass


def remove_container(name: str) -> bool:
    """Force-remove a container by name. Absent/gone is success (teardown
    paths run on error paths too); only ``docker.errors.NotFound`` says so.
    Any refusal stays not-reaped: the next scan re-sweeps it."""
    try:
        client_for().api.remove_container(name, force=True)
        return True
    except Exception as e:
        return _is_not_found(e)  # absent == gone == reaped


def _is_not_found(e: Exception) -> bool:
    try:
        import docker.errors
    except ImportError:
        return False
    return isinstance(e, docker.errors.NotFound)


def list_sandbox_names() -> list[str]:
    """Names of every container carrying the run label (all states).

    Low-level on purpose: ``APIClient.containers()`` returns ``docker ps``
    wire dicts — the name lives in the ``Names`` array, slashes stripped.
    The high-level sparse listing yields ``None`` names: it feeds list-endpoint
    attrs into ``Container`` objects whose ``.name`` reads ``attrs['Name']``,
    a field the list endpoint never sends.
    """
    rows = client_for().api.containers(all=True, filters={"label": RUN_LABEL})
    names: list[str] = []
    for row in rows:
        listed = row.get("Names") or []
        raw = str(listed[0]) if listed else ""
        name = raw.lstrip("/")
        if not name:
            name = str(row.get("Id") or "")  # no name assigned: fall back to Id
        if name:
            names.append(name)
    return names


def container_alive(name: str) -> bool:
    """True when the daemon currently reports ``name`` as Running
    (``inspect_container`` is ``docker inspect``; absent raises → False)."""
    try:
        state = client_for().api.inspect_container(name).get("State") or {}
        return bool(state.get("Running"))
    except Exception:
        return False


def _created_stamp(name: str) -> float | None:
    """The container's ``Created`` epoch from the listing endpoint, or None
    when the daemon will not say."""
    try:
        rows = client_for().api.containers(all=True, filters={"name": name})
    except Exception:
        return None
    for row in rows:
        # name filter is a substring match on the daemon side; pick the row
        # whose stripped Names head IS this container.
        listed = row.get("Names") or []
        head = str(listed[0]).lstrip("/") if listed else ""
        if head == name:
            try:
                return float(row.get("Created"))
            except (TypeError, ValueError):
                return None
    return None


def put_archive(name: str, path: str, data: bytes) -> None:
    """Copy a tar stream into a container directory (the upload transfer
    plane). Raises SDK errors — the adapter turns them into per-file error
    responses. ``path`` must already exist (the parent is ensured first)."""
    client_for().api.put_archive(name, path, data)


def get_archive(name: str, path: str) -> bytes:
    """Download a container file's tar stream (the download transfer plane).
    The caller untars the member."""
    stream, _stat = client_for().api.get_archive(name, path)
    return b"".join(stream)


def last_exec_event_age(name: str) -> float | None:
    """Age (seconds) of the newest daemon event for ``name``, or None when
    unmeasurable (the sweep never removes what it cannot measure).

    Primary: the events log queried retroactively over the sweep window.
    Fallback: the listing's ``Created`` birth stamp — a young never-exec'ed
    orphan is kept, an old one is swept.
    """
    now = time.time()
    window = 7 * 24 * 3600  # ≥ ORPHAN_IDLE_SECONDS; bounded history
    try:
        client = client_for()
    except Exception:
        return None
    try:
        events = client.events(
            since=int(now - window), until=int(now),
            filters={"container": name, "event": "exec_start"},
            decode=True)
        newest = 0.0
        for event in events:
            if str(event.get("Action", "")).startswith("exec_start"):
                newest = max(newest, float(event.get("time") or 0))
    except Exception:
        return _created_stamp_age(name, now)
    if not newest:
        return _created_stamp_age(name, now)
    return max(0.0, now - newest)


def _created_stamp_age(name: str, now: float) -> float | None:
    created = _created_stamp(name)
    if created is None:
        return None
    return max(0.0, now - created)


def _inspect_rc(api, exec_id: str) -> int | None:
    try:
        return int(api.exec_inspect(exec_id)["ExitCode"])
    except Exception:
        return None


def _child_gone(e: Exception) -> str:
    """exec_create/exec_start against a dead or removed container: the
    ``exec failed`` shape the backend's recovery greps for."""
    return f"exec failed: {_first_line(e)}"


def _first_line(e: Exception) -> str:
    text = str(e).strip()
    if not text:
        text = repr(e)
    # docker-py embeds the daemon explanation inconsistently; prefer a JSON
    # body's message field.
    if text.startswith("{"):
        try:
            import json
            text = json.loads(text).get("message", text)
        except ValueError:
            pass
    return text.splitlines()[0][:200]

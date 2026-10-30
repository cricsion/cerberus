"""docker-py channel: one transport for every docker-lane sandbox action.

Replaces the per-action ``docker`` CLI argv splicing with the Docker SDK for
Python (docker-py), doc-verified 7.x:

- ``exec_start(stream=True, demux=True)`` yields (stdout, stderr) frames —
  exactly one side is bytes per frame, the other None
  (``utils/socket.py`` ``demux_adaptor``) — and ``exec_inspect()`` gives
  the exit code; the sentinel-file composition the merged-CLI stream
  required is gone (system_exec's ``system_shell`` reads the demuxed
  frames directly).
- ``put_archive``/``get_archive`` are the tar transfer plane (BaseSandbox
  upload_files/download_files land on these in M4).
- ``containers.create`` expresses the full confinement contract:
  ``cap_drop``, ``security_opt``, ``pids_limit``, ``mem_limit``,
  ``memswap_limit``, ``nano_cpus``, ``network_mode``, ``read_only``, the
  ``tmpfs`` dict, and ``types.Mount`` binds (RO repo, RW .codegraph shadow).
- The low-level plane drives the sweep: ``api.containers(all=True,
  filters={"label": ...})`` (``docker ps`` dicts with ``Names``/``Created``),
  ``api.inspect_container`` (``State.Running``), and ``events()``.
- ``docker.from_env()`` honors the same env as the CLI (DOCKER_HOST; Docker
  Desktop contexts are the SDK default, ``use_context=True``).
- Start-failure diagnosis: ``DockerClient.ping`` (an exception when the
  server is not responsive) separates "docker refused the mount/image"
  (container advice applies) from "no daemon answered — Docker Desktop not
  running, DOCKER_HOST wrong, or the SDK missing"; the start error then
  names the daemon instead of inventing container advice.
- Missing-image recovery is opt-in (``sandbox.pull_image``): ONE explicit
  daemon-side pull (``client.images.pull``, X-Registry-Auth credentials
  resolved from the client's own docker config) precedes a single create
  retry — private-registry ``sandbox.image`` support. The default keeps the
  fail-fast contract for a typo'd image ref (``containers.run``'s hidden
  auto-pull stays avoided).

Timeout policy (no in-container ``timeout`` wrapper — deliberate): the
CLIENT read deadline is the only enforcement. On deadline or byte-cap exceed
this channel pkills the exec's ``EXEC_TAG``-marked shell itself (the API has
no exec-kill endpoint), so a runaway command cannot survive its caller.

Every failure is funneled into :class:`ExecResult` — infra problems are
``error`` strings, never raised past this module; lazy ``docker`` imports
keep local mode and the in-container compute pack free of the SDK. Tests
inject through ``client_for``.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from .cli_utils import BYTE_CAP_FACTOR, EXEC_TAG

__all__ = ["ExecResult", "client_for", "create_sandbox", "start_sandbox",
           "daemon_unreachable_reason", "pull_missing_image",
           "exec_core", "kill_exec_marker", "remove_container",
           "list_sandbox_names", "container_alive", "put_archive",
           "get_archive", "last_exec_event_age",
           "DOCKER_LABEL_KEY", "DOCKER_LABEL_VALUE", "RUN_LABEL"]

DOCKER_LABEL_KEY = "cyber.agent.sandbox"
DOCKER_LABEL_VALUE = "run"
RUN_LABEL = f"{DOCKER_LABEL_KEY}={DOCKER_LABEL_VALUE}"

# The CLI lane's deadline was timeout+15 (merged select reads cannot tolerate
# a socket lull); parity for the SDK lane.
_HANG_SLACK = 15

# cli_utils.BYTE_CAP_FACTOR parity: the exec cap counts COMBINED stream bytes
# (stdout + stderr together), same accounting as the CLI-lane runner.


@dataclass(frozen=True)
class ExecResult:
    """One exec result. ``error`` non-empty marks INFRA (setup failure,
    container gone, daemon unreachable) — never the command's own exit."""
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    truncated: bool = False
    error: str = ""


_client_cache: dict[int, object] = {}
_client_lock = threading.Lock()


def client_for(timeout: float = 60.0):
    """Cached ``DockerClient`` whose requests read-timeout covers the longest
    per-call phase (bucket = timeout + slack). Lazy import: local mode and
    the in-container compute pack never import the SDK. Tests patch this
    single seam with a fake client."""
    bucket = max(60, int(timeout) + _HANG_SLACK)
    with _client_lock:
        client = _client_cache.get(bucket)
        if client is not None:
            return client
        try:
            import docker
        except ImportError as e:
            raise RuntimeError(
                "the docker SDK is not installed: pip install docker") from e
        client = docker.from_env(timeout=bucket)
        _client_cache[bucket] = client
        return client


def create_sandbox(*, name: str, image: str, repo: str, network: str,
                   cpus: str, pids_limit: int, memory: str, user: str,
                   codegraph_shadow: str = "",
                   pull_image: bool = False) -> str:
    """Create (not start) the confined per-repo container; returns ``name``.

    Raises the SDK's own exceptions — parity with the CLI lane's
    create-failure semantics (image bad, mount refused, name taken).
    Every kwarg here is a documented ``containers.create``/``run`` argument
    (cap_drop, security_opt, pids_limit, mem_limit, memswap_limit, nano_cpus,
    network_mode, read_only, tmpfs, mounts of ``docker.types.Mount``).

    ``pull_image`` is the opt-in ``sandbox.pull_image`` lane: when the first
    create fails because the daemon lacks the image, ONE explicit
    :func:`pull_missing_image` precedes a single retry. Any other error
    (mount refusal, name conflict) and any second failure still raise
    untouched — fail-fast except for exactly the failure the setting names.

    The name is returned as passed — the channel never reads ``Container``
    attributes (the Model layer is what turned the sparse sweep listing into
    ``None`` names) and the caller-supplied name is the only identity the
    low-level, ``str``-addressed API ever needs.
    """
    from docker.types import Mount

    try:
        nano = int(round(float(str(cpus)) * 1_000_000_000))
    except ValueError:
        nano = 1_000_000_000

    mounts = [Mount(target=repo, source=repo, type="bind", read_only=True)]
    if codegraph_shadow:
        mounts.append(Mount(target=codegraph_shadow,
                            source=codegraph_shadow, type="bind"))

    client = client_for(120)

    def _create() -> None:
        # ``containers.create`` per the docker-py docs returns a Container
        # object, NOT the name — and every low-level caller downstream
        # (``api.start`` et al., via check_resource + _url) is str-addressed: a
        # Container reached api.start raises "Expected a string but found
        # <Container ...> instead". This channel never reads Container
        # attributes and the caller-supplied name is the only identity the
        # low-level API ever needs — so the return value is discarded here;
        # ``create_sandbox`` returns the name that was passed in.
        client.containers.create(
            image, ["sleep", "infinity"], name=name, detach=True,
            user=str(user), network_mode=network,
            cap_drop=["ALL"], security_opt=["no-new-privileges"],
            # ``init``: a tini PID 1 reaps the exec children this channel
            # pkill -KILLs (the bare ``sleep infinity`` CMD never reaps, so
            # without it every killed command lingers as a zombie).
            init=True,
            pids_limit=max(16, int(pids_limit)), mem_limit=str(memory),
            memswap_limit=str(memory), nano_cpus=nano,
            read_only=True,
            tmpfs={"/tmp": "rw,size=1g,mode=1777",
                   "/work": "rw,size=2g,mode=1777"},
            mounts=mounts,
            environment={"HOME": "/work", "TMPDIR": "/tmp",
                         "PYTHONPYCACHEPREFIX": "/work/.pyc",
                         "GIT_PAGER": "cat", "PAGER": "cat", "TERM": "dumb"},
            labels={DOCKER_LABEL_KEY: DOCKER_LABEL_VALUE},
        )

    try:
        _create()
    except Exception as e:
        if not pull_image or not _image_missing(e):
            raise
        try:
            pull_missing_image(image)
        except Exception as pull_error:
            raise RuntimeError(
                f"image {image} is on no registry this daemon can reach and "
                f"pulling it failed: {_first_line(pull_error)}") from e
        _create()  # one retry only
    return name


def daemon_unreachable_reason(timeout: float = 30) -> str | None:
    """Why no daemon will answer right now, or ``None`` when one will.

    ``DockerClient.ping`` (docker-py docs, client.rst: "Throws an exception
    if the server isn't reachable") runs on the START-FAILURE path only —
    after the corpse removal — and separates a REFUSING daemon (mount/image
    advice applies; ``None`` here) from an UNREACHABLE one (Docker Desktop
    down, DOCKER_HOST wrong, or the SDK missing — the returned line is the
    reason to show). Deliberately not a happy-path preflight: a working
    daemon pays no extra round-trip per exec.
    """
    try:
        client_for(timeout).ping()
    except RuntimeError as e:
        # ``client_for`` itself: the SDK is not installed — the most common
        # reason a local-only install reaches the docker lane at all.
        return str(e)
    except Exception as e:  # ping: "an exception if the server isn't reachable"
        return _first_line(e)
    return None


def pull_missing_image(image: str, *, platform: str | None = None) -> None:
    """ONE explicit daemon-side ``client.images.pull`` of ``image``.

    Private-registry support for the opt-in pull lane: credentials come from
    the docker user's own config (X-Registry-Auth, resolved in
    :func:`_registry_auth`) — the harness never holds secrets. Deliberately
    not ``containers.run``'s hidden auto-pull: this runs only when the caller
    opted in AND the create already failed on a missing image. Raises on
    failure; the caller wraps it into the create error's companion message.
    """
    client_for(600).images.pull(image, platform=platform,
                                auth_config=_registry_auth(image))


def _registry_auth(image: str) -> dict | None:
    """X-Registry-Auth for ``image`` from the docker user's own config
    (``~/.docker/config.json`` through the SDK's ``docker.auth`` helpers).

    Fail-soft by contract: no config, no matching registry entry, or any
    lookup failure resolves to ``None`` — an unauthenticated pull, the same
    shape the CLI's ``docker pull`` gets without ``docker login``. A
    credsStore-managed daemon is deliberately NOT consulted: exec'ing the
    credential helper from the harness is out of contract here (the sweep's
    "never exceed what you can see" posture — the daemon itself authenticates
    what its user already logged in).

    Test seam: monkeypatch this function, never ``load_config``, so no test
    depends on the invoking host's docker config.
    """
    try:
        import docker.auth
        config = docker.auth.load_config()
        registry = docker.auth.resolve_repository_name(image)
        return docker.auth.resolve_authconfig(config, registry) or None
    except Exception:
        return None


def _image_missing(e: Exception) -> bool:
    """True when a create failure is the daemon's "image not found" — the
    ONLY error the opt-in pull may retry (a mount refusal or a name conflict
    must keep failing fast). Lazy import: the SDK-missing case cannot be an
    image problem, so it returns False."""
    try:
        import docker.errors
    except ImportError:
        return False
    return isinstance(e, docker.errors.ImageNotFound)


def start_sandbox(name: str) -> None:
    """Start a created container (create then start — deliberately NOT
    ``containers.run(detach=True)``, which auto-pulls a missing image and
    retries instead of failing fast). A start failure still names its corpse
    for the caller's force-remove."""
    client_for(60).api.start(name)


def exec_core(name: str, *, command: str, marker: str, timeout: int,
              max_output_bytes: int,
              env: list[tuple[str, str]] | None = None,
              workdir: str | None = None) -> ExecResult:
    """One bounded exec: demuxed frames, client-side read deadline as THE
    timeout, marker pkill on deadline/cap exceed. Never raises infra.

    Name-addressed (the low-level API takes ``container: str`` throughout);
    deliberately not ``Container.exec_run`` — streaming returns
    ``exit_code=None`` and no exec id, and the byte-cap path needs
    ``exec_inspect`` for the true rc.
    """
    api = client_for(timeout).api
    try:
        created = api.exec_create(
            name,
            ["/bin/bash", "-c",
             f"{EXEC_TAG}={marker}; "
             f'mkdir -p "$HOME" "$TMPDIR"; {command}'],
            stdout=True, stderr=True, stdin=False,
            environment=[f"{k}={v}" for k, v in (env or ())],
            workdir=workdir)
    except Exception as e:
        return ExecResult(exit_code=126, error=_child_gone(e))
    exec_id = created["Id"]

    stdout: list[bytes] = []
    stderr: list[bytes] = []
    total = 0
    cap = max(1, int(max_output_bytes)) * BYTE_CAP_FACTOR
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
                                "(exec client hang)")

    try:
        stream = api.exec_start(exec_id, stream=True, demux=True)
    except Exception as e:
        return ExecResult(exit_code=126, error=_child_gone(e))

    # Client-side watchdog: if next(stream) blocks on an idle socket because
    # the container command produced no output, kill the marked shell and its
    # children so the socket closes and next(stream) unblocks.
    watchdog = threading.Timer(max(1.0, float(timeout)), lambda: kill_exec_marker(name, marker))
    watchdog.daemon = True
    watchdog.start()

    try:
        while True:
            if time.monotonic() > deadline:
                return hang()
            if total > cap:
                # Over-budget: stop reading so a chatty command cannot drive
                # harness memory up, keep the tail emitted so far, and kill the
                # marked shell (nothing else will — no in-container wrapper).
                kill_exec_marker(name, marker)
                out, err = partial()
                return ExecResult(stdout=out, stderr=err, exit_code=_inspect_rc(
                    api, exec_id), truncated=True)
            try:
                frame = next(stream)
            except StopIteration:
                break
            except Exception as e:
                # Read-timeout family past the deadline = client hang; before
                # = daemon/socket trouble. Fail-soft either way (the "exec
                # failed" shape is what the backend's recovery greps).
                if time.monotonic() > deadline:
                    return hang()
                return ExecResult(exit_code=126, error=_child_gone(e))
            # docker-py demuxes into (stdout, stderr) frames with EXACTLY one
            # side bytes and the other None (utils/socket.py demux_adaptor —
            # the docs' "a tuple with two elements of type byte: stdout and
            # stderr"). It is NOT (stream_type, chunk).
            out_chunk, err_chunk = frame
            if out_chunk is not None:
                total += len(out_chunk)
                stdout.append(out_chunk)
            if err_chunk is not None:
                total += len(err_chunk)
                stderr.append(err_chunk)
    finally:
        watchdog.cancel()

    return ExecResult(stdout=partial()[0], stderr=partial()[1],
                      exit_code=_inspect_rc(api, exec_id))


def kill_exec_marker(name: str, marker: str) -> None:
    """Kill ONLY this exec's tagged shell and its children (the sandbox is shared).
    Fail-soft by contract: dead shells and dead containers never raise here."""
    try:
        api = client_for(30).api
        kill_cmd = (
            f"pids=$(pgrep -f {EXEC_TAG}={marker} 2>/dev/null); "
            f"for p in $pids; do pkill -KILL -P $p 2>/dev/null; kill -9 $p 2>/dev/null; done"
        )
        created = api.exec_create(
            name,
            ["/bin/sh", "-c", kill_cmd],
            stdout=False, stderr=False, stdin=False, environment=[])
        api.exec_start(created["Id"], stream=False, demux=False)
    except Exception:
        pass


def remove_container(name: str) -> bool:
    """Force-remove a container by name. Absent/gone is success (teardown
    paths run on error paths too). Returns True only when the daemon
    ACCEPTED the removal — a refusal must never be reported as reaped (the
    next scan re-sweeps the corpse)."""
    try:
        client_for(60).api.remove_container(name, force=True)
        return True
    except Exception:
        return False


def list_sandbox_names() -> list[str]:
    """Names of every container carrying the run label (all states).

    Low-level API on purpose (docker-py docs, "Low-level API → Containers":
    ``APIClient.containers()`` returns "a list of dicts, one per container",
    i.e. ``docker ps`` wire shape where the name lives in the ``Names``
    array with leading slashes). The high-level
    ``containers.list(sparse=True)`` feeds those same list-endpoint attrs
    into ``Container`` objects whose ``.name`` property reads only
    ``attrs['Name']`` — a field the list endpoint never sends — so sparse
    listing yields ``None`` names; only a full per-container
    ``inspect_container`` populates ``Name``. Going low-level sidesteps the
    Model layer entirely.
    """
    client = client_for(60)
    rows = client.api.containers(all=True, filters={"label": RUN_LABEL})
    names: list[str] = []
    for row in rows:
        # Names is "/name1,/name2" (legacy links can append extras); the
        # docker CLI prints the first entry, slashes stripped.
        listed = row.get("Names") or []
        raw = str(listed[0]) if listed else ""
        name = raw.lstrip("/")
        if not name:
            name = str(row.get("Id") or "")  # no name assigned: fall back to Id
        if name:
            names.append(name)
    return names


def container_alive(name: str) -> bool:
    """True when the daemon currently reports ``name`` as Running.

    ``APIClient.inspect_container`` is "identical to the ``docker inspect``
    command" (docker-py docs, Low-level API): its ``State.Running`` is the
    daemon's own answer, and an absent container raises — both facts the
    sweep's keep-alive probe needs.
    """
    try:
        state = client_for(60).api.inspect_container(name).get("State") or {}
        return bool(state.get("Running"))
    except Exception:
        return False


def _created_stamp(name: str) -> float | None:
    """The container's ``Created`` instant (Unix epoch) from the listing
    endpoint, or None when the daemon will not say."""
    try:
        rows = client_for(60).api.containers(
            all=True, filters={"name": name})
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
    plane behind ``BaseSandbox.upload_files``). Raises SDK errors — the
    adapter turns them into per-file error responses."""
    client_for(120).api.put_archive(name, path, data)


def get_archive(name: str, path: str) -> bytes:
    """Download a container file's tar stream (``BaseSandbox.download_files``'s
    transfer plane). The caller untars the member."""
    stream, _stat = client_for(60).api.get_archive(name, path)
    return b"".join(stream)


def last_exec_event_age(name: str) -> float | None:
    """Age in seconds of the newest activity for ``name``, or None when the
    daemon answers nothing measurable.

    Primary source: the daemon events log (the only history the daemon
    keeps; queried retroactively over the sweep window, mirroring the CLI
    lane's ``events --since 0 --until 0s``). Fallback: the container's
    ``Created`` epoch from the listing endpoint — a freshly created but
    never-exec'ed container reports its birth instead of being declared
    unmeasurable, so a young orphan is kept and only a genuinely old one is
    swept. Both are daemon-published facts; there is no harness-side state.
    """
    now = time.time()
    window = 7 * 24 * 3600  # ≥ ORPHAN_IDLE_SECONDS; bounded history
    try:
        client = client_for(60)
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
        # Events unavailable: the listing endpoint's Created is the next
        # daemon-published timestamp (None here keeps the corpse-sparing
        # contract — unmeasurable is never removed).
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

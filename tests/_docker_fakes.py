"""SDK-lane fakes: a docker-py ``DockerClient`` standing in for the daemon.

Injected through the ONE seam the channel leaves for tests
(``docker_channel.client_for``), so the real docker-py transport code in
``cerberus.sandbox.docker_channel`` runs against this fake: ``exec_create`` /
``exec_start(stream=True, demux=True)`` / ``exec_inspect``, the tar transfer
plane (``put_archive``/``get_archive``), container create (the confinement
contract, recorded as raw kwargs) + ``api.start``, teardown
(``remove_container``), and the
sweep recon (the LOW-LEVEL ``api.containers`` wire listing — ``docker ps``
dicts with ``Names``/``Created``/``Labels`` — plus ``api.inspect_container``
and ``events``).

Start-failure diagnosis rides the fake too: ``client.ping()`` (True
default; ``ping_error`` scripts the unreachable daemon).

Two exec modes:

* canned (default): each non-pkill exec replays a queued
  ``(stdout, exit_code[, stderr])`` triple from ``exec_results`` — the last
  entry repeats. Modeled on the CLI fakes' response queue.
* script mode (``run_scripts=True``): the composed ``bash -c`` is EXECUTED
  on the host with the same workdir (same-path mounts make repo paths
  identical), with HOME/TMPDIR/PYCACHEPREFIX sanitized into a temp dir. The
  deepagents FS scripts are read-only, so this yields the *real* parsed
  contracts of ``read``/``ls``/``glob``/``grep`` and the write preflight —
  never used for mutation paths (the RO-bind refusal is a container-runtime
  property no fake can reproduce).

Not a test module (leading underscore), so pytest never collects it.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import tempfile
import time
from pathlib import Path

import pytest


class FakeDockerError(Exception):
    """``docker.errors.*`` stand-in carrying the daemon explanation.

    ``cerberus.sandbox.docker_backend._transfer_error`` and ``RunSandbox._start_locked``
    read ``e.explanation`` first, mirroring how docker-py errors shape up.
    """

    def __init__(self, explanation: str) -> None:
        super().__init__(explanation)
        self.explanation = explanation


class _FakeAPI:
    """Low-level API half of the fake client."""

    def __init__(self, client: FakeDockerClient) -> None:
        self._client = client

    # -- exec plane ---------------------------------------------------------

    def exec_create(self, container, cmd, *, stdout=True, stderr=True,
                    stdin=False, environment=None, workdir=None):
        rec = {"container": container, "cmd": list(cmd),
               "env": list(environment or []), "workdir": workdir}
        self._client.exec_creates.append(rec)
        return {"Id": f"exec-{len(self._client.exec_creates)}"}

    def exec_start(self, exec_id, *, stream=True, demux=True):
        client = self._client
        idx = int(exec_id.split("-")[-1]) - 1
        rec = client.exec_creates[idx]
        cmd = rec["cmd"]
        if cmd[0] == "pkill" or (cmd[0] == "/bin/sh" and len(cmd) > 2
                                 and "pgrep" in cmd[2]):
            # kill_exec_marker is unconditional fire-and-forget: record it,
            # answer empty, and never touch the response queue.
            client.pkills.append(rec)
            code = 0
            rec["rc"] = code
            client.exec_codes[exec_id] = code
            return b"" if not stream else self._gen([])
        if client.run_scripts:
            frames, code = client._run_script(rec)
        else:
            frames, code = client._next_canned()
        rec["rc"] = code
        rec["frames"] = frames
        client.exec_codes[exec_id] = code
        if stream:
            return self._gen(frames)
        return b"".join(chunk for _, chunk in frames)

    def exec_inspect(self, exec_id):
        return {"ExitCode": self._client.exec_codes.get(exec_id, 0)}

    @staticmethod
    def _gen(frames):
        def gen():
            yield from frames
        return gen()

    # -- teardown / transfer / recon ----------------------------------------

    def start(self, name):
        client = self._client
        if client.start_error is not None:
            err, client.start_error = client.start_error, None
            raise err
        client.starts.append(name)

    def remove_container(self, name, *, force=True):
        client = self._client
        if client.remove_error is not None:
            err, client.remove_error = client.remove_error, None
            raise err
        client.removes.append(name)

    def containers(self, *, all=False, filters=None, limit=-1):
        """The listing endpoint's wire shape (docker-py docs, Low-level API →
        Containers: "A list of dicts, one per container"). Honors the ``label``
        (``"k=v"``) and ``name`` (substring, as the daemon matches) filters;
        ``all`` is accepted and the fake always reports everything."""
        client = self._client
        client.list_calls.append(dict(filters or {}))
        flt = filters or {}

        def matches(row: dict) -> bool:
            label = flt.get("label")
            if label:
                terms = [label] if isinstance(label, str) else list(label)
                for kv in terms:
                    key, _, value = str(kv).partition("=")
                    if row["Labels"].get(key) != value:
                        return False
            name = flt.get("name")
            if name:
                wanted = [name] if isinstance(name, str) else list(name)
                if not any(str(w) in row["Names"][0] for w in wanted):
                    return False
            return True

        return [row for row in (self.wire_row(n) for n in client.list_names)
                if matches(row)]

    def wire_row(self, name: str) -> dict:
        """One ``docker ps`` wire row: leading-slash ``Names`` head, epoch
        ``Created``, label dict — exactly the fields the low-level endpoint
        sends (and the high-level sparse listing does NOT carry as ``Name``)."""
        from cerberus.sandbox.docker_channel import DOCKER_LABEL_KEY, DOCKER_LABEL_VALUE

        return {
            "Id": f"sha256:{name}",
            "Names": [f"/{name}"],
            "Created": int(self._client.container_created.get(
                name, time.time())),
            "Labels": {DOCKER_LABEL_KEY: DOCKER_LABEL_VALUE},
        }

    def inspect_container(self, name):
        """``docker inspect`` shape (docker-py docs: "Identical to the docker
        inspect command"). Defaults to raising the daemon's no-such-container
        error; ``client.container_alive=True`` reports a Running container."""
        client = self._client
        if not client.container_alive:
            raise FakeDockerError(f"No such container: {name}")
        from cerberus.sandbox.docker_channel import DOCKER_LABEL_KEY

        return {
            "Id": f"sha256:{name}",
            "Name": f"/{name}",
            "State": {"Running": True},
            "Config": {"Labels": {DOCKER_LABEL_KEY: "run"}},
        }

    def put_archive(self, container, path, data):
        self._client.puts.append((container, path, data))
        nxt = (self._client.put_responses.pop(0)
               if self._client.put_responses else None)
        if isinstance(nxt, Exception):
            raise nxt

    def get_archive(self, container, path):
        self._client.gets.append((container, path))
        nxt = (self._client.get_responses.pop(0)
               if self._client.get_responses else None)
        if isinstance(nxt, Exception):
            raise nxt
        data = nxt if nxt is not None else b""
        return iter([data]), {"size": len(data)}


class _ContainersCollection:
    def __init__(self, client: FakeDockerClient) -> None:
        self._client = client

    def create(self, image, command=None, **kwargs):
        rec = dict(kwargs)
        rec["image"] = image
        rec["command"] = list(command) if command else None
        self._client.creates.append(rec)
        if self._client.create_error is not None:
            err, self._client.create_error = self._client.create_error, None
            raise err
        name = str(kwargs.get("name"))
        return FakeContainer(self._client, name)


class FakeContainer:
    """What the high-level ``containers.create`` returns; the channel
    addresses everything by the name it passed, so this is inert."""

    def __init__(self, client: FakeDockerClient, name: str) -> None:
        self._client = client
        self.name = name


_B64_OPERAND = re.compile(r"base64\.b64decode\('([^']*)'\)")


def embedded_paths(cmd_text: str) -> list[str]:
    """The absolute paths a deepagents ``python3 -c`` script operates on.

    The templates pass paths as ``base64.b64decode('...')`` operands to stay
    shell-safe; decoding them turns an exec record into a confinement fact.
    """
    inner = cmd_text
    return [base64_path.decode()
            for b64 in _B64_OPERAND.findall(inner)
            for base64_path in (_b64decode(b64),) if base64_path is not None]


def _b64decode(text):
    try:
        return __import__("base64").b64decode(text)
    except Exception:
        return None


class FakeDockerClient:
    """No-daemon stand-in for ``docker.from_env(...).``"""

    def __init__(self, *, run_scripts: bool = False) -> None:
        self.run_scripts = run_scripts
        # create plane: kwargs records + scripted failure
        self.creates: list[dict] = []
        self.starts: list[str] = []
        self.create_error: Exception | None = None
        self.start_error: Exception | None = None
        self.remove_error: Exception | None = None
        # exec plane
        self.exec_creates: list[dict] = []
        self.exec_codes: dict[str, int] = {}
        self.exec_results: list = [("hello\n", 0)]
        self._exec_seq = 0
        self.pkills: list[dict] = []
        # teardown / transfer / recon
        self.removes: list[str] = []
        self.puts: list[tuple[str, str, bytes]] = []
        self.gets: list[tuple[str, str]] = []
        self.get_responses: list = []
        self.put_responses: list = []
        # ping plane (start-failure diagnosis)
        self.pings: list[bool] = []
        self.ping_error: Exception | None = None
        # sweep recon: names the listing endpoint reports, per-query filter
        # records, per-container birth stamps (default: now = fresh), and
        # inspect_container's verdict (default: no such container).
        self.list_names: list[str] = []
        self.list_calls: list[dict] = []
        self.container_created: dict[str, float] = {}
        self.container_alive: bool = False
        self.exec_events: list[dict] = []
        self.event_calls: list[dict] = []
        self._script_base: str | None = None

    @property
    def api(self) -> _FakeAPI:
        return _FakeAPI(self)

    @property
    def containers(self) -> _ContainersCollection:
        return _ContainersCollection(self)

    def ping(self) -> bool:
        """DockerClient.ping (docs, client.rst): True when the daemon
        answers; an exception is the unreachable reason the channel
        converts into the start-failure message."""
        self.pings.append(True)
        if self.ping_error is not None:
            err, self.ping_error = self.ping_error, None
            raise err
        return True

    def events(self, *, since=None, until=None, filters=None, decode=True):
        # The channel pre-filters by container name; the fake answers the
        # scripted exec_start event list for any query (single-name tests).
        self.event_calls.append(dict(filters or {}))
        return list(self.exec_events)

    # -- canned + script exec backends ---------------------------------------

    def _next_canned(self) -> tuple[list[tuple[bytes, bytes]], int]:
        """Frames in the DOCUMENTED demux shape: (stdout, stderr) with
        exactly one side bytes and the other None (docker-py
        ``utils/socket.py`` ``demux_adaptor``) — NOT (stream_type, chunk)."""
        entry = self.exec_results[min(self._exec_seq, len(self.exec_results) - 1)]
        self._exec_seq += 1
        out, rc = entry[0], entry[1]
        err = entry[2] if len(entry) > 2 else ""
        frames = []
        if out:
            frames.append((out.encode() if isinstance(out, str) else out, None))
        if err:
            frames.append((None, err.encode() if isinstance(err, str) else err))
        return frames, rc

    def _run_script(self, rec: dict) -> tuple[list[tuple[bytes, bytes]], int]:
        """Execute the composed ``bash -c`` on the host identically.

        Same-path mounts mean the repo is the SAME directory, so read-only
        deepagents scripts yield their real JSON contract. Writable dirs the
        wrapper creates (HOME/TMPDIR/pycache) are redirected into a temp dir
        so the host tree is untouched.

        The channel composes commands as ``/bin/bash -c <inner>`` (the
        ``timeout -k 5`` wrapper is gone from the production composition);
        the fake runs the composed command directly with host Python —
        coverage/confinement facts come from the real argv above.
        """
        if self._script_base is None:
            self._script_base = tempfile.mkdtemp(prefix="fakesdk-exec-")
        env = {}
        for kv in rec["env"]:
            key, _, value = kv.partition("=")
            env[key] = value
        for key, sub in (("HOME", "home"), ("TMPDIR", "tmp"),
                         ("PYTHONPYCACHEPREFIX", "pyc")):
            if key in env:
                env[key] = str(Path(self._script_base) / sub)
        env.setdefault("PATH", os.environ.get("PATH", "/usr/bin:/bin"))
        base = Path(self._script_base)
        for sub in ("home", "tmp", "pyc"):
            (base / sub).mkdir(parents=True, exist_ok=True)
        inner = rec["cmd"][2] if rec["cmd"][0] == "/bin/bash" else rec["cmd"]
        argv = rec["cmd"] if not isinstance(inner, str) \
            else ["/bin/bash", "-c", inner]
        proc = subprocess.run(argv, cwd=rec["workdir"], env=env,
                              capture_output=True, text=True, timeout=120)
        frames = []
        if proc.stdout:
            frames.append((proc.stdout.encode(), None))   # demux shape: stdout only
        return frames, proc.returncode


@pytest.fixture
def docker_client(monkeypatch):
    """Install the fake ``DockerClient`` at the channel's test seam."""
    client = FakeDockerClient()
    monkeypatch.setattr("cerberus.sandbox.docker_channel.client_for",
                        lambda *a, **k: client)
    # Reap between tests while the fake channel is still installed, so a run
    # started by one test can never reach a real daemon at teardown.
    from cerberus.sandbox.docker_backend import reap_orphans
    try:
        yield client
    finally:
        reap_orphans()

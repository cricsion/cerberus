"""Docker sandbox backend: containment, lifecycle (no docker daemon needed).

The docker-py SDK is faked at the ONE seam the channel leaves for tests
(``docker_channel.client_for``), so the real transport code runs against the
fake. These tests assert the *contract* of the confinement (what create
kwargs compose the container, what execs carry, what is refused, what gets
reaped) — plus, in ``run_scripts`` mode, the real deepagents FS-script
contracts against the host copy of the repo (same-path mounts make the repo
the same directory on both sides).

Mutation-path refusals (the RO repo bind) are a container-runtime property
and are deliberately NOT faked; the tests pin confinement of the paths and
the transfer mechanics instead.
"""
from __future__ import annotations

import io
import re
import tarfile
import time

import pytest
from _docker_fakes import (
    FakeDockerError,
    docker_client,
    embedded_paths,
)
from _sandbox_fakes import repo
from cerberus.sandbox import close_backend, resolve_backend, shutdown_run_sandbox
from cerberus.sandbox.cli_utils import EXEC_TAG
from cerberus.sandbox.docker_backend import (
    DockerSandboxBackend,
    RunSandbox,
    reap_orphans,
    sweep_orphans,
)
from cerberus.sandbox.docker_channel import ExecResult
from cerberus.sandbox.local_backend import RepoLocalBackend
from deepagents.backends.protocol import SandboxBackendProtocol
from deepagents.backends.sandbox import BaseSandbox
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel


def env_dict(exec_rec: dict) -> dict[str, str]:
    """The per-agent env one exec carries (``environment`` list)."""
    out: dict[str, str] = {}
    for kv in exec_rec["env"]:
        key, _, value = kv.partition("=")
        out[key] = value
    return out


@pytest.fixture
def backend(repo, docker_client):
    b = DockerSandboxBackend(repo_path=repo)
    try:
        yield b
    finally:
        # Close even on failure: an unclosed backend dies on GC only, and a
        # GC under a LATER test's fake client would remove THIS run's
        # container through the wrong client's records.
        b.close()


@pytest.fixture
def delegate(monkeypatch):
    """Record the path args reaching the BaseSandbox delegates.

    The adapter's whole FS contract is 'confine, then delegate'; this pins
    the SECOND half of the call (what BaseSandbox actually sees) for every
    op, without depending on template internals.
    """
    calls: list[tuple[str, tuple, dict]] = []
    real = {op: getattr(BaseSandbox, op)
            for op in ("read", "ls", "write", "edit", "delete", "glob",
                       "grep")}

    def wrap(op_name, fn):
        def rec(self_, *args, **kwargs):
            calls.append((op_name, args, kwargs))
            return fn(self_, *args, **kwargs)
        return rec

    for op, fn in real.items():
        monkeypatch.setattr(BaseSandbox, op, wrap(op, fn))
    return calls


class CoreSpy:
    """Stand-in for ``docker_channel.exec_core`` recording its argv.

    Response entries are ``(stdout, exit_code)`` tuples, or dicts passed
    through to ``ExecResult`` so a hang (``error=`` + ``exit_code=None``)
    can be scripted exactly as the channel reports one.
    """

    def __init__(self, responses=None):
        self.calls: list[dict] = []
        self.responses = list(responses or [("hello\n", 0)])

    def __call__(self, container, *, command, marker, timeout,
                 max_output_bytes, env=None, workdir=None):
        self.calls.append({
            "container": container, "command": command, "marker": marker,
            "timeout": timeout, "max_output_bytes": max_output_bytes,
            "env": list(env or []), "workdir": workdir})
        entry = self.responses[min(len(self.calls),
                                   len(self.responses)) - 1]
        if isinstance(entry, dict):
            return ExecResult(**entry)
        out, rc = entry
        return ExecResult(stdout=out, exit_code=rc)


@pytest.fixture
def core(monkeypatch):
    spy = CoreSpy()
    monkeypatch.setattr("cerberus.sandbox.docker_channel.exec_core", spy)
    return spy


# -- protocol surface ------------------------------------------------------


def test_isinstance_sandbox_protocol(backend):
    # deepagents adds the `execute` tool only when this holds.
    assert isinstance(backend, SandboxBackendProtocol)


def test_backend_is_a_base_sandbox_adapter(backend):
    # M4: FS ops derive from the BaseSandbox primitives; `execute` comes
    # from the run-backed shell lane beside it.
    from cerberus.sandbox.backend_base import SandboxShellBackend
    assert isinstance(backend, BaseSandbox)
    assert isinstance(backend, SandboxShellBackend)


def test_local_backend_has_no_shell(repo):
    assert not isinstance(RepoLocalBackend(repo_path=repo),
                          SandboxBackendProtocol)


def test_execute_accepts_timeout_kw():
    from deepagents.backends.protocol import execute_accepts_timeout
    assert execute_accepts_timeout(DockerSandboxBackend)


# -- container confinement contract ----------------------------------------


def test_run_args_confine_the_container(backend, repo, docker_client):
    backend.execute("ls")
    (create,) = docker_client.creates
    assert create["command"] == ["sleep", "infinity"] and create["detach"]
    assert re.fullmatch(r"cerberus-sandbox-run-[0-9a-f]{12}", create["name"])
    assert create["cap_drop"] == ["ALL"] and "no-new-privileges" in create["security_opt"]
    assert create["read_only"] is True
    assert create["init"] is True  # daemon init reaps killed exec processes
    assert create["mem_limit"] == create["memswap_limit"]
    assert create["nano_cpus"] >= 1 and create["pids_limit"] >= 16
    assert create["user"] == "1000:1000"
    assert create["network_mode"] == "bridge"
    # Scratch tmpfs mounts a directory, as tmpfs requires.
    assert create["tmpfs"] == {"/tmp": "rw,size=1g,mode=1777",
                               "/work": "rw,size=2g,mode=1777"}
    # Labels so an operator can sweep containers orphaned by a SIGKILLed run.
    assert create["labels"] == {"cerberus.agent.sandbox": "run"}
    # Env never carries host secrets; only the safe set we pass.
    assert create["environment"] == {"HOME": "/work", "TMPDIR": "/tmp",
                                     "PYTHONPYCACHEPREFIX": "/work/.pyc",
                                     "GIT_PAGER": "cat", "PAGER": "cat",
                                     "TERM": "dumb"}
    # Exactly two bind mounts: the RO repo and the RW .codegraph shadow —
    # same paths on both sides, so nothing else of the host is visible.
    mounts = create["mounts"]
    assert len(mounts) == 2
    assert {m["Source"] for m in mounts} == {
        str(repo), str(repo / ".codegraph")}
    repo_mount = next(m for m in mounts if m["Source"] == str(repo))
    assert repo_mount["Target"] == str(repo) and repo_mount["Type"] == "bind"
    assert repo_mount["ReadOnly"] is True
    shadow = next(m for m in mounts if m["Source"] == str(repo / ".codegraph"))
    assert shadow["Target"] == str(repo / ".codegraph")
    assert shadow["ReadOnly"] is False


def test_network_mode_is_configurable(repo, docker_client):
    """bridge (default) = full egress; none = fail closed; host refused."""
    default = resolve_backend({"sandbox": {"backend": "docker"}}, repo)
    default.execute("ls")
    assert docker_client.creates[0]["network_mode"] == "bridge"

    shutdown_run_sandbox(repo)
    none = resolve_backend({"sandbox": {"backend": "docker",
                                        "network": "none"}}, repo)
    none.execute("ls")
    assert docker_client.creates[1]["network_mode"] == "none"
    shutdown_run_sandbox(repo)

    with pytest.raises(ValueError, match="invalid sandbox network"):
        resolve_backend({"sandbox": {"backend": "docker", "network": "host"}},
                        repo)


def test_execute_channel_shape(backend, repo, docker_client):
    """The exec rides the channel: same container, repo workdir, per-agent
    scratch env, tagged shell, and the raw command as the tail — with NO
    in-container ``timeout`` wrapper (the client read deadline is the only
    enforcement; a deadline exceed pkills this exec's tagged shell)."""
    backend.execute("python -m pytest")
    (rec, *rest) = docker_client.exec_creates
    assert rec["container"] == backend.id
    assert rec["workdir"] == str(repo)
    assert rec["cmd"][:2] == ["/bin/bash", "-c"]
    script = rec["cmd"][2]
    assert script.startswith(f"{EXEC_TAG}={backend.agent_id}-")
    assert 'mkdir -p "$HOME" "$TMPDIR";' in script
    # The bound is enforced by the CLIENT deadline (channel watchdog), not an
    # in-container wrapper. After the command the shell surfaces the exec's
    # own exit status (`:; exit $?` sentinel) so the exec rc survives the tag.
    assert "timeout -k 5" not in script
    assert script.endswith("python -m pytest; :; exit $?")
    env = env_dict(rec)
    assert env["HOME"] == f"/work/agent-{backend.agent_id}"
    assert env["TMPDIR"] == f"/tmp/agent-{backend.agent_id}"
    assert env["PYTHONPYCACHEPREFIX"] == f"/work/agent-{backend.agent_id}/.pyc"
    # The scratch dirs are created inside the same exec (no setup step).
    assert script.count('mkdir -p "$HOME" "$TMPDIR"') == 1
    # Shared caches outlive the per-agent scratch env.
    assert env["PIP_CACHE_DIR"] == "/work/_shared/pip"
    assert env["npm_config_cache"] == "/work/_shared/npm"


def test_container_starts_once_per_backend(backend, docker_client):
    backend.execute("ls")
    backend.execute("cat app.py")
    assert len(docker_client.creates) == 1
    assert len(docker_client.starts) == 1
    assert len(docker_client.exec_creates) == 2


# -- one container per run, shared by every agent ------------------------------


def test_one_container_shared_by_every_agent(repo, docker_client):
    cfg = {"sandbox": {"backend": "docker"}}
    a, b = resolve_backend(cfg, repo), resolve_backend(cfg, repo)
    try:
        assert a.execute("ls").exit_code == 0
        assert b.execute("cat app.py").exit_code == 0
        # ONE create for the whole run, and both agents exec into the
        # same container.
        assert len(docker_client.creates) == 1
        assert a.id == b.id
        assert all(rec["container"] == a.id
                   for rec in docker_client.exec_creates)
        assert len(docker_client.exec_creates) == 2
    finally:
        close_backend(a)
        close_backend(b)
    # A per-agent close ends that agent's session only: the run's container
    # survives for the rest of the scan.
    assert docker_client.removes == []
    # Only the run-level teardown removes it.
    shutdown_run_sandbox(repo)
    assert docker_client.removes == [a.id]


def test_per_agent_scratch_is_isolated(repo, docker_client):
    cfg = {"sandbox": {"backend": "docker"}}
    a = resolve_backend(cfg, repo, agent_id="alpha")
    b = resolve_backend(cfg, repo, agent_id="beta")
    try:
        a.execute("ls")
        b.execute("cat app.py")
    finally:
        close_backend(a)
        close_backend(b)
    shutdown_run_sandbox(repo)
    first, second = docker_client.exec_creates
    env_a, env_b = env_dict(first), env_dict(second)
    assert env_a["HOME"] != env_b["HOME"]
    assert env_a["TMPDIR"] != env_b["TMPDIR"]
    assert env_a["HOME"] == f"/work/agent-{a.agent_id}"
    assert env_b["HOME"] == f"/work/agent-{b.agent_id}"
    # Each exec tags its own command line (so a hung client can be cleaned
    # up without killing another agent's shell).
    def tag(rec):
        return rec["cmd"][2].split(";", 1)[0]
    assert tag(first) != tag(second)
    assert tag(first).startswith(f"{EXEC_TAG}={a.agent_id}")
    assert tag(second).startswith(f"{EXEC_TAG}={b.agent_id}")


def test_agent_id_cannot_escape_the_scratch_root(repo, docker_client):
    # Agent ids come from partitioner model output: they must not steer the
    # scratch path out of /work inside the shared container.
    b = resolve_backend({"sandbox": {"backend": "docker"}}, repo,
                        agent_id="../../etc/cron.d")
    try:
        b.execute("ls")
        rec = docker_client.exec_creates[0]
        home = env_dict(rec)["HOME"]
        # The traversal was flattened into ONE scratch name under /work.
        assert home == f"/work/agent-{b.agent_id}"
        assert ".." not in home and "/" not in b.agent_id
    finally:
        close_backend(b)
    shutdown_run_sandbox(repo)


def test_explicit_timeout_is_honored(backend, repo, core):
    backend.execute("pytest", timeout=30)
    assert core.calls[0]["timeout"] == 30
    assert core.calls[0]["workdir"] == str(repo)


def test_explicit_timeout_capped(repo, docker_client, core):
    b = DockerSandboxBackend(repo_path=repo, command_timeout=10)
    try:
        b.execute("pytest", timeout=9999)
        assert core.calls[0]["timeout"] == 600  # absolute ceiling, all timeouts
    finally:
        b.close()


def test_client_hang_is_killed_by_tag(repo, docker_client, monkeypatch):
    """A read that outlives the deadline — the client socket deadline's
    raise on a stream the daemon never EOFs — kills the exec's own tagged
    shell inside the SAME container (never a blanket kill; the container is
    shared) and the agent gets the exact hang response (exit 124, the
    "(exec client hang)" note) plus the partial tail the deadline kept.
    """
    from _docker_fakes import _FakeAPI
    from cerberus.sandbox.backend_base import SandboxShellBackend

    real_start = _FakeAPI.exec_start

    def hung_start(self, exec_id, *, stream=True, demux=True):
        # The kill exec (kill_exec_marker's /bin/sh pgrep|pkill) rides the
        # real path so its pkill is recorded; the EXEC under test hangs past
        # its deadline, then raises like the client's socket deadline does.
        rec = self._client.exec_creates[int(exec_id.split("-")[-1]) - 1]
        if rec["cmd"][0] == "/bin/sh":
            return real_start(self, exec_id, stream=stream, demux=demux)

        def frames():
            time.sleep(1.5)                  # the hung read, past 1s
            yield (b"late", None)            # the tail the deadline keeps
            raise TimeoutError("timed out")  # the socket deadline's raise
        return frames()

    monkeypatch.setattr(_FakeAPI, "exec_start", hung_start)
    b = DockerSandboxBackend(repo_path=repo, command_timeout=10)
    try:
        res = b.execute("pytest", timeout=1)
        assert res.exit_code == 124
        assert "command timed out after 1s" in res.output
        assert SandboxShellBackend.HANG_NOTE in res.output  # docker note
        assert "late" in res.output   # the partial tail survives the hang
        # The watchdog and/or the read loop pkill the tagged shell; every
        # recorded kill targets THIS exec's tag, never a blanket one.
        assert docker_client.pkills
        assert all(p["container"] == b.id for p in docker_client.pkills)
        assert all("cyber_exec_tag" in " ".join(p["cmd"])
                   for p in docker_client.pkills)
    finally:
        b.close()


def test_image_reference_validation(repo):
    with pytest.raises(ValueError, match="invalid docker image reference"):
        DockerSandboxBackend(repo_path=repo, image="--privileged")
    ok = DockerSandboxBackend(repo_path=repo, image="registry.io/team/ci:1.2@sha256:"
                             + "a" * 64)
    assert ok.image.endswith("a" * 64)
    # Empty falls back to the default image (not a docker flag).
    assert DockerSandboxBackend(repo_path=repo, image="").image == "cerberus-sandbox:local"


# -- output handling ---------------------------------------------------------


def test_output_truncated_with_footer(repo, docker_client):
    b = DockerSandboxBackend(repo_path=repo, max_output_bytes=100)
    docker_client.exec_results = [("x" * 5000, 0)]
    try:
        res = b.execute("cat big.txt")
        assert res.truncated is True
        assert len(res.output) < 5000
        assert "more bytes" in res.output
        # The channel stopped reading at the combined cap and killed this
        # exec's tagged shell (OOM guard, protocol §4: cap *4 in channel).
        assert docker_client.pkills, "a capped exec must be reaped"
    finally:
        # Close even on failure: an unclosed backend only dies on GC, and a
        # GC while the NEXT test's fake client is installed would land this
        # run's remove on the wrong test's records.
        b.close()


def test_run_bounded_streams_caps_memory_and_keeps_streams_separate():
    """The real reader must stop at the byte cap (OOM guard) and return
    stdout/stderr separately — the local lane's runner, pinned once here.
    The chatty process floods stdout and stays silent on stderr."""
    from cerberus.sandbox.cli_utils import run_bounded_streams
    out, err, rc, truncated = run_bounded_streams(
        ["python3", "-c",
         "import sys\nwhile True: sys.stdout.write('A'*4096)\n"],
        timeout=10, byte_cap=20000)
    assert truncated and len(out) <= 20000
    assert err == ""
    assert rc is not None


def test_command_failure_returns_result_not_raise(backend, docker_client):
    docker_client.exec_results = [("pytest: assertion failed\n", 1)]
    res = backend.execute("pytest")
    assert res.exit_code == 1
    assert "assertion failed" in res.output


def test_start_failure_surfaces_reason(backend, repo, docker_client):
    docker_client.create_error = FakeDockerError(
        "Unable to find image 'cerberus-sandbox:local'")
    res = backend.execute("ls")
    assert res.exit_code is None
    assert "docker run failed" in res.output
    assert "cerberus-sandbox:local" in res.output
    assert docker_client.exec_creates == []  # no exec attempted


def test_unshared_host_path_gives_actionable_message(backend, repo,
                                                    docker_client):
    docker_client.create_error = FakeDockerError(
        f"error mounting: {repo} is not shared with the Docker VM")
    res = backend.execute("ls")
    assert "File Sharing" in res.output


# -- start-failure diagnosis -----------------------------------------------


def test_daemon_unreachable_failure_names_the_daemon(backend, docker_client):
    docker_client.create_error = FakeDockerError("cannot reach the mount")
    docker_client.ping_error = FakeDockerError(
        "Connection refused: no daemon at unix:///var/run/docker.sock")
    res = backend.execute("ls")
    assert res.exit_code is None
    assert "docker daemon unreachable" in res.output
    assert "Docker Desktop" in res.output and "DOCKER_HOST" in res.output
    assert "Connection refused" in res.output
    assert "docker run failed" not in res.output
    # The probe runs exactly once, AFTER the corpse removal (an unreachable
    # daemon must never skip it).
    assert docker_client.pings == [True]
    assert docker_client.removes == [backend._run.name]


# -- lifecycle ----------------------------------------------------------------

def test_close_removes_container_once(backend, docker_client):
    backend.execute("ls")
    backend.close()
    backend.close()
    assert docker_client.removes == [backend.id]


def test_execute_after_close_refused(backend, docker_client):
    backend.execute("ls")  # starts this agent's private container
    backend.close()
    res = backend.execute("ls")
    assert res.exit_code == 126 and "closed" in res.output
    assert docker_client.removes == [docker_client.creates[0]["name"]]


def test_dead_container_restarts_on_next_execute(repo, docker_client):
    """A corpse (channel reports ``exec failed``) is removed and the run
    recreates under a fresh name on the next execute."""
    b = DockerSandboxBackend(repo_path=repo)
    try:
        docker_client.exec_results = [("", 126,
                                       "exec failed: container c1 is not running")]
        first = b.execute("ls")
        assert first.exit_code == 126
        old_name = b.id
        docker_client.exec_results = [("hello\n", 0)]
        res = b.execute("ls")
        assert res.exit_code == 0
        # corpse removed; fresh container created; exec retried.
        assert docker_client.removes == [old_name]
        assert [c["name"] for c in docker_client.creates] == [old_name, b.id]
        assert b.id != old_name
        assert len(docker_client.exec_creates) == 2
    finally:
        b.close()


def test_transient_exec_failure_spares_a_live_container(repo, docker_client):
    """``exec failed`` reports the exec, not the container: while the daemon
    (inspect → State.Running) says the shared container is alive, recovery
    tears nothing down and the next exec retries on the SAME container."""
    b = DockerSandboxBackend(repo_path=repo)
    try:
        docker_client.container_alive = True
        docker_client.exec_results = [("", 126,
                                       "exec failed: transient daemon hiccup")]
        assert b.execute("ls").exit_code == 126
        assert b.execute("ls").exit_code == 126
        # No corpse removal, no recreation: one container keeps serving.
        assert docker_client.removes == []
        assert [c["name"] for c in docker_client.creates] == [b.id]
        assert len(docker_client.exec_creates) == 2
    finally:
        b.close()


def test_exec_demuxes_both_streams_documented_shape(repo, docker_client):
    """docker-py demux frames are (stdout, stderr) tuples with EXACTLY one
    side bytes per frame (utils/socket.py demux_adaptor) — the fake emits
    that shape, and the channel must merge both without any stream-type
    code. A (stream_type, chunk) reading crashes with len(None) on the very
    first stdout frame."""
    b = DockerSandboxBackend(repo_path=repo)
    try:
        docker_client.exec_results = [("out\n", 0, "err\n")]
        res = b.execute("ls")
        assert res.exit_code == 0
        assert "out" in res.output and "err" in res.output
    finally:
        b.close()


def test_stream_failure_before_deadline_fails_soft(repo, docker_client,
                                                   monkeypatch):
    """A mid-stream daemon/socket error (before the deadline) is returned as
    an ``exec failed`` result — never raised past the channel; the recovery
    probe then decides the container's fate."""
    from _docker_fakes import _FakeAPI

    def broken_start(self, exec_id, *, stream=True, demux=True):
        raise RuntimeError("connection reset by peer")

    monkeypatch.setattr(_FakeAPI, "exec_start", broken_start)
    b = DockerSandboxBackend(repo_path=repo)
    try:
        res = b.execute("ls")
        assert res.exit_code == 126
        assert "exec failed" in res.output
    finally:
        b.close()


def test_start_failure_removes_the_corpse_and_freshens_the_name(
        repo, docker_client):
    """create-ok/start-fail: the corpse is removed at once and the retry
    allocates a fresh name — the old name could otherwise collide with the
    leaked corpse on every subsequent start."""
    b = DockerSandboxBackend(repo_path=repo)
    try:
        docker_client.start_error = FakeDockerError("cannot start container")
        first = b.execute("ls")
        assert first.exit_code is None and "docker run failed" in first.output
        corpse = docker_client.creates[0]["name"]
        assert docker_client.removes == [corpse]
        # Retry: fresh name, clean start, exec succeeds.
        res = b.execute("ls")
        assert res.exit_code == 0
        assert [c["name"] for c in docker_client.creates] == [corpse, b.id]
        assert b.id != corpse
    finally:
        b.close()


def test_atexit_reaps_orphans(repo, docker_client):
    a = resolve_backend({"sandbox": {"backend": "docker"}}, repo)
    a.execute("ls")  # starts the run's ONE container
    reap_orphans()
    assert a._run.started is False
    assert docker_client.removes == [a.id]
    close_backend(a)


def test_channel_sweep_removes_idle_orphans(repo, docker_client):
    """The sweep rides the channel's recon: label-filtered listing, the
    daemon events log for script age, force removal."""
    stale = "cerberus-sandbox-run-" + "a" * 12
    docker_client.list_names = [stale, "unrelated-thing"]
    docker_client.exec_events = [{"Action": "exec_start",
                                  "time": time.time() - 8 * 3600}]
    removed = sweep_orphans(idle_seconds=60)
    # name-pattern filter and idle-age rule: only the stale sandbox goes.
    assert removed == [stale]
    assert docker_client.removes == [stale]
    assert docker_client.list_calls == [{"label": "cerberus.agent.sandbox=run"}]
    # a container with NO measurable age is never removed.
    docker_client.removes.clear()
    docker_client.list_names = ["cerberus-sandbox-run-" + "b" * 12]
    docker_client.exec_events = []
    assert sweep_orphans(idle_seconds=60) == []
    assert docker_client.removes == []


# -- virtual path contract (the fix that made read_file work at all) ---------


def test_virtual_paths_round_trip(backend, repo, delegate):
    """Middleware-normalized paths (/app.py, ., /) map INTO the repo before
    any delegate runs."""
    assert backend.read("/app.py") is not None
    assert backend.read("app.py") is not None
    assert backend.ls("/") is not None
    reads = [args[0] for op, args, kw in delegate if op == "read"]
    assert reads == [str(repo / "app.py"), str(repo / "app.py")]
    (ls_path,) = [args[0] for op, args, kw in delegate if op == "ls"]
    assert ls_path == str(repo)
    # and the derived scripts never target anything outside the repo
    # (asserted at the behavior level in the script-mode tests below).


def test_file_tools_still_confined(backend, repo, delegate):
    # An escaping symlink is rejected, not followed.
    (repo / "leak").symlink_to("/etc")
    backend.read("leak/passwd")
    backend.ls("../")
    backend.write("staging.txt", "x")  # escape-by-prefix is re-pointed too
    paths = {args[0] for op, args, kw in delegate}
    assert all(p.startswith(str(repo)) for p in paths), paths
    sentinels = [p for p in paths if ".denied-" in p]
    assert sentinels, "escapes must resolve to the never-created sentinel"
    # nothing was created and no host path is ever addressed
    assert not list(repo.glob(".denied-*"))
    assert not any(str(p).startswith("/etc") for p in paths)


# -- in-container FS behavior (script mode: real deepagents scripts) ---------


def test_fs_read_round_trip_runs_in_container(repo, docker_client):
    """BaseSandbox.read derives a python script that rides the execute
    channel INSIDE the container: real content comes back real."""
    docker_client.run_scripts = True
    b = DockerSandboxBackend(repo_path=repo)
    try:
        res = b.read("/app.py")
        assert res.error is None
        content = (res.file_data or {}).get("content", "")
        assert "print('hi')" in content
        (rec,) = [r for r in docker_client.exec_creates
                  if "python3 -c" in r["cmd"][2]]
        assert rec["workdir"] == str(repo)
        assert embedded_paths(rec["cmd"][2]) == [str(repo / "app.py")]
    finally:
        b.close()


def test_fs_ls_round_trip_runs_in_container(repo, docker_client):
    docker_client.run_scripts = True
    b = DockerSandboxBackend(repo_path=repo)
    try:
        (repo / "sub").mkdir()
        (repo / "sub" / "keep.py").write_text("k = 1\n")
        res = b.ls("/")
        assert res.error is None
        assert "app.py" in str(res.entries)
        (rec,) = [r for r in docker_client.exec_creates
                  if "python3 -c" in r["cmd"][2]]
        assert embedded_paths(rec["cmd"][2]) == [str(repo)]
    finally:
        b.close()


def test_escape_read_is_sandbox_not_found(repo, docker_client):
    """The escape resolves to a never-created in-repo sentinel, so the
    container's own script answers with its not-found error — the host file
    at the escaped path is never addressed."""
    docker_client.run_scripts = True
    b = DockerSandboxBackend(repo_path=repo)
    try:
        (repo / "leak").symlink_to("/etc")
        res = b.read("leak/passwd")
        assert res.error
        # the script addressed exactly one path: the repo-local sentinel
        paths = [p for r in docker_client.exec_creates
                 for p in embedded_paths(r["cmd"][2])]
        assert paths == [str(b._sentinel)]
    finally:
        b.close()


def test_agent_write_confines_transfer(repo, docker_client, delegate):
    """Write = in-container parent preflight + upload transfer plane; escape
    paths resolve to the sentinel BEFORE the upload is requested."""
    b = DockerSandboxBackend(repo_path=repo)
    docker_client.run_scripts = True  # preflight is a mkdir in-container
    try:
        res = b.write("app.py", "z = 9\n")
        assert res.error is None
        uploads, = list(docker_client.puts)
        name, path, tar_bytes = uploads
        assert path == str(repo) and name == b.id
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
            member = tar.getmember("app.py")
            assert member.isfile() and member.mode == 0o644
            assert member.uid == member.gid == 1000
            assert tar.extractfile(member).read() == b"z = 9\n"
        # escapes never reach the transfer plane pointing outside the repo
        res2 = b.write("../escape.txt", "no\n")
        escape_uploads = list(docker_client.puts[1:])
        assert escape_uploads, "confined write still transfers in-container"
        escape_path = None
        for op, args, kw in delegate:
            if op == "write" and ".denied-" in str(args[0]):
                escape_path = str(args[0])
        assert escape_path and escape_path.startswith(str(repo))
        assert escape_path == str(b._sentinel)
    finally:
        b.close()


# -- transfer plane (BaseSandbox's fourth primitive) --------------------------


def test_upload_files_round_trip(backend, repo, docker_client):
    from deepagents.backends.protocol import FileUploadResponse
    res = backend.upload_files([("/tmp/scratch/data.bin", b"\x00payload")])
    assert isinstance(res[0], FileUploadResponse)
    assert res[0].path == "/tmp/scratch/data.bin" and res[0].error is None
    # parents ensured by a single mkdir exec first ...
    mkdirs = [r for r in docker_client.exec_creates
              if "mkdir -p /tmp/scratch" in r["cmd"][2]]
    assert mkdirs
    # ... then one in-memory tar put_archive with an agent-owned member.
    ((name, path, tar_bytes),) = docker_client.puts
    assert name == backend.id and path == "/tmp/scratch"
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        member = tar.getmember("data.bin")
        assert member.isfile() and member.size == len(b"\x00payload")
        assert tar.extractfile(member).read() == b"\x00payload"


def test_upload_files_sandbox_unavailable(repo, docker_client):
    b = DockerSandboxBackend(repo_path=repo)
    try:
        docker_client.create_error = FakeDockerError("boom")
        res = b.upload_files([("/opt/x", b"a")])
        assert all(r.error.startswith("sandbox unavailable") for r in res)
        assert docker_client.puts == []
    finally:
        b.close()


def test_upload_files_invalid_path(backend, docker_client):
    res = backend.upload_files([("relative.txt", b"x"), ("", b"x")])
    assert all(r.error == "invalid_path" for r in res)
    assert docker_client.puts == []


def test_upload_files_reports_api_errors(repo, docker_client):
    b = DockerSandboxBackend(repo_path=repo)
    try:
        docker_client.put_responses = [
            FakeDockerError("No such file or directory")]
        res = b.upload_files([("/tmp/x/f.txt", b"a")])
        assert res[0].error == "file_not_found"
    finally:
        b.close()


def test_download_files_round_trip(backend, repo, docker_client):
    from cerberus.sandbox.docker_backend import _tar_bytes
    docker_client.get_responses = [_tar_bytes("app.py", b"x = 1\n")]
    res = backend.download_files([f"{repo}/app.py"])
    assert len(res) == 1 and res[0].error is None
    assert res[0].content == b"x = 1\n"
    assert docker_client.gets == [(backend.id, f"{repo}/app.py")]


def test_download_files_directory_reports_is_directory(backend,
                                                       docker_client):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name="dir")
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
    docker_client.get_responses = [buf.getvalue()]
    res = backend.download_files(["/some/dir"])
    assert res[0].error == "is_directory" and res[0].content is None


def test_download_files_errors_are_normalized(backend, docker_client):
    from deepagents.backends.protocol import FileDownloadResponse
    b_notfound = FakeDockerError("Could not find the file /x in container")
    b_denied = FakeDockerError("permission denied while reading /etc/shadow")
    docker_client.get_responses = [b_notfound, b_denied]
    res = backend.download_files(["/x", "/etc/shadow"])
    assert all(isinstance(r, FileDownloadResponse) for r in res)
    assert res[0].error == "file_not_found"
    assert res[1].error == "permission_denied"


def test_download_files_invalid_path(backend, docker_client):
    res = backend.download_files(["relative", ""])
    assert all(r.error == "invalid_path" for r in res)
    assert docker_client.gets == []


# -- resolve / close helpers --------------------------------------------------


def test_resolve_backend_defaults_local(repo):
    assert type(resolve_backend({}, repo)) is RepoLocalBackend


def test_run_settings_reach_the_run_sandbox():
    """Every RunSandbox setting must survive the run/session split.

    `resolve_backend` hands the whole sandbox settings dict to the run
    registry, which slices off the per-agent session keys (rules_dir). A new
    RunSandbox setting missing from that key set would be silently dropped
    and the run would quietly use its default instead.
    """
    import inspect

    from cerberus.sandbox.docker_backend import _RUN_SETTING_KEYS
    params = set(inspect.signature(RunSandbox.__init__).parameters) - {"self"}
    dropped = params - _RUN_SETTING_KEYS - {"repo_path"}
    assert not dropped, f"run settings never reach RunSandbox: {sorted(dropped)}"


def test_resolve_backend_docker_from_cfg(repo, docker_client):
    cfg = {"sandbox": {"backend": "docker", "image": "img"}}
    a, b = resolve_backend(cfg, repo), resolve_backend(cfg, repo)
    assert isinstance(a, DockerSandboxBackend) and a.image == "img"
    # Both agents of the run share ONE container.
    assert a.id == b.id
    close_backend(a)
    close_backend(b)
    shutdown_run_sandbox()


def test_resolve_backend_docker_from_env(repo, docker_client, monkeypatch):
    monkeypatch.setenv("SANDBOX_BACKEND", "docker")
    assert isinstance(resolve_backend({}, repo), DockerSandboxBackend)


# (The malformed-sandbox-section degradation contract rides the fail-open
# ladder itself: a garbage sandbox setting raises ValueError inside
# resolve_backend, and _acquire_backend's degrade-to-local is pinned in
# test_backend_refusal_degrades_with_a_refusal_message above.)
def test_resolve_backend_rejects_flags_as_image_name(repo):
    # A docker-flag-like image name raises at resolve time (callers fail soft
    # to the local backend; it must never become a privileged container).
    with pytest.raises(ValueError, match="invalid docker image"):
        resolve_backend({"sandbox": {"backend": "docker",
                                     "image": "--privileged"}}, repo)


def test_backend_refusal_degrades_with_a_refusal_message(repo, monkeypatch,
                                                         capsys):
    """The fail-open ladder's loud path: a refused sandbox backend prints the
    caller's refusal (deep.py's exact wording) to stderr and degrades to the
    repo-confined LOCAL backend — it must never raise past the caller."""
    import cerberus.sandbox as sandbox_mod

    def refused(cfg, root, *, agent_id=None):
        raise RuntimeError(
            "Bind for 0.0.0.0 failed: port is already allocated")

    monkeypatch.setattr(sandbox_mod, "resolve_backend", refused)
    backend = sandbox_mod._acquire_backend(
        {"sandbox": {"backend": "docker"}}, repo, label="agent",
        fallback="local",
        refused_msg="[deep] sandbox backend refused ({exc}); "
                    "using the local backend")
    assert isinstance(backend, RepoLocalBackend)
    err = capsys.readouterr().err
    assert "sandbox backend refused" in err
    assert "port is already allocated" in err


def test_close_backend_noop_on_local(repo):
    # must not raise; close_backend returns None for close-less local backends
    assert close_backend(RepoLocalBackend(repo_path=repo)) is None


# -- prompt wiring -------------------------------------------------------------


def test_prompt_describes_sandbox_in_docker_mode(repo):
    """Config plumbing only: the rules dir and the *configured* command timeout
    must reach the prompt (a hardcoded 120 would truncate slow scans)."""
    from cerberus.prompts.hunter import build_unit_system_prompt
    b = DockerSandboxBackend(repo_path=repo, command_timeout=600)
    prompt = build_unit_system_prompt("focus", backend=b)
    assert b.rules_dir in prompt
    assert "~600s" in prompt


def test_prompt_reflects_the_configured_network_mode(repo):
    """The configured network posture must change the prompt — a builder that
    ignored it would tell the model a boundary that is not there. Asserted as
    a *difference* between the two prompts, not as exact wording."""
    from cerberus.prompts.hunter import build_unit_system_prompt
    default = build_unit_system_prompt(
        "focus", backend=DockerSandboxBackend(repo_path=repo))
    none = build_unit_system_prompt(
        "focus", backend=DockerSandboxBackend(repo_path=repo, network="none"))
    assert none != default


# -- deepagents integration (the three gates that were broken) -----------------
# (Local mode keeping the sandbox section out of the prompt is asserted in
# test_skills.py::test_local_mode_gets_neither_shell_nor_skills, which checks
# the stronger form: the whole sandbox section is empty.)


class _ToolFake(GenericFakeChatModel):
    """Fake chat model that emits one tool call, then a final message.

    bind_tools returns self because canned messages carry the tool calls;
    the agent's ToolNode holds the real tools.
    """

    def bind_tools(self, tools, **kw):
        return self


def _invoke_with(backend, tool_name, args, tmp_path):
    """Run a one-tool-call deep agent; return the tool result message."""
    from cerberus.agents.deep import build_deep_agent
    from langchain_core.messages import HumanMessage, ToolMessage

    llm = _ToolFake(messages=iter([
        _tool_call_message(tool_name, args), _final_message()]))
    agent = build_deep_agent(llm, system_prompt="x", tools=[], name="t",
                             backend=backend)
    res = agent.invoke({"messages": [HumanMessage(content="go")]})
    return next((m for m in res["messages"] if isinstance(m, ToolMessage)),
                None)


def _tool_call_message(name, args):
    from langchain_core.messages import AIMessage
    return AIMessage(content="", tool_calls=[
        {"name": name, "args": args, "id": "1"}])


def _final_message():
    from langchain_core.messages import AIMessage
    return AIMessage(content="done")


def test_docker_agent_builds_and_executes(repo, docker_client):
    """build_deep_agent must not raise; execute must reach the container."""
    from cerberus.agents.deep import _supports_shell

    assert not _supports_shell(RepoLocalBackend(repo_path=repo))  # control
    assert _supports_shell(DockerSandboxBackend(repo_path=repo))

    b = DockerSandboxBackend(repo_path=repo)
    try:
        tm = _invoke_with(b, "execute", {"command": "echo hi"}, repo)
        assert tm is not None and "hello" in str(tm.content)  # faked container
        assert "succeeded" in str(tm.content)
    finally:
        b.close()


def test_local_agent_has_no_execute(repo):
    tm = _invoke_with(RepoLocalBackend(repo_path=repo), "execute",
                      {"command": "echo hi"}, repo)
    assert tm is not None
    assert "not a valid tool" in str(tm.content)


def test_agent_without_explicit_backend_gets_the_shared_sandbox(repo,
                                                                monkeypatch):
    """Validator/triage/partitioner agents pass no backend: in docker mode
    they must resolve the run's shared sandbox (not the shell-less local
    one)."""
    import itertools

    import cerberus.sandbox as sandbox_mod
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel

    seen: list[tuple[str, str]] = []
    real = sandbox_mod.resolve_backend

    def spy(cfg, repo_path, *, agent_id=None):
        out = real(cfg, repo_path, agent_id=agent_id)
        seen.append((type(out).__name__, str(agent_id)))
        return out

    monkeypatch.setattr(sandbox_mod, "resolve_backend", spy)
    monkeypatch.setattr("cerberus.config.load_config",
                        lambda *a, **k: {"sandbox": {"backend": "docker"}})

    from cerberus.agents.deep import build_deep_agent

    llm = GenericFakeChatModel(messages=itertools.repeat("ok"))
    build_deep_agent(llm, system_prompt="x", tools=[], name="validator",
                     root_dir=repo)
    assert seen, "no backend resolved"
    assert seen[0][0] == "DockerSandboxBackend"
    assert seen[0][1].startswith("validator-")  # per-agent scratch id
    shutdown_run_sandbox(repo)

"""Orphan sweep: reaping the sandboxes a killed run left behind.

Teardown paths (atexit, SIGTERM) cover a harness that EXITS. A harness that
was SIGKILL'd, OOM-killed by the host, or lost power cannot run any of them,
so its sandbox outlives it. These tests assert the sweep that runs at the
next scan start removes exactly those, and nothing else: not a sandbox
another harness process on this machine is using right now, and never a
sandbox this harness did not create.

Docker asks its daemon "when was this container last used?": the SDK-lane
recon lists every container carrying the run label, the daemon's events
log reports ``exec_start`` per command with a unix timestamp, and a
container with no exec history at all answers with its ``Created`` birth
stamp from the listing endpoint. The daemon is
the ONLY liveness source, which is the point: the process that would have
maintained harness-side state is exactly the one that died.

(The SDK lane's per-call contracts — label filter, newest-exec rule,
created-stamp fallback, unmeasurable-never-removed — are pinned against
the fake client here; the confinement contracts around the exec channel
live in test_docker_backend.)
"""
from __future__ import annotations

import time

import pytest
from _docker_fakes import FakeDockerClient
from cerberus.sandbox import docker_backend, docker_channel, sweep_orphans
from cerberus.sandbox.run_base import ORPHAN_IDLE_SECONDS, RUN_NAME_RE, orphan_targets


def _unixtime(seconds_ago: float) -> float:
    """A `time` field the docker daemon could have reported."""
    return time.time() - seconds_ago


def _exec_events(name: str, *, age_seconds: float, count: int = 1) -> list[dict]:
    """Decoded daemon events for a busy container (``decode=True`` shape)."""
    stamp = _unixtime(age_seconds)
    events = [{"Action": "create", "Type": "container", "time": stamp - 60}]
    for i in range(count):
        events.append({"Action": "exec_start: /bin/bash -c 'ls'",
                       "Type": "container", "time": stamp + i})
    return events


@pytest.fixture
def docker_client(monkeypatch):
    """The fake SDK client at the channel's test seam (as in test_docker_backend)."""
    client = FakeDockerClient()
    monkeypatch.setattr(docker_channel, "client_for", lambda timeout=60.0: client)
    # Reap between tests while the fake channel is still installed, so a run
    # started by one test can never reach a real daemon at teardown.
    from cerberus.sandbox.docker_backend import reap_orphans
    try:
        yield client
    finally:
        reap_orphans()


# -- target selection (shared rule, docker namespace) -------------------------


def test_only_our_names_are_candidates():
    """Someone else's sandbox is never a sweep target, however named."""
    assert orphan_targets([
        "cerberus-sandbox-run-abcdef012345",
        "my-project", "agent-work", "cerberus-sandbox-run-short",
        "cerberus-sandbox-run-upper", "default",
        "cyber-sbx-0123456789ab",  # the removed sbx namespace is not ours now
        "WARN: docker hub refresh lock held by another process",
    ], live=()) == ["cerberus-sandbox-run-abcdef012345"]


def test_a_live_run_is_never_a_target():
    """The registry's own runs are excluded before anything else is read."""
    live = "cerberus-sandbox-run-abcdef012345"
    assert orphan_targets([live], live=[live]) == []


def test_run_names_match_the_pattern():
    assert RUN_NAME_RE.match("cerberus-sandbox-run-abcdef012345")
    assert not RUN_NAME_RE.match("cerberus-sandbox-run-upper")
    assert not RUN_NAME_RE.match("xcerberus-sandbox-run-abcdef012345")
    assert not RUN_NAME_RE.match("cyber-sbx-0123456789ab")


def test_the_backend_shares_the_one_idle_threshold():
    """"Idle" is the run_base constant; the backend does not fork it."""
    assert docker_backend.ORPHAN_IDLE_SECONDS is ORPHAN_IDLE_SECONDS
    assert 3600 <= ORPHAN_IDLE_SECONDS < 24 * 3600


# -- the SDK-lane sweep rides the daemon's exec events ------------------------


def test_sweep_reads_names_from_the_wire_listing(docker_client):
    """The listing endpoint's ``Names`` array (docker ps wire shape) is the
    name source. docker-py's sparse high-level listing leaves ``Container.name``
    None on real 7.x (list-endpoint attrs carry ``Names``, not ``Name``), so
    the channel decodes the wire form itself and strips the leading slash."""
    stale, other = "cerberus-sandbox-run-aaaaaaaaaaaa", "someone-elses"
    docker_client.list_names = [stale, other]
    assert docker_channel.list_sandbox_names() == [stale, other]
    # end-to-end: the names the sweep derives from that listing are real,
    # and the pattern rule still skips the other namespace.
    docker_client.exec_events = [{"Action": "exec_start",
                                  "time": time.time() - 8 * 3600}]
    assert docker_backend.sweep_orphans() == [stale]
    assert docker_client.removes == [stale]


def test_docker_sweep_uses_the_daemons_exec_events(docker_client, tmp_path):
    """A container exec'd recently is alive; one idle past the threshold is
    not — and the registry's own run is excluded before any event is read."""
    stale, fresh = "cerberus-sandbox-run-aaaaaaaaaaaa", "cerberus-sandbox-run-bbbbbbbbbbbb"
    live_run = docker_backend.RUNS.get(str(tmp_path))     # our own, still open
    docker_client.list_names = [stale, fresh, live_run.name, "someone-elses"]
    ages = {stale: 100_000, fresh: 30, live_run.name: 30, "someone-elses": 30}

    def events(*, since=None, until=None, filters=None, decode=True):
        name = filters["container"]
        docker_client.event_calls.append(dict(filters or {}))
        return _exec_events(name, age_seconds=ages.get(name, 30))

    docker_client.events = events
    assert docker_backend.sweep_orphans() == [stale]
    assert docker_client.list_calls == [{"label": "cerberus.agent.sandbox=run"}]
    # per-candidate events queries, scoped to one container each — exactly
    # the name-matching candidates that are not a live run of this process
    assert [c["container"] for c in docker_client.event_calls] == [stale, fresh]
    # force removal of exactly the stale one; the fresh and live ones stay
    assert docker_client.removes == [stale]


def test_docker_sweep_uses_the_newest_exec_when_there_are_many(docker_client):
    """A long-lived container's history: only the newest exec_start counts."""
    busy = "cerberus-sandbox-run-aaaaaaaaaaaa"
    docker_client.list_names = [busy]
    # 50 old execs, then one recent one -> alive
    docker_client.exec_events = (
        _exec_events(busy, age_seconds=100_000, count=50)
        + [{"Action": "exec_start: ls", "time": _unixtime(45)}])
    assert docker_backend.sweep_orphans() == []
    assert docker_client.removes == []


def test_docker_sweep_leaves_what_it_cannot_measure(docker_client):
    """No exec events at all (never used, or rotated out of the daemon's
    log) is not evidence of death."""
    never_used = "cerberus-sandbox-run-aaaaaaaaaaaa"
    docker_client.list_names = [never_used]
    docker_client.exec_events = [{"Action": "create", "time": _unixtime(999)}]
    assert docker_backend.sweep_orphans() == []
    assert docker_client.removes == []


def test_docker_sweep_falls_back_to_the_created_stamp(docker_client):
    """A container with NO exec history still reports its birth: the listing
    endpoint's ``Created`` epoch stands in for the missing events, so a
    never-exec'ed old orphan is swept instead of living forever."""
    corpse = "cerberus-sandbox-run-aaaaaaaaaaaa"
    docker_client.list_names = [corpse]      # exec_events stays empty
    docker_client.container_created[corpse] = time.time() - 8 * 3600
    assert docker_backend.sweep_orphans() == [corpse]
    assert docker_client.removes == [corpse]


def test_docker_sweep_keeps_a_young_birth_stamp_only(docker_client):
    """Freshly created but never exec'ed (killed between create and first
    command): the birth stamp reads young, so it is kept — and recreated on
    the next command anyway."""
    newborn = "cerberus-sandbox-run-aaaaaaaaaaaa"
    docker_client.list_names = [newborn]
    docker_client.container_created[newborn] = time.time() - 30
    assert docker_backend.sweep_orphans() == []
    assert docker_client.removes == []


def test_docker_sweep_keeps_a_corpse_it_cannot_measure_at_all(docker_client,
                                                              monkeypatch):
    """Events unavailable AND the listing endpoint refuses the Created
    query: nothing measurable remains, and unmeasurable is never removed."""
    from _docker_fakes import FakeDockerError, _FakeAPI

    corpse = "cerberus-sandbox-run-aaaaaaaaaaaa"
    docker_client.list_names = [corpse]

    def boom(*, since=None, until=None, filters=None, decode=True):
        raise FakeDockerError("events unavailable")

    monkeypatch.setattr(docker_client, "events", boom)
    real_containers = _FakeAPI.containers

    def refuse_name_query(self, *, all=False, filters=None, limit=-1):
        if "name" in (filters or {}):
            raise FakeDockerError("listing unavailable")
        return real_containers(self, all=all, filters=filters, limit=limit)

    monkeypatch.setattr(_FakeAPI, "containers", refuse_name_query)
    assert docker_backend.sweep_orphans() == []
    assert docker_client.removes == []


def test_docker_sweep_tolerates_garbage_events(docker_client):
    """Junk in the events log (wrong action, missing/odd time) reads as
    unmeasurable — and unmeasurable is kept, never removed."""
    busy = "cerberus-sandbox-run-aaaaaaaaaaaa"
    docker_client.list_names = [busy]
    docker_client.exec_events = [
        {"Action": "create", "time": _unixtime(999)},      # not an exec event
        {"Action": "exec_start: ls"},                      # no time at all
        {"Action": "exec_start: ls", "time": "not-a-number"},
    ]
    assert docker_backend.sweep_orphans() == []
    assert docker_client.removes == []


def test_docker_sweep_with_nothing_to_do_makes_no_queries(docker_client):
    docker_client.list_names = []
    assert docker_backend.sweep_orphans() == []
    assert docker_client.list_calls == [{"label": "cerberus.agent.sandbox=run"}]
    assert docker_client.event_calls == []      # no events query
    assert docker_client.removes == []          # no rm


def test_docker_sweep_survives_a_broken_daemon(monkeypatch):
    """No SDK, no daemon: the sweep is fail-soft by contract."""
    def boom(timeout=60.0):
        raise RuntimeError("the docker SDK is not installed")

    monkeypatch.setattr(docker_channel, "client_for", boom)
    assert docker_backend.sweep_orphans() == []


def test_docker_events_query_is_never_fatal(docker_client, monkeypatch):
    """A daemon that refuses the events query leaves the container alone."""
    def boom(*, since=None, until=None, filters=None, decode=True):
        raise RuntimeError("events unavailable")

    docker_client.list_names = ["cerberus-sandbox-run-aaaaaaaaaaaa"]
    docker_client.exec_events = _exec_events(
        "cerberus-sandbox-run-aaaaaaaaaaaa", age_seconds=100_000)
    monkeypatch.setattr(docker_client, "events", boom)
    assert docker_backend.sweep_orphans() == []
    assert docker_client.removes == []


def test_docker_sweep_does_not_report_a_refused_removal(docker_client):
    """A daemon that refuses the removal cannot fail the scan (fail-soft by
    channel contract) — and is not reported as reaped either: the next scan
    re-sweeps the corpse."""
    stale = "cerberus-sandbox-run-aaaaaaaaaaaa"
    docker_client.list_names = [stale]
    docker_client.exec_events = _exec_events(stale, age_seconds=100_000)
    from _docker_fakes import FakeDockerError

    docker_client.remove_error = FakeDockerError("cannot remove")
    assert docker_backend.sweep_orphans() == []


def test_docker_sweep_reports_only_accepted_removals(docker_client):
    """Per-name honesty: one refused rm among several reports only the ones
    the daemon actually accepted."""
    from _docker_fakes import FakeDockerError

    dead1 = "cerberus-sandbox-run-aaaaaaaaaaaa"
    dead2 = "cerberus-sandbox-run-bbbbbbbbbbbb"
    docker_client.list_names = [dead1, dead2]
    docker_client.exec_events = (
        _exec_events(dead1, age_seconds=100_000)
        + _exec_events(dead2, age_seconds=100_000))
    docker_client.remove_error = FakeDockerError("cannot remove")  # one-shot
    assert docker_backend.sweep_orphans() == [dead2]
    assert docker_client.removes == [dead2]


# -- the harness-facing entry point ------------------------------------------


def test_sweep_orphans_covers_the_backends(docker_client, tmp_path):
    """The facade sweeps every backend's registry; a live run of this
    process is never a target."""
    stale = "cerberus-sandbox-run-aaaaaaaaaaaa"
    live_run = docker_backend.RUNS.get(str(tmp_path))
    docker_client.list_names = [stale, live_run.name]
    ages = {stale: 100_000, live_run.name: 30}

    def events(*, since=None, until=None, filters=None, decode=True):
        name = filters["container"]
        docker_client.event_calls.append(dict(filters or {}))
        return _exec_events(name, age_seconds=ages.get(name, 30))

    docker_client.events = events
    assert sweep_orphans() == [stale]
    assert docker_client.removes == [stale]


def test_sweep_orphans_is_silent_when_a_backend_is_absent(monkeypatch):
    def boom(timeout=60.0):
        raise RuntimeError("no runtime here")

    monkeypatch.setattr(docker_channel, "client_for", boom)
    assert sweep_orphans() == []


# -- the scan-start gate -----------------------------------------------------


def test_scan_start_sweeps_and_reports(monkeypatch):
    from cerberus import pipeline

    monkeypatch.setattr("cerberus.config.load_config",
                        lambda: {"sandbox": {"sweep_orphans": 1}})
    seen: list[list[str]] = []
    monkeypatch.setattr("cerberus.sandbox.sweep_orphans",
                        lambda: seen.append(["x"]))
    pipeline._sweep_orphan_sandboxes()
    assert seen == [["x"]]


def test_scan_start_respects_the_off_switch(monkeypatch):
    from cerberus import pipeline

    monkeypatch.setattr("cerberus.config.load_config",
                        lambda: {"sandbox": {"sweep_orphans": 0}})
    monkeypatch.setattr("cerberus.sandbox.sweep_orphans",
                        lambda: pytest.fail("sweep ran while disabled"))
    pipeline._sweep_orphan_sandboxes()


def test_scan_start_survives_a_broken_sweep(monkeypatch):
    from cerberus import pipeline

    calls = []
    monkeypatch.setattr("cerberus.config.load_config",
                        lambda: {"sandbox": {"sweep_orphans": 1}})

    def boom():
        calls.append("sweep")
        raise RuntimeError("boom")

    monkeypatch.setattr("cerberus.sandbox.sweep_orphans", boom)
    pipeline._sweep_orphan_sandboxes()      # must not raise
    assert calls == ["sweep"]               # ran once, then failed open


# -- no harness-side liveness state ------------------------------------------


def test_the_backend_keeps_no_liveness_state_on_disk(docker_client, tmp_path):
    """The daemon's events log is the liveness record: nothing is written
    anywhere. This is the property that makes the sweep survive SIGKILL —
    a harness-side mark is exactly the state a killed process cannot keep."""
    before = {p.name for p in tmp_path.rglob("*")}
    docker_client.list_names = ["cerberus-sandbox-run-aaaaaaaaaaaa"]
    docker_client.exec_events = _exec_events(
        "cerberus-sandbox-run-aaaaaaaaaaaa", age_seconds=100_000)
    docker_backend.sweep_orphans()
    assert {p.name for p in tmp_path.rglob("*")} == before

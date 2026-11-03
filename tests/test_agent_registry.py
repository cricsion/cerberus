from cerberus.progress import AgentRegistry, AgentState


def test_registry_lifecycle():
    reg = AgentRegistry(run_id="r")
    h = reg.create("a", "hunter", unit="u", model="m")
    assert h.state == AgentState.pending
    reg.transition("a", AgentState.running, message="start")
    assert h.state == AgentState.running
    assert h.started_at is not None
    reg.transition("a", AgentState.succeeded, message="done")
    assert h.state == AgentState.succeeded
    assert h.finished_at is not None

    handles = reg.dump()
    assert handles[0]["agent_id"] == "a"
    evts = reg.events_list()
    assert len(evts) >= 3
    assert all(e["run_id"] == "r" for e in evts)

    summary = reg.summary()
    assert summary["total"] == 1
    assert summary["by_state"]["succeeded"] == 1


def test_registry_terminal_does_not_regress():
    reg = AgentRegistry(run_id="r")
    reg.create("a", "hunter")
    reg.transition("a", AgentState.failed, error="boom")
    reg.transition("a", AgentState.succeeded)  # should not override terminal
    assert reg.get("a").state == AgentState.failed

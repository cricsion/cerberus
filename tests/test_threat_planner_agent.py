"""The planner and the historian run as repo-confined Deep Agents.

Regression guard: ``_llm_structured`` routed only ``SwarmResearch`` to the
deepagents path; ``SwarmHistory`` and ``SwarmPlan`` took the raw
``with_structured_output`` path (with a hand-rolled retry loop for the
planner). Both repo-reading schemas now go through ``run_structured`` with a
resolved backend and the task's explicit repo root, so malformed replies are
re-prompted by the framework instead of a bespoke loop.

The routing contract is identical for both schemas, so it is asserted once
per (schema, agent-name) pair below rather than in two copies.
"""
from __future__ import annotations

import cerberus.agents.deep as deep
import cerberus.sandbox as sandbox
import cerberus.threat as th
import pytest
from cerberus.prompts.threat import (
    HISTORIAN_SYSTEM,
    SYNTH_SYSTEM,
    SwarmHistory,
    SwarmPlan,
    build_historian_task,
    build_synth_task,
)


class _Backend:
    """Stand-in for a resolved backend (not a Sandbox --> no `execute`)."""


def _historian_task(root: str) -> str:
    return build_historian_task(root, "abc123 fix overflow", "draft", [])


def _planner_task(root: str) -> str:
    return build_synth_task(root, "draft", "{}", "{}")


# (agent name, schema, system prompt, brief builder, empty reply, batched?)
# historian keeps the deepagent route (it may read the repo); planner input is
# fully embedded, so it takes the one-shot batched transport (no agent build).
_AGENT_CASES = [
    pytest.param("threat:historian", SwarmHistory, HISTORIAN_SYSTEM,
                 _historian_task, SwarmHistory(vulns=[]), False,
                 id="historian"),
    pytest.param("threat:synthesizer", SwarmPlan, SYNTH_SYSTEM, _planner_task,
                 SwarmPlan(), True, id="planner"),
]


@pytest.mark.parametrize("name,schema,system,task_fn,reply,batched", _AGENT_CASES)
def test_routes_through_deepagents(monkeypatch, tmp_path, name, schema, system,
                                   task_fn, reply, batched):
    captured: dict = {}

    if batched:
        def fake_batch(mk, model, system_, humans, **kw):
            captured["model"] = model
            captured["name"] = kw.get("name")
            return [reply]

        monkeypatch.setattr(deep, "run_structured_batch", fake_batch)
    else:
        def fake_run_structured(mk, model, system, human, **kw):
            captured["model"] = model
            captured["name"] = kw.get("name")
            captured["backend"] = kw.get("backend")
            captured["root_dir"] = kw.get("root_dir")
            return reply, ""

        monkeypatch.setattr(deep, "run_structured", fake_run_structured)

    def _boom(*_a, **_k):
        raise AssertionError(f"{name} took the raw make_llm path")

    # The raw branch is the only one that builds a model; if the agent falls
    # back to it, this trips.
    monkeypatch.setattr(deep, "make_llm", _boom)
    monkeypatch.setattr(sandbox, "resolve_backend",
                        lambda cfg, root, agent_id=None: _Backend())
    monkeypatch.setattr(sandbox, "close_backend",
                        lambda b: captured.setdefault("closed", b))
    monkeypatch.setattr("cerberus.config.load_config", lambda: {})

    task = task_fn(str(tmp_path))
    parsed = th._llm_structured({"hunter_model": "m"}, schema, system, task)

    assert captured["model"] is schema
    assert captured["name"] == name
    if not batched:
        assert captured["backend"] is not None
        assert captured["root_dir"] is not None
        assert captured.get("closed") is not None
    else:
        # run_structured_batch takes no backend: resolving one would leak it.
        assert captured.get("closed") is None
    assert isinstance(parsed, schema)


@pytest.mark.parametrize("task_fn", [_historian_task, _planner_task],
                         ids=["historian", "planner"])
def test_task_carries_repo_root_first_line(task_fn):
    """The Deep Agent branch derives its root from the task's first line, so
    every swarm brief must carry the same ``Repository (read-only):`` prefix."""
    assert task_fn("/some/repo").splitlines()[0] == \
        "Repository (read-only): /some/repo"


def test_unknown_schema_is_rejected():
    """Only the three known threat schemas are accepted; anything else must
    raise rather than silently run through an unconfigured path."""

    class NotASchema:
        pass

    with pytest.raises(ValueError):
        th._llm_structured({"hunter_model": "m"}, NotASchema,
                           "system", "Repository (read-only): /tmp")

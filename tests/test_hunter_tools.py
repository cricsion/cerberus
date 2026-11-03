"""Hunter tool surface: the shared list in local and sandbox modes, never SAST wrappers."""
from __future__ import annotations

import types


def _capturing_build(monkeypatch):
    captured: dict = {}

    def spy(llm, **kw):
        captured.update(kw)
        return types.SimpleNamespace(**kw)

    monkeypatch.setattr("cerberus.agents.deep.build_deep_agent", spy)
    return captured


_MK = {"model": "m", "api_key": "dummy", "timeout": 10}

STRUCTURE = (
    "callers",
    "callees",
    "framework_routes",
    "affected",
    "reachability_check",
    "get_ast_slice",
    "trace_interprocedural_hop",
    "resolve_blind_spot",
    "compare_sibling_route_security",
    "trace_state_machine_transitions",
    "trace_effect_category",
)

WRAPPERS = ("semgrep_scan", "opengrep_scan")


def _names(captured):
    return sorted(t.name for t in captured["tools"])


def test_local_mode_binds_no_sast_wrappers(monkeypatch, tmp_path):
    from cerberus.agents.hunters import build_unit_hunter_agent
    from cerberus.sandbox.local_backend import RepoLocalBackend

    captured = _capturing_build(monkeypatch)
    backend = RepoLocalBackend(repo_path=tmp_path)
    build_unit_hunter_agent("u", _MK, repo=str(tmp_path), backend=backend)
    names = _names(captured)
    for expected in STRUCTURE:
        assert expected in names, expected
    for absent in WRAPPERS:
        assert absent not in names, absent


def test_sandbox_mode_binds_no_sast_wrappers(monkeypatch, tmp_path):
    """A sandbox shell + skills are the scan surface; a wrapper would be a second,
    weaker scan path competing with it."""
    import cerberus.sandbox.docker_backend as db
    from cerberus.agents.hunters import build_unit_hunter_agent

    captured = _capturing_build(monkeypatch)
    backend = db.DockerSandboxBackend(repo_path=tmp_path)
    try:
        build_unit_hunter_agent("u", _MK, repo=str(tmp_path), backend=backend)
    finally:
        backend.close()
    names = _names(captured)
    for expected in STRUCTURE:
        assert expected in names, expected
    for absent in WRAPPERS:
        assert absent not in names, absent


def test_fs_and_execute_tools_are_not_in_the_harness_list(monkeypatch, tmp_path):
    from cerberus.agents.hunters import build_unit_hunter_agent
    from cerberus.sandbox.local_backend import RepoLocalBackend

    captured = _capturing_build(monkeypatch)
    backend = RepoLocalBackend(repo_path=tmp_path)
    build_unit_hunter_agent("u", _MK, repo=str(tmp_path), backend=backend)
    names = _names(captured)
    for injected in ("read_file", "ls", "glob", "grep", "execute"):
        assert injected not in names, injected

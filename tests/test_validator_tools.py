"""Pins the shared agent tool surface and the validator's ``tools=`` wiring."""
from __future__ import annotations

SHARED = (
    "codegraph_explore",
    "find_path",
    "impact_radius",
    "type_hierarchy",
    "build_context",
    "get_routing_manifest",
    "callers",
    "callees",
    "framework_routes",
    "affected",
    "reachability_check",
    "get_ast_slice",
    "trace_interprocedural_hop",
    "resolve_blind_spot",
    "compare_sibling_route_security",
    "find_shared_state_readers_writers",
    "inspect_type_contract",
    "trace_egress_and_ssrf_targets",
    "trace_state_machine_transitions",
    "trace_effect_category",
    "detect_circular_and_dead_code",
)



def _f(id="a", path="a.py", status="needs-review"):
    return {
        "id": id, "title": "t", "path": path, "cwe": "CWE-89",
        "status": status, "severity": "high", "confidence": 0.5,
        "start_line": 1, "end_line": 1, "snippet": "s",
        "taint": {"source": "u", "sink": "q", "path": []}, "evidence": "e",
    }


def test_shared_surface_has_reachability_and_no_sast_wrappers():
    from cerberus.agents.toolsets import graph_tools

    names = {getattr(t, "name", "") for t in graph_tools()}
    assert names == set(SHARED)


def test_validator_batch_passes_tools_and_backend(monkeypatch, tmp_path):
    monkeypatch.setenv("API_KEY", "dummy-for-test")
    import cerberus.agents.deep as deep
    from cerberus.agents import validator as v

    captured: dict = {}

    def fake_run_structured(mk, model, system, human, **kw):
        captured.update(kw)
        from cerberus.prompts.validator import VerdictBatch, VerdictItem
        return (VerdictBatch(verdicts=[VerdictItem(
            id="a", status="confirmed",
            evidence="db.py:1 parameterized query")]), "")

    monkeypatch.setattr(deep, "run_structured", fake_run_structured)
    cfg = {"sandbox": {"backend": "local"}, "validator_model": "m"}
    out = v._validate_unit_batch("u1", [_f(id="a")], cfg, "", 1,
                                 repo=str(tmp_path))
    names = {getattr(t, "name", "") for t in captured.get("tools", [])}
    assert names == set(SHARED)
    assert captured.get("backend") is not None
    assert out[0]["status"] == "confirmed"
    monkeypatch.delenv("API_KEY", raising=False)

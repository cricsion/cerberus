"""Pipelined validation: a validator pass starts the moment a hunter pass
completes, instead of waiting for all hunters.

Contracts under test:
- hunter_worker returns raw findings; the window validates and appends.
- aggregator_node queues only raw findings with no validated counterpart.
- validator_node validates the remainder and appends (never rewrites).
- triage_node / scorer_node replace the channel instead of doubling it.
"""
import cerberus.pipeline as g


def _f(fid, path="a.py", cwe="CWE-89", line=1, status="needs-review"):
    return {"id": fid, "title": fid, "cwe": cwe, "path": path,
            "start_line": line, "end_line": line, "snippet": "q",
            "status": status, "confidence": 0.5}


def test_verified_overwrite_replaces_not_doubles():
    state = {}
    g.apply_update(state, {"verified": [_f("a"), _f("b")]})
    g.apply_update(state, {"verified": g.Overwrite([_f("z")])})
    assert [f["id"] for f in state["verified"]] == ["z"]


def test_hunter_worker_returns_raw_only(monkeypatch):
    monkeypatch.setattr("cerberus.agents.hunters._run_unit",
                        lambda *a, **k: [_f("u1")])
    calls = []
    monkeypatch.setattr(
        "cerberus.agents.validator.run_validation",
        lambda *a, **k: calls.append(1) or [])
    out = g.hunter_worker({"unit": "api", "repo": ".", "files": ["a.py"],
                           "candidates": [], "cfg": {"concurrency": 4},
                           "threat_model_md": "tm", "focus": []})
    # Validation is the window's job now; the hunt stays raw.
    assert [f["id"] for f in out["findings"]] == ["u1"]
    assert "verified" not in out and not calls


def test_unvalidated_hunt_self_heals_via_join(monkeypatch):
    monkeypatch.setattr("cerberus.agents.hunters._run_unit",
                        lambda *a, **k: [_f("u9")])
    out = g.hunter_worker({"unit": "api", "repo": ".", "files": ["a.py"],
                           "candidates": [], "cfg": {}, "threat_model_md": "",
                           "focus": []})
    # Raw passes through unvalidated; aggregator's join re-queues it.
    assert "verified" not in out
    agg = g.aggregator_node({"candidates": [], "findings": out["findings"],
                             "verified": []})
    assert [f["id"] for f in agg["pending"]] == ["u9"]


def test_aggregator_queues_only_unvalidated():
    done = _f("x", status="confirmed")
    raw_x = _f("x")          # same id as the validated copy -> already done
    raw_y = _f("y", line=2)  # distinct id: no validated counterpart
    out = g.aggregator_node({"candidates": [raw_x, raw_y], "findings": [],
                             "verified": [done]})
    assert "verified" not in out
    assert [f["id"] for f in out["pending"]] == ["y"]


def test_validator_correction_does_not_rebill_the_same_claim():
    """A corrected cwe/snippet must not change identity.

    The raw hunter finding and its validator-corrected copy share an ``id``
    (``_merge_verdict`` preserves it), so the aggregator's join on the second
    pass drops the raw copy instead of re-queuing — and re-billing — the same
    underlying claim.
    """
    from cerberus.agents.validator import _merge_verdict

    raw = _f("u1", cwe="CWE-89", line=7)
    raw["snippet"] = "original snippet"
    corrected = _merge_verdict(dict(raw), {"status": "confirmed",
                                           "cwe": "CWE-78",
                                           "snippet": "corrected snippet",
                                           "confidence": 0.9})
    # The merge rewrote mutable payload but preserved the id...
    assert corrected["id"] == raw["id"] == "u1"
    assert corrected["cwe"] != raw["cwe"]
    assert corrected["snippet"] != raw["snippet"]
    # ...so the second pass re-queues nothing (memo hit on stable identity).
    agg = g.aggregator_node({"candidates": [], "findings": [raw],
                             "verified": [corrected]})
    assert agg["pending"] == []


def test_aggregator_does_not_collapse_two_ids_on_one_location():
    """Identity is the id, not path+line: a genuinely distinct finding that
    merely shares a location with an already-validated one must not be
    silently treated as validated."""
    corrected = _f("u1", cwe="CWE-78", line=7, status="confirmed")
    other = _f("u2", cwe="CWE-78", line=7, status="needs-review")
    agg = g.aggregator_node({"candidates": [other], "findings": [],
                             "verified": [corrected]})
    assert [f["id"] for f in agg["pending"]] == ["u2"]


def test_norm_key_id_primary_with_coordinate_fallback():
    # Id present -> identity is the id (different ids never collapse).
    assert g._norm_key({"id": "i1", "path": "x.py", "start_line": 3}) \
        != g._norm_key({"id": "i2", "path": "x.py", "start_line": 3})
    # No id -> fall back to (path, start_line, end_line).
    a = {"path": "x.py", "start_line": 3, "end_line": 4}
    b = {"path": "./x.py", "start_line": 3, "end_line": 4}
    c = {"path": "x.py", "start_line": 9, "end_line": 9}
    assert g._norm_key(a) == g._norm_key(b)
    assert g._norm_key(a) != g._norm_key(c)


def test_validator_node_appends_remainder_only(monkeypatch):
    import cerberus.config as _cfg
    monkeypatch.setattr(_cfg, "load_config", lambda *a, **k: {})
    monkeypatch.setattr(
        "cerberus.agents.validator.run_validation",
        lambda findings, cfg, md, votes=None, units=None, max_workers=None,
        repo=None, agent_registry=None: [
            {**f, "status": "confirmed"} for f in findings])
    already = [_f("old", status="confirmed")]
    out = g.validator_node({"pending": [_f("new")], "verified": already,
                            "fanout_payloads": []})
    # Appends the validated remainder; the earlier entries are untouched
    # (the reducer concatenates; nothing is rewritten here).
    assert [f["id"] for f in out["verified"]] == ["new"]
    assert out["verified"][0]["status"] == "confirmed"


def test_triage_and_scorer_replace_do_not_double(monkeypatch):
    import cerberus.agents.triage as _tr
    monkeypatch.setattr(_tr, "run_triage",
                        lambda verified, cfg, md, repo="": {
                            "findings": [{**f, "duplicate_of": ""} for f in verified]})
    import cerberus.config as _cfg
    monkeypatch.setattr(_cfg, "load_config", lambda *a, **k: {})
    Overwrite = g.Overwrite
    t = g.triage_node({"verified": [_f("a"), _f("b")], "threat_model_md": ""})
    assert isinstance(t["verified"], Overwrite)
    assert len(t["verified"].value) == 2
    s = g.scorer_node({"verified": [_f("a"), _f("b")]})
    assert isinstance(s["verified"], Overwrite)
    assert [f["rank"] for f in s["verified"].value] == [1, 2]


def _hot(fid, status="confirmed", severity="high"):
    f = _f(fid, status=status)
    f["severity"] = severity
    return f


def test_confirm_step_approved_changes_nothing():
    asked = []
    state = {"verified": [_hot("a"), _f("b")]}
    out = g.confirm_critical_step(state, lambda p: asked.append(p) or True)
    assert out == {}
    assert [f["id"] for f in asked[0]["findings"]] == ["a"]


def test_confirm_step_does_not_demote_hot_findings():
    state = {"verified": [_hot("a"), _hot("m", severity="medium"), _hot("c", status="fp")]}
    out = g.confirm_critical_step(state, lambda p: False)
    assert out == {}

    out_none = g.confirm_critical_step(state, None)
    assert out_none == {}


def test_confirm_step_silent_when_nothing_hot():
    called = []
    out = g.confirm_critical_step({"verified": [_f("a")]},
                                  lambda p: called.append(p) or True)
    assert out == {} and not called


def test_apply_update_channel_semantics():
    st = {"candidates": [{"id": "c0"}], "verified": [_f("a")]}
    g.apply_update(st, {"candidates": [{"id": "c1"}], "tools_used": ["x"],
                        "verified": [_f("b")], "files": ["f.py"]})
    g.apply_update(st, {"tools_used": ["y"]})
    assert [c["id"] for c in st["candidates"]] == ["c0", "c1"]
    assert st["tools_used"] == ["x", "y"]
    assert [f["id"] for f in st["verified"]] == ["a", "b"]
    assert st["files"] == ["f.py"]
    g.apply_update(st, {"verified": g.Overwrite([_f("z")])})
    assert [f["id"] for f in st["verified"]] == ["z"]


def test_fan_out_is_bounded_and_ordered(monkeypatch):
    import threading
    import time

    live, peak, lock = [0], [0], threading.Lock()

    def worker(p):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.05)
        with lock:
            live[0] -= 1
        return {"findings": [_f(p["unit"])], "tools_used": [p["unit"]]}

    monkeypatch.setattr(g, "hunter_worker", worker)
    monkeypatch.setattr(g, "_validate_inline", lambda f, *a, **k: f)
    monkeypatch.setattr(g, "system_pass_node", lambda s, **_k: {})
    state = {"fanout_payloads": [{"unit": f"u{i}"} for i in range(6)]}
    g._fan_out_hunters(state, max_workers=2)
    assert peak[0] <= 2
    # Completion order is free; the append-only channel keeps every unit.
    assert sorted(f["id"] for f in state["findings"]) == [f"u{i}" for i in range(6)]


def test_fan_out_survives_a_crashing_worker(monkeypatch):
    def worker(p):
        if p["unit"] == "bad":
            raise RuntimeError("boom")
        return {"findings": [_f(p["unit"])]}

    monkeypatch.setattr(g, "hunter_worker", worker)
    monkeypatch.setattr(g, "_validate_inline", lambda f, *a, **k: f)
    monkeypatch.setattr(g, "system_pass_node", lambda s, **_k: {})
    state = {"fanout_payloads": [{"unit": "ok", "repo": ".", "files": ["a.py"]},
                                 {"unit": "bad", "repo": ".", "files": ["a.py"]}]}
    g._fan_out_hunters(state, max_workers=2)
    ids = [f["id"] for f in state["findings"]]
    assert "ok" in ids and any("bad" in i for i in ids)  # fail-open fallback


def test_run_scan_stage_order_and_confirm_between_validation_and_triage(monkeypatch):
    order = []

    def stage(name, update=None):
        def fn(state, **_kwargs):
            order.append(name)
            return update or {}
        return fn

    monkeypatch.setattr(g, "indexer_node", stage("indexer", {"files": ["a.py"]}))
    monkeypatch.setattr(g, "threat_model_node", stage("threat_model"))
    monkeypatch.setattr(g, "hunters_router", stage(
        "hunters", {"fanout_payloads": [{"unit": "u"}]}))
    monkeypatch.setattr(g, "hunter_worker", lambda p: (order.append("worker") or {}))
    monkeypatch.setattr(g, "system_pass_node", stage("system_pass"))
    monkeypatch.setattr(g, "aggregator_node", stage("aggregator"))
    monkeypatch.setattr(g, "validator_node", stage(
        "validator", {"verified": [_hot("a")]}))
    monkeypatch.setattr(g, "triage_node", stage("triage"))
    monkeypatch.setattr(g, "threat_update_node", stage("threat_update"))
    monkeypatch.setattr(g, "scorer_node", stage("scorer"))
    asked = []
    out = g.run_scan("repo", confirm_critical=True,
                     confirm=lambda p: (order.append("confirm") or asked.append(p) or False))
    assert order == ["indexer", "threat_model", "hunters", "worker", "system_pass",
                     "aggregator", "validator", "confirm", "triage",
                     "threat_update", "scorer"]
    assert out["verified"][0]["status"] == "confirmed"  # preserved, not demoted


def test_run_scan_skips_fanout_without_payloads(monkeypatch):
    order = []
    for name in ("indexer_node", "threat_model_node", "hunters_router",
                 "system_pass_node", "aggregator_node", "validator_node",
                 "triage_node", "threat_update_node", "scorer_node"):
        monkeypatch.setattr(g, name,
                            (lambda n: lambda s, **_k: (order.append(n) or {}))(name))
    monkeypatch.setattr(g, "hunter_worker",
                        lambda p: (order.append("worker") or {}))
    g.run_scan("repo")
    # Fan-out is skipped without payloads (no units, no workers) ...
    assert "worker" not in order
    assert order[:3] == ["indexer_node", "threat_model_node", "hunters_router"]
    # ... but system pass still runs first in the tail: the node itself
    # gates on API key and hunter.system_pass (plan-1345 M2), not payloads.
    assert order[3] == "system_pass_node"

"""Lazy-synthesis detection + narrowed retry in the threat-model planner.

Reproduces the observable bug: the planner returns a "valid" (non-None)
structured payload that fills the DESCRIPTIVE half (context prose, entry
points, assets, parked rows, open questions) but leaves ``threats`` and
``mitigations`` EMPTY. That payload used to merge straight into an 8-section
document with an empty §4 Threats (no ranked threats for the hunters) and a
quality score that hid it.

The fix: ``enrich_threat`` detects the empty judgment half, retries once with
the narrowed brief, and — when both attempts come back empty — tags the
document via ``meta["judgment_empty"]`` and a code-owned §7 Provenance line so
it cannot masquerade as complete.

Tests drive the swarm through the real code paths by monkeypatching the single
seam ``cerberus.threat.swarm._llm_structured`` (signature ``(cfg, model, system,
human)``); the researcher / historian / planner stages are distinguished by the
schema class passed as ``model`` (``SwarmResearch`` / ``SwarmHistory``;
anything else is a planner call), so prompt wording edits cannot trip the
stand-in.
"""
from cerberus import threat as th
from test_threat import _history_payload, _research_payload


def _candidates():
    """A manifest candidate so ``_measured_blocks`` builds a real surface
    skeleton (rather than the 'unclassified entry points' fallback)."""
    return [
        {"id": "prefilter", "title": "p", "cwe": "", "severity": "info",
         "path": "r", "start_line": 0, "end_line": 0,
         "snippet": "## sqli-cursor\nfoo", "evidence": "e",
         "status": "needs-review"},
        {"id": "manifest", "title": "m", "cwe": "", "severity": "info",
         "path": "r", "start_line": 0, "end_line": 0, "snippet": "flask app",
         "evidence": "e", "status": "needs-review"},
    ]


def _empty_plan():
    """A lazy-synthesis payload: descriptive half filled, judgment half empty —
    exactly the shape the bug reproduced on real repos."""
    from cerberus.prompts.threat import SwarmPlan
    return SwarmPlan(
        context_prose="Flask shop with a login form and an order-comments field.",
        entry_points=[{"entry_point": "HTTP route GET /login",
                       "description": "login form",
                       "trust_boundary": "untrusted network → app",
                       "file_refs": ["app.py:12"]}],
        assets=[{"asset": "customer PII", "description": "orders",
                 "sensitivity": "high"}],
        threats=[],
        deprioritized=[{"threat": "Repudiation",
                        "reason": "no multi-user audit trail"}],
        open_questions=["Is there a WAF upstream?"],
        mitigations=[],
    )


def _plan_with_threats():
    from cerberus.prompts.threat import SwarmPlan, SwarmThreat
    return SwarmPlan(
        context_prose="Flask shop with a login form.",
        entry_points=[{"entry_point": "HTTP route GET /login",
                       "description": "login form",
                       "trust_boundary": "untrusted network → app",
                       "file_refs": ["app.py:12"]}],
        assets=[{"asset": "customer PII", "description": "orders",
                 "sensitivity": "high"}],
        threats=[SwarmThreat(
            threat="Auth bypass via SQL injection in login",
            actor="remote_unauth", surface="HTTP route GET /login",
            asset="customer PII", impact="critical", likelihood="likely",
            status="unmitigated", controls="none", evidence="app.py:12")],
        deprioritized=[{"threat": "Repudiation",
                        "reason": "no multi-user audit trail"}],
        open_questions=["Is there a WAF upstream?"],
        mitigations=[{"mitigation": "parameterized queries everywhere",
                      "threat_numbers": [1], "closes_class": "yes",
                      "effort": "S"}],
    )


def _fake_swarm(monkeypatch, planner_sequence):
    """Script the three swarm calls through ``cerberus.threat.swarm._llm_structured``.

    ``planner_sequence`` is consumed one entry per planner call (index 0 =
    first attempt, 1 = narrowed retry). Returns a state dict recording the
    planner-call count and each planner's human-task text so tests can assert
    exactly how many planner calls ran and which brief the retry used.
    """
    state = {"planner": 0, "humans": []}
    from cerberus.prompts.threat import SwarmHistory, SwarmResearch

    def _fake(cfg, model, system, human):
        if model is SwarmResearch:
            return _research_payload()
        if model is SwarmHistory:
            return _history_payload()
        # planner
        state["planner"] += 1
        state["humans"].append(human)
        idx = min(state["planner"] - 1, len(planner_sequence) - 1)
        return planner_sequence[idx]

    monkeypatch.setattr("cerberus.threat.swarm._llm_structured", _fake)
    return state


def test_empty_judgment_retries_once_with_narrowed_brief(monkeypatch, tmp_path):
    """Descriptive half filled, judgment half empty -> ONE narrowed retry that
    recovers, and the document ships with real threat rows."""
    (tmp_path / "app.py").write_text("x=1")
    cands = _candidates()
    floor = th.bootstrap_threat(str(tmp_path), ["app.py"], cands, "summ")

    # The narrowed brief is observable at the build_synth_task seam: the
    # recorder emits distinct text per `narrow`, and _synth_task threads the
    # kwarg through (or falls back when build_synth_task lacks it).
    synth_seen = []

    def rec_build_synth_task(repo, draft, research, history,
                             measured_facts="", narrow=False):
        synth_seen.append(bool(narrow))
        return f"TASK narrow={narrow}"

    monkeypatch.setattr("cerberus.prompts.threat.build_synth_task",
                        rec_build_synth_task)

    state = _fake_swarm(monkeypatch, [_empty_plan(), _plan_with_threats()])
    md, meta = th.enrich_threat(str(tmp_path), ["app.py"], cands, "summ",
                                floor, {})

    # Exactly two planner calls; the second used the narrowed brief.
    assert state["planner"] == 2
    assert synth_seen == [False, True]
    assert state["humans"][0] == "TASK narrow=False"
    assert state["humans"][1] == "TASK narrow=True"
    # meta records the retry, and the doc did NOT ship empty.
    assert meta["judgment_retry"] == "narrowed"
    assert "judgment_empty" not in meta
    rows = th._parse_threats(md)
    assert [r["id"] for r in rows] == ["T1"]
    assert "SQL injection" in rows[0]["threat"]
    # No honesty line — the retry recovered the judgment half.
    assert "- judgment: empty" not in th._section(md, "7. Provenance")
    assert meta["threat_rows"] == 1


def test_empty_judgment_on_both_attempts_ships_honestly(monkeypatch, tmp_path):
    """Both attempts come back empty: the descriptive half is still useful, so
    the document ships — but §7 carries the provenance tag and meta flags it."""
    (tmp_path / "app.py").write_text("x=1")
    cands = _candidates()
    floor = th.bootstrap_threat(str(tmp_path), ["app.py"], cands, "summ")
    state = _fake_swarm(monkeypatch, [_empty_plan(), _empty_plan()])
    md, meta = th.enrich_threat(str(tmp_path), ["app.py"], cands, "summ",
                                floor, {})

    # Two planner calls: the original plus exactly one narrowed retry.
    assert state["planner"] == 2
    # The document still ships — the descriptive half is worth keeping.
    assert md.strip()
    for section in th.SECTIONS:
        assert f"## {section}" in md
    assert meta["judgment_empty"]
    assert meta.get("judgment_retry") is None
    # §4 stays the schema header with no rows.
    assert th._parse_threats(md) == []
    # §7 provenance carries the code-owned honesty line.
    prov = th._section(md, "7. Provenance")
    assert "- judgment: empty" in prov
    assert "returned no threat rows; retried with a narrowed brief" in prov
    # ...and the descriptive half genuinely landed (not a bare floor).
    assert "Flask shop with a login form" in th._section(md, "1. System context")
    # The merged document is still structurally valid (ships, not discarded).
    assert th.validate_threat_md(md) == []


def test_planner_returns_none_is_unchanged(monkeypatch, tmp_path):
    """A None payload is the pre-existing failure path and is untouched: no
    md, an error mentioning the planner, and no narrowed retry."""
    (tmp_path / "app.py").write_text("x=1")
    cands = _candidates()
    floor = th.bootstrap_threat(str(tmp_path), ["app.py"], cands, "summ")
    state = _fake_swarm(monkeypatch, [None])
    md, meta = th.enrich_threat(str(tmp_path), ["app.py"], cands, "summ",
                                floor, {})
    assert md == ""
    assert "planner" in meta["error"]
    # No lazy synthesis on a None payload: never retried, never flagged.
    assert state["planner"] == 1
    assert "judgment_empty" not in meta
    assert "judgment_retry" not in meta


def test_normal_plan_with_threats_first_attempt_no_retry(monkeypatch, tmp_path):
    """A healthy judgment half on the first attempt: exactly one planner call,
    no retry, and no provenance honesty line."""
    (tmp_path / "app.py").write_text("x=1")
    cands = _candidates()
    floor = th.bootstrap_threat(str(tmp_path), ["app.py"], cands, "summ")
    state = _fake_swarm(monkeypatch, [_plan_with_threats()])
    md, meta = th.enrich_threat(str(tmp_path), ["app.py"], cands, "summ",
                                floor, {})

    assert state["planner"] == 1
    assert "judgment_retry" not in meta
    assert "judgment_empty" not in meta
    assert [r["id"] for r in th._parse_threats(md)] == ["T1"]
    assert "- judgment: empty" not in th._section(md, "7. Provenance")
    assert meta["threat_rows"] == 1


def test_merge_plan_provenance_line_is_gated_on_threat_rows():
    """The §7 honesty line is a pure function of the merged plan's threat rows:
    appended only when the judgment half is empty, and it never invents a
    second line when a retry already happened (one code-owned line is enough)."""
    blocks = {"ep_skeleton": "", "context_facts": "F"}

    empty_plan = {"context_prose": "a system", "threats": [],
                  "entry_points": [], "assets": [], "deprioritized": [],
                  "open_questions": [], "mitigations": []}
    md_empty, _ = th._merge_plan("repo", blocks, empty_plan)
    prov_empty = th._section(md_empty, "7. Provenance")
    assert prov_empty.count("- judgment: empty") == 1
    assert th._parse_threats(md_empty) == []

    rows = [{"threat": "X", "actor": "remote_unauth", "surface": "s",
             "asset": "a", "impact": "high", "likelihood": "likely",
             "status": "unmitigated", "controls": "", "evidence": ""}]
    md_rows, _ = th._merge_plan("repo", blocks, {"threats": rows})
    assert "- judgment: empty" not in th._section(md_rows, "7. Provenance")
    assert len(th._parse_threats(md_rows)) == 1


def test_mitigations_only_empty_triggers_retry_and_is_named(monkeypatch,
                                                             tmp_path):
    """Threat rows present but mitigations empty is the same lazy-synthesis
    slip one column over: the retry must fire and §8's emptiness must be
    named in provenance (observed live: 8 threat rows, 0 mitigations)."""
    from cerberus.prompts.threat import SwarmPlan, SwarmThreat
    (tmp_path / "app.py").write_text("x=1")
    floor = th.bootstrap_threat(str(tmp_path), ["app.py"], [], "s")

    threat = SwarmThreat(threat="SQL injection in login", actor="remote_unauth",
                         surface="HTTP route GET /login", asset="customer PII",
                         impact="critical", likelihood="likely",
                         status="unmitigated", controls="none", evidence="")

    from cerberus.prompts.threat import SwarmAsset, SwarmEntryPoint
    eps = [SwarmEntryPoint(entry_point="HTTP route GET /login",
                           description="login form",
                           trust_boundary="untrusted network -> app",
                           file_refs=["app.py:12"])]
    assets = [SwarmAsset(asset="customer PII", description="orders",
                         sensitivity="high")]

    half = SwarmPlan(context_prose="p", entry_points=eps, assets=assets,
                     threats=[threat], mitigations=[])
    whole = SwarmPlan(context_prose="p", entry_points=eps, assets=assets,
                      threats=[threat],
                      mitigations=[{"mitigation": "parameterize queries",
                                    "threat_numbers": [1], "closes_class": "yes",
                                    "effort": "S"}])

    from cerberus.prompts.threat import SwarmHistory, SwarmResearch
    research = SwarmResearch(system_context="p", entry_points=eps, assets=assets)
    history = SwarmHistory()
    calls = {"n": 0}

    def _fake(cfg, model, system, human):
        if system.startswith("You are a threat-model research"):
            return research
        if system.startswith("You are a threat-model history"):
            return history
        calls["n"] += 1
        return half if calls["n"] == 1 else whole

    monkeypatch.setattr("cerberus.threat.swarm._llm_structured", _fake)
    md, meta = th.enrich_threat(str(tmp_path), ["app.py"], [], "s", floor, {})
    assert calls["n"] == 2  # the retry fired
    assert meta.get("judgment_retry") == "narrowed"
    rows = th._parse_threats(md)
    assert len(rows) == 1
    assert "| parameterize queries | T1 |" in th._section(
        md, "8. Recommended mitigations")

    # and when the retry still brings no mitigations, §7 says so
    calls["n"] = 0

    def _stub(cfg, model, system, human):
        if system.startswith("You are a threat-model research"):
            return research
        if system.startswith("You are a threat-model history"):
            return history
        return half

    monkeypatch.setattr("cerberus.threat.swarm._llm_structured", _stub)
    md2, meta2 = th.enrich_threat(str(tmp_path), ["app.py"], [], "s", floor, {})
    assert meta2.get("mitigations_empty") is True
    assert "- mitigations: empty" in md2
    assert "- judgment: empty" not in md2


# --- backend-resolution degrade contract (mirrors build_deep_agent) ---------


def test_backend_failure_degrades_on_any_non_fatal_error(monkeypatch, tmp_path):
    """resolve_backend failures degrade past ValueError: any non-fatal error
    (ImportError/TypeError/...) from a future backend change must still fall
    back to the repo-confined local backend and reach the LLM seam."""
    import cerberus.threat.swarm as sw
    from cerberus.prompts.threat import SwarmResearch

    (tmp_path / "a.py").write_text("x=1")
    hits = {"n": 0}

    def boom(*a, **k):
        raise ImportError("backend module moved")

    def fake_run_structured(mk, model, system, human, **kw):
        hits["n"] += 1
        return {"dummy": True}, ""

    monkeypatch.setattr("cerberus.sandbox.resolve_backend", boom)
    monkeypatch.setattr("cerberus.agents.deep.run_structured",
                        fake_run_structured)
    sw._llm_structured({}, SwarmResearch, "You are a threat-model research",
                       f"Repository (read-only): {tmp_path}")
    assert hits["n"] == 1  # reached the LLM seam with the local fallback


def test_backend_failure_is_loud_on_config_error(monkeypatch, tmp_path):
    """Config-class resolve_backend failures re-raise (is_fatal_error
    contract), never silently degrade the threat stage."""
    import cerberus.threat.swarm as sw
    import pytest
    from cerberus.prompts.threat import SwarmResearch
    from langchain_core.exceptions import ModelAuthenticationError

    (tmp_path / "a.py").write_text("x=1")

    def boom(*a, **k):
        raise ModelAuthenticationError("bad key")

    monkeypatch.setattr("cerberus.sandbox.resolve_backend", boom)
    with pytest.raises(ModelAuthenticationError):
        sw._llm_structured({}, SwarmResearch, "You are a threat-model research",
                           f"Repository (read-only): {tmp_path}")

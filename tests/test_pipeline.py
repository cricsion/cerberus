from pathlib import Path

import pytest
from cerberus.pipeline import indexer_node


def _window_finding(fid):
    return {"id": fid, "title": fid, "cwe": "CWE-89", "path": "a.py",
            "start_line": 1, "end_line": 1, "snippet": "q",
            "status": "needs-review"}


def test_fan_out_window_validates_and_runs_system_pass(monkeypatch):
    import cerberus.pipeline as g

    log = []
    sizes = {"u1": 3, "u2": 12, "u3": 0}

    def run_unit(unit, *a, **k):
        log.append("hunt:" + unit["name"])
        return [_window_finding(f"{unit['name']}-{i}")
                for i in range(sizes[unit["name"]])]

    def validate(findings, *a, **k):
        log.append("bundle:" + a[3])
        assert len(findings) <= 25
        return [dict(f, verified=True) for f in findings]

    seen_at_syspass = {}

    def syspass(state, **_kwargs):
        log.append("system_pass")
        # Drain contract: every hunt's findings are already applied here.
        seen_at_syspass["ids"] = {f["id"] for f in state.get("findings", [])}
        return {"findings": [_window_finding("sys-1")]}

    monkeypatch.setattr("cerberus.agents.hunters._run_unit", run_unit)
    monkeypatch.setattr(g, "_validate_inline", validate)
    monkeypatch.setattr(g, "system_pass_node", syspass)
    state = {"repo": ".", "fanout_payloads": [{"unit": u} for u in sizes]}
    g._fan_out_hunters(state, max_workers=2)

    ids = {f["id"] for f in state["findings"]}
    assert {"u1-0", "u1-2", "u2-11", "sys-1"} <= ids
    assert len(state["verified"]) == 15 and all(f["verified"]
                                                 for f in state["verified"])
    hunts = [i for i, s in enumerate(log) if s.startswith("hunt:")]
    assert log.count("system_pass") == 1
    assert log.index("system_pass") > max(hunts)
    # System pass must start only after every hunt completed (not merely
    # submitted): it can see all hunt findings in the shared state.
    expected = {f"{u}-{i}" for u, n in sizes.items() for i in range(n)}
    assert expected <= seen_at_syspass["ids"]
    for unit in ("u1", "u2"):
        first = log.index("bundle:" + unit)
        assert first > log.index("hunt:" + unit)


def test_fan_out_window_reraises_a_fatal_hunt(monkeypatch):
    import time

    import cerberus.pipeline as g

    def run_unit(unit, *a, **k):
        if unit["name"] == "bad":
            raise KeyError("operator config")
        return [_window_finding(unit["name"])]

    monkeypatch.setattr("cerberus.agents.hunters._run_unit", run_unit)
    monkeypatch.setattr(g, "_validate_inline",
                        lambda f, *a, **k: [dict(x, ok=True) for x in f])
    monkeypatch.setattr(g, "system_pass_node", lambda s, **_k: {})
    state = {"repo": ".", "fanout_payloads": [{"unit": "good"},
                                              {"unit": "bad"}]}
    t0 = time.perf_counter()
    with pytest.raises(KeyError):
        g._fan_out_hunters(state, max_workers=2)
    # Hang guard only (cancelled futures must not block the join).
    assert time.perf_counter() - t0 < 5.0


def test_fan_out_window_bundle_size_follows_cell_size(monkeypatch):
    import cerberus.pipeline as g

    sizes = []

    def hunt(state):
        return {"findings": [_window_finding(f"u-{i}") for i in range(14)]}

    def validate(findings, *a, **k):
        sizes.append(len(findings))
        return [dict(f, verified=True) for f in findings]

    monkeypatch.setattr(g, "hunter_worker", hunt)
    monkeypatch.setattr(g, "_validate_inline", validate)
    monkeypatch.setattr(g, "system_pass_node", lambda s, **_k: {})
    cfg = {"verification": {"cell_size": 6}}
    state = {"repo": ".", "fanout_payloads": [{"unit": "u", "cfg": cfg}]}
    # max_workers=1 keeps bundle execution FIFO, so chunk order is stable.
    g._fan_out_hunters(state, max_workers=1)
    assert sizes == [6, 6, 2]
    assert len(state["verified"]) == 14


def test_fan_out_window_flips_validator_running_at_task_start(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    import cerberus.pipeline as g
    from cerberus.progress import AgentRegistry, AgentState

    reg = AgentRegistry()
    seen = {}

    def run_unit(unit, *a, **k):
        # While hunting, the unit's validator agent must not exist yet:
        # its bundles are only submitted after the hunt returns.
        seen[unit["name"]] = reg.get("validator:" + unit["name"])
        return [_window_finding(f"{unit['name']}-0")]

    def validate(findings, *a, **k):
        h = reg.get("validator:" + a[3])
        assert h is not None and h.state == AgentState.running
        return [dict(f, verified=True) for f in findings]

    real_submit = ThreadPoolExecutor.submit

    def submit(self, fn, *a, **k):
        # Bundle submissions are the only ones carrying _validate_inline.
        # At submit time the unit's agent must still be queued: on a shared
        # pool the task may sit queued behind hunts, so the `running` flip
        # must happen at execution start, not at submission.
        if len(a) >= 6 and a[0] is g._validate_inline:
            h = reg.get("validator:" + str(a[5]))
            assert h is not None and h.state == AgentState.queued
        return real_submit(self, fn, *a, **k)

    monkeypatch.setattr("cerberus.agents.hunters._run_unit", run_unit)
    monkeypatch.setattr(g, "_validate_inline", validate)
    monkeypatch.setattr(g, "system_pass_node", lambda s, **_k: {})
    monkeypatch.setattr("concurrent.futures.ThreadPoolExecutor.submit", submit)
    state = {"repo": ".", "fanout_payloads": [{"unit": "u1"}, {"unit": "u2"}]}
    g._fan_out_hunters(state, max_workers=2, agent_registry=reg)
    assert len(state["verified"]) == 2
    for u in ("u1", "u2"):
        assert seen[u] is None
        assert reg.get("validator:" + u).state == AgentState.succeeded


def test_fan_out_window_packs_llm_stream_and_rides_passthrough(monkeypatch):
    import cerberus.pipeline as g

    sizes = []

    def hunt(state):
        items = [_window_finding(f"llm-{i}") for i in range(12)]
        # Passthrough by routing rule 2: no CWE, severity=info.
        items += [{"id": f"info-{i}", "title": f"info-{i}", "cwe": "",
                   "severity": "info", "path": "a.py", "start_line": 1,
                   "end_line": 1, "snippet": "q", "status": "needs-review"}
                  for i in range(2)]
        return {"findings": items}

    def validate(findings, *a, **k):
        sizes.append(list(findings))
        return [dict(f, verified=True) for f in findings]

    monkeypatch.setattr(g, "hunter_worker", hunt)
    monkeypatch.setattr(g, "_validate_inline", validate)
    monkeypatch.setattr(g, "system_pass_node", lambda s, **_k: {})
    cfg = {"verification": {"cell_size": 6}}
    state = {"repo": ".", "fanout_payloads": [{"unit": "u", "cfg": cfg}]}
    g._fan_out_hunters(state, max_workers=1)
    ids = [[f.get("id") for f in chunk] for chunk in sizes]
    # Dense llm packing equals pre-P1: ceil(12/6) = 2 prompt calls, unrelated
    # to the passthrough count; passthrough rides bundle 0 (never a prompt).
    assert ids == [[f"llm-{i}" for i in range(6)]
                   + [f"info-{i}" for i in range(2)],
                   [f"llm-{i}" for i in range(6, 12)]]
    assert len(state["verified"]) == 14


def test_fan_out_window_survives_hunter_garbage(monkeypatch):
    """Split anomaly (non-dict finding) degrades to raw chunking — the
    pre-split in-call fail-open stance, never a scan-killing fatal.
    cell_size=1 makes fallback (1 combined chunk) distinguishable from a
    hypothetical garbage-skipping split (two 1-item chunks)."""
    import cerberus.pipeline as g

    sizes = []

    def hunt(state):
        return {"findings": [_window_finding("ok-0"), "garbage-string"]}

    def validate(findings, *a, **k):
        sizes.append(list(findings))
        return [dict(x, verified=True) if isinstance(x, dict) else
                {"title": str(x), "status": "needs-review"}
                for x in findings]

    monkeypatch.setattr(g, "hunter_worker", hunt)
    monkeypatch.setattr(g, "_validate_inline", validate)
    monkeypatch.setattr(g, "system_pass_node", lambda s, **_k: {})
    cfg = {"verification": {"cell_size": 1}}
    state = {"repo": ".", "fanout_payloads": [{"unit": "u", "cfg": cfg}]}
    g._fan_out_hunters(state, max_workers=1)
    # Raw fallback: the list re-chunks at cell_size (2 tasks of 1 item here),
    # in hunt order — a split that skipped the garbage would leave only
    # [ok-0] and 1 verified.
    assert [[f if isinstance(f, str) else f.get("id") for f in chunk]
            for chunk in sizes] == [["ok-0"], ["garbage-string"]]
    assert len(state.get("verified", [])) == 2


def test_fan_out_window_duplicate_unit_names_no_crash(monkeypatch):
    """Duplicate payload unit names (hand-built/adversarial; partitioning
    dedups) must not KeyError the bookkeeping or collide registry ids:
    counters and agent ids ride the per-payload ukey, labels stay real."""
    import time as _time

    import cerberus.pipeline as g
    from cerberus.progress import AgentRegistry, AgentState

    def hunt(state):
        n = 12 if len(state.get("files", [])) == 2 else 6
        return {"findings": [_window_finding(f"{state['unit']}-{n}-{i}")
                             for i in range(n)]}

    def validate(findings, *a, **k):
        _time.sleep(0.05)  # keep both _submit_bundles ahead of first apply
        return [dict(x, verified=True) for x in findings]

    monkeypatch.setattr(g, "hunter_worker", hunt)
    monkeypatch.setattr(g, "_validate_inline", validate)
    monkeypatch.setattr(g, "system_pass_node", lambda s, **_k: {})
    cfg = {"verification": {"cell_size": 6}}
    state = {"repo": ".", "fanout_payloads": [
        {"unit": "dup", "files": ["a1", "a2"], "cfg": cfg},
        {"unit": "dup", "files": ["b1"], "cfg": cfg}]}
    reg = AgentRegistry(run_id="t")
    g._fan_out_hunters(state, max_workers=2, agent_registry=reg)
    assert len(state.get("verified", [])) == 18
    # Distinct registry ids per payload; both reached succeeded.
    assert reg.get("validator:dup") is not None
    assert reg.get("validator:dup:1") is not None
    assert reg.get("validator:dup").state == AgentState.succeeded
    assert reg.get("validator:dup:1").state == AgentState.succeeded
    assert reg.get("hunter:dup") is not None
    assert reg.get("hunter:dup:1") is not None


def test_fan_out_window_applies_results_in_payload_order(monkeypatch):
    """Hunt results apply in payload order regardless of completion order —
    the pre-P1 application order — so position-sensitive consumers
    (system-pass findings[:500], report rank ties, HIL hot[:20]) see
    deterministic content."""
    import time as _time

    import cerberus.pipeline as g

    def hunt(state):
        if state["unit"] == "slow":
            _time.sleep(0.2)
        return {"findings": [_window_finding(state["unit"])]}

    monkeypatch.setattr(g, "hunter_worker", hunt)
    monkeypatch.setattr(g, "_validate_inline", lambda f, *a, **k: f)
    monkeypatch.setattr(g, "system_pass_node", lambda s, **_k: {})
    state = {"repo": ".", "fanout_payloads": [
        {"unit": "slow"}, {"unit": "fast1"}, {"unit": "fast2"}]}
    g._fan_out_hunters(state, max_workers=3)
    assert [f["id"] for f in state["findings"]] == ["slow", "fast1", "fast2"]


def test_indexer_prefilter_and_files():
    state = indexer_node({"repo": "tests/fixtures/pygoat-sample"})
    paths = state["files"]
    assert len(paths) == 3, paths
    ids = [c["id"] for c in state["candidates"]]
    assert "prefilter" in ids
    pre = next(c for c in state["candidates"] if c["id"] == "prefilter")
    assert "sqli-cursor" in pre["snippet"] or "sql" in pre["snippet"].lower()


def test_threat_model_node():
    from cerberus.pipeline import indexer_node, threat_model_node
    st = indexer_node({"repo": "tests/fixtures/pygoat-sample"})
    out = threat_model_node({**st, "repo": "tests/fixtures/pygoat-sample"})
    assert "STRIDE" in out["threat_model"]
    assert any(c["id"] == "threat-model" for c in out["candidates"])


def test_threat_summary_shared_by_cli():
    # `harness threat-model` builds the summary from indexer candidates (the
    # "threat-model" candidate only ever exists inside a scan); with no
    # indexer candidates it degrades to "unknown stack", never "".
    from cerberus.pipeline import threat_summary
    assert "unknown stack" in threat_summary("r", [])
    st = indexer_node({"repo": "tests/fixtures/pygoat-sample"})
    s = threat_summary("tests/fixtures/pygoat-sample", st["candidates"])
    assert "stack:" in s and "STRIDE" in s


def test_scorer_cvss_rank():
    from cerberus.pipeline import scorer_node
    st = scorer_node({"verified": [
        {"id": "a", "severity": "low", "confidence": 0.5},
        {"id": "b", "severity": "high", "confidence": 0.9},
    ]})
    v = st["verified"].value  # Overwrite: same set, annotated
    assert v[0]["id"] == "b" and v[0]["cvss"] > v[1]["cvss"]
    assert v[0]["rank"] == 1 and v[1]["rank"] == 2


def test_opengrep_iac_degrade(monkeypatch):
    """A missing binary degrades to a skip marker, never a raise: one agent
    command later the scan must continue, so the tools cannot throw."""
    import cerberus.tools._compat as compat

    # Force the not-installed path regardless of what the host has.
    monkeypatch.setattr(compat.shutil, "which", lambda name: None)
    from cerberus.tools.sast import iac_check, secrets_scan

    for t in (secrets_scan, iac_check):
        fn = t.func if hasattr(t, "func") else t
        res = fn(target="tests/fixtures/pygoat-sample")
        assert '"skipped": true' in res, res
        assert "binary not found" in res, res


def test_fanout_pipeline_runs_end_to_end(monkeypatch):
    # Offline contract: no API_KEY means LLM hunters are skipped entirely.
    monkeypatch.delenv("API_KEY", raising=False)
    from cerberus.pipeline import run_scan
    st = run_scan("tests/fixtures/pygoat-sample")
    assert len(st.get("files", [])) == 3
    assert st.get("verified")
    assert all("cvss" in f for f in st["verified"])


def test_inventory_files_golden():
    """The live walk's inventory for the checked-in fixtures is unchanged.

    The walk resolves its skip policy through ``tools/code.is_skipped_dir``:
    hard skip names plus the gated target/env rules.
    """
    from cerberus.pipeline import _inventory_files

    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    assert _inventory_files((fixtures / "pygoat-sample").resolve()) == [
        "app.py", "auth.py", "xss.py"]
    assert _inventory_files((fixtures / "polyglot").resolve()) == [
        "Dockerfile", "Program.cs", "Vuln.java", "lib.rs", "main.go",
        "main.tf", "vuln.c", "vuln.js", "vuln.php", "vuln.rb", "xss.html"]

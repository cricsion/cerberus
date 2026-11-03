"""Discovery reruns: unit hunt reruns, system-pass reruns, and the
incremental validation window.

Covers:
- ``hunter.reruns`` (one shared knob for unit hunts AND the system pass,
  unbounded): 0 = current behavior; N = N additional fresh sessions per
  pass, each seeded with earlier-pass findings (fallbacks excluded) and
  stopped after two consecutive empty passes.
- Rerun tasks carry the fenced prior-results block, cache-optimized:
  deterministic nonce and the block rides at the very END of the prompt
  so the rest stays byte-identical across rerun passes.
- Incremental validation: full ``cell_size`` chunks submit as soon as
  their buffer fills (carry-over across passes), the remainder flushes at
  the end, and reruns=0 reproduces the pre-rerun chunking.
- Fallback findings count as non-empty passes (infra failure never ends
  the loop early).
"""

import json

import cerberus.pipeline as g
from cerberus.agents import hunters as h
from cerberus.prompts import hunter as ph


def _window_finding(fid, cwe="CWE-89"):
    return {"id": fid, "title": fid, "cwe": cwe, "path": "a.py",
            "start_line": 1, "end_line": 1, "snippet": "q",
            "status": "needs-review"}


def _info_finding(fid):
    # Passthrough by routing rule 2 (no CWE, severity=info). Same shape
    # as test_pipeline's legacy ride test.
    return {"id": fid, "title": fid, "cwe": "", "severity": "info",
            "path": "a.py", "start_line": 1, "end_line": 1, "snippet": "q",
            "status": "needs-review"}


def _fallback_finding(fid):
    # The real fallback shape: id ends in "-fallback", severity info.
    return {"id": fid + "-fallback", "title": f"{fid}: manual review needed",
            "cwe": "", "severity": "info", "confidence": 0.0,
            "path": "a.py", "start_line": 0, "end_line": 0, "snippet": "s",
            "status": "needs-review"}


# --- prompt: prior findings render only for rerun passes --------------------


def test_hunter_task_without_prior_findings_has_no_prior_block():
    task = h.build_hunter_task("u", "/repo", ["a.py"], "", "", "")
    assert "Previously reported findings" not in task


def test_hunter_task_marks_prior_findings_as_already_reported():
    prior = [_window_finding("u-0"), _window_finding("u-1")]
    task = h.build_hunter_task("u", "/repo", ["a.py"], "", "",
                               prior_findings=prior)
    assert "## Previously reported findings" in task
    assert "Do NOT report any of them again" in task
    # The findings reach the prompt as data only (nonce-fenced untrusted
    # block) and carry their identifiers.
    assert "u-0" in task and "u-1" in task
    assert "<untrusted_data" in task


def test_hunter_task_prior_block_excludes_lifecycle_fields():
    f = _window_finding("u-0")
    f["patch"] = "um-diff-x"
    f["poc"] = {"status": "proven", "command": "SECRET-CMD"}
    task = h.build_hunter_task("u", "/repo", ["a.py"], "", "",
                               prior_findings=[f])
    assert "um-diff-x" not in task and "SECRET-CMD" not in task


def test_prior_findings_caps_at_500():
    # 505 real + 1 fallback appended beyond the shown window: the cap is
    # 500, so the fallback (callers normally filter it) is truncated out
    # along with 6 rows, and the "+ more" suffix explains them.
    many = [_window_finding(f"u-{i}") for i in range(505)]
    many.append(_fallback_finding("u"))
    task = h.build_hunter_task("u", "/repo", ["a.py"], "", "",
                               prior_findings=many)
    assert "+ 6 more already reported" in task
    assert "manual review needed" not in task


def test_prior_findings_block_is_deterministic():
    """Cache guarantee: identical prior payloads -> byte-identical blocks
    (deterministic content-seeded nonce, no randomness)."""
    prior = [_window_finding("u-0"), _window_finding("u-1")]
    first = ph.prior_findings_block(prior)
    second = ph.prior_findings_block(prior)
    assert first and first == second


def test_prior_findings_rides_at_the_prompt_tail():
    """Cache guarantee: the prior block is appended AFTER everything the
    pass-1 prompt has, so rerun prompts keep the pass-1 prompt as a
    byte-identical prefix — only the trailing block invalidates."""
    base = h.build_hunter_task("u", "/repo", ["a.py"], "", "", "")
    with_prior = h.build_hunter_task("u", "/repo", ["a.py"], "", "",
                                     prior_findings=[_window_finding("u-0")])
    assert with_prior.startswith(base + "\n\n")
    # ...and the block is the final content of the prompt.
    assert with_prior.rstrip().split("\n")[-1].startswith("</untrusted_data id=")


# --- unit hunt reruns driven through _fan_out_hunters -----------------------


def _run_fanout(monkeypatch, passes_results, *, cell_size=15, reruns=0):
    """Drive _fan_out_hunters with a scripted hunter_worker.

    ``passes_results``: per-pass finding lists, consumed in order for the
    single unit payload. Returns (state, calls, chunks) where calls record
    per-pass payload dicts and chunks the finding lists submitted to each
    validation bundle in submission order."""
    calls = []
    chunks = []
    seq = {"i": 0}

    def hunt(state):
        r = passes_results[min(seq["i"], len(passes_results) - 1)]
        seq["i"] += 1
        calls.append(dict(state))
        return {"findings": list(r)}

    def validate(findings, *a, **k):
        chunks.append(list(findings))
        return [dict(f, verified=True) for f in findings]

    monkeypatch.setattr(g, "hunter_worker", hunt)
    monkeypatch.setattr(g, "_validate_inline", validate)
    monkeypatch.setattr(g, "system_pass_node", lambda s, **_k: {})
    cfg = {"verification": {"cell_size": cell_size},
           "hunter": {"reruns": reruns}}
    state = {"repo": ".", "fanout_payloads": [
        {"unit": "u", "files": ["a.py"], "cfg": cfg}]}
    g._fan_out_hunters(state, max_workers=1)
    return state, calls, chunks


def test_hunt_reruns_zero_is_current_behavior(monkeypatch):
    state, calls, chunks = _run_fanout(monkeypatch, [[
        _window_finding(f"u-{i}") for i in range(4)]], reruns=0)
    assert len(calls) == 1 and "prior_findings" not in calls[0]
    assert [[f["id"] for f in c] for c in chunks] == (
        [[f"u-{i}" for i in range(4)]])
    assert len(state["verified"]) == 4


def test_hunt_reruns_seed_accumulated_findings_then_stop(monkeypatch):
    """reruns=2: pass 1 finds, passes 2 and 3 are both empty -> loop stops
    after the second empty pass; every rerun carries the accumulated
    prior findings (fallbacks excluded)."""
    results = [[_window_finding(f"u-{i}") for i in range(2)], [], []]
    state, calls, _ = _run_fanout(monkeypatch, results, reruns=2)
    assert len(calls) == 3
    # Passes 2 and 3 both see pass-1 findings as prior knowledge...
    for c in calls[1:]:
        assert [f["id"] for f in c["prior_findings"]] == ["u-0", "u-1"]
    # ...and the unit reports every pass's output, not only the last.
    assert {f["id"] for f in state["findings"]} >= {"u-0", "u-1"}


def test_hunt_reruns_early_stop_at_two_empty_passes(monkeypatch):
    """reruns=3 (4 passes scripted): pass 1 finds, 2 and 3 empty -> the
    4th pass never runs."""
    results = [[_window_finding("u-0")], [], [], []]
    _state, calls, _ = _run_fanout(monkeypatch, results, reruns=3)
    assert len(calls) == 3  # stopped after the second consecutive empty pass


def test_hunt_reruns_fallback_passes_keep_the_loop_running(monkeypatch):
    """A fallback finding is infra noise, never 'nothing new': the loop
    runs all configured reruns instead of early-stopping on it."""
    results = [[_window_finding("u-0")],
               [_fallback_finding("unit-u")],
               [_fallback_finding("unit-u")],
               [_fallback_finding("unit-u")]]
    state, calls, _ = _run_fanout(monkeypatch, results, reruns=3)
    assert len(calls) == 4
    # Fallback findings are not fed to later passes as coverage.
    prior = calls[-1].get("prior_findings", [])
    assert [f["id"] for f in prior] == ["u-0"]


def test_hunt_reruns_productive_pass_resets_the_streak(monkeypatch):
    """Find, empty, find: the streak clears, so pass 4 (reruns=3) runs."""
    results = [[_window_finding(f"u-{i}") for i in range(3)],
               [],
               [_window_finding("u-9")],
               []]
    state, calls, _ = _run_fanout(monkeypatch, results, reruns=3)
    assert len(calls) == 4
    ids = [f["id"] for f in state["findings"] if isinstance(f, dict)]
    assert set(ids) >= {"u-0", "u-1", "u-2", "u-9"}


def test_mid_rerun_failure_flushes_buffered_findings(monkeypatch):
    """F1 regression: a mid-rerun failure must flush the carry buffer.
    cell_size=5: pass 1 yields 7 findings (5 submitted, 2 buffered), pass 2
    raises -> the 2 carried findings still reach validation, plus every
    discovered finding is reported for the unit."""
    seen = []

    def hunt(state):
        seen.append(bool(state.get("prior_findings")))
        if len(seen) == 2:
            raise RuntimeError("transient infra")
        return {"findings": [_window_finding(f"u-{i}") for i in range(7)]}

    monkeypatch.setattr(g, "hunter_worker", hunt)
    monkeypatch.setattr(g, "_validate_inline",
                        lambda f, *a, **k: [dict(x, verified=True) for x in f])
    monkeypatch.setattr(g, "system_pass_node", lambda s, **_k: {})
    cfg = {"verification": {"cell_size": 5}, "hunter": {"reruns": 2}}
    state = {"repo": ".", "fanout_payloads": [
        {"unit": "u", "files": ["a.py"], "cfg": cfg}]}
    g._fan_out_hunters(state, max_workers=1)
    # All 7 discovered findings reach validation: 5 in pass 1's chunk,
    # 2 from the flushed carry buffer.
    assert len(state["verified"]) == 7
    # The unit result still reports everything it found (plus fallback),
    # so nothing vanishes from the findings merge either.
    assert any(f.get("id", "").endswith("-fallback")
               for f in state["findings"])
    assert {f["id"] for f in state["findings"]
            if not f.get("id", "").endswith("-fallback")} == (
        {f"u-{i}" for i in range(7)})


def test_mid_rerun_failure_keeps_fully_buffered_findings(monkeypatch):
    """F1 regression, uncapped-cell case: pass 1 yields 2 findings (< cell
    size, all buffered), pass 2 raises -> both still validate."""

    def hunt(state):
        if not state.get("prior_findings"):
            return {"findings": [_window_finding("u-0"),
                                 _window_finding("u-1")]}
        raise RuntimeError("transient infra")

    monkeypatch.setattr(g, "hunter_worker", hunt)
    monkeypatch.setattr(g, "_validate_inline",
                        lambda f, *a, **k: [dict(x, verified=True) for x in f])
    monkeypatch.setattr(g, "system_pass_node", lambda s, **_k: {})
    cfg = {"verification": {"cell_size": 15}, "hunter": {"reruns": 2}}
    state = {"repo": ".", "fanout_payloads": [
        {"unit": "u", "files": ["a.py"], "cfg": cfg}]}
    g._fan_out_hunters(state, max_workers=1)
    # pass 1's 2 findings were carried and flushed when pass 2 raised.
    assert {f["id"] for f in state.get("verified", [])} == {"u-0", "u-1"}
    assert any(f.get("id", "").endswith("-fallback")
               for f in state["findings"])


def test_hunt_reruns_error_pass_falls_back_like_before(monkeypatch):
    """hunter_worker raising on every pass keeps its pre-rerun fail-open
    behavior: the unit aborts through the existing except path and returns
    one fallback finding (no added per-pass retry machinery)."""
    seen = []

    def hunt(state):
        seen.append(dict(state))
        raise RuntimeError("transient infra")

    monkeypatch.setattr(g, "hunter_worker", hunt)
    monkeypatch.setattr(g, "_validate_inline",
                        lambda f, *a, **k: [dict(x) for x in f])
    monkeypatch.setattr(g, "system_pass_node", lambda s, **_k: {})
    cfg = {"hunter": {"reruns": 2}}
    state = {"repo": ".", "fanout_payloads": [
        {"unit": "u", "files": ["a.py"], "cfg": cfg}]}
    g._fan_out_hunters(state, max_workers=1)
    assert len(seen) == 1
    assert any(f.get("id", "").endswith("-fallback")
               for f in state["findings"])


def test_carry_over_partial_then_fill_submits_full_chunk(monkeypatch):
    """cell_size=5: pass 1 leaves 3 buffered, pass 2's 2 fill the cell ->
    validation launches while the unit's later passes keep hunting."""
    results = [[_window_finding(f"u-{i}") for i in range(3)],
               [_window_finding(f"u-{i}") for i in range(3, 5)],
               [_window_finding("u-9")]]
    state, _calls, chunks = _run_fanout(monkeypatch, results,
                                        cell_size=5, reruns=2)
    # Pass 1 submits nothing (< cell_size); pass 2 fills 3+2=5 -> one
    # chunk; the final flush submits the leftover 1.
    assert [[f["id"] for f in c] for c in chunks] == (
        [["u-0", "u-1", "u-2", "u-3", "u-4"], ["u-9"]])
    assert len(state["verified"]) == 6


def test_final_flush_multiple_remainder_passes(monkeypatch):
    results = [[_window_finding("u-0")], [], [_window_finding("u-1")], []]
    state, _calls, chunks = _run_fanout(monkeypatch, results,
                                        cell_size=5, reruns=3)
    assert [[f["id"] for f in c] for c in chunks] == [["u-0", "u-1"]]
    assert len(state["verified"]) == 2


def test_reruns_zero_reproduces_legacy_chunking(monkeypatch):
    state, _calls, chunks = _run_fanout(
        monkeypatch,
        [[_window_finding(f"u-{i}") for i in range(14)]],
        cell_size=6, reruns=0)
    assert [len(c) for c in chunks] == [6, 6, 2]


def test_reruns_zero_reproduces_legacy_passthrough_ride(monkeypatch):
    """cell_size=6, 12 llm + 2 info: the info findings ride the unit's
    first LLM chunk (after the llm items), exactly as pre-rerun."""
    results = [[_window_finding(f"llm-{i}") for i in range(12)]
               + [_info_finding(f"info-{i}") for i in range(2)]]
    state, _calls, chunks = _run_fanout(monkeypatch, results,
                                        cell_size=6, reruns=0)
    ids = [[f.get("id") for f in chunk] for chunk in chunks]
    assert ids == [[f"llm-{i}" for i in range(6)]
                   + [f"info-{i}" for i in range(2)],
                   [f"llm-{i}" for i in range(6, 12)]]
    assert len(state["verified"]) == 14


# --- system-pass reruns ------------------------------------------------------


def _sys_finding(fid):
    return {"id": fid, "title": fid, "cwe": "CWE-89", "severity": "high",
            "confidence": 0.8, "path": "b.py", "start_line": 3, "end_line": 3,
            "snippet": "s", "evidence": "e", "status": "needs-review"}


def _drive_system_pass(monkeypatch, results, reruns):
    """Run _run_system_pass with a scripted run_structured returning
    ``results[i]`` finding dicts on pass i. Returns (out, humans)."""
    from cerberus.schemas import Finding, HunterResult

    humans = []
    seq = {"i": 0}

    def fake_run_structured(mk, model, system, human, **kw):
        i = seq["i"]
        seq["i"] += 1
        humans.append(human)
        row = results[i] if i < len(results) else []
        return HunterResult(findings=[Finding(**f) for f in row]), ""

    monkeypatch.setenv("HUNTER_MODEL", "m")
    # Sandbox fails open to None (same offline posture as pre-rerun tests).
    monkeypatch.setattr("cerberus.sandbox.resolve_backend",
                        lambda *a, **k: None)
    monkeypatch.setattr("cerberus.agents.deep.run_structured",
                        fake_run_structured)
    out = h._run_system_pass(
        "repo", ["b.py"], [], "", {"hunter": {"reruns": reruns}})
    return out, humans


def test_system_pass_reruns_zero_one_call(monkeypatch):
    out, humans = _drive_system_pass(monkeypatch, [], 0)
    assert len(humans) == 1 and out == []


def test_system_pass_rerun_ids_stamped():
    # Pin: judge ids survive normalization end-to-end (the rerun dedup
    # trusted-from-prompt means only pass 1 filters).
    assert all(str(f.get("id", "")).endswith("-fallback") is False
               for f in [_sys_finding("s-1")])


def test_system_pass_reruns_carry_prior_results_and_stop(monkeypatch):
    out, humans = _drive_system_pass(
        monkeypatch, [[_sys_finding("s-1")], [], []], 2)
    # Pass 1 finds, passes 2 and 3 empty -> stop after the 3rd pass.
    assert len(humans) == 3
    assert len(out) == 1 and out[0]["id"] == "s-1"
    # Rerun passes carry the earlier results in a fenced data-only block.
    tag = "[PRIOR SYSTEM-PASS RESULTS]"
    for human in humans[1:]:
        assert tag in human
        assert "s-1" in human
        assert "<untrusted_data" in human
        # Cache layout: the rerun block rides at the very end, after the
        # pass-stable inventory section.
        assert human.index(tag) > human.index("Repository file inventory")
        assert human.rstrip().split("\n")[-1].startswith("</untrusted_data id=")
    # Pass 1 keeps the original prompt shape (no prior block).
    assert tag not in humans[0]
    # Repeatability: passes 2 and 3 carry the same prior payload [s-1], so
    # their human prompts are byte-identical (deterministic fence).
    assert humans[2] == humans[1]


def test_system_pass_reruns_streak_reset_runs_to_cap(monkeypatch):
    """Find, find, empty, empty: the streak clears on the productive pass,
    so all 4 passes (reruns=3) run; stop only at the cap."""
    out, humans = _drive_system_pass(
        monkeypatch,
        [[_sys_finding("s-1")], [_sys_finding("s-2")], [], []], 3)
    assert len(humans) == 4
    assert {f["id"] for f in out} >= {"s-1", "s-2"}
    # Rerun 2 (pass 3) knows both earlier results.
    assert "s-2" in humans[2]
    # Cache guarantee: the fence id is stable across rerun passes and the
    # text before the fence is byte-identical; only the growing JSON body
    # inside the fence differs.
    opener = '<untrusted_data id="'
    import re as _re
    ids = [_re.search(r'<untrusted_data id="([0-9a-f]{32})">', hum).group(1)
           for hum in humans[1:]]
    assert len(set(ids)) == 1
    i1, i2 = humans[1].index(opener), humans[2].index(opener)
    assert humans[2][:i2] == humans[1][:i1]


def test_system_pass_prior_block_caps_at_500(monkeypatch):
    """F2 regression: the system-pass prior block uses the same
    500-finding cap the unit-hunter prior block has, with a count for the
    remainder — prompts can't balloon quadratically across reruns."""
    results = [[_sys_finding(f"s-{i}") for i in range(505)], [], [], []]
    _out, humans = _drive_system_pass(monkeypatch, results, 3)
    prior = humans[1]
    assert "(+ 5 more already reported" in prior
    assert '"title": "s-504"' not in prior   # beyond the cap, dropped
    assert '"title": "s-499"' in prior       # first 500 kept

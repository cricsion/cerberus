"""M4 (plan-1345): triage dedup by root cause + severity rubric, uncapped."""
import re

import cerberus.agents.deep as _deep
from cerberus.agents import triage as t
from cerberus.pipeline import triage_node
from cerberus.prompts.triage import TriageBatch, TriageVerdict


def _f(fid, path="a.py", cwe="CWE-89", conf=0.5, line=1, sev="high"):
    return {"id": fid, "title": f"t-{fid}", "cwe": cwe, "severity": sev,
            "confidence": conf, "path": path, "start_line": line, "end_line": line,
            "snippet": f"exec({fid})", "evidence": "e", "status": "needs-review"}


def _patch_batch(monkeypatch, fn):
    """Patch the per-chunk agent runner triage uses (deep.run_structured)."""
    monkeypatch.setattr(_deep, "run_structured", fn)


def _batch(verdicts):
    """Wrap raw verdict dicts in the schema the batch call returns."""
    return TriageBatch(verdicts=[TriageVerdict(**v) for v in verdicts])


def _ids_in(msg: str) -> list[str]:
    return re.findall(r'"id":\s*"([^"]+)"', msg)


def _cwes_in(msg: str) -> list[str]:
    return re.findall(r'"cwe":\s*"([^"]+)"', msg)



def test_stage_a_groups_and_primary():
    # Same file + same CWE family group into one stub and the max-confidence
    # finding is elected primary. Lines must sit within _LINE_GAP: Stage A
    # splits same-file/same-class sinks that are further apart
    # (test_stage_a_distant_lines_stay_distinct locks that in — distant sinks
    # are distinct instances, so a group needs close lines too).
    out = t.stage_a([_f("1", conf=0.9, line=1),
                     _f("2", conf=0.4, line=1 + t._LINE_GAP)])
    by_id = {f["id"]: f for f in out}
    assert by_id["1"]["duplicate_of"] == ""
    assert by_id["2"]["duplicate_of"] == "1"


def test_stage_a_distant_lines_stay_distinct():
    # Same file + same class 10+ lines apart are distinct sinks, not one
    # instance. Collapsing them loses recall permanently without an API key.
    out = t.stage_a([_f("1", conf=0.9, line=1), _f("2", conf=0.4, line=50)])
    by_id = {f["id"]: f for f in out}
    assert by_id["1"]["duplicate_of"] == ""
    assert by_id["2"]["duplicate_of"] == ""
    # Boundary: exactly _LINE_GAP apart still groups.
    out = t.stage_a([_f("1", conf=0.9, line=1),
                     _f("2", conf=0.4, line=1 + t._LINE_GAP)])
    by_id = {f["id"]: f for f in out}
    assert by_id["2"]["duplicate_of"] == "1"


def test_stage_a_skips_info_and_distinct():
    out = t.stage_a([
        {"id": "ctx", "title": "p", "cwe": "", "severity": "info", "path": "a.py",
         "start_line": 0, "end_line": 0, "snippet": "s", "evidence": "e",
         "status": "needs-review"},
        _f("1", cwe="CWE-89"), _f("2", cwe="CWE-78"),
    ])
    by_id = {f["id"]: f for f in out}
    assert by_id["ctx"]["duplicate_of"] == ""
    assert by_id["1"]["duplicate_of"] == "" and by_id["2"]["duplicate_of"] == ""


def test_no_key_stage_a_only(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    called = []
    _patch_batch(monkeypatch, lambda *a, **k: called.append(1) or (None, ""))
    res = t.run_triage([_f("1", conf=0.9), _f("2", conf=0.4)], {}, "")
    assert res["findings"][1]["duplicate_of"] == "1"
    assert called == [] and res["triage_llm_calls"] == 0
    assert res["n_duplicates"] == 1


def _verdict(fid, dup, sev="medium"):
    return {"id": fid, "duplicate_of": dup, "severity": sev,
            "triage": {"reachable": "yes", "control": "full", "preconditions": [],
                       "auth": "none", "rw": "write", "blast": "all",
                       "rationale": "r"},
            "reason": "same sink"}


def test_llm_confirms_duplicate_and_rubric(monkeypatch):
    _patch_batch(monkeypatch,
                 lambda mk, model, system, human, **kw: (
                     _batch([_verdict("2", "1", "critical")]), ""))
    res = t.run_triage([_f("1", conf=0.9), _f("2", conf=0.4)], {}, "")
    by_id = {f["id"]: f for f in res["findings"]}
    assert by_id["2"]["duplicate_of"] == "1"
    assert by_id["2"]["severity"] == "critical"
    assert by_id["2"]["triage"]["blast"] == "all"
    assert "triage: same sink" in by_id["2"]["evidence"]
    assert res["triage_llm_calls"] == 1


def test_llm_split_clears_provisional(monkeypatch):
    _patch_batch(monkeypatch,
                 lambda mk, model, system, human, **kw: (
                     _batch([_verdict("2", None, "low")]), ""))
    res = t.run_triage([_f("1", conf=0.9), _f("2", conf=0.4)], {}, "")
    by_id = {f["id"]: f for f in res["findings"]}
    assert by_id["2"]["duplicate_of"] == ""  # distinct vars/sinks
    assert by_id["2"]["severity"] == "low"


def test_verdicts_ignore_unknown_ids_and_bad_severity(monkeypatch):
    bad = {"id": "ghost", "duplicate_of": "1", "severity": "critical"}
    worse = {"id": "2", "duplicate_of": "ghost", "severity": "cosmic"}
    _patch_batch(monkeypatch,
                 lambda mk, model, system, human, **kw: (_batch([bad, worse]),
                                                        ""))
    res = t.run_triage([_f("1", conf=0.9), _f("2", conf=0.4)], {}, "")
    by_id = {f["id"]: f for f in res["findings"]}
    assert by_id["2"]["duplicate_of"] == "1"  # Stage-A stands
    assert by_id["2"]["severity"] == "high"  # unchanged


def test_single_call_covers_all_families(monkeypatch):
    calls = []
    seen = {}

    def fake(mk, model, system, human, **kw):
        calls.append(1)
        for fid in _ids_in(human):
            seen[fid] = 1
        return _batch([_verdict(f"{i}b", f"{i}a", "medium")
                       for i in range(5)]), ""

    _patch_batch(monkeypatch, fake)
    findings = [_f(f"{i}a", cwe=f"CWE-{89 + i}", line=1) for i in range(5)]
    findings += [_f(f"{i}b", cwe=f"CWE-{89 + i}", line=2) for i in range(5)]
    findings.append(_f("solo", cwe="CWE-798", line=1))  # singleton graded too
    res = t.run_triage(findings, {}, "")
    assert res["triage_llm_calls"] == 1  # one call, not per family
    assert calls == [1]  # every eligible finding in that call
    assert "solo" in seen and "0a" in seen
    by_id = {f["id"]: f for f in res["findings"]}
    assert by_id["0b"]["duplicate_of"] == "0a"
    assert by_id["0b"]["severity"] == "medium"
    assert res["n_duplicates"] == 5


def test_batching_splits_large_scans(monkeypatch):
    monkeypatch.setenv("TRIAGER_BATCH", "30")  # test-supplied, not the prod default
    sizes = []

    def fake(mk, model, system, human, **kw):
        sizes.append(len(_ids_in(human)))
        return None, ""

    _patch_batch(monkeypatch, fake)
    findings = [_f(f"f{i}", cwe="CWE-89", line=i) for i in range(65)]
    res = t.run_triage(findings, {}, "")
    assert res["triage_llm_calls"] == 3
    assert sorted(sizes) == [5, 30, 30]
    assert len(res["triage_log"]) == 65
    assert max(e["batch"] for e in res["triage_log"]) == 3


def test_batches_keep_families_together(monkeypatch):
    monkeypatch.setenv("TRIAGER_BATCH", "30")  # test-supplied, not the prod default
    seen_batches = []

    def fake(mk, model, system, human, **kw):
        seen_batches.append(_cwes_in(human))
        return None, ""

    _patch_batch(monkeypatch, fake)
    findings = ([_f(f"a{i}", cwe="CWE-78", line=i) for i in range(35)]
                + [_f(f"b{i}", cwe="CWE-89", line=i) for i in range(5)])
    t.run_triage(findings, {}, "")
    assert len(seen_batches) == 2
    # Concurrent chunk agents finish in any order; identify the pure-CWE-78
    # chunk by its members, not by arrival (both chunks start with CWE-78,
    # so a first-element sort key collides and stable sort keeps arrival
    # order — the old key raced on correct code).
    pure = [c for c in seen_batches if set(c) == {"CWE-78"}]
    assert len(pure) == 1 and len(pure[0]) == 30
    assert sorted(map(len, seen_batches)) == [10, 30]


def test_batch_size_configurable_and_clamped(monkeypatch):
    from cerberus.config import effective_config, reset_config

    monkeypatch.delenv("TRIAGER_BATCH", raising=False)
    reset_config()
    assert effective_config({})["triage"]["batch_size"] == 100
    assert effective_config({"triage": {"batch_size": "2"}})["triage"]["batch_size"] == 2
    assert effective_config({"triage": {"batch_size": 0}})["triage"]["batch_size"] >= 10**9  # unlimited
    assert effective_config({"triage": {"batch_size": 9999}})["triage"]["batch_size"] == 200
    calls = []

    def fake(mk, model, system, human, **kw):
        calls.append(human)
        return None, ""

    _patch_batch(monkeypatch, fake)
    res = t.run_triage([_f(f"f{i}", line=i) for i in range(5)],
                       {"triage": {"batch_size": 2}}, "")
    assert res["triage_llm_calls"] == 3
    assert calls and len(calls) == 3


def test_failed_chunk_keeps_stage_a_and_is_not_counted(monkeypatch):
    """Per-input batch failures fail open: that chunk keeps Stage-A verdicts,
    other chunks still apply, and triage_llm_calls counts completed chunks."""

    def fake(mk, model, system, human, **kw):
        assert len(_ids_in(human)) == 1  # batch_size=1: one finding per chunk
        if _ids_in(human) == ["1"]:
            raise RuntimeError("down")
        return _batch([_verdict("2", "1", "critical")]), ""

    _patch_batch(monkeypatch, fake)
    findings = [_f("1", conf=0.9), _f("2", conf=0.4, line=2)]
    res = t.run_triage(findings, {"triage": {"batch_size": 1}}, "")
    by_id = {f["id"]: f for f in res["findings"]}
    assert res["triage_llm_calls"] == 1
    assert by_id["2"]["severity"] == "critical"
    assert len(res["triage_log"]) == 2


def test_returned_fatal_chunk_fails_loudly(monkeypatch):
    """``batch(return_exceptions=True)`` RETURNS fatal-class errors instead
    of raising them: run_triage must re-raise (loud config failure), never
    silently keep Stage-A verdicts for the dead chunk."""
    import pytest
    from langchain_core.exceptions import ModelAuthenticationError


    def fake(mk, model, system, human, **kw):
        raise ModelAuthenticationError("bad key")

    _patch_batch(monkeypatch, fake)
    with pytest.raises(ModelAuthenticationError):
        t.run_triage([_f("1", conf=0.9)], {}, "")


def test_render_triage_log():
    log = [{"id": "1", "batch": 1, "path": "a.py", "lines": "1-1",
            "cwe": "CWE-89", "severity": "high", "status": "confirmed",
            "duplicate_of": "",
            "triage": {"reachable": "yes", "auth": "none", "rationale": "r"},
            "evidence_tail": "proof here"},
           {"id": "2", "batch": 1, "path": "a.py", "lines": "2-2",
            "cwe": "CWE-89", "severity": "high", "status": "needs-review",
            "duplicate_of": "1", "triage": {}, "evidence_tail": ""}]
    # Derived counts only — the markdown layout itself is not a contract.
    text = t.render_triage_log(log, 1, 30)
    assert "duplicates: 1" in text and "LLM calls: 1" in text


def test_triage_node_carries_log(monkeypatch):
    # Offline contract: with no API_KEY, triage runs its deterministic path.
    monkeypatch.delenv("API_KEY", raising=False)
    out = triage_node({"verified": [_f("1"), _f("2", cwe="CWE-78")]})
    assert len(out["triage_log"]) == 2
    assert [f["id"] for f in out["verified"].value] == ["1", "2"]
    # Empty in, nothing out — the node emits no update at all.
    assert triage_node({"verified": []}) == {}


def test_schema_and_reports(tmp_path):
    from cerberus.reporting.reports import write_html, write_markdown
    rows = [_f("1", conf=0.9), _f("2", conf=0.4)]
    rows[1]["duplicate_of"] = "1"
    md_path = tmp_path / "t4-report.md"
    write_markdown(rows, md_path)
    text = md_path.read_text()
    assert "+1 duplicate(s)" in text
    html_path = tmp_path / "t4-report.html"
    write_html(rows, html_path)
    assert "+1 duplicate" in html_path.read_text()

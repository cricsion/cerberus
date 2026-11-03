"""Discovery: task building, findings parsing/normalization, and the system pass.

Cluster file covering:
- ``build_hunter_task`` (cerberus/prompts/hunter.py): the assembled
  prompt introduces no vulnerability identifiers the caller did not supply.
- ``hunters._normalize_finding``: id/scope stamping and rationale
  preservation.
- ``system_pass_node``: the no-key/fail-open/flag gates and add-only merge.
- CLI ``--focus`` plumbing through ``run_scan`` and the scan meta.

The unit-reading behaviour (the task prompt never inlines source) was
prompt English with no machine contract, so it is not asserted here.
"""
import re

from cerberus.agents import hunters as h
from cerberus.agents.hunters import _normalize_finding
from cerberus.pipeline import run_scan, system_pass_node


def test_task_builder_introduces_no_vulnerability_classes():
    # Property of the builder, not its wording: any CWE identifier in the
    # assembled prompt must already be present in the caller-supplied inputs.
    # Which classes matter is data (threat model, candidates), never prompt
    # text, so this holds under any rephrasing that adds no new identifiers.
    task = h.build_hunter_task("u", "/repo", ["a.py"], "[{}]",
                                  "threat model without identifiers")
    out_ids = set(re.findall(r"CWE-\d+", task))
    in_ids = set(re.findall(r"CWE-\d+",
                            "a.py [{}] threat model without identifiers"))
    assert out_ids <= in_ids, out_ids - in_ids


def test_normalizer_preserves_rationale():
    f = _normalize_finding({"id": "a", "rationale": "user->sink story"}, "h", 0, "p.py")
    assert f["rationale"] == "user->sink story"


def test_agent_tools_used_parsing():
    class TA:
        def __init__(self, name):
            self.tool_calls = [{"name": name}]
            self.type = "ai"

    class TT:
        type = "tool"
        name = "grep"

    assert h._agent_tools_used({"messages": [TA("read_file"), TT()]}) == ["read_file", "grep"]
    assert h._agent_tools_used({}) == []
    assert h._agent_tools_used(None) == []


def test_system_pass_skipped_without_key(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    out = system_pass_node({"repo": "r", "files": ["a.py"],
                            "findings": [{"id": "1", "path": "a.py"}]})
    assert out == {}


def test_system_pass_adds_without_loss(monkeypatch):
    extra = [{"id": "sys-1", "title": "x", "cwe": "CWE-306", "severity": "high",
              "confidence": 0.8, "path": "b.py", "start_line": 3, "end_line": 3,
              "snippet": "s", "evidence": "e", "status": "needs-review"}]
    monkeypatch.setattr(
        h, "_run_system_pass",
        lambda repo, files, findings, md, cfg, focus=None, tools=None,
        stats_out=None, agent_registry=None: extra)
    mine = [{"id": "u-1", "path": "a.py", "cwe": "CWE-89", "start_line": 1}]
    out = system_pass_node({"repo": "r", "files": ["a.py"], "findings": mine,
                            "threat_model_md": "tm"})
    assert out["findings"] == extra
    assert all(f not in out["findings"] for f in mine)  # only ADDS


def test_system_pass_fail_open(monkeypatch):

    def boom(*a, **k):
        raise RuntimeError("llm down")
    monkeypatch.setattr(h, "_run_system_pass", boom)
    out = system_pass_node({"repo": "r", "files": [], "findings": [{"id": "1"}]})
    assert out == {}


def test_system_pass_respects_flag(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTER_MODEL", "m")
    import cerberus.config as cfgmod
    real = cfgmod.load_config
    monkeypatch.setattr(cfgmod, "load_config",
                        lambda path=None: {**real(path), "hunter": {"system_pass": False}})
    out = system_pass_node({"repo": "r", "files": [], "findings": [{"id": "1"}]})
    assert out == {}


def _nonce_fence(text: str, marker: str) -> tuple[int, int, str]:
    """Return (opener_index, closer_index, nonce) for the untrusted_block
    wrapping ``marker``; asserts the block is nonce-delimited."""
    opener = '<untrusted_data id="'
    start = text.index(opener)
    nonce = text[start + len(opener):text.index('"', start + len(opener))]
    close = f'</untrusted_data id="{nonce}">'
    end = text.index(close)
    assert start < text.index(marker) < end
    return start, end, nonce


def test_run_system_pass_success_path_fences_threat_model(monkeypatch):
    """Regression pin for the D1 fence on ``_run_system_pass`` (success path,
    no LLM): a faked structured response round-trips to normalized findings,
    and ``threat_md`` reaches the human task only inside the nonce-fenced
    ``untrusted_block`` — with the threat-model framing left OUTSIDE the fence.
    """
    from cerberus.prompts.hunter import build_hunter_task
    from cerberus.schemas import Finding, HunterResult

    monkeypatch.setenv("HUNTER_MODEL", "m")
    monkeypatch.setattr("cerberus.sandbox.resolve_backend", lambda *a, **k: None)

    captured: dict[str, str] = {}

    def fake_run_structured(mk, model, system, human, **kw):
        captured["human"] = human
        return HunterResult(findings=[Finding(
            id="sys-1", title="cross-unit", cwe="CWE-89", severity="high",
            confidence=0.8, path="b.py", start_line=3, end_line=3,
            snippet="s", evidence="e")]), ""

    monkeypatch.setattr("cerberus.agents.deep.run_structured", fake_run_structured)

    out = h._run_system_pass("repo", ["b.py"], [], "SECRET-TM-MARKER", {})
    assert [f["id"] for f in out] == ["sys-1"]         # (a) normalized findings

    human = captured["human"]                          # (b) D1 fence holds
    start, end, _ = _nonce_fence(human, "SECRET-TM-MARKER")
    assert "[THREAT MODEL]" not in human[start:end]    # framing is outside...
    assert human.index("[THREAT MODEL]") < start       # ...the fence
    # The hunter-task path fences the same artifact under "## Threat model".
    task = build_hunter_task("u", "repo", ["a.py"],
                                threat_md="SECRET-TM-MARKER")
    t_start, t_end, _ = _nonce_fence(task, "SECRET-TM-MARKER")
    assert "## Threat model" not in task[t_start:t_end]
    assert task.index("## Threat model") < t_start


def test_cli_focus_and_run_scan_focus(monkeypatch):
    from cerberus.cli import build_parser
    args = build_parser().parse_args(["scan", "r", "--focus", "CWE-89,injection"])
    assert args.focus == "CWE-89,injection"
    monkeypatch.delenv("API_KEY", raising=False)
    st = run_scan("tests/fixtures/pygoat-sample", focus="CWE-89,injection")
    assert st.get("focus") == ["CWE-89", "injection"]
    assert "regex_prefilter" in st.get("tools_used", [])


def test_scan_meta_tools_used(tmp_path, monkeypatch):
    import json
    import pathlib
    import subprocess
    import sys
    # Offline contract for the subprocess scan: no API_KEY -> LLM skipped.
    monkeypatch.delenv("API_KEY", raising=False)
    out = tmp_path / "m2-out"
    import os
    env = dict(os.environ, PYTHONPATH=str(pathlib.Path(".").resolve().parent))
    subprocess.run([sys.executable, "-m", "cerberus.cli", "scan",
                    str(pathlib.Path("tests/fixtures/pygoat-sample")), "--out", str(out)],
                   check=True, capture_output=True, env=env)
    meta = json.loads((out / "scan_meta.json").read_text())
    assert "regex_prefilter" in meta["tools_used"]
    assert meta["focus"] is None


# --- apply_update additive channels -----------------------------------------


def test_add_keys_accumulate_in_state():
    import cerberus.pipeline as g

    st: dict = {}
    g.apply_update(st, {"tools_used": ["regex_prefilter"]})
    g.apply_update(st, {"tools_used": ["regex_prefilter", "unit:api"]})
    assert st["tools_used"] == [
        "regex_prefilter",
        "regex_prefilter", "unit:api"]

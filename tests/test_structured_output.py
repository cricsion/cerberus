"""Structured-output wiring: deep agents schema first, existing text parsers as fallback.

All LLM boundaries are mocked; these assert composition (which result wins),
never prompt wording.
"""
import types

import cerberus.agents.hunters as h
import pytest
from cerberus.agents.deep import build_deep_agent, final_text, message_text, run_structured
from pydantic import BaseModel


def _finding_dict(fid="a"):
    return {"id": fid, "title": fid, "cwe": "CWE-89", "path": "a.py",
            "start_line": 1, "end_line": 1, "snippet": "q",
            "evidence": "e:1", "rationale": "r",
            "taint": {"source": "u", "sink": "ex", "path": []},
            "status": "needs-review", "confidence": 0.9, "severity": "high"}


class Q(BaseModel):
    question: str


def test_run_structured_returns_parsed_and_raw(monkeypatch):
    class FakeAgent:
        def invoke(self, *args, **kwargs):
            return {
                "structured_response": Q(question="test?"),
                "messages": [types.SimpleNamespace(content="raw text")],
            }

    monkeypatch.setattr("cerberus.agents.deep.build_deep_agent", lambda *a, **k: FakeAgent())
    parsed, raw = run_structured({}, Q, "sys", "human")
    assert isinstance(parsed, Q)
    assert parsed.question == "test?"
    assert raw == "raw text"


def test_run_structured_fallback_to_raw(monkeypatch):
    class FakeAgent:
        def invoke(self, *args, **kwargs):
            return {
                "structured_response": None,
                "messages": [types.SimpleNamespace(content="not json at all")],
            }

    monkeypatch.setattr("cerberus.agents.deep.build_deep_agent", lambda *a, **k: FakeAgent())
    parsed, raw = run_structured({}, Q, "sys", "human")
    assert parsed is None
    assert raw == "not json at all"


def test_run_structured_transport_failure_raises(monkeypatch):
    class FakeAgent:
        def invoke(self, *args, **kwargs):
            raise RuntimeError("down")

    monkeypatch.setattr("cerberus.agents.deep.build_deep_agent", lambda *a, **k: FakeAgent())
    with pytest.raises(RuntimeError):
        run_structured({}, Q, "sys", "human")


def test_bare_schema_wraps_in_tool_strategy(monkeypatch, tmp_path):
    """Pin the deep.py wrap: a bare schema must reach create_deep_agent as
    ToolStrategy(handle_errors=True) — deleting the wrap or flipping the
    flag (one garbled reply kills the stage) must fail loudly here."""
    import deepagents
    from cerberus.sandbox.local_backend import RepoLocalBackend
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage

    seen = {}

    def fake_cda(*a, **k):
        seen.update(k)
        return object()

    monkeypatch.setattr(deepagents, "create_deep_agent", fake_cda)
    build_deep_agent(
        GenericFakeChatModel(messages=iter([AIMessage(content="hi")])),
        system_prompt="s", response_format=Q,
        backend=RepoLocalBackend(repo_path=tmp_path))
    from langchain.agents.structured_output import ToolStrategy
    rf = seen["response_format"]
    assert isinstance(rf, ToolStrategy)
    assert rf.schema is Q
    assert rf.handle_errors is True


def test_run_structured_batch_is_one_shot_and_per_input_fail_open(monkeypatch):
    """The batched runner skips the agent loop: one structured call per input,
    function-calling schema (OpenAI-compatible), per-input exceptions surfaced."""
    import cerberus.agents.deep as d

    class FakeStructured:
        def batch(self, msgs, config=None, return_exceptions=False):
            assert [m[1]["content"] for m in msgs] == ["h0", "h1", "h2"]
            # The system message carries the appended tool-call contract
            # (base system text, then structured_output_contract for `Q`).
            sys_msg = msgs[0][0]
            assert sys_msg["role"] == "system"
            assert sys_msg["content"].startswith("sys")
            assert "## Output Format" in sys_msg["content"]
            assert "invoking the `Q` tool call" in sys_msg["content"]
            assert config["max_concurrency"] == 3
            assert return_exceptions is True
            return [Q(question="a"), ValueError("bad reply"), Q(question="c")]

    class FakeLLM:
        def with_structured_output(self, model, **kwargs):
            assert model is Q
            assert kwargs.get("method") == "function_calling"
            return FakeStructured()

    monkeypatch.setattr(d, "make_llm", lambda *a, **k: FakeLLM())
    out = d.run_structured_batch({}, Q, "sys", ["h0", "h1", "h2"],
                                 max_concurrency=3)
    assert out[0].question == "a" and out[2].question == "c"
    assert isinstance(out[1], ValueError)
    assert d.run_structured_batch({}, Q, "sys", []) == []


def test_run_structured_batch_toolless_reply_is_a_failure(monkeypatch):
    """A tool-less reply parses to None without raising: the batch runner must
    surface it as a per-input failure (it previously flowed through as a
    'completed' call)."""
    import cerberus.agents.deep as d

    class FakeStructured:
        def batch(self, msgs, config=None, return_exceptions=False):
            return [None, Q(question="ok")]

    class FakeLLM:
        def with_structured_output(self, model, **kwargs):
            return FakeStructured()

    monkeypatch.setattr(d, "make_llm", lambda *a, **k: FakeLLM())
    out = d.run_structured_batch({}, Q, "sys", ["h0", "h1"])
    assert isinstance(out[0], RuntimeError)
    assert out[1].question == "ok"


def test_run_structured_batch_carries_observability(monkeypatch):
    import cerberus.agents.deep as d
    from cerberus import observability as obs

    seen: dict = {}

    class FakeStructured:
        def batch(self, msgs, config=None, return_exceptions=False):
            seen["cfg"] = config
            return [None] * len(msgs)

    class FakeLLM:
        def with_structured_output(self, model, **kwargs):
            return FakeStructured()

    monkeypatch.setattr(d, "make_llm", lambda *a, **k: FakeLLM())
    monkeypatch.setattr(obs, "_STATE",
                        {"scan_id": "scan-x", "handler": object()})
    d.run_structured_batch({}, Q, "s", ["h"], name="triage",
                           meta_extra={"unit": "u"})
    cfg = seen["cfg"]
    assert cfg["run_name"] == "triage"
    assert cfg["metadata"]["langfuse_session_id"] == "scan-x"
    assert cfg["metadata"]["unit"] == "u"
    assert cfg["callbacks"] and "max_concurrency" not in cfg


def test_message_and_final_text():
    class Msg:
        def __init__(self, content):
            self.content = content

    assert message_text(Msg("hello")) == "hello"
    assert message_text(Msg([{"text": "part1"}, "part2"])) == "part1 part2"
    assert final_text({"messages": [Msg("m1"), Msg("m2")]}) == "m2"
    assert final_text({}) == ""


def test_findings_from_hunter_converts_and_fail_opens():
    from cerberus.schemas import Finding, HunterResult
    got = h._findings_from_hunter(
        HunterResult(findings=[Finding(**_finding_dict())]),
        "u", ["a.py"], "/repo")
    assert len(got) == 1 and got[0]["cwe"] == "CWE-89"
    assert h._findings_from_hunter(None, "u", ["a.py"], "/repo") == []
    assert h._findings_from_hunter("garbage", "u", ["a.py"], "/repo") == []


def test_unit_agent_prefers_structured_response(monkeypatch):
    from cerberus.schemas import Finding, HunterResult

    class FakeAgent:
        def invoke(self, *a, **k):
            return {"messages": [],
                    "structured_response": HunterResult(
                        findings=[Finding(**_finding_dict())])}

    monkeypatch.setattr(h, "build_unit_hunter_agent", lambda *a, **k: FakeAgent())
    out = h._run_unit({"name": "u"}, "/repo", ["a.py"], [], {},
                      threat_md="", focus=None)
    assert [f["id"] for f in out] == ["a"]


def test_unit_agent_without_structured_response_degrades(monkeypatch):
    class FakeAgent:
        def invoke(self, *a, **k):
            return {"messages": [types.SimpleNamespace(
                role="assistant",
                content='[{"id":"b","cwe":"CWE-78"}]')]}

    monkeypatch.setattr(h, "build_unit_hunter_agent", lambda *a, **k: FakeAgent())
    out = h._run_unit({"name": "u"}, "/repo", ["a.py"], [], {},
                      threat_md="", focus=None)
    # No structured_response: a failed call, never text scraped into findings.
    assert [f["id"] for f in out] == ["unit-u-fallback"]
    assert out[0]["status"] == "needs-review"
    assert "no structured output" in out[0]["evidence"]


def test_triage_uses_structured_verdicts(monkeypatch):
    import cerberus.agents.triage as tr
    from cerberus.prompts.triage import TriageBatch, TriageVerdict

    def fake_run(mk, model, system, human, **kwargs):
        assert model is TriageBatch
        return (TriageBatch(verdicts=[TriageVerdict(id="1", duplicate_of=None,
                                                    severity="high")]), "")

    monkeypatch.setattr("cerberus.agents.deep.run_structured",
                        fake_run)
    monkeypatch.setenv("API_KEY", "dummy")
    f = dict(_finding_dict("1"))
    out = tr.run_triage([f], {}, "")["findings"]
    assert out[0]["id"] == "1" and out[0]["severity"] == "high"
    assert out[0]["triage"]["rationale"] == ""
    monkeypatch.delenv("API_KEY", raising=False)


def test_partitioner_uses_structured_units(monkeypatch):
    import cerberus.config as _cfg
    import cerberus.partitioning.llm as pt
    from cerberus.partitioning.prompts import UnitItem, UnitList

    monkeypatch.setattr(_cfg, "get_model_kwargs",
                        lambda *a, **k: {"model": "m", "api_key": "k"})
    monkeypatch.setattr(
        "cerberus.agents.deep.run_structured",
        lambda mk, model, system, human, **kwargs: (
            UnitList(units=[UnitItem(name="web", files=["a.py", "b.py"],
                                     rationale="r")]), ""))

    units = pt.run_partitioner_agent("/repo", ["a.py", "b.py"], [], {}, "")
    assert units and units[0]["name"] == "web"


def test_deepagents_hunter_disables_delete_and_task(monkeypatch):
    """Mutating tools (`delete`, `write_file`, `edit_file`) must be refused at
    the call boundary, no `task` tool may exist (no subagent recursion), and
    no `execute` tool may exist (no shell by design).
    Direct native file tools (`read_file`, `grep`, `glob`, `ls`) are unblocked
    and active."""
    deepagents = pytest.importorskip("deepagents")

    from langchain_core.messages import AIMessage
    from langchain_core.outputs import ChatGeneration, ChatResult
    from langchain_openai import ChatOpenAI as RealChat

    # This test is about the LOCAL posture (no shell tool at all), so pin the
    # backend instead of inheriting the operator's .env sandbox config.
    monkeypatch.setenv("SANDBOX_BACKEND", "local")

    blocked = ["delete", "write_file", "edit_file", "execute"]
    calls = {"n": 0}

    class FakeLLM(RealChat):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            calls["n"] += 1
            n = calls["n"]
            if n <= len(blocked):
                name = blocked[n - 1]
                if name == "execute":
                    args = {"command": "echo exec_ok"}
                elif name == "write_file":
                    args = {"file_path": "/x", "content": "data"}
                elif name == "edit_file":
                    args = {"file_path": "/x", "old_string": "a", "new_string": "b"}
                else:
                    args = {"file_path": "/x"}
                msg = AIMessage(content="", tool_calls=[
                    {"name": name, "args": args,
                     "id": f"call-{n}", "type": "tool_call"}])
            else:
                msg = AIMessage(content="done")
            return ChatResult(generations=[ChatGeneration(message=msg)])

    # 30 supersteps: the call-limit middleware in build_deep_agent adds graph
    # steps per model call (no extra LLM calls), so the old 15 no longer
    # covered four blocked tool calls + the final answer.
    monkeypatch.setattr("langchain_openai.ChatOpenAI", FakeLLM)
    agent = h.build_unit_hunter_agent(
        "u", {"model": "m", "api_key": "k",
              "base_url": "http://127.0.0.1:9", "timeout": 10,
              "max_retries": 0})
    res = agent.invoke({"messages": [{"role": "user", "content": "hi"}]},
                       config={"recursion_limit": 30})
    tool_msgs = [m for m in res["messages"] if getattr(m, "type", "") == "tool"]
    # Three rejection mechanisms: an excluded tool that exists ("is not available"),
    # a tool that was never created for this backend ("is not a valid tool"),
    # and permission denied on repo writes ("permission denied for write" / "operation is disabled").
    rejected = [str(m.content) for m in tool_msgs
                if "is not available" in str(m.content)
                or "is not a valid tool" in str(m.content)
                or "permission denied for write" in str(m.content)
                or "operation is disabled on target repository" in str(m.content)]
    assert len(rejected) == len(blocked), [str(m.content)[:60] for m in tool_msgs]
    exec_msgs = [m for m in tool_msgs if getattr(m, "name", "") == "execute"]
    assert not any("exec_ok" in str(m.content) for m in exec_msgs)


def test_extract_structured_tool_call_and_json_fallback():
    """Unit-hunter final-state extraction now lives in the shared rescuer
    (deep.extract_structured): structured_response -> schema-named tool call
    (args validated) -> fenced JSON in assistant text."""
    from cerberus.agents.deep import extract_structured
    from cerberus.schemas import HunterResult

    # 1. Primary structured_response
    res1 = {"structured_response": HunterResult(findings=[])}
    assert extract_structured(res1, HunterResult) is res1["structured_response"]

    # 2. HunterResult tool call in messages
    tc_msg = types.SimpleNamespace(
        type="ai",
        tool_calls=[{"name": "HunterResult", "args": {"findings": [_finding_dict("tc-1")]}}]
    )
    res2 = {"messages": [tc_msg]}
    extracted2 = extract_structured(res2, HunterResult)
    assert extracted2 is not None
    assert len(extracted2.findings) == 1
    assert extracted2.findings[0].id == "tc-1"

    # 3. HunterResult JSON object in assistant text
    import json
    json_text = json.dumps({"findings": [_finding_dict("txt-1")]})
    txt_msg = types.SimpleNamespace(
        type="ai",
        content=f"Here are the findings:\n```json\n{json_text}\n```"
    )
    res3 = {"messages": [txt_msg]}
    extracted3 = extract_structured(res3, HunterResult)
    assert extracted3 is not None
    assert len(extracted3.findings) == 1
    assert extracted3.findings[0].id == "txt-1"

    # 4. Garbage / invalid text returns None
    res4 = {"messages": [types.SimpleNamespace(type="ai", content="I found nothing interesting.")]}
    assert extract_structured(res4, HunterResult) is None


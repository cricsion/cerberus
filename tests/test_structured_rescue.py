"""Lock-in tests for the shared structured-output rescue layer (agents/deep.py).

Fabricated result dicts only — no LLM calls. Invariants pinned here:
- tier 1 (``structured_response``) passes through untouched (happy path is
  bit-identical; rescue only engages when structured_response is None);
- tier 2 recovers a valid schema-named tool call past garbled ones
  (per-candidate validation skip);
- tier 3 accepts fenced/brace JSON from prose — an EMPTY payload list is
  legitimate success, never converted into a fallback row;
- nothing validates -> None (callers' tier-3 fail-open is unchanged);
- the builder wraps bare schemas in ToolStrategy exactly once, with a short
  tool_message_content;
- the batch path stubs (include_raw / salvage) are constructible without
  a live provider.
"""

from __future__ import annotations

from cerberus.agents.deep import (
    _coerce_response_format,
    extract_structured,
    recover_structured,
    run_structured,
)
from cerberus.prompts.triage import TriageBatch
from cerberus.schemas import HunterResult
from langchain.agents.structured_output import ProviderStrategy, ToolStrategy
from structured_support import Msg as _Msg

# Shared seams with the adversarial companion file (single source of the
# message/agent/tool-call stand-ins this pair fabricates).
from structured_support import StubAgent as _StubAgent
from structured_support import tc as _tc

TC_HUNTER_EMPTY = _tc(args={"findings": []})
TC_HUNTER_GARBLED = _tc(args={"findings": "not-a-list"})

TC_TRIAGE_GARBLED = _tc(name="TriageBatch", args={"verdicts": [{"id": {"deep": 1}}]})
TC_TRIAGE_VALID = _tc(name="TriageBatch", args={"verdicts": [{"id": "a", "severity": "high"}]})

FENCE_EMPTY = 'I could not call the tool. ```json\n{"findings": []}\n```'
PROSE_VERDICTS = 'Final answer: {"verdicts": [{"id": "a", "severity": "high"}]}'


def test_tier1_passes_validated_instance_through():
    """structured_response wins immediately — garbage history is never rescanned."""
    sr = HunterResult(findings=[])
    result = {
        "structured_response": sr,
        "messages": [_Msg(tool_calls=[TC_HUNTER_GARBLED], text="no json here")],
    }
    out = extract_structured(result, HunterResult)
    assert out is sr


def test_tier2_skips_garbled_recovers_valid_tool_call():
    """A garbled schema-named tool call is skipped; a later valid one is validated."""
    result = {
        "structured_response": None,
        "messages": [
            _Msg(tool_calls=[TC_TRIAGE_GARBLED, TC_TRIAGE_VALID],
                 text="interim narration"),
        ],
    }
    out = extract_structured(result, TriageBatch)
    assert isinstance(out, TriageBatch)
    assert [(v.id, v.severity) for v in out.verdicts] == [("a", "high")]


def test_tier2_empty_args_is_legitimate_success():
    """An empty payload list inside the tool call validates as 'nothing found'."""
    result = {"structured_response": None, "messages": [_Msg(tool_calls=[TC_HUNTER_EMPTY])]}
    out = extract_structured(result, HunterResult)
    assert isinstance(out, HunterResult)
    assert out.findings == []


def test_tier3_fenced_empty_list_is_legitimate_success():
    """Prose-only reply with an empty findings list -> valid HunterResult, not None."""
    result = {"structured_response": None, "messages": [_Msg(text=FENCE_EMPTY)]}
    out = extract_structured(result, HunterResult)
    assert isinstance(out, HunterResult)
    assert out.findings == []
    # Same outcome via the prose rescuer directly.
    assert recover_structured(FENCE_EMPTY, HunterResult) == out


def test_tier3_rescues_verdict_prose_and_rejects_garbage():
    """Brace-span JSON validates into the schema; garbage prose and non-dict
    final states yield None (callers keep their fail-open behavior)."""
    result = {"structured_response": None, "messages": [_Msg(text=PROSE_VERDICTS)]}
    out = extract_structured(result, TriageBatch)
    assert isinstance(out, TriageBatch)
    assert [(v.id, v.severity) for v in out.verdicts] == [("a", "high")]

    assert recover_structured("no json at all", HunterResult) is None
    # Payload key present but not a list is rejected, never half-validated.
    assert recover_structured('{"findings": 7}', HunterResult) is None
    # Non-dict final states: nothing to extract.
    assert extract_structured(None, HunterResult) is None
    assert extract_structured("not a dict", HunterResult) is None
    assert extract_structured([], TriageBatch) is None


def test_run_structured_rescues_only_when_structured_response_missing():
    """run_structured wiring: tier-1 result passes through untouched; None triggers
    the shared rescue; the final text is still returned alongside."""
    # Happy path: validated instance returned as-is despite garbage history.
    sr = HunterResult(findings=[])
    happy = _StubAgent({"structured_response": sr,
                        "messages": [_Msg(tool_calls=[TC_HUNTER_GARBLED],
                                          text="garbage")], })
    parsed, text = run_structured(None, HunterResult, "sys", "go", agent=happy)
    assert parsed is sr

    # None structured_response: rescue from prose works through run_structured.
    rescue = _StubAgent({"structured_response": None,
                         "messages": [_Msg(text=PROSE_VERDICTS)]})
    parsed, text = run_structured(None, TriageBatch, "sys", "go", agent=rescue)
    assert isinstance(parsed, TriageBatch)
    assert parsed.verdicts[0].id == "a"
    assert "Final answer" in text


def test_builder_wraps_bare_schema_once_with_short_tool_message():
    """_coerce_response_format: bare pydantic type -> ToolStrategy(handle_errors=True,
    short tool_message_content); strategies pass through unwrapped."""
    st = _coerce_response_format(HunterResult)
    assert isinstance(st, ToolStrategy)
    assert st.schema is HunterResult
    assert st.handle_errors is True
    assert st.tool_message_content == "HunterResult accepted."
    # No double wrap.
    assert _coerce_response_format(st) is st
    ps = ProviderStrategy(HunterResult)
    assert _coerce_response_format(ps) is ps
    # Bare passthroughs.
    assert _coerce_response_format(None) is None
    # JSON-schema dict gains the wrap too, with the title as the tool name.
    schema = {"title": "RobotStatus", "type": "object", "properties": {}}
    st2 = _coerce_response_format(schema)
    assert isinstance(st2, ToolStrategy)
    assert st2.tool_message_content == "RobotStatus accepted."


def test_batch_include_raw_contract_is_constructible():
    """include_raw=True + provider-gated method: construction smoke, no network.
    The salvage loop consumes exactly the {'raw','parsed','parsing_error'}
    payloads this binding produces."""
    from langchain_openai import ChatOpenAI

    llm = ChatOpenAI(model="gpt-4o", api_key="x", base_url="http://127.0.0.1:9")
    for method in ("function_calling", "json_schema"):
        bound = llm.with_structured_output(HunterResult, include_raw=True,
                                           method=method)
        assert bound is not None
    # Profile gate: provider advertises structured output -> json_schema.
    method = ("json_schema"
              if (getattr(llm, "profile", None) or {}).get("structured_output")
              else "function_calling")
    assert method == "json_schema"

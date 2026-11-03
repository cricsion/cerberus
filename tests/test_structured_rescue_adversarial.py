"""Adversarial lock-ins for the shared structured-output rescue layer.

Companion to test_structured_rescue.py: fabricated result/message states only,
no LLM. Three kinds of cases live here:

- proofs that every documented rescue invariant holds under hostile inputs;
- pins for legacy-parity behaviors whose semantics were deliberately preserved
  (dict-shaped messages, brace-span contamination, fence priority);
- regression pins for hardening fixes (non-iterable ``tool_calls`` is skipped,
  never raised — the rescuer is the code that *cannot* raise).
"""
from __future__ import annotations

import cerberus.agents.deep as deep
import pytest
from cerberus.agents.deep import (
    _coerce_response_format,
    _first_list_field,
    extract_structured,
    recover_structured,
    run_structured,
)
from cerberus.prompts.triage import TriageBatch, TriageVerdict
from cerberus.prompts.validator import VerdictBatch, VerdictItem
from cerberus.schemas import Finding, HunterResult
from langchain.agents.structured_output import ProviderStrategy, ToolStrategy
from langchain_core.messages import AIMessage
from pydantic import BaseModel
from structured_support import Msg, StubAgent, tc

# ---------------------------------------------------------------- helpers


def finding(fid):
    return {"id": fid, "title": fid, "cwe": "CWE-89", "path": "a.py",
            "start_line": 1, "end_line": 1, "snippet": "q", "evidence": "e",
            "rationale": "r", "status": "needs-review", "confidence": 0.9,
            "severity": "high", "taint": {"source": "u", "sink": "s", "path": []}}


# ---------------------------------------------------------------- recover


def test_recover_rejects_non_string_and_useless_text():
    assert recover_structured(None, HunterResult) is None
    assert recover_structured(b'{"findings": []}', HunterResult) is None
    assert recover_structured("   \n\t ", HunterResult) is None
    assert recover_structured('{"findings": []', HunterResult) is None
    assert recover_structured('"findings": []}', HunterResult) is None
    assert recover_structured('```\n\n```', HunterResult) is None


def test_recover_fence_priority_and_legacy_brace_contamination():
    # A valid later fence wins over earlier garbage fences / junk braces.
    got = recover_structured('x { junk } ```json {"findings": []}```',
                             HunterResult)
    assert got == HunterResult(findings=[])
    # Legacy parity: two JSON objects inside ONE fence are unparseable.
    assert recover_structured('```json\n{"a": 1}\n{"findings": []}\n```',
                              HunterResult) is None
    # Legacy parity: the first "{" through last "}" span includes a garbage
    # fence, so a later good brace object is NOT rescued (pre-existing
    # algorithm; identical semantics to the deleted per-copy rescuers).
    assert recover_structured('```json\n{garbage}\n``` then {"findings": []}',
                              HunterResult) is None


def test_recover_per_candidate_skip_including_nan_and_wrong_schema():
    # NaN payloads fail Finding's ge/le float constraints -> candidate skipped.
    assert recover_structured('{"findings": [{"confidence": NaN}]}',
                              HunterResult) is None
    # First fence is schema-invalid (wrong payload key), second fence wins.
    got = recover_structured(
        '```json\n{"verdicts": [{"id": "z"}]}\n```\n'
        '```json\n{"findings": []}\n```', HunterResult)
    assert got == HunterResult(findings=[])


def test_recover_unicode_keys_and_scalar_payload_gate():
    got = recover_structured('{"findings": [], "✓": "ok"}', HunterResult)
    assert isinstance(got, HunterResult) and got.findings == []
    # extra="allow" keeps non-schema keys on the instance — never a rejection
    assert getattr(got, "✓", None) == "ok"
    # extra="allow" would accept {"other": []} silently — the list_field gate
    # is what stops an unstructured dict from validating as 'nothing found'.
    assert recover_structured('{"other": "x"}', HunterResult) is None
    assert recover_structured('{"findings": "x"}', HunterResult) is None


class ScalarFirst(BaseModel):
    id: int
    items: list[str] = []


def test_first_list_field_skips_scalar_first_fields():
    assert _first_list_field(ScalarFirst) == "items"
    got = recover_structured('{"id": 3, "items": ["a"]}', ScalarFirst)
    assert got == ScalarFirst(id=3, items=["a"])
    assert recover_structured('{"id": 3, "items": []}', ScalarFirst,
                              "items") == ScalarFirst(id=3, items=[])


def test_first_list_field_derivation_gaps_are_consistent():
    """Assessment pins: Optional[list] / Union / bare list / non-model schemas
    derive no list_field, so the prefilter drops off (documented consequence:
    tier-1 trusts any non-None sr; empty args {} can validate). harness-level
    schemas (HunterResult/TriageBatch/VerdictBatch) all use plain list
    fields, so these shapes never occur in the agents today."""
    from typing import Optional

    class OptList(BaseModel):
        findings: Optional[list[Finding]] = None

    class UnionField(BaseModel):
        payload: list[str] | str = ""

    class BareList(BaseModel):
        items: list = []

    assert _first_list_field(OptList) is None
    assert _first_list_field(UnionField) is None
    assert _first_list_field(BareList) is None
    assert _first_list_field({"type": "object"}) is None
    assert _first_list_field(None) is None


# ---------------------------------------------------------------- extract


def test_tool_calls_non_iterable_is_skipped():
    """A non-iterable tool_calls (fabricated/hostile state) is skipped
    per-message: the rescuer never raises, scanning continues on the other
    messages, and tier 3 still applies."""
    assert extract_structured({"messages": [Msg(tool_calls=5)]},
                              HunterResult) is None


def test_tool_calls_string_and_dict_membership_do_not_crash():
    # Strings iterate into 1-char tokens that never match the tool name.
    assert extract_structured({"messages": [Msg(tool_calls="snippets")]},
                              HunterResult) is None
    # A stray dict membership yields its keys: no name match, no crash.
    stray = {"role": "assistant", "tool_calls": {"HunterResult": {"args": {}}}}
    assert extract_structured({"messages": [stray]}, HunterResult) is None


def test_tier1_foreign_instance_falls_through_to_tier2():
    """structured_response present but lacking the payload attr (e.g. a
    TriageVerdict) must not win tier 1 — the scan rescues the real payload."""
    sr = TriageVerdict(id="x", severity="high")
    msg = Msg(tool_calls=[tc(args={"findings": [finding("u1")]})])
    out = extract_structured({"structured_response": sr, "messages": [msg]},
                             HunterResult)
    assert isinstance(out, HunterResult)
    assert [f.id for f in out.findings] == ["u1"]


def test_tier1_dict_shaped_sr_is_not_trusted():
    """hasattr(dict_instance, payload) is False: a dict-shaped tier-1 value
    falls through (legacy behavior) instead of being handed back raw."""
    out = extract_structured({"structured_response": {"findings": []},
                              "messages": []}, HunterResult)
    assert out is None


@pytest.mark.parametrize("args", [
    {},
    {"findings": "nope"},
    {"findings": {"not": "a list"}},
    {"verdicts": [{"id": "a"}]},
])
def test_bad_tier2_args_skip_to_prose_rescue(args):
    msg = Msg(tool_calls=[tc(args=args)], text='{"findings": []}')
    out = extract_structured({"messages": [msg]}, HunterResult)
    assert out == HunterResult(findings=[])
    # Without rescuable prose nothing validates at all.
    bare = extract_structured({"messages": [Msg(tool_calls=[tc(args=args)])]},
                              HunterResult)
    assert bare is None


def test_tier2_reversed_scan_newest_wins_and_garbled_skipped():
    old = tc(args={"findings": [finding("old")]})
    new = tc(args={"findings": [finding("new")]})
    msg_old, msg_new = Msg(tool_calls=[old]), Msg(tool_calls=[new])
    out = extract_structured({"messages": [msg_old, msg_new]}, HunterResult)
    assert out.findings[0].id == "new"
    garbled = tc(args={"findings": {"nope": 1}})
    out = extract_structured({"messages": [Msg(tool_calls=[garbled]),
                                           Msg(tool_calls=[old])]},
                             HunterResult)
    assert out.findings[0].id == "old"


def test_real_aimessage_tool_calls_rescue_and_skip():
    def call(args, cid):
        return {"name": "HunterResult", "args": args, "id": cid,
                "type": "tool_call"}

    good = AIMessage(content="", tool_calls=[call({"findings": [finding("aim")]}, "1")])
    out = extract_structured({"messages": [good]}, HunterResult)
    assert [f.id for f in out.findings] == ["aim"]
    bad = AIMessage(content="", tool_calls=[call({"findings": "bad"}, "2")])
    out = extract_structured({"messages": [bad, Msg(text='{"findings": []}')]},
                             HunterResult)
    assert out == HunterResult(findings=[])


def test_dict_shaped_messages_stay_unscanned():
    dict_msg = {"role": "assistant",
                "tool_calls": [tc(args={"findings": [finding("d1")]})]}
    out = extract_structured({"messages": [dict_msg,
                                           Msg(text='{"findings": []}')]},
                             HunterResult)
    # The dict message contributes nothing; only prose rescue applies.
    assert out == HunterResult(findings=[])


def test_explicit_tool_name_and_list_field_overrides():
    out = extract_structured({"messages": [Msg(tool_calls=[tc("Other", {"findings": [finding("on")]})])]},
                             HunterResult, tool_name="Other")
    assert [f.id for f in out.findings] == ["on"]
    out = extract_structured({"messages": [Msg(tool_calls=[tc(args={"findings": []})])]},
                             HunterResult, list_field="findings")
    assert out.findings == []


def test_non_dict_and_empty_final_states_yield_none():
    assert extract_structured(None, HunterResult) is None
    assert extract_structured("nope", HunterResult) is None
    assert extract_structured([], HunterResult) is None
    assert extract_structured({}, HunterResult) is None
    assert extract_structured({"messages": None}, HunterResult) is None
    assert extract_structured({"messages": []}, HunterResult) is None


def test_dict_schema_extraction_is_harmless():
    """JSON-schema dicts have no __name__/model_fields/model_validate: every
    candidate is skipped harmlessly instead of crashing."""
    schema = {"type": "object", "properties": {}}
    res = {"messages": [Msg(tool_calls=[tc(args={"findings": []})])],
           "structured_response": None}
    assert extract_structured(res, schema) is None


def test_verdictbatch_derivation_and_tier2():
    assert _first_list_field(VerdictBatch) == "verdicts"
    msg = Msg(tool_calls=[tc("VerdictBatch", {"verdicts": [{"id": "v", "status": "confirmed"}]})])
    out = extract_structured({"messages": [msg]}, VerdictBatch)
    assert [(v.id, v.status) for v in out.verdicts] == [("v", "confirmed")]


# ---------------------------------------------------------------- run_structured


def test_run_structured_preserves_falsy_sr_and_non_dict_results():
    # Falsy-but-not-None sr passes through untouched (bit-identical to legacy).
    parsed, text = run_structured(None, HunterResult, "s", "h",
                                  agent=StubAgent({"structured_response": 0,
                                                   "messages": []}))
    assert (parsed, text) == (0, "")
    # A non-dict invoke result never crashes the wiring.
    stub = StubAgent(None)
    stub.invoke = lambda *a, **k: "garbage"
    assert run_structured(None, HunterResult, "s", "h", agent=stub) == (None, "")


def test_run_structured_model_none_disables_rescue_but_keeps_text():
    parsed, text = run_structured(
        None, None, "s", "h",
        agent=StubAgent({"structured_response": None,
                         "messages": [Msg(text='{"findings": []}')]}))
    assert parsed is None
    assert text == '{"findings": []}'


def test_run_structured_tier1_identity_beats_junk_text():
    inst = HunterResult(findings=[])
    result = {"structured_response": inst,
              "messages": [Msg(text='{"findings": [{"id":"zzz"}]}')]}
    parsed, text = run_structured(None, HunterResult, "s", "h",
                                  agent=StubAgent(result))
    assert parsed is inst
    assert text == '{"findings": [{"id":"zzz"}]}'


# ---------------------------------------------------------------- batch


class FakeStructured:
    def __init__(self, payloads):
        self._p = payloads

    def batch(self, msgs, config=None, return_exceptions=False):
        assert return_exceptions is True
        return list(self._p)


class FakeLLM:
    profile = None
    _structured = None

    def __init__(self):
        self.seen = {}

    def with_structured_output(self, model, **kwargs):
        self.seen = {"model": model}
        self.seen.update(kwargs)
        return self._structured


def run_batch(llm, payloads):
    llm._structured = FakeStructured(payloads)
    orig = deep.make_llm
    deep.make_llm = lambda *a, **k: llm
    try:
        return deep.run_structured_batch({}, VerdictBatch, "sys", ["h0"])
    finally:
        deep.make_llm = orig


def batch_method(profile):
    llm = FakeLLM()
    llm.profile = profile
    llm._structured = FakeStructured([None])
    orig = deep.make_llm
    deep.make_llm = lambda *a, **k: llm
    try:
        deep.run_structured_batch({}, VerdictBatch, "x", ["h"])
    finally:
        deep.make_llm = orig
    return llm.seen.get("method")


def test_batch_method_is_profile_gated():
    assert batch_method({"structured_output": True}) == "json_schema"
    assert batch_method({"name": "m"}) == "function_calling"
    assert batch_method({}) == "function_calling"
    assert batch_method(None) == "function_calling"
    assert batch_method({"structured_output": False}) == "function_calling"


def test_batch_parsed_instance_preferred_over_salvage():
    inst = VerdictBatch(verdicts=[VerdictItem(id="ok", status="confirmed")])
    llm = FakeLLM()
    llm.seen = {}
    out = run_batch(llm, [{"raw": AIMessage(content='{"verdicts": [{"id": "WRONG"}]}'),
                           "parsed": inst, "parsing_error": None}])
    assert out[0] is inst
    assert llm.seen.get("include_raw") is True
    assert llm.seen.get("method") == "function_calling"


def test_batch_salvage_accepts_empty_list_and_list_content():
    out = run_batch(FakeLLM(), [{"raw": AIMessage(content='prose\n```json\n{"verdicts": []}\n```'),
                                 "parsed": None, "parsing_error": ValueError("x")}])
    assert out[0] == VerdictBatch(verdicts=[])
    out = run_batch(FakeLLM(), [{"raw": AIMessage(content=[{"type": "text", "text": '{"verdicts": []}'}]),
                                 "parsed": None, "parsing_error": ValueError("x")}])
    assert out[0] == VerdictBatch(verdicts=[])


def test_batch_runtimeerror_contract_exact_string():
    exact = "structured reply contained no tool call"
    out = run_batch(FakeLLM(), [{"raw": AIMessage(content="nothing"), "parsed": None,
                                 "parsing_error": ValueError("x")}])
    assert isinstance(out[0], RuntimeError) and str(out[0]) == exact
    # Missing / None raw degrade to the same failure, never a crash.
    out = run_batch(FakeLLM(), [{"parsed": None, "parsing_error": ValueError("x")}])
    assert str(out[0]) == exact
    out = run_batch(FakeLLM(), [{"raw": None, "parsed": None,
                                 "parsing_error": ValueError("x")}])
    assert str(out[0]) == exact
    out = run_batch(FakeLLM(), [None])
    assert isinstance(out[0], RuntimeError) and str(out[0]) == exact


def test_batch_passthroughs_remain():
    err = ValueError("bad reply")
    instance = TriageBatch(verdicts=[])
    out = run_batch(FakeLLM(), [err, {"parsed": 0}, instance])
    assert out[0] is err
    assert out[1] == {"parsed": 0}
    assert out[2] == instance


# ---------------------------------------------------------------- builder


def test_coerce_wraps_once_with_short_tool_message():
    st = _coerce_response_format(HunterResult)
    assert isinstance(st, ToolStrategy)
    assert st.schema is HunterResult
    assert st.handle_errors is True
    assert st.tool_message_content == "HunterResult accepted."
    assert _coerce_response_format(st) is st


def test_coerce_dict_schemas_and_passthroughs():
    st = _coerce_response_format({"title": "RobotStatus", "type": "object",
                                  "properties": {}})
    assert isinstance(st, ToolStrategy)
    assert st.tool_message_content == "RobotStatus accepted."
    bare = _coerce_response_format({"type": "object", "properties": {}})
    assert bare.tool_message_content == "Structured output accepted."
    ps = ProviderStrategy(TriageBatch)
    assert _coerce_response_format(ps) is ps
    assert _coerce_response_format(None) is None


def test_coerce_dataclass_typeddict_union():
    from dataclasses import dataclass
    from typing import TypedDict, Union

    @dataclass
    class DCSchema:
        a: int

    class TDSchema(TypedDict):
        a: int

    st = _coerce_response_format(DCSchema)
    assert isinstance(st, ToolStrategy)
    assert st.tool_message_content == "DCSchema accepted."
    st2 = _coerce_response_format(TDSchema)
    assert type(st2).__name__ == "ToolStrategy"
    assert st2.tool_message_content == "TDSchema accepted."
    u = Union[HunterResult, TriageBatch]
    assert _coerce_response_format(u) is u  # typing alias is not a type

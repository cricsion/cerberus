"""M3 (plan-1345): N-vote majority-or-tie, votes default 1, no judge."""
import pytest
from cerberus.agents import validator as v


def _finding(**kw):
    base = {"id": "h-1", "title": "t", "cwe": "CWE-89", "severity": "high",
            "confidence": 0.8, "path": "a.py", "start_line": 1, "end_line": 1,
            "snippet": "exec(q)",
            "taint": {"source": "u", "sink": "execute", "path": []},
            "evidence": "e", "status": "needs-review"}
    base.update(kw)
    return base


def test_votes_normalized_and_override_clamped(monkeypatch):
    from cerberus.config import effective_config, reset_config

    monkeypatch.delenv("VERIFIER_VOTES", raising=False)
    reset_config()

    def votes(value):
        return effective_config(
            {"verification": {"votes": value}})["verification"]["votes"]

    assert effective_config({})["verification"]["votes"] == 1
    assert votes("3") == 3
    assert votes(0) == 1
    assert votes(9) == 5
    assert votes("garbage") == 1

    # The CLI override clamps at its own site, so -c 9 cannot buy nine ballots.
    captured = {}

    def fake_cells(planned, workers, *, cfg, n_votes, **kw):
        captured["votes"] = n_votes
        return {}

    monkeypatch.setattr(v, "_run_validation_cells", fake_cells)
    monkeypatch.setattr("cerberus.config.api_key_present", lambda cfg=None: True)
    v.run_validation([_finding()], {}, votes=4)
    assert captured["votes"] == 4
    v.run_validation([_finding()], {"verification": {"votes": 2}}, votes=3)
    assert captured["votes"] == 3
    v.run_validation([_finding()], {}, votes=9)
    assert captured["votes"] == 5
    v.run_validation([_finding()], {}, votes=0)
    assert captured["votes"] == 1


def test_majority_verdict_agree_and_tie():
    ok = v._majority_verdict(_finding(), [_finding(status="confirmed"),
                                          _finding(status="confirmed")])
    assert ok["status"] == "confirmed" and "2/2" in ok["evidence"]
    tie = v._majority_verdict(_finding(), [_finding(status="confirmed"),
                                           _finding(status="fp")])
    assert tie["status"] == "needs-review" and "tie/no-majority" in tie["evidence"]
    three_way = v._majority_verdict(_finding(), [_finding(status="confirmed"),
                                                 _finding(status="fp"),
                                                 _finding(status="needs-review")])
    assert three_way["status"] == "needs-review"
    single = v._majority_verdict(_finding(), [_finding(status="fp")])
    assert single["status"] == "fp"


def _run_with_ballots(monkeypatch, tmp_path, ballots, votes):
    """Script per-round batch replies through the real batch->majority path.

    Mocks only the LLM transport (langchain_openai.ChatOpenAI): grouping,
    ballots, majority, and the fp guardrail all run for real. Each ballot is
    one round's verdict; fp ballots carry sanitizer evidence so the guardrail
    lets a genuine fp majority stand.

    The double SUBCLASSES the real ChatOpenAI instead of duck-typing a
    ``.invoke`` object: the validator path runs a deep agent, so `make_llm`
    must hand `build_deep_agent` a real langchain BaseChatModel. A duck-typed
    fake is refused with a TypeError before any call, every round fail-opens
    and the assertions see zero invocations. TARGET_REPO roots the agent's
    repo-confined backend (never the harness CWD); SANDBOX_BACKEND=local pins
    the no-shell posture so an operator's sandbox env cannot leak in.
    """
    from langchain_core.messages import AIMessage
    from langchain_core.outputs import ChatGeneration, ChatResult
    from langchain_openai import ChatOpenAI as RealChat

    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    monkeypatch.setenv("SANDBOX_BACKEND", "local")
    calls = []
    def _reply(b):
        if b == "confirmed":
            return {"id": "h-1", "status": "confirmed", "confidence": 0.9,
                    "evidence": "tainted into execute:1"}
        return {"id": "h-1", "status": "fp", "confidence": 0.9,
                "evidence": "parameterized query bound:1"}

    class FakeLLM(RealChat):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            calls.append(1)
            b = ballots[min(len(calls) - 1, len(ballots) - 1)]
            if isinstance(b, Exception):
                raise b
            # Structured output is a tool call. A content-only JSON reply is
            # now a failed round (no structured output), not a parseable ballot.
            return ChatResult(generations=[ChatGeneration(
                message=AIMessage(content="", tool_calls=[{
                    "name": "VerdictBatch",
                    "args": {"verdicts": [_reply(b)]},
                    "id": f"call-{len(calls)}", "type": "tool_call"}]))])

    monkeypatch.setattr("langchain_openai.ChatOpenAI", FakeLLM)
    out = v.run_validation([_finding()], {"verification": {"votes": votes}})
    return out[0], calls


# One table over the real batch->majority path: only the LLM transport is faked
# (see _run_with_ballots), so grouping, ballots, majority, and the fp guardrail
# all run for real. Fixtures stay function-scoped on purpose: the per-test
# monkeypatch plus the autouse _clear_llm_provider_cache in conftest.py are what
# make the ChatOpenAI double take effect — hoisting either silently breaks it.
@pytest.mark.parametrize(
    ("ballots", "votes", "expected_status", "expected_calls",
     "expected_evidence"),
    [
        pytest.param(["confirmed", "confirmed"], 2, "confirmed", 2, (),
                     id="two_agreeing_votes_stand"),
        pytest.param(["confirmed", "fp"], 2, "needs-review", 2,
                     ("tie/no-majority",), id="split_is_tie_no_judge"),
        pytest.param(["fp", "confirmed", "fp"], 3, "fp", 3, (),
                     id="three_vote_majority_wins"),
        pytest.param(["confirmed"], 1, "confirmed", 1, (),
                     id="single_vote_stands_no_second_pass"),
        # A raising ballot is just another scripted round (the helper raises it
        # from the fake _generate), so the error row shares the body unchanged.
        pytest.param([RuntimeError("down"), "confirmed"], 2, "needs-review", 2,
                     (), id="failed_vote_counts_as_needs_review"),  # 1c/1n: no majority
    ],
)
def test_vote_tally_over_scripted_ballots(monkeypatch, tmp_path, ballots,
                                          votes, expected_status,
                                          expected_calls,
                                          expected_evidence):
    got, calls = _run_with_ballots(monkeypatch, tmp_path, ballots, votes)
    assert got["status"] == expected_status
    assert len(calls) == expected_calls  # exactly N calls — no judge call after
    # Per-row evidence markers (empty where only status/calls were asserted),
    # so the split row's tie check survives without branching the shared body.
    assert all(marker in got["evidence"] for marker in expected_evidence)


def test_same_model_no_warning(capsys, monkeypatch):
    # Same-model runs are the normal configuration (single free model);
    # validation runs silent.
    monkeypatch.setattr(v, "_validate_unit_batch",
                        lambda name, items, cfg, threat_md="", n_votes=1, **k:
                            [_finding(status="fp") for _ in items])
    v.run_validation([_finding()], {"verification": {"votes": 1},
                                    "hunter_model": "m", "validator_model": "m"})
    assert "WARNING" not in capsys.readouterr().err


def test_threat_block_in_message():
    from cerberus.prompts.validator import build_batch_task

    md = "## Out-of-scope\n\nNone. " + "z" * 20000
    msg = build_batch_task("g", md, [_finding()])
    assert md in msg  # no truncation
    assert "threat-model-excluded" not in msg  # scope never acquits
    assert "NEVER justify" in msg or "never" in msg.lower()
    plain = build_batch_task("g", "", [_finding()])
    assert "threat-model-excluded" not in plain


def test_custom_rule_faces_llm(monkeypatch, tmp_path):
    # A custom taint-rule finding is a vulnerability claim, not a gate-killed
    # fp, so it must reach the LLM. Same double contract as
    # _run_with_ballots: a real BaseChatModel with a scripted batch reply.
    from langchain_core.messages import AIMessage
    from langchain_core.outputs import ChatGeneration, ChatResult
    from langchain_openai import ChatOpenAI as RealChat

    monkeypatch.setenv("TARGET_REPO", str(tmp_path))
    monkeypatch.setenv("SANDBOX_BACKEND", "local")
    called = []

    class FakeLLM(RealChat):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            called.append(1)
            # Structured output is the VerdictBatch tool call, as the batch
            # prompt demands.
            return ChatResult(generations=[ChatGeneration(
                message=AIMessage(content="", tool_calls=[{
                    "name": "VerdictBatch",
                    "args": {"verdicts": [
                        {"id": "cerberus.rules.x", "status": "fp",
                         "confidence": 0.9, "evidence": "parameterized:1"}]},
                    "id": "call-1", "type": "tool_call"}]))])

    monkeypatch.setattr("langchain_openai.ChatOpenAI", FakeLLM)
    out = v.run_validation([_finding(id="cerberus.rules.x")], {"verification": {"votes": 3}})
    assert len(called) >= 1  # custom-rule claims reach the LLM
    assert len(out) == 1 and out[0]["id"] == "cerberus.rules.x"


def test_no_key_path_unchanged(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    called = []
    monkeypatch.setattr(v, "_validate_unit_batch",
                        lambda *a, **k: called.append(1) or [])
    out = v.run_validation([_finding()], {"verification": {"votes": 3}})
    assert out[0]["status"] == "needs-review"
    assert called == []

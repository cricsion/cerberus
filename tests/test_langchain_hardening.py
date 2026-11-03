"""LangChain/deepagents hardening contracts (docs-driven, behavior-locked).

Covers what `cerberus/agents/deep.py` now guarantees on top of the repo-confined
backend: provider-derived model profiles, call-site fs allowlist + deny-write
permissions, call-limit middleware, and config-error taxonomy (fail loudly).

Sources: docs/src/oss/deepagents/{profiles,overview,permissions,fault-tolerance,
going-to-production}.mdx; verified against deepagents 0.7.21 / langgraph 1.2.
"""
import json as _json
import types

import cerberus.agents.deep as deep_mod
import deepagents
import pytest
from cerberus.agents import hunters as h
from cerberus.agents import triage as t
from cerberus.agents import validator as v
from cerberus.agents.deep import (
    BASE_EXCLUDED_TOOLS,
    FS_TOOLS,
    build_deep_agent,
    final_text,
    is_config_error,
    run_structured,
)
from cerberus.config import get_config
from cerberus.sandbox.local_backend import RepoLocalBackend
from langchain_core.exceptions import ModelAuthenticationError, ModelRateLimitError
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from llm_fakes import ToolCallableLLM
from pydantic import BaseModel


class _Q(BaseModel):
    question: str


def _f(fid, unit="u", cwe="CWE-89", line=1, evidence="e"):
    return {"id": fid, "title": fid, "cwe": cwe, "path": "a.py",
            "start_line": line, "end_line": line, "snippet": "q",
            "severity": "high", "confidence": 0.5, "status": "needs-review",
            "unit": unit,
            "taint": {"source": "u", "sink": "ex", "path": []},
            "evidence": evidence}




class _StaticLLM(ToolCallableLLM):
    """This file's static spelling; keeps the provider key \"_staticllm\"."""

    @property
    def _llm_type(self) -> str:
        return "staticllm"


def _fake_llm():
    return _StaticLLM()


# --- profiles -----------------------------------------------------------

def test_profile_registers_under_the_models_own_provider(monkeypatch):
    """Hardening must not be keyed to a hardcoded "openai" (no wildcard key)."""
    seen = []

    def spy(key, profile):
        seen.append((key, profile))

    monkeypatch.setattr(deepagents, "register_harness_profile", spy)
    monkeypatch.setattr(deep_mod, "_registered", set())
    deep_mod._register_profile(_fake_llm())
    keys = [k for k, _ in seen]
    # The key is whatever the model itself reports ("_staticllm"), NOT the
    # hardcoded "openai" the old registration used.
    assert deep_mod._model_provider(_fake_llm()) in keys, keys
    assert "openai" not in keys
    profiles = dict(seen)
    p = profiles[deep_mod._model_provider(_fake_llm())]
    # Registry carries the mode-INDEPENDENT set only: registry entries merge
    # on re-registration, so `execute` (excluded for local backends, kept
    # for sandbox backends) must live in the per-agent fs allowlist
    # (`_fs_tools`), not in the profile.
    assert p.excluded_tools == BASE_EXCLUDED_TOOLS
    assert p.general_purpose_subagent.enabled is False


def test_profile_provider_fallback_for_exotic_models():
    """A model with no derivable provider still gets the "openai" key."""
    class Opaque:
        pass

    assert deep_mod._model_provider(Opaque()) == "openai"


def test_exotic_provider_keys_are_not_downgraded(monkeypatch):
    """Non-alnum providers must register under their OWN key.

    register_harness_profile accepts arbitrary key text (only empty/whitespace
    keys are rejected), so falling back to "openai" for e.g. "vertex.ai" is a
    silent-miss: the model would resolve a key that was never registered.
    """
    import deepagents._models as dmod

    seen = []

    def spy(key, profile):
        seen.append(key)

    monkeypatch.setattr(dmod, "get_model_provider", lambda llm: "vertex.ai")
    monkeypatch.setattr(deepagents, "register_harness_profile", spy)
    monkeypatch.setattr(deep_mod, "_registered", set())
    deep_mod._register_profile(_fake_llm())
    assert seen == ["vertex.ai"], seen


def test_colon_provider_falls_back(monkeypatch):
    """A colon in the provider half would make `provider:model` malformed."""
    import deepagents._models as dmod

    monkeypatch.setattr(dmod, "get_model_provider", lambda llm: "a:b")
    assert deep_mod._model_provider(_fake_llm()) == "openai"


def test_build_deep_agent_composes_hardening(monkeypatch, tmp_path):
    """The call site carries the fs allowlist, call caps and deny-write rule
    (model-independent layers)."""
    captured = {}

    def fake(**kw):
        captured.update(kw)
        return "agent"

    monkeypatch.setattr(deepagents, "create_deep_agent", fake)
    backend = RepoLocalBackend(repo_path=tmp_path)
    build_deep_agent(_fake_llm(), system_prompt="x", tools=[], backend=backend,
                     name="t")
    mw = captured["middleware"]
    kinds = {type(m).__name__ for m in mw}
    assert "FilesystemMiddleware" in kinds and "ModelCallLimitMiddleware" in kinds
    fs = next(m for m in mw if type(m).__name__ == "FilesystemMiddleware")
    # tools= accepts names and materializes the built tools for that allowlist.
    assert {t_.name for t_ in fs.tools} == set(FS_TOOLS)
    # The deny rule rides OUR FilesystemMiddleware: deepagents merges custom
    # middleware by name, so a separate `permissions=` kwarg to
    # create_deep_agent would be dropped when our instance replaces the base.
    assert "permissions" not in captured
    perms = fs._permissions
    assert perms and perms[0].mode == "deny"
    assert perms[0].operations == ["write"]
    # The scope is the whole tree — dot segments included: bare `/**` cannot
    # match `.env`/`.git`-style paths (wcmatch globstar skips dot segments),
    # so `/.git/config`-style writes would slip through the permissive
    # default without the explicit `/.**`-family patterns.
    assert perms[0].paths == ["/**", "/.*", "/.*/**"]
    # Ephemeral by design: no checkpointer, no thread ids.
    assert "checkpointer" not in captured


def test_non_chat_model_is_refused(monkeypatch):
    monkeypatch.setenv("TARGET_REPO", "/tmp")
    with pytest.raises(TypeError, match="BaseChatModel"):
        build_deep_agent(object(), system_prompt="x", tools=[])


# --- error taxonomy ------------------------------------------------------

def test_config_error_fails_the_stage_loudly(monkeypatch):
    """Bad key / wrong model must not masquerade as needs-review."""
    monkeypatch.setenv("API_KEY", "dummy")

    def boom(*a, **k):
        raise ModelAuthenticationError("bad key")

    monkeypatch.setattr(h, "build_unit_hunter_agent", boom)
    with pytest.raises(ModelAuthenticationError):
        h._run_unit({"name": "u"}, "/repo", ["a.py"], [], {})

    monkeypatch.setattr("cerberus.agents.deep.run_structured", boom)
    monkeypatch.setattr("cerberus.agents.deep.run_structured_batch", boom)
    with pytest.raises(ModelAuthenticationError):
        v.run_validation([_f("a")], {}, "", votes=1)
    with pytest.raises(ModelAuthenticationError):
        t.run_triage([_f("a")], {}, "")


def test_transient_error_still_fails_open(monkeypatch):
    """Rate limits remain retryable noise: the unit degrades, never explodes."""

    def flaky(*a, **k):
        raise ModelRateLimitError("429")

    monkeypatch.setattr(h, "build_unit_hunter_agent", flaky)
    out = h._run_unit({"name": "u"}, "/repo", ["a.py"], [], {})
    assert out[0]["id"] == "unit-u-fallback"
    assert "ModelRateLimitError" in out[0]["snippet"]


def test_config_errors_escape_the_pipeline_nodes(monkeypatch):
    """validator_node / _validate_inline / triage_node fail open on infra
    noise but must not swallow a config-class failure into needs-review."""
    import cerberus.pipeline as g

    def boom(*a, **k):
        raise ModelAuthenticationError("bad key")

    monkeypatch.setattr("cerberus.agents.deep.run_structured", boom)
    monkeypatch.setattr("cerberus.agents.deep.run_structured_batch", boom)
    monkeypatch.setenv("API_KEY", "dummy")

    with pytest.raises(ModelAuthenticationError):
        g.validator_node({"pending": [_f("a")]})

    with pytest.raises(ModelAuthenticationError):
        g._validate_inline([_f("a")], {}, "", None, "u", repo="/tmp")

    with pytest.raises(ModelAuthenticationError):
        g.triage_node({"verified": [_f("a")]})


def test_transient_error_fails_open_in_nodes(monkeypatch):
    """The pipeline's own fail-open still holds for rate limits."""
    import cerberus.pipeline as g

    def flaky(*a, **k):
        raise ModelRateLimitError("429")

    monkeypatch.setattr("cerberus.agents.deep.run_structured", flaky)
    monkeypatch.setenv("API_KEY", "dummy")

    out = g.validator_node({"pending": [_f("a")]})
    assert out["verified"][0]["status"] == "needs-review"


def test_is_config_error_partitions_the_taxonomy():
    from langchain_core.exceptions import ContextOverflowError

    assert is_config_error(ModelAuthenticationError("x"))
    assert not is_config_error(ContextOverflowError("x"))
    assert not is_config_error(ModelRateLimitError("x"))
    assert not is_config_error(TimeoutError("x"))


# --- message extraction ---------------------------------------------------

def test_final_text_skips_tool_results():
    class M:
        def __init__(self, type_, content):
            self.type = type_
            self.content = content

    # Structured-output success ends on this ToolMessage (repr, not an answer).
    res = {"messages": [M("ai", "real answer"),
                        M("tool", "Returning structured response: Q(question='q')")]}
    assert final_text(res) == "real answer"
    assert final_text({"messages": [M("tool", "x")]}) == ""


# --- ephemeral execution ---------------------------------------------------

def test_run_structured_invokes_without_persistence(monkeypatch):
    """No thread ids and no checkpointer: an invoke carries only the
    recursion limit and, when set, the drain control."""
    seen = {}

    class FakeAgent:
        def invoke(self, msgs, **kw):
            seen.update(kw)
            return {"messages": []}

    monkeypatch.setattr(deep_mod, "build_deep_agent",
                        lambda *a, **k: FakeAgent())
    run_structured({}, _Q, "sys", "human", name="probe")
    # Persistence contract: the invoke config carries ONLY the recursion
    # limit (no checkpointer / thread ids); its value is relational — the
    # resolved config number, never pinned from prod.
    assert set(seen["config"]) == {"recursion_limit"}
    assert seen["config"]["recursion_limit"] > 0
    assert "control" not in seen


# --- fs allowlist / deny-write regression (recommendation tests) ---------

def test_fs_tools_strict_allowlist_by_backend(monkeypatch):
    """execute appears only for sandbox backends; never otherwise."""
    # Sandbox backend: FS_TOOLS plus execute.
    monkeypatch.setattr(deep_mod, "_supports_shell", lambda _b: True)
    assert set(deep_mod._fs_tools(object())) == set(FS_TOOLS) | {deep_mod.SHELL_TOOL}
    # Local backend: FS_TOOLS only.
    monkeypatch.setattr(deep_mod, "_supports_shell", lambda _b: False)
    assert set(deep_mod._fs_tools(object())) == set(FS_TOOLS)
    assert deep_mod.SHELL_TOOL not in deep_mod._fs_tools(object())


# --- resilience middleware (docs: langchain middleware/built-in) -----------

# Model retries belong to the OpenAI client (make_llm max_retries), not to a
# second middleware layer: two owners multiplied retries and the deleted
# monkeypatch capped the client's backoff at 5s.
_MIDDLEWARE_ORDER = ["FilesystemMiddleware", "ModelCallLimitMiddleware",
                     "ToolErrorMiddleware", "ToolRetryMiddleware"]


def test_scan_middleware_stack_composition(tmp_path):
    """Documented composition order, first = OUTERMOST: the tool error handler
    sits outer, retry inner (closest to the tool) — exhausted retries reach
    the handler, and tool exceptions get retried at all (langchain factory)."""
    names = [type(m).__name__
             for m in deep_mod._scan_middleware(RepoLocalBackend(
                 repo_path=tmp_path))]
    assert names == _MIDDLEWARE_ORDER
    assert (names.index("ToolErrorMiddleware")
            < names.index("ToolRetryMiddleware"))


def test_tool_retry_middleware_raises_on_exhaustion(tmp_path):
    """on_failure="error": exhaustion must reach the stage's fail-open
    classifier, not a fabricated AIMessage."""
    mw = {type(m).__name__: m for m in deep_mod._scan_middleware(
        RepoLocalBackend(repo_path=tmp_path))}
    assert mw["ToolRetryMiddleware"].on_failure == "error"


def test_local_write_permissions_cover_dot_paths():
    """`/**` does NOT match dot segments (wcmatch BRACE|GLOBSTAR), and an
    unmatched write means ALLOW (permissive default, docs#permissions) —
    hence the explicit `/.*` / `/.*/**` deny patterns. First-match-wins:
    the scratchpad allow listed before the catch-all deny stays honored."""
    from deepagents.middleware.filesystem import _check_fs_permission

    scratch = deep_mod._local_permissions(scratchpad=True)
    readonly = deep_mod._local_permissions()
    w = "write"
    assert (_check_fs_permission(scratch, w, "/.cerberus/scratch/x.txt")
            == "allow")
    for rules in (scratch, readonly):
        assert _check_fs_permission(rules, w, "/main.py") == "deny"
        assert _check_fs_permission(rules, w, "/.env") == "deny"
        assert _check_fs_permission(rules, w, "/.git/config") == "deny"
        assert _check_fs_permission(rules, w, "/.git/hooks/pre-commit") == "deny"


def test_single_model_retry_owner_is_the_client(tmp_path, monkeypatch):
    """No model-retry middleware and no retry-delay monkeypatch: the OpenAI
    client's max_retries is the sole model-retry owner (it honors Retry-After
    and backs off properly)."""
    names = [type(m).__name__ for m in deep_mod._scan_middleware(
        RepoLocalBackend(repo_path=tmp_path))]
    assert "Model" + "RetryMiddleware" not in names
    seen: dict = {}

    def fake_init(**kwargs):
        seen.update(kwargs)
        return _fake_llm()

    monkeypatch.setattr("langchain.chat_models.init_chat_model", fake_init)
    deep_mod.make_llm({"model": "m", "api_key": "k"})
    # Config-resolved (the one cfg), not a hardcoded client default.
    assert seen["max_retries"] == get_config()["max_retries"]
    seen.clear()
    deep_mod.make_llm({"model": "m", "api_key": "k"}, max_retries=3)
    assert seen["max_retries"] == 3


def test_make_llm_forwards_reasoning_effort_and_shapes_timeout(monkeypatch):
    """mk passthrough: config's reasoning_effort reaches ChatOpenAI (the
    field exists there), and a scalar timeout becomes an attempt-budget tuple
    with a fast-fail connect phase so a blackholed host can't stall a stage."""
    seen: dict = {}

    def fake_init2(**kwargs):
        seen.update(kwargs)
        return _fake_llm()

    monkeypatch.setattr("langchain.chat_models.init_chat_model", fake_init2)
    deep_mod.make_llm({"model": "m", "api_key": "k",
                       "reasoning_effort": "high", "timeout": 30})
    assert seen["reasoning_effort"] == "high"
    assert seen["timeout"] == (float(get_config()["connect_timeout"]),
                               30.0, 30.0, 30.0)
    seen.clear()
    deep_mod.make_llm({"model": "m", "api_key": "k"})
    assert "reasoning_effort" not in seen  # unset effort stays unset


def test_tool_error_message_converts_recoverable_only():
    """LLM-recoverable classes convert; harness defects propagate."""
    from langchain_core.tools import ToolException

    req = types.SimpleNamespace(tool_call={"name": "grep_files"})
    assert "grep_files" in deep_mod._tool_error_message(
        ValueError("bad pattern"), req)
    assert "grep_files" in deep_mod._tool_error_message(
        ToolException("not a file"), req)
    # json.JSONDecodeError subclasses ValueError: the malformed-tool-call
    # args class from live runs converts too.
    msg = deep_mod._tool_error_message(
        _json.JSONDecodeError("line 1", "doc", 1), req)
    assert msg and "JSONDecodeError" in msg
    # harness defect: never absorbed by the retry stack.
    assert deep_mod._tool_error_message(TypeError("bug"), req) is None


# --- model profile pins (docs: langchain models, "Model profiles") --------

def test_make_llm_profile_override_beats_registry_auto_load():
    # 77443 is off every registry value on purpose: when the ctor gets an
    # explicit profile, BaseChatModel must skip auto-load entirely — so
    # `profile` is exactly our two pins, not a registry merge.
    llm = deep_mod.make_llm({"model": "gpt-4o-mini", "api_key": "dummy",
                             "model_profile": {"max_input_tokens": "77443",
                                               "structured_output": "true"}})
    assert llm.profile == {"max_input_tokens": 77443,
                           "structured_output": True}


def test_model_kwargs_carries_model_profile():
    from cerberus.config import get_model_kwargs

    mk = get_model_kwargs({"hunter_model": "m",
                           "model_profile": {"max_input_tokens": 64000}},
                          "hunter")
    assert mk["model_profile"] == {"max_input_tokens": 64000}
    # A partial cfg falls back to cerberus/config/default.yaml's profile pins.
    default_profile = get_model_kwargs({"hunter_model": "m"},
                                       "hunter")["model_profile"]
    assert default_profile["max_input_tokens"] == "400000"
    assert default_profile["structured_output"] == ""

"""Deep Agents factory: every LLM stage of the harness runs through here.

One place builds the `ChatOpenAI` (on langchain-openai's cached HTTP
client), one place builds the deep agent (scoped harness profile,
response_format), and `run_structured`
gives every call site the same contract the old `structured_first` had —
`(parsed, raw_text, agent_state)`, raising on transport failure so each site
keeps its own fail-open chain. Deep Agents is used as a library component:
our tools and prompts, the built-in planning/filesystem harness, no write
tools, no general-purpose subagent (no `task` recursion), and no shell
tool unless a sandbox backend is configured.

Containment is layered (defense in depth), because no single layer is a
security boundary on its own:

1. Backend: `RepoLocalBackend` is read-only and refuses mutation with
   structured errors; it is not a sandbox backend, so no `execute` tool exists.
2. Call site: a `FilesystemMiddleware` allowlist (read_file/ls/glob/grep only)
   and a deny-write `FilesystemPermission` attached to that SAME instance.
   These layers are harness policy and apply regardless of the model; the
   docs describe the underlying middleware/permission mechanics, while the
   package (`tool_exclusion.py`) frames exclusion lists as visibility filters.
3. Profile: `HarnessProfile(excluded_tools=...)` + subagents disabled, keyed on
   the model's own provider so a non-OpenAI model cannot silently miss it
   (profiles.mdx describes `excluded_tools` as a tool-visibility filter that
   resolves per model; the package source, not the doc site, states that
   exclusion lists are not a security surface).
"""
from __future__ import annotations

import os
import sys
import threading
import uuid
from pathlib import Path
from typing import Any

from langchain_core.exceptions import (ModelAuthenticationError,
                                        ModelInvalidRequestError,
                                        ModelNotFoundError,
                                        ModelPermissionDeniedError)
from langchain_core.language_models.chat_models import BaseChatModel

try:
    from langchain_core.callbacks import BaseCallbackHandler as _BaseCallbackHandler
except Exception:  # pragma: no cover - optional dependency
    class _BaseCallbackHandler:  # type: ignore[no-redef]
        pass

BaseCallbackHandler = _BaseCallbackHandler

try:
    from langchain_core.exceptions import ModelRateLimitError as _ModelRateLimitError
except Exception:  # pragma: no cover
    _ModelRateLimitError = None

ModelRateLimitError = _ModelRateLimitError

# Tools a scan agent must never have: mutating target code (write/edit/delete)
# and subagent recursion (task). ``execute`` (raw shell) is excluded UNLESS the
# backend is a sandbox: its ``execute`` runs inside a container or microVM,
# with egress controlled by the selected backend's network settings.
BASE_EXCLUDED_TOOLS = frozenset({
    "delete", "write_file", "edit_file", "task"
})
SHELL_TOOL = "execute"
# The only built-in filesystem tools a scan agent needs (allowlist, layer 2).
FS_TOOLS = ("read_file", "ls", "glob", "grep")
# Deep agents' FilesystemMiddleware refuses permissions rules with sandbox
# backends (NotImplementedError), unless every permission path is scoped to a
# CompositeBackend route: with a shell tool path-based deny cannot cover
# commands, so the container is the confinement layer and we keep the
# permissions list empty here.
# Run-level caps per invocation: ModelCallLimit caps agent turns/LLM calls;
# recursion_limit lives in `run_structured` config.
MODEL_CALL_LIMIT = 100

# Model failures that are the operator's configuration, not a transient
# condition: a bad key or a wrong model name must fail the scan loudly, never
# masquerade as a needs-review verdict (langchain/models.mdx exception types).
# ContextOverflowError is deliberately NOT here: an oversized unit is a
# per-input problem, so it must fail that unit open, not abort the whole scan.
CONFIG_ERRORS = (ModelAuthenticationError, ModelPermissionDeniedError,
                 ModelInvalidRequestError, ModelNotFoundError)

# Harness *bugs*, not model/transport failures. The docs' error taxonomy says
# to let unexpected errors bubble up instead of converting them into a
# needs-review verdict: a TypeError/KeyError in our own code is a defect we
# want surfaced loudly, while provider, parse, and transport failures are the
# fail-open cases the scanner exists to absorb. Deliberately excludes
# ValueError (pydantic ValidationError subclasses it, and a bad model reply is
# a parse failure, not a bug) and RuntimeError (the call sites' transport
# stand-in).
PROGRAMMING_ERRORS = (AttributeError, NameError, UnboundLocalError, TypeError,
                      IndexError, KeyError, AssertionError,
                      NotImplementedError, SyntaxError)


class AgentVisibilityCallback(BaseCallbackHandler):
    """Lightweight callback that updates an ``AgentRegistry``.

    Only tool names and (optionally) file paths reach the registry: no prompt or
    tool output content is ever recorded, so cross-agent breadcrumbs stay free
    of secrets.
    """

    raise_error = False

    def __init__(self, agent_registry=None, agent_id=None, *, parent_stage="",
                 registry=None, id=None, **kw):
        # Accept either positional or keyword spellings.
        if agent_registry is None:
            agent_registry = registry if registry is not None else kw.get("agent_registry")
        if agent_id is None:
            agent_id = id if id is not None else kw.get("agent_id")
        self.agent_registry = agent_registry
        self.agent_id = None if agent_id is None else str(agent_id)
        self.parent_stage = parent_stage or kw.get("parent_stage", "")
        self._lock = __import__("threading").RLock()
        self._tool_counts = 0
        self._last_tool = ""
        self._last_path = ""

    def _is_rate_limit(self, exc):
        if exc is None:
            return False
        if ModelRateLimitError is not None and isinstance(exc, ModelRateLimitError):
            return True
        text = f"{type(exc).__name__}: {exc}".lower()
        return "rate limit" in text or "ratelimit" in text or "429" in text

    def _seconds(self, retry_state):
        for attr in ("upcoming_sleep", "idle_for"):
            try:
                val = getattr(retry_state, attr, None)
                if val is not None:
                    return float(val)
            except (TypeError, ValueError):
                pass
        try:
            exc = getattr(retry_state, "outcome", None)
            if exc is not None:
                e = exc.exception() if hasattr(exc, "exception") else None
                # Some providers expose Retry-After on the exception.
                for attr in ("retry_after", "retry_after_seconds"):
                    v = getattr(e, attr, None) if e is not None else None
                    if v is not None:
                        return float(v)
        except Exception:
            pass
        return 0.0

    def on_retry(self, retry_state, *, run_id=None, parent_run_id=None, **kwargs):
        try:
            exc = None
            outcome = getattr(retry_state, "outcome", None)
            if outcome is not None and hasattr(outcome, "exception"):
                exc = outcome.exception()
            if not self._is_rate_limit(exc):
                return
            seconds = self._seconds(retry_state)
            seconds_txt = int(seconds) if float(seconds).is_integer() else seconds
            reg = self.agent_registry
            aid = self.agent_id
            if reg is not None and aid:
                try:
                    reg.transition(aid, "running",
                                   message=f"rate_limited: waiting {seconds_txt}s")
                except Exception:
                    pass
        except Exception:
            pass
        return None

    def _tool_name(self, serialized):
        if isinstance(serialized, dict):
            return str(serialized.get("name") or serialized.get("id") or "")
        return str(getattr(serialized, "name", "") or "")

    def _path_hint(self, inputs):
        # Extract a file path from tool inputs without retaining content.
        try:
            if isinstance(inputs, dict):
                for key in ("path", "file_path", "target_path", "filename",
                            "filepath", "file"):
                    v = inputs.get(key)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
                # Some tools nest inputs under a "input" key.
                nested = inputs.get("input")
                if isinstance(nested, dict):
                    for key in ("path", "file_path", "target_path", "filename"):
                        v = nested.get(key)
                        if isinstance(v, str) and v.strip():
                            return v.strip()
            elif isinstance(inputs, str):
                # Never treat free text as a path.
                return ""
        except Exception:
            return ""
        return ""

    def on_tool_start(self, serialized, input_str, *, run_id=None,
                      parent_run_id=None, tags=None, metadata=None,
                      **kwargs):
        name = self._tool_name(serialized)
        path = self._path_hint(kwargs.get("inputs") if isinstance(kwargs.get("inputs"), dict)
                              else None)
        if not path:
            # kwargs may carry `inputs` as a kwarg of on_tool_start in some
            # versions; also accept explicit `input`/`inputs`.
            for cand in (kwargs.get("input"), kwargs.get("inputs")):
                p = self._path_hint(cand)
                if p:
                    path = p
                    break
        with self._lock:
            self._tool_counts += 1
            self._last_tool = name
            if path:
                self._last_path = path
        reg = self.agent_registry
        aid = self.agent_id
        if reg is not None and aid:
            updates = {"tool_calls": 1, "emit": False}
            if name:
                updates["last_tool"] = name
            if path:
                updates["last_path"] = path
            # Path/tool names only -- never prompt or tool output content.
            try:
                reg.update_stats(aid, **updates)
            except Exception:
                pass
            # Also mark running with a compact breadcrumb.
            msg = name or "tool"
            if path:
                msg = f"{msg} {path}"
            try:
                # Throttle-free enough for tests; production callers can pass
                # emit via extra controls if needed.
                pass
            except Exception:
                pass
        return None

    def on_tool_end(self, output, *, run_id=None, parent_run_id=None, **kwargs):
        # Best-effort file-read counting based on tool name only.
        name = ""
        serialized = kwargs.get("serialized")
        if serialized is not None:
            name = self._tool_name(serialized)
        tool = getattr(self, "_last_tool", "") or name
        reg = self.agent_registry
        aid = self.agent_id
        if reg is not None and aid and tool and "read" in tool.lower():
            try:
                reg.update_stats(aid, files_read=1, emit=False)
            except Exception:
                pass
        return None

    def on_tool_error(self, error, *, run_id=None, parent_run_id=None, **kwargs):
        return None

_registered: set[str] = set()
_reg_lock = threading.Lock()


def is_config_error(exc: BaseException) -> bool:
    """True for provider config-class failures (not retryable, fail loudly)."""
    return isinstance(exc, CONFIG_ERRORS)


def is_programming_error(exc: BaseException) -> bool:
    """True for harness-code defects (not model/transport failures).

    These are the "unexpected" row of the docs' error taxonomy: they must
    bubble up for debugging rather than being fail-opened into a needs-review
    verdict. See ``PROGRAMMING_ERRORS`` for the deliberate exclusions.
    """
    return isinstance(exc, PROGRAMMING_ERRORS)


def is_fatal_error(exc: BaseException) -> bool:
    """Boundary decision: re-raise (config or bug) instead of failing open.

    The fail-open chain absorbs model, parse, and transport failures only;
    operator misconfiguration and harness defects both stop the stage loudly.
    """
    return is_config_error(exc) or is_programming_error(exc)


def sanitize_model_kwargs(model_kwargs: dict | None) -> dict:
    """Copy kwargs for ChatOpenAI, refusing to invent a model on a real key.

    An explicitly supplied ``model`` is always kept. When ``model`` is
    missing there are two cases:

    * a *real* ``api_key`` (non-empty and not the offline "dummy"
      placeholder) means this run will spend real budget, so silently
      substituting a default model name would point that spend at an
      unintended model (the silent-model-default misconfig) -- raise
      ``ValueError`` naming the missing ``model`` instead of hiding it;
    * no usable key -- nothing, or the "dummy" placeholder itself (offline
      construction; unit tests that never reach a provider) -- keeps the
      historical dummy substitution: ``api_key`` of "dummy" and ``model``
      of "gpt-4o-mini", so ChatOpenAI can still be built without a provider.
    """
    mk = dict(model_kwargs or {})
    # A "real" key is non-empty and not the "dummy" offline placeholder that
    # this function itself injects: only a usable key that is about to spend
    # must fail loudly on a missing model; "dummy" (tests, keyless runs)
    # keeps the default-model substitution.
    _key = mk.get("api_key")
    _real_key = bool(_key) and _key != "dummy"
    if not mk.get("model"):
        if _real_key:
            raise ValueError(
                "model_kwargs is missing 'model' but supplies a real "
                "'api_key': refusing to substitute a default model that "
                "would spend real budget on an unintended model; "
                "set 'model' explicitly"
            )
        mk["api_key"] = "dummy"
        mk["model"] = "gpt-4o-mini"
    elif not mk.get("api_key"):
        mk["api_key"] = "dummy"
    return mk


def make_llm(mk: dict | None, *, timeout: int | None = None,
             max_retries: int | None = None, reasoning: bool = True) -> Any:
    """The single model constructor for every LLM stage.

    Built on langchain's ``init_chat_model``, with NO custom HTTP pool:
    ChatOpenAI creation goes through langchain-openai's own cache, which is
    ``lru_cache``d process-wide and keyed on (base_url, timeout,
    socket_options) with max_connections=1000 — every model built here
    therefore shares one connection pool with keep-alive reuse.

    langchain's provider-class resolution here is separately ``lru_cache``d
    process-wide, so the test suite clears that cache per test
    (tests/conftest.py) to keep the per-test ``langchain_openai.ChatOpenAI``
    doubles effective.
    """
    from langchain.chat_models import init_chat_model

    mk = sanitize_model_kwargs(mk)
    # Only trailing slashes are normalized: BASE_URL is a base URL (see
    # .env.example), and the OpenAI client handles the rest.
    base_url = (mk.get("base_url", "") or "").removesuffix("/") or None
    kwargs: dict[str, Any] = dict(
        model=mk.get("model", ""),
        api_key=mk.get("api_key", "dummy"),
        base_url=base_url,
        timeout=timeout if timeout is not None else mk.get("timeout", 60),
        max_retries=max_retries if max_retries is not None else mk.get("max_retries", 3),  # deliberately below LangChain's documented default of 6
    )
    if reasoning and mk.get("reasoning_effort"):
        kwargs["reasoning_effort"] = mk["reasoning_effort"]
    return init_chat_model(model_provider="openai", **kwargs)


def _model_provider(llm: Any) -> str:
    """Provider key deepagents resolves this model against, or "openai".

    Profile lookup matches `provider` (then `provider:model`); docs state there
    is no wildcard key, so the key must be derived from the model itself or a
    non-OpenAI/wrapped model silently loses the profile.

    Only an unusable provider falls back: register_harness_profile accepts
    arbitrary key text (verified: "vertex.ai", "openai:v1/model" register
    fine) and rejects only empty, whitespace-padded, or empty-half keys. A
    colon in the provider half would make `provider:model` malformed.
    """
    provider = ""
    try:
        from deepagents._models import get_model_provider

        provider = str(get_model_provider(llm) or "").strip()
    except Exception:
        provider = ""
    if not provider or ":" in provider:
        return "openai"
    return provider


def _model_name(llm: Any) -> str:
    name = str(getattr(llm, "model_name", "") or getattr(llm, "model", "") or "")
    return name.strip()


def _supports_shell(backend: Any) -> bool:
    """True when the backend is a deepagents sandbox (offers real `execute`)."""
    from deepagents.backends.protocol import SandboxBackendProtocol
    return isinstance(backend, SandboxBackendProtocol)


def _fs_tools(backend: Any) -> tuple[str, ...]:
    """Filesystem tool allowlist; `execute` joins only for sandbox backends."""
    return FS_TOOLS + ((SHELL_TOOL,) if _supports_shell(backend) else ())


def _register_profile(llm: Any) -> None:
    """Register the scan harness profile under the keys this model resolves to.

    Registers the provider-level key (lookup falls back to it when no exact
    `provider:model` entry matches) plus the exact model key when a name is
    available. The key is derived from the model, NOT hardcoded to "openai":
    a duck-typed or alternative-provider model must not silently run
    unhardened. Never registers an empty or malformed key — the keys module
    rejects "openai:" (an empty half) outright.

    The set here is deliberately mode-INDEPENDENT: registry entries merge
    on re-registration, so a sandbox-run later un-excluding `execute` would
    silently fail. The backend-dependent shell handling lives in the
    per-agent fs allowlist (:func:`_fs_tools`) instead. `execute` never
    exists for non-sandbox backends: :func:`_fs_tools` does not materialize
    it.
    """
    provider = _model_provider(llm)
    name = _model_name(llm)
    keys = [provider]
    # _model_name already strips its result, so `name == name.strip()` would
    # always hold; the empty check alone is the real guard.
    if name:
        keys.append(f"{provider}:{name}")
    with _reg_lock:
        from deepagents import (GeneralPurposeSubagentProfile, HarnessProfile,
                                register_harness_profile)

        for key in keys:
            if key in _registered:
                continue
            try:
                register_harness_profile(
                    key,
                    HarnessProfile(
                        excluded_tools=BASE_EXCLUDED_TOOLS,
                        general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False),
                    ),
                )
            except Exception as e:
                # Registration must never sink the scan; layer 2 (the
                # FilesystemMiddleware allowlist + deny-write rule on the
                # same instance) still applies. Say so once instead of
                # failing silently.
                print(f"[deep] harness profile skipped for key {key!r}: "
                      f"{type(e).__name__}: {e}", file=sys.stderr)
                continue
            _registered.add(key)


def _scan_middleware(backend: Any, fallbacks: list | None = None) -> list:
    """Model-independent hardening: fs allowlist + deny-write + call caps.

    The per-agent fs allowlist (read_file/ls/glob/grep, plus `execute` only
    for sandbox backends) and the deny-write rule ride the SAME
    ``FilesystemMiddleware``: deepagents merges custom middleware by ``.name``,
    so a separate ``permissions=`` kwarg on ``create_deep_agent`` would be
    dropped the moment our instance replaces the base one. Tool exclusion is
    the harness profile's job, not a middleware here.

    ``fallbacks`` is the configured provider-outage list (docs:
    ``ModelFallbackMiddleware``): when non-empty, a failed primary model call
    is retried on the next model before the stage's own fail-open chain runs.
    Empty (the default) adds nothing and changes no behavior.
    """
    from deepagents.middleware import FilesystemMiddleware
    from langchain.agents.middleware import (ModelCallLimitMiddleware,
                                             ModelFallbackMiddleware)

    permissions = [] if _supports_shell(backend) else _read_only_permissions()
    middleware = [
        FilesystemMiddleware(backend=backend, tools=list(_fs_tools(backend)),
                             _permissions=permissions),
        ModelCallLimitMiddleware(run_limit=MODEL_CALL_LIMIT),
    ]
    if fallbacks:
        middleware.append(ModelFallbackMiddleware(*fallbacks))
    return middleware


def _read_only_permissions() -> list:
    """Deny writes on every path for the built-in filesystem tools."""
    from deepagents.middleware.filesystem import FilesystemPermission

    return [FilesystemPermission(operations=["write"], paths=["/**"],
                                 mode="deny")]


def build_deep_agent(llm: Any, *, system_prompt: str, tools: list | None = None,
                     response_format: Any = None, name: str | None = None,
                     backend: Any = None, root_dir: Any = None,
                     fallbacks: list | None = None,
                     agent_registry: Any = None, agent_id: Any = None,
                     callbacks: Any = None, agent_callbacks: Any = None):
    """create_deep_agent with the scan profile applied to `llm`'s model.

    Agents run on a repo-confined backend: every filesystem tool call is
    resolve-then-check confined to the target repository. Selecting
    ``sandbox.backend: local`` disables the shell tool. Docker and sbx add
    ``execute`` and let agents share one
    sandboxed runtime with configured egress and agent-specific scratch paths
    (not per-agent access controls); see :mod:`harness.sandbox`.
    """
    from deepagents import create_deep_agent
    from harness.prompts import UNTRUSTED_CONTEXT_NOTE

    system_prompt = f"{UNTRUSTED_CONTEXT_NOTE}\n\n{system_prompt}"

    if backend is None:
        if root_dir:
            rd = Path(root_dir)
        elif os.environ.get("TARGET_REPO"):
            rd = Path(os.environ["TARGET_REPO"])
        else:
            # Never fall back to the process CWD: it is the harness repo,
            # which holds .env with the live API key. An agent rooted there
            # would have its tools pointed at our own secrets instead of
            # the target, and the sandbox upload would ship them.
            raise ValueError(
                "build_deep_agent requires root_dir or TARGET_REPO; "
                "refusing to default to the harness working directory"
            )
        from harness.config import load_config
        from harness.sandbox import resolve_backend
        try:
            # Docker mode: every agent of the run shares ONE container with
            # configured egress and agent-specific scratch paths. A
            # sandbox that cannot be built (e.g. a flag-shaped image name)
            # degrades to the repo-confined local backend, never to a crash.
            backend = resolve_backend(
                load_config(), rd.resolve(),
                agent_id=f"{name or 'agent'}-{uuid.uuid4().hex[:8]}")
        except ValueError as e:
            print(f"[deep] sandbox backend refused ({e}); "
                  "using the local backend", file=sys.stderr)
            from harness.sandbox.local_backend import RepoLocalBackend
            backend = RepoLocalBackend(repo_path=rd.resolve())

    # Profile keyed on this model's provider + this run's sandbox mode, so the
    # no-subagent / no-mutating posture holds for any model, not only
    # ChatOpenAI, and `execute` survives for sandbox backends only.
    _register_profile(llm)

    if not isinstance(llm, BaseChatModel):
        # create_deep_agent dispatches on BaseChatModel; fail with the reason
        # instead of an opaque TypeError from deep inside the graph build.
        raise TypeError(
            "build_deep_agent needs a LangChain BaseChatModel; got "
            f"{type(llm).__name__} (use make_llm or a langchain fake model)"
        )

    # A caller passes either a Pydantic schema class / JSON schema dict (the
    # bare forms) or an already-built strategy. Leave a strategy alone, but
    # DO NOT hand a bare schema to create_deep_agent: langchain would wrap it
    # in AutoStrategy, which resolves per model at build time
    # (langchain/agents/factory._supports_provider_strategy) and picks
    # ProviderStrategy for every provider-native model -- strict native
    # json_schema with NO handle_errors, so one garbled reply raises
    # StructuredOutputValidationError and kills the stage instead of being
    # retried, and which models get that treatment varies by name.
    # ToolStrategy keeps error handling identical for every model.
    if response_format is not None and isinstance(response_format, (type, dict)):
        from langchain.agents.structured_output import ToolStrategy
        response_format = ToolStrategy(response_format, handle_errors=True)

    _visibility_callbacks = []
    if callbacks:
        _visibility_callbacks.extend(list(callbacks) if not isinstance(callbacks, (list, tuple))
                                    else list(callbacks))
    if agent_callbacks:
        _visa = agent_callbacks
        _visibility_callbacks.extend(list(_visa) if not isinstance(_visa, (list, tuple)) else list(_visa))
    if agent_registry is not None and (agent_id is not None or name):
        _visibility_callbacks.append(AgentVisibilityCallback(
            agent_registry, agent_id if agent_id is not None else name))

    kwargs: dict[str, Any] = dict(
        model=llm, tools=list(tools or []), system_prompt=system_prompt,
        middleware=_scan_middleware(backend, fallbacks),
    )
    # backend is never None here: a None argument is resolved (or, on the
    # sandbox resolver's refusal, falls back to RepoLocalBackend) in the
    # `if backend is None:` block above, so the value is always concrete.
    kwargs["backend"] = backend
    if response_format is not None:
        kwargs["response_format"] = response_format
    if name:
        kwargs["name"] = name
    agent = create_deep_agent(**kwargs)
    try:
        agent._visibility_callbacks = list(_visibility_callbacks)
    except Exception:
        pass
    return agent


def message_text(msg: Any, *, sep: str = " ") -> str:
    """Reply text from an AIMessage (or anything with .content).

    Prefers langchain-core's documented ``.text`` property (typed text blocks
    joined without a separator). Duck-typed fakes without it (tests) fall
    back to a manual join with ``sep``.
    """
    text = getattr(msg, "text", None)
    if isinstance(text, str):
        return text
    try:
        content = getattr(msg, "content", "") or ""
        if isinstance(content, list):
            # LangChain's .text joins only typed ``text`` blocks without a
            # separator; duck-typed fakes (and tests) join their untyped
            # blocks with ``sep`` so multi-part messages stay readable.
            typed = any(isinstance(b, dict) and b.get("type") == "text"
                        for b in content)
            joiner = "" if typed else sep
            content = joiner.join(
                str(b.get("text", b)) if isinstance(b, dict) else str(b)
                for b in content)
        return str(content)
    except Exception:
        return ""


def final_text(result: Any, *, sep: str = " ") -> str:
    """Final assistant message text of a result ('' if none).

    Scans backwards and skips tool results: a structured-output run ends on a
    ToolMessage whose content is a repr string ("Returning structured
    response: ..."), which is neither prose nor JSON (langchain/agents/
    factory returns it as the last message).
    """
    try:
        msgs = result.get("messages") if isinstance(result, dict) else None
        if msgs:
            for m in reversed(msgs):
                if getattr(m, "type", "") == "tool":
                    continue
                text = message_text(m, sep=sep)
                if text.strip():
                    return text
    except Exception:
        pass
    return ""


def _fallback_models(mk: dict | None, *, timeout: int | None,
                     max_retries: int | None, reasoning: bool) -> list:
    """ChatOpenAI fallbacks for the configured comma-separated model list.

    Names come from ``mk["fallback_models"]`` (config ``fallback_models``,
    threaded through ``get_model_kwargs``). Each fallback reuses the primary's
    base_url/api_key, so only the model id differs. A name that fails to build
    is skipped rather than sinking the stage.
    """
    raw = (mk or {}).get("fallback_models")
    if not raw:
        return []
    items = raw if isinstance(raw, (list, tuple)) else str(raw).split(",")
    primary = str((mk or {}).get("model", "") or "").strip()
    out: list = []
    seen: set[str] = set()
    for item in items:
        name = str(item or "").strip()
        if not name or name == primary or name in seen:
            continue
        seen.add(name)
        try:
            out.append(make_llm({**(mk or {}), "model": name},
                                timeout=timeout, max_retries=max_retries,
                                reasoning=reasoning))
        except Exception:
            continue
    return out


def run_structured(mk: dict | None, model: Any, system: str, human: str, *,
                   tools: list | None = None, timeout: int | None = None,
                   max_retries: int | None = None, recursion_limit: int = 1000,
                   name: str | None = None, reasoning: bool = True,
                   backend: Any = None, root_dir: Any = None,
                   control: Any = None,
                   agent_registry: Any = None, agent_id: Any = None,
                   agent_callbacks: Any = None, callbacks: Any = None,
                   ) -> tuple[Any, str, Any]:
    """Run one deep agent to a structured answer.

    Returns (parsed, raw_text, result). `parsed` is the validated schema
    instance from the agent's structured_response (None when the backend
    refused the schema); `raw_text` is the final assistant text for the
    caller's own fallback parser; `result` is the full agent state (tool-use
    inspection). Transport failures raise so callers keep their fail-open
    chains.

    `model` is passed through build_deep_agent, which wraps a bare schema in
    ToolStrategy(handle_errors=True): a malformed reply is re-prompted by the
    strategy rather than aborting the stage, uniformly across models.

    Ephemeral by design: no checkpointer and no thread ids — nothing is
    persisted, and a drained run's work is lost (the caller's fail-open
    covers it). The recursion limit is a backstop only; agent-turn control is
    the ModelCallLimit middleware in build_deep_agent.
    """
    llm = make_llm(mk, timeout=timeout, max_retries=max_retries, reasoning=reasoning)
    fallbacks = _fallback_models(mk, timeout=timeout, max_retries=max_retries,
                                 reasoning=reasoning)
    _cb_list = []
    if callbacks:
        _cb_list.extend(list(callbacks) if not isinstance(callbacks, (list, tuple)) else list(callbacks))
    if agent_callbacks:
        _cb_list.extend(list(agent_callbacks) if not isinstance(agent_callbacks, (list, tuple)) else list(agent_callbacks))
    _aid = agent_id if agent_id is not None else name
    if agent_registry is not None:
        _cb_list.append(AgentVisibilityCallback(agent_registry, _aid))
    agent = build_deep_agent(llm, system_prompt=system, tools=tools,
                             response_format=model, name=name,
                             backend=backend, root_dir=root_dir,
                             fallbacks=fallbacks,
                             agent_registry=None, agent_id=None,
                             callbacks=_cb_list)
    kwargs: dict[str, Any] = {"config": {"recursion_limit": recursion_limit}}
    if _cb_list:
        kwargs["config"]["callbacks"] = list(_cb_list)
    if control is not None:
        kwargs["control"] = control
    result = agent.invoke({"messages": [{"role": "user", "content": human}]},
                          **kwargs)
    parsed = result.get("structured_response") if isinstance(result, dict) else None
    return parsed, final_text(result), result

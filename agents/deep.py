from __future__ import annotations

import os
import re
import sys
import threading
from pathlib import Path
from typing import Any

from langchain_core.exceptions import (ModelAuthenticationError, ModelInvalidRequestError, ModelNotFoundError, ModelPermissionDeniedError)
from langchain_core.language_models.chat_models import BaseChatModel

from harness.config import as_bool, get_default_config, resolve_recursion_limit

try:
    from harness import observability as _obs
except Exception:  # observability module unavailable → tracing disabled (fail-open)
    _obs = None

BASE_EXCLUDED_TOOLS = frozenset({
    "delete", "task"
})
SHELL_TOOL = "execute"
FS_READ_TOOLS = ("read_file", "ls", "glob", "grep")
FS_WRITE_TOOLS = ("write_file", "edit_file")
FS_TOOLS = FS_READ_TOOLS
# FilesystemMiddleware rejects unscoped permission rules on execution-capable
# backends. model_call_limit is the real budget: each agent run may make at most
# harness/config/default.yaml's model_call_limit model calls.
MODEL_CALL_LIMIT = int(get_default_config("model_call_limit"))
DEFAULT_RETRY_SLEEP_CAP = float(get_default_config("retry_sleep_cap"))


def _model_call_limit() -> int:
    """Runtime model-call budget: process env > .env > YAML default."""
    from harness.config import config_default

    try:
        return max(1, int(config_default("model_call_limit")))
    except (TypeError, ValueError):
        return MODEL_CALL_LIMIT

# Scanner skill docs are served the deepagents way: routed into the agent's
# own backend (no write tool exists for the agent, and a route-scoped deny
# rule backs it), where SkillsMiddleware indexes each SKILL.md into the
# prompt and `read_file` opens the full doc on demand. The scan image bakes
# the same docs at SKILLS_ROUTE (Dockerfile COPY), so in-container reads via
# `execute` agree with the routed file tools.
SKILLS_ROUTE = "/opt/harness-skills/"
SKILLS_SOURCES = [(SKILLS_ROUTE, "Scanner")]
SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"
SCRATCH_ROUTE = "/.harness/scratch/"

# Fail-loud operator-config errors (never a needs-review verdict); ContextOverflowError deliberately excluded (oversized unit fails open).
CONFIG_ERRORS = (ModelAuthenticationError, ModelPermissionDeniedError,
                 ModelInvalidRequestError, ModelNotFoundError)

# Harness bugs must bubble up (never fail open into needs-review); excludes ValueError (pydantic) and RuntimeError (transport stand-in).
PROGRAMMING_ERRORS = (AttributeError, NameError, UnboundLocalError, TypeError,
                      IndexError, KeyError, AssertionError,
                      NotImplementedError, SyntaxError, re.error)


_registered: set[str] = set()
_reg_lock = threading.Lock()


def is_config_error(exc: BaseException) -> bool:
    return isinstance(exc, CONFIG_ERRORS)


def is_programming_error(exc: BaseException) -> bool:
    return isinstance(exc, PROGRAMMING_ERRORS)


def is_fatal_error(exc: BaseException) -> bool:
    return is_config_error(exc) or is_programming_error(exc)


def sanitize_model_kwargs(model_kwargs: dict | None) -> dict:
    mk = dict(model_kwargs or {})
    # "dummy" is this function's offline placeholder (tests/keyless runs): only a real key must fail loudly on a missing model.
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
             max_retries: int | None = None) -> Any:
    from langchain.chat_models import init_chat_model

    from harness.config import (config_default, get_harness_connect_timeout,
                                resolve_call_retries, resolve_call_timeout)

    mk = sanitize_model_kwargs(mk)
    base_url = (mk.get("base_url", "") or "").removesuffix("/") or None
    kwargs: dict[str, Any] = dict(
        model=mk.get("model", ""),
        api_key=mk.get("api_key", "dummy"),
        base_url=base_url,
        timeout=timeout if timeout is not None else resolve_call_timeout(mk),
        max_retries=(max_retries if max_retries is not None
                     else resolve_call_retries(mk)),
    )
    if mk.get("reasoning_effort"):
        kwargs["reasoning_effort"] = str(mk["reasoning_effort"]).strip()
    t = kwargs.get("timeout")
    if isinstance(t, (int, float)) and not isinstance(t, bool):
        t = max(1.0, float(t))
        connect = float(get_harness_connect_timeout())
        kwargs["timeout"] = (connect, t, t, t)

    try:
        from openai import _base_client as _oai_base
        try:
            _cap = float(config_default("retry_sleep_cap"))
        except (TypeError, ValueError):
            _cap = DEFAULT_RETRY_SLEEP_CAP
        _oai_base.MAX_RETRY_DELAY = _cap
        _oai_base.MAX_RETRY_AFTER_DELAY = _cap

        if not getattr(_oai_base.BaseClient, "_resilient_429_patched", False):
            _orig_should_retry = _oai_base.BaseClient._should_retry

            def _resilient_should_retry(self, response):
                if response.status_code == 429:
                    return True
                return _orig_should_retry(self, response)

            _oai_base.BaseClient._should_retry = _resilient_should_retry
            _oai_base.BaseClient._resilient_429_patched = True

        from openai.resources.chat.completions import AsyncCompletions, Completions

        if not getattr(Completions, "_universal_tool_choice_patched", False):
            _orig_comp_create = Completions.create

            def _universal_comp_create(self, *args, **kwargs):
                tc = kwargs.get("tool_choice")
                if tc is not None and tc != "auto":
                    kwargs["tool_choice"] = "auto"
                return _orig_comp_create(self, *args, **kwargs)

            Completions.create = _universal_comp_create
            Completions._universal_tool_choice_patched = True

        if not getattr(AsyncCompletions, "_universal_tool_choice_patched", False):
            _orig_async_comp_create = AsyncCompletions.create

            async def _universal_async_comp_create(self, *args, **kwargs):
                tc = kwargs.get("tool_choice")
                if tc is not None and tc != "auto":
                    kwargs["tool_choice"] = "auto"
                return await _orig_async_comp_create(self, *args, **kwargs)

            AsyncCompletions.create = _universal_async_comp_create
            AsyncCompletions._universal_tool_choice_patched = True
    except (ImportError, AttributeError, TypeError, ValueError):
        pass

    raw = mk.get("model_profile")
    if isinstance(raw, dict):
        profile = {}
        val = raw.get("max_input_tokens")
        if val not in (None, ""):
            try:
                profile["max_input_tokens"] = int(val)
            except (TypeError, ValueError):
                pass
        val_so = raw.get("structured_output")
        if val_so not in (None, ""):
            profile["structured_output"] = as_bool(val_so)
        if profile:
            kwargs["profile"] = profile

    llm = init_chat_model(model_provider="openai", **kwargs)
    return llm


def _model_provider(llm: Any) -> str:
    provider = ""
    try:
        from deepagents._models import get_model_provider

        provider = str(get_model_provider(llm) or "").strip()
    except Exception:
        provider = ""
    if not provider or ":" in provider:
        return "openai"
    return provider


def _supports_shell(backend: Any) -> bool:
    from deepagents.backends import CompositeBackend
    from deepagents.backends.protocol import SandboxBackendProtocol
    while isinstance(backend, CompositeBackend):
        # Routed backends (scanner skills) delegate `execute` to their default.
        backend = backend.default
    return isinstance(backend, SandboxBackendProtocol)


def _fs_tools(backend: Any, *, scratchpad: bool = False) -> tuple[str, ...]:
    tools = list(FS_READ_TOOLS)
    if scratchpad:
        tools.extend(FS_WRITE_TOOLS)
    if _supports_shell(backend):
        tools.append(SHELL_TOOL)
    return tuple(tools)


_skills_shadow_warned = False


def _with_skills_route(backend: Any) -> Any:
    # Skills live outside the repo, where the repo-confined file tools cannot
    # reach them: route harness/skills into the agent's own backend so
    # SkillsMiddleware and `read_file` can serve the docs.
    global _skills_shadow_warned
    repo = getattr(backend, "repo_path", None)
    shadow = Path(repo) / SKILLS_ROUTE.lstrip("/") if repo else None
    if (shadow is not None and not _skills_shadow_warned
            and (shadow.exists() or shadow.is_symlink())):
        _skills_shadow_warned = True
        print(f"[deep] warning: {shadow} exists in the target repo and is "
              "shadowed by the skills route (read_file/ls/grep serve the "
              "harness skill docs there; glob still lists the repo files)",
              file=sys.stderr)
    from deepagents.backends import CompositeBackend, FilesystemBackend

    routes = {SKILLS_ROUTE: FilesystemBackend(root_dir=str(SKILLS_DIR),
                                              virtual_mode=True)}
    if isinstance(backend, CompositeBackend):
        routes.update(backend.routes)
        return CompositeBackend(default=backend.default, routes=routes)
    return CompositeBackend(default=backend, routes=routes)


def _resolve_scratch_dir(root_dir: Any = None, agent_name: str | None = None,
                         run_id: str | None = None) -> Path | None:
    """Resolve a persistent host directory for agent scratchpad files (under .harness/<run_id>/scratch/)."""
    env_dir = os.environ.get("HARNESS_SCRATCH_DIR")
    if env_dir:
        base = Path(env_dir)
    else:
        repo_root = root_dir or os.environ.get("TARGET_REPO")
        if not repo_root:
            return None
        rid = (
            run_id
            or os.environ.get("HARNESS_RUN_ID")
            or os.environ.get("RUN_ID")
            or "latest"
        )
        safe_rid = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in str(rid).strip()) or "latest"
        base = Path(repo_root) / ".harness" / safe_rid / "scratch"

    safe_agent = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in str(agent_name or "").strip())
    p = base / safe_agent if safe_agent else base
    try:
        p.mkdir(parents=True, exist_ok=True)
        return p
    except OSError:
        return None


def _with_scratch_route(backend: Any, scratch_dir: Path | str | None = None) -> Any:
    from deepagents.backends import CompositeBackend, FilesystemBackend, StateBackend

    if scratch_dir is not None:
        try:
            p = Path(scratch_dir)
            p.mkdir(parents=True, exist_ok=True)
            scratch_backend: Any = FilesystemBackend(root_dir=str(p), virtual_mode=True)
        except Exception:
            scratch_backend = StateBackend()
    else:
        scratch_backend = StateBackend()

    routes = {SCRATCH_ROUTE: scratch_backend}
    if isinstance(backend, CompositeBackend):
        routes.update(backend.routes)
        return CompositeBackend(default=backend.default, routes=routes)
    return CompositeBackend(default=backend, routes=routes)


def _register_profile(llm: Any) -> None:
    provider = _model_provider(llm)
    if provider in _registered:
        return
    with _reg_lock:
        from deepagents import (GeneralPurposeSubagentProfile, HarnessProfile,
                                register_harness_profile)
        try:
            register_harness_profile(
                provider,
                HarnessProfile(
                    excluded_tools=BASE_EXCLUDED_TOOLS,
                    general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False),
                ),
            )
        except Exception as e:
            print(f"[deep] harness profile skipped for key {provider!r}: "
                  f"{type(e).__name__}: {e}", file=sys.stderr)
            return
        _registered.add(provider)


def _tool_error_message(exc: Exception, request: Any) -> str | None:
    from langchain_core.tools import ToolException

    if not isinstance(exc, (ToolException, ValueError)):
        return None
    try:
        name = str((request.tool_call or {}).get("name") or "tool")
    except Exception:
        name = "tool"
    return (f"`{name}` failed: {type(exc).__name__}. Fix the arguments "
            "and retry.")


def _scan_middleware(backend: Any, *, scratchpad: bool = False) -> list:
    from deepagents.middleware import FilesystemMiddleware
    from langchain.agents.middleware import (ModelCallLimitMiddleware,
                                             ToolErrorMiddleware,
                                             ToolRetryMiddleware)

    permissions = (_sandbox_permissions(backend, scratchpad=scratchpad)
                   if _supports_shell(backend)
                   else _local_permissions(scratchpad=scratchpad))
    middleware = [
        FilesystemMiddleware(backend=backend,
                             tools=list(_fs_tools(backend, scratchpad=scratchpad)),
                             _permissions=permissions),
        ModelCallLimitMiddleware(run_limit=_model_call_limit()),
        ToolErrorMiddleware(on_error=_tool_error_message),
        ToolRetryMiddleware(on_failure="error"),
    ]
    return middleware


def _local_permissions(*, scratchpad: bool = False) -> list:
    from deepagents.middleware.filesystem import FilesystemPermission

    # `/.*` and `/.*/**` are load-bearing: globstar does not cross dot
    # segments (`.env`, `.git/config`), and the permissive default allows
    # any write no rule matches (first-match-wins; docs#permissions).
    deny = FilesystemPermission(operations=["write"],
                                paths=["/**", "/.*", "/.*/**"],
                                mode="deny")
    if scratchpad:
        return [FilesystemPermission(operations=["write"],
                                     paths=[f"{SCRATCH_ROUTE}**"],
                                     mode="allow"), deny]
    return [deny]


def _sandbox_permissions(backend: Any, *, scratchpad: bool = False) -> list:
    # On execution-capable backends, DeepAgents requires all permission rules
    # to be scoped strictly to composite route prefixes. (No catch-all by
    # design: permissions don't govern `execute` backends — container
    # isolation is the write boundary.)
    from deepagents.backends import CompositeBackend
    from deepagents.middleware.filesystem import FilesystemPermission

    perms = []
    if isinstance(backend, CompositeBackend):
        if SKILLS_ROUTE in backend.routes:
            perms.append(FilesystemPermission(operations=["write"],
                                              paths=[f"{SKILLS_ROUTE}**"],
                                              mode="deny"))
        if scratchpad and SCRATCH_ROUTE in backend.routes:
            perms.append(FilesystemPermission(operations=["write"],
                                              paths=[f"{SCRATCH_ROUTE}**"],
                                              mode="allow"))
    return perms


def build_deep_agent(llm: Any, *, system_prompt: str, tools: list | None = None,
                     response_format: Any = None, name: str | None = None,
                     backend: Any = None, root_dir: Any = None,
                     scratchpad: bool = False):
    from deepagents import create_deep_agent
    from harness.prompts import UNTRUSTED_CONTEXT_NOTE

    system_prompt = f"{UNTRUSTED_CONTEXT_NOTE}\n\n{system_prompt}"

    target_repo = None
    if backend is None:
        if root_dir:
            rd = Path(root_dir)
        elif os.environ.get("TARGET_REPO"):
            rd = Path(os.environ["TARGET_REPO"])
        else:
            # Never fall back to the process CWD: the harness repo holds .env with the live API key.
            raise ValueError(
                "build_deep_agent requires root_dir or TARGET_REPO; "
                "refusing to default to the harness working directory"
            )
        target_repo = rd
        from harness.config import load_config_safe
        from harness.sandbox import _acquire_backend
        from harness.sandbox.local_backend import RepoLocalBackend

        cfg, cfg_err = load_config_safe()
        if cfg_err is not None:
            # Config failure is operator-facing: loud, then the same repo-confined
            # degrade as an unbuildable sandbox (never a silent {} resolve).
            print(f"[deep] config load failed ({cfg_err}); "
                  "using the local backend", file=sys.stderr)
            backend = RepoLocalBackend(repo_path=rd.resolve())
        else:
            # All agents of the run share ONE container; unbuildable sandbox degrades to the repo-confined local backend.
            backend = _acquire_backend(
                cfg, rd.resolve(), label=name or "agent", fallback="local",
                refused_msg="[deep] sandbox backend refused ({exc}); "
                            "using the local backend")
    else:
        if root_dir:
            target_repo = Path(root_dir)
        elif os.environ.get("TARGET_REPO"):
            target_repo = Path(os.environ["TARGET_REPO"])
        elif hasattr(backend, "repo_path"):
            target_repo = Path(backend.repo_path)
        else:
            target_repo = Path(".")

    # Scanner skill docs ride the deepagents skills mechanism (index injected
    # by SkillsMiddleware, full SKILL.md on demand via read_file); local mode
    # keeps neither shell nor skills.
    skills: list | None = None
    if _supports_shell(backend):
        skills = list(SKILLS_SOURCES)
        backend = _with_skills_route(backend)

    if scratchpad:
        scratch_dir = _resolve_scratch_dir(target_repo, name)
        backend = _with_scratch_route(backend, scratch_dir=scratch_dir)

    # Profile keyed on this model's provider: the no-subagent/no-mutating posture must hold for any model.
    _register_profile(llm)

    if not isinstance(llm, BaseChatModel):
        raise TypeError(
            "build_deep_agent needs a LangChain BaseChatModel; got "
            f"{type(llm).__name__} (use make_llm or a langchain fake model)"
        )

    # A bare schema becomes AutoStrategy->ProviderStrategy (strict json_schema, no handle_errors): one garbled reply kills the stage; ToolStrategy is uniform.
    if response_format is not None and isinstance(response_format, (type, dict)):
        from langchain.agents.structured_output import ToolStrategy
        response_format = ToolStrategy(response_format, handle_errors=True)

    # Sort tools deterministically by name to guarantee identical schema order across LLM calls for prefix caching
    sorted_tools = sorted(list(tools or []),
                          key=lambda t: str(getattr(t, "name", None) or getattr(t, "__name__", "") or t))
    kwargs: dict[str, Any] = dict(
        model=llm, tools=sorted_tools, system_prompt=system_prompt,
        middleware=_scan_middleware(backend, scratchpad=scratchpad),
    )
    kwargs["backend"] = backend
    if skills:
        kwargs["skills"] = skills
    if response_format is not None:
        kwargs["response_format"] = response_format
    if name:
        kwargs["name"] = name
    return create_deep_agent(**kwargs)


def message_text(msg: Any, *, sep: str = " ") -> str:
    text = getattr(msg, "text", None)
    if isinstance(text, str):
        return text
    try:
        content = getattr(msg, "content", "") or ""
        if isinstance(content, list):
            # LangChain .text joins typed text blocks with no separator; untyped blocks (fakes, tests) join with sep.
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


def run_structured(mk: dict | None, model: Any, system: str, human: str, *,
                   tools: list | None = None, timeout: int | None = None,
                   max_retries: int | None = None,
                   recursion_limit: int | None = None,
                   name: str | None = None,
                   backend: Any = None, root_dir: Any = None,
                   trace_suffix: str | None = None,
                   meta_extra: dict | None = None,
                   agent: Any = None,
                   scratchpad: bool = False,
                   ) -> tuple[Any, str]:
    if agent is None:
        agent = build_deep_agent(
            make_llm(mk, timeout=timeout, max_retries=max_retries),
            system_prompt=system, tools=tools,
            response_format=model, name=name,
            backend=backend, root_dir=root_dir,
            scratchpad=scratchpad)
    if recursion_limit is None:
        recursion_limit = resolve_recursion_limit()
    config: dict[str, Any] = {"recursion_limit": recursion_limit}
    if _obs is not None:
        _obs.run_config(config, name=name, extra=meta_extra,
                        trace_suffix=trace_suffix)
    result = agent.invoke({"messages": [{"role": "user", "content": human}]},
                          config=config)
    parsed = result.get("structured_response") if isinstance(result, dict) else None
    return parsed, final_text(result)


def run_structured_batch(mk: dict | None, model: Any, system: str,
                         humans: list[str], *, timeout: int | None = None,
                         max_retries: int | None = None, name: str | None = None,
                         max_concurrency: int | None = None,
                         meta_extra: dict | None = None) -> list[Any]:
    """Batched one-shot structured output : one LLM call per
    input;"""
    llm = make_llm(mk, timeout=timeout, max_retries=max_retries)
    structured = llm.with_structured_output(model, method="function_calling")
    msgs = [[{"role": "system", "content": system},
             {"role": "user", "content": h}] for h in humans]
    config: dict[str, Any] = (
        {"max_concurrency": max_concurrency} if max_concurrency is not None else {})
    if _obs is not None:
        _obs.run_config(config, name=name, extra=meta_extra)
    if not msgs:
        return []
    results = structured.batch(msgs, config=config, return_exceptions=True)
    return [r if r is not None
            else RuntimeError("structured reply contained no tool call")
            for r in results]

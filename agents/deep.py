from __future__ import annotations

import os
import sys
import threading
import uuid
from pathlib import Path
from typing import Any

from langchain_core.exceptions import (ModelAuthenticationError, ModelInvalidRequestError, ModelNotFoundError, ModelPermissionDeniedError)
from langchain_core.language_models.chat_models import BaseChatModel

try:
    from harness import observability as _obs
except Exception:  # observability module unavailable → tracing disabled (fail-open)
    _obs = None

# Never-granted tools: write/edit/delete + subagent recursion (`task`); `execute` only for sandbox backends.
BASE_EXCLUDED_TOOLS = frozenset({
    "delete", "write_file", "edit_file", "task"
})
SHELL_TOOL = "execute"
# The only built-in filesystem tools a scan agent needs (allowlist, layer 2).
FS_TOOLS = ("read_file", "ls", "glob", "grep")
# FilesystemMiddleware rejects unscoped permission rules on execution-capable backends; MODEL_CALL_LIMIT caps turns; recursion_limit: run_structured.
MODEL_CALL_LIMIT = 100

# Scanner skill docs are served the deepagents way: routed into the agent's
# own backend (no write tool exists for the agent, and a route-scoped deny
# rule backs it), where SkillsMiddleware indexes each SKILL.md into the
# prompt and `read_file` opens the full doc on demand. The scan image bakes
# the same docs at SKILLS_ROUTE (Dockerfile COPY), so in-container reads via
# `execute` agree with the routed file tools.
SKILLS_ROUTE = "/opt/harness-skills/"
SKILLS_SOURCES = [(SKILLS_ROUTE, "Scanner")]
SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"

# Fail-loud operator-config errors (never a needs-review verdict); ContextOverflowError deliberately excluded (oversized unit fails open).
CONFIG_ERRORS = (ModelAuthenticationError, ModelPermissionDeniedError,
                 ModelInvalidRequestError, ModelNotFoundError)

# Harness bugs must bubble up (never fail open into needs-review); excludes ValueError (pydantic) and RuntimeError (transport stand-in).
PROGRAMMING_ERRORS = (AttributeError, NameError, UnboundLocalError, TypeError,
                      IndexError, KeyError, AssertionError,
                      NotImplementedError, SyntaxError)


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


def _cap_openai_retry_delays(max_delay: float = 5.0) -> None:
    try:
        import openai._base_client as _oac
    except Exception:  # pragma: no cover - ships with langchain-openai
        return
    _oac.MAX_RETRY_DELAY = max_delay
    _oac.MAX_RETRY_AFTER_DELAY = max_delay


def _apply_model_profile(llm: Any, mk: dict) -> Any:
    raw = mk.get("model_profile")
    if not isinstance(raw, dict):
        return llm
    updates: dict[str, Any] = {}
    for key in ("max_input_tokens", "structured_output"):
        val = raw.get(key)
        if val in (None, ""):
            continue
        if key == "max_input_tokens":
            try:
                updates[key] = int(val)
            except (TypeError, ValueError):
                continue
        else:
            updates[key] = str(val).strip().lower() in ("1", "true",
                                                        "yes", "on")
    if not updates:
        return llm
    try:
        profile = dict(getattr(llm, "profile", {}) or {})
        profile.update(updates)
        return llm.model_copy(update={"profile": profile})
    except (TypeError, ValueError):
        return llm


def make_llm(mk: dict | None, *, timeout: int | None = None,
             max_retries: int | None = None) -> Any:
    from langchain.chat_models import init_chat_model

    mk = sanitize_model_kwargs(mk)
    base_url = (mk.get("base_url", "") or "").removesuffix("/") or None
    kwargs: dict[str, Any] = dict(
        model=mk.get("model", ""),
        api_key=mk.get("api_key", "dummy"),
        base_url=base_url,
        timeout=timeout if timeout is not None else mk.get("timeout", 60),
        max_retries=max_retries if max_retries is not None else mk.get("max_retries", 5),
    )
    _cap_openai_retry_delays()

    llm = init_chat_model(model_provider="openai", **kwargs)
    return _apply_model_profile(llm, mk)


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


def _fs_tools(backend: Any) -> tuple[str, ...]:
    return FS_TOOLS + ((SHELL_TOOL,) if _supports_shell(backend) else ())


_skills_shadow_warned = False


def _with_skills_route(backend: Any) -> Any:
    # Skills live outside the repo, where the repo-confined file tools cannot
    # reach them: route harness/skills into the agent's own backend so
    # SkillsMiddleware and `read_file` can serve the docs. The agent cannot
    # write it -- no write tool exists, and `_sandbox_permissions` backstops
    # the route with a scoped deny rule.
    global _skills_shadow_warned
    repo = getattr(backend, "repo_path", None)
    shadow = Path(repo) / SKILLS_ROUTE.lstrip("/") if repo else None
    if (shadow is not None and not _skills_shadow_warned
            and (shadow.exists() or shadow.is_symlink())):
        # A repo owning this path would be shadowed for read_file/ls/grep;
        # surface it once rather than silently mis-serving the harness docs.
        _skills_shadow_warned = True
        print(f"[deep] warning: {shadow} exists in the target repo and is "
              "shadowed by the skills route (read_file/ls/grep serve the "
              "harness skill docs there; glob still lists the repo files)",
              file=sys.stderr)
    from deepagents.backends import CompositeBackend, FilesystemBackend

    return CompositeBackend(
        default=backend,
        routes={SKILLS_ROUTE: FilesystemBackend(root_dir=str(SKILLS_DIR),
                                                virtual_mode=True)},
    )


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


def _retryable_model_error(exc: BaseException) -> bool:
    return bool(getattr(exc, "is_retryable", False))


def _scan_middleware(backend: Any) -> list:
    # fs allowlist + deny-write ride ONE FilesystemMiddleware (deepagents merges by .name); on_failure="error" so exhausted retries still raise.
    from deepagents.middleware import FilesystemMiddleware
    from langchain.agents.middleware import (ModelCallLimitMiddleware,
                                             ModelRetryMiddleware,
                                             ToolErrorMiddleware,
                                             ToolRetryMiddleware)

    permissions = (_sandbox_permissions(backend) if _supports_shell(backend)
                   else _read_only_permissions())
    middleware = [
        FilesystemMiddleware(backend=backend, tools=list(_fs_tools(backend)),
                             _permissions=permissions),
        ModelCallLimitMiddleware(run_limit=MODEL_CALL_LIMIT),
        ModelRetryMiddleware(on_failure="error",
                             retry_on=_retryable_model_error),
        # Retry inner, error handler outer: the handler sees only exhausted retries.
        ToolRetryMiddleware(on_failure="error"),
        ToolErrorMiddleware(on_error=_tool_error_message),
    ]
    return middleware


def _read_only_permissions() -> list:
    from deepagents.middleware.filesystem import FilesystemPermission

    return [FilesystemPermission(operations=["write"], paths=["/**"],
                                 mode="deny")]


def _sandbox_permissions(backend: Any) -> list:
    # Unscoped deny rules are rejected on execution-capable backends; a rule
    # scoped to the skills route is accepted (deepagents allows permissions
    # whose paths stay inside composite routes) and keeps that host directory
    # write-proof even if a write tool ever joins the allowlist.
    from deepagents.backends import CompositeBackend
    from deepagents.middleware.filesystem import FilesystemPermission

    if isinstance(backend, CompositeBackend) and SKILLS_ROUTE in backend.routes:
        return [FilesystemPermission(operations=["write"],
                                     paths=[f"{SKILLS_ROUTE}**"],
                                     mode="deny")]
    return []


def build_deep_agent(llm: Any, *, system_prompt: str, tools: list | None = None,
                     response_format: Any = None, name: str | None = None,
                     backend: Any = None, root_dir: Any = None):
    from deepagents import create_deep_agent
    from harness.prompts import UNTRUSTED_CONTEXT_NOTE

    system_prompt = f"{UNTRUSTED_CONTEXT_NOTE}\n\n{system_prompt}"

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
        from harness.config import load_config_safe
        from harness.sandbox import resolve_backend
        cfg, cfg_err = load_config_safe()
        backend_ready = False
        if cfg_err is not None:
            # Config failure is operator-facing: loud, then the same repo-confined
            # degrade as an unbuildable sandbox (never a silent {} resolve).
            print(f"[deep] config load failed ({cfg_err}); "
                  "using the local backend", file=sys.stderr)
        else:
            try:
                # All agents of the run share ONE container; unbuildable sandbox degrades to the repo-confined local backend.
                backend = resolve_backend(
                    cfg, rd.resolve(),
                    agent_id=f"{name or 'agent'}-{uuid.uuid4().hex[:8]}")
                backend_ready = True
            except Exception as e:
                if is_fatal_error(e):
                    raise
                print(f"[deep] sandbox backend refused ({e}); "
                      "using the local backend", file=sys.stderr)
        if not backend_ready:
            from harness.sandbox.local_backend import RepoLocalBackend
            backend = RepoLocalBackend(repo_path=rd.resolve())

    # Scanner skill docs ride the deepagents skills mechanism (index injected
    # by SkillsMiddleware, full SKILL.md on demand via read_file); local mode
    # keeps neither shell nor skills.
    skills: list | None = None
    if _supports_shell(backend):
        skills = list(SKILLS_SOURCES)
        backend = _with_skills_route(backend)

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

    kwargs: dict[str, Any] = dict(
        model=llm, tools=list(tools or []), system_prompt=system_prompt,
        middleware=_scan_middleware(backend),
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
                   max_retries: int | None = None, recursion_limit: int = 1000,
                   name: str | None = None,
                   backend: Any = None, root_dir: Any = None,
                   trace_suffix: str | None = None,
                   meta_extra: dict | None = None,
                   ) -> tuple[Any, str, Any]:
    llm = make_llm(mk, timeout=timeout, max_retries=max_retries)
    _cb_list = []
    if _obs is not None:
        _handler = _obs.get_handler()
        if _handler is not None:
            _cb_list.append(_handler)
    agent = build_deep_agent(llm, system_prompt=system, tools=tools,
                             response_format=model, name=name,
                             backend=backend, root_dir=root_dir)
    kwargs: dict[str, Any] = {"config": {"recursion_limit": recursion_limit}}
    if _cb_list:
        kwargs["config"]["callbacks"] = list(_cb_list)
    if _obs is not None and name:
        _role = _obs.stable_role(name)
        _meta = (_obs.scan_metadata(stage=_role, role=_role, extra=meta_extra)
                 if _role else {})
        if _meta:
            kwargs["config"]["metadata"] = _meta
            _scope = _obs.scope_path(trace_suffix)
            kwargs["config"]["run_name"] = (
                f"{_role}:{_scope}" if _scope else _role)
    result = agent.invoke({"messages": [{"role": "user", "content": human}]},
                          **kwargs)
    parsed = result.get("structured_response") if isinstance(result, dict) else None
    return parsed, final_text(result), result

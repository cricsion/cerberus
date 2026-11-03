"""Shared chat-model fakes for the agent-behavior test files.

``GenericFakeChatModel.bind_tools`` raises, so any test that drives a
deepagents agent through a tool-bound LLM needs a hand-rolled minimal fake;
those lived as parallel copies in test_langchain_hardening (_StaticLLM) and
test_skills (_CaptureLLM). One class with an optional capture hook replaces
them: pass ``capture=<list>`` and every prompt the agent sends lands in it.
"""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult


class ToolCallableLLM(BaseChatModel):
    """Minimal tool-callable fake: GenericFakeChatModel.bind_tools raises."""

    _capture: object = None

    def __init__(self, *, capture: list | None = None):
        super().__init__()
        object.__setattr__(self, "_capture", capture)

    @property
    def _llm_type(self) -> str:
        return "toolcallablefake"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        if self._capture is not None:
            self._capture.append(list(messages))
        return ChatResult(
            generations=[ChatGeneration(message=AIMessage(content="ok"))])

    def bind_tools(self, tools, **kwargs):
        return self

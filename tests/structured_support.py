"""Shared seams for the structured-output rescue test pair.

test_structured_rescue.py (contract) and test_structured_rescue_adversarial.py
(hostile inputs) pin the same rescue layer against the same fabricated message
shapes; the stand-ins they replay those shapes with live here once.

Fabricated result dicts only — no LLM calls and no CLI involved, mirroring the
``codegraph_support`` bare-import convention.
"""

from __future__ import annotations


class Msg:
    """Minimal message stand-in: attribute-style .tool_calls / .text / .type.

    Mirrors what the rescuer sees in a LangGraph final state: real message
    objects expose tool_calls as an attribute (dict-shaped messages were also
    tolerated historically and stay tolerated).
    """

    def __init__(self, tool_calls=None, text="", type="ai"):
        self.tool_calls = tool_calls or []
        self.text = text
        self.type = type


class StubAgent:
    """Agent stand-in for run_structured: invoke() replays a fabricated state."""

    def __init__(self, result):
        self._result = result

    def invoke(self, *args, **kwargs):
        return self._result


def tc(name="HunterResult", args=None):
    """One schema-named tool call in the shape extract_structured scans for."""
    return {"name": name, "args": {} if args is None else args}

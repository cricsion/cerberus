"""Universal structured output tool contract helper.

Generates concise, unambiguous instructions for models using LangChain ToolStrategy
or function calling, eliminating markdown JSON text vs tool call ambiguity.
"""
from __future__ import annotations

from typing import Any


def structured_output_contract(
    schema_or_name: Any,
    *,
    guidance: str = "",
) -> str:
    """Format an explicit tool invocation contract for a Pydantic schema or tool name.

    Args:
        schema_or_name: Pydantic model class (e.g. DiscoveryResult, VerdictBatch, TriageBatch)
                        or string tool name.
        guidance: Optional stage-specific guidance (e.g. empty list constraints).

    Returns:
        A formatted contract instructing the model to invoke the specified tool call.
    """
    if hasattr(schema_or_name, "__name__"):
        tool_name = schema_or_name.__name__
    elif isinstance(schema_or_name, str):
        tool_name = schema_or_name
    elif hasattr(schema_or_name, "name"):
        tool_name = getattr(schema_or_name, "name")
    else:
        tool_name = str(schema_or_name)

    guidance_part = f"\n{guidance.strip()}\n" if guidance and guidance.strip() else ""
    return (
        f"## Output Format\n\n"
        f"Submit your final output by invoking the `{tool_name}` tool call.{guidance_part}\n"
        f"You MUST invoke the `{tool_name}` tool call to submit your result. "
        f"Do not output your response as raw text or markdown prose."
    )

"""Threat model synthesizer: transforms research + history into structured SwarmPlan.

Applies the universal structured_output_contract pattern to ensure models use
function calling / tool use and never return empty threat rows.
"""
from __future__ import annotations


def get_synthesizer_contract() -> str:
    """Format the structured output contract for the threat synthesizer."""
    from harness.prompts.contract import structured_output_contract
    from harness.prompts.threat import SwarmPlan

    return structured_output_contract(
        SwarmPlan,
        guidance=(
            "- Submit your complete threat model plan by invoking the `SwarmPlan` tool call.\n"
            "- Do NOT output raw markdown or text; you MUST invoke the `SwarmPlan` tool call.\n"
            "- The `threats` list MUST contain at least 1-8 concrete threat rows (never return an empty list).\n"
            "- Every entry point from section 3 must appear in at least one threat's surface.\n"
            "- Mitigations must provide class-level controls covering the identified threat classes."
        ),
    )
